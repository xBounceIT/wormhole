package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"sync/atomic"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxCredentialReleaseBytes = 64 * 1024 * 1024

type credentialReleaseWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Profile       string          `json:"profile"`
	Metadata      json.RawMessage `json:"metadata"`
	Account       json.RawMessage `json:"account"`
	Roots         json.RawMessage `json:"roots"`
	Accounts      json.RawMessage `json:"accounts"`
}

type inlineCredentialReleaseWire struct {
	credentialReleaseWire
	NodeFields json.RawMessage `json:"nodeFields"`
}

type enrolledCredentialReleaseWire struct {
	inlineCredentialReleaseWire
	Enrollment *string `json:"enrollment"`
}

type credentialReleaseAccountWire struct {
	Account string          `json:"account"`
	Values  json.RawMessage `json:"values"`
	Copies  json.RawMessage `json:"copies"`
}

type credentialReleaseAccount struct {
	role     string
	boundary uuid.UUID
	values   []UnverifiedSharedValue
	copies   []UnverifiedKeyCopy
}

// UnverifiedCredentialRelease contains only encrypted material. Its private
// fields are constructed together by the bounded decoder; neither parsing nor
// possession confers Use/Reveal permission or permits private-key operations.
type UnverifiedCredentialRelease struct {
	metadata   *UnverifiedConnectionSnapshot
	profile    []byte
	account    vault.UserKeyState
	roots      []UnverifiedKeyCopy
	accounts   []credentialReleaseAccount
	inline     *UnverifiedSelectionRecord
	enrollment *vault.UserEnrollmentCertificate
	pairedRDP  bool
	rdpGateway *UnverifiedCredentialRelease
}

func releaseKeyRef(row [][]byte, column int) (vault.KeyRef, error) {
	id, ok := treeID(row[column])
	version, vok := treeNumber(row[column+1], 1, math.MaxInt32)
	if !ok || !vok {
		return vault.KeyRef{}, ErrAdmissionResponse
	}
	return vault.KeyRef{ID: id, Version: uint32(version)}, nil
}

func releaseRootLabel(ref vault.KeyRef) string {
	return ref.ID.String() + "/" + strconv.FormatUint(uint64(ref.Version), 10)
}

func parseCredentialRelease(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedCredentialRelease, error) {
	return parseCredentialPathRelease(raw, request, node, epoch, sequence, "")
}

func parseCredentialPathRelease(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64, rdpPath string) (*UnverifiedCredentialRelease, error) {
	if len(raw) == 0 || len(raw) > MaxCredentialReleaseBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	var version struct {
		FormatVersion uint16 `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &version) != nil {
		return nil, ErrAdmissionResponse
	}
	if version.FormatVersion > 6 {
		return nil, vault.ErrNewerFormat
	}
	if version.FormatVersion == 6 {
		if rdpPath != "" {
			return nil, ErrAdmissionResponse
		}
		return parseRDPRelease(raw, request, node, epoch, sequence)
	}
	var wire credentialReleaseWire
	var nodeFields json.RawMessage
	var enrollment *string
	if version.FormatVersion == 5 {
		var extended enrolledCredentialReleaseWire
		if _, e := strictCatalogObject(raw, extended, "nodeFields", "enrollment"); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &extended) != nil {
			return nil, ErrAdmissionResponse
		}
		wire, nodeFields, enrollment = extended.credentialReleaseWire, extended.NodeFields, extended.Enrollment
	} else if version.FormatVersion == 3 || version.FormatVersion == 4 {
		var extended inlineCredentialReleaseWire
		if _, e := strictCatalogObject(raw, extended, "nodeFields"); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &extended) != nil {
			return nil, ErrAdmissionResponse
		}
		wire, nodeFields = extended.credentialReleaseWire, extended.NodeFields
	} else {
		if _, e := strictCatalogObject(raw, wire); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &wire) != nil {
			return nil, ErrAdmissionResponse
		}
	}
	if (wire.FormatVersion != 2 && wire.FormatVersion != 3 && wire.FormatVersion != 4 && wire.FormatVersion != 5) || len(wire.Profile) == 0 || len(wire.Profile) > 2*65536 {
		return nil, ErrAdmissionResponse
	}
	material, e := parseConnectionMaterial(wire.Profile, wire.Account, wire.Metadata, request, node, epoch, sequence)
	if e != nil {
		return nil, e
	}
	metadata := material.metadata
	// Format four binds the selected tunnel manifest and settings account.
	path := metadata.records.Path
	if rdpPath != "" {
		if wire.FormatVersion != 5 || path != rdpPath || metadata.plan.Protocol != 1 || metadata.plan.GatewayCredentialID != "" ||
			metadata.records.Gateway != nil {
			return nil, ErrAdmissionResponse
		}
	} else if path == WebConnectionPlanPath {
		if wire.FormatVersion != 5 || DefaultPlanPath(metadata.plan.Protocol) != path || metadata.plan.TunnelID == "" ||
			metadata.plan.Credential.Kind != "none" || metadata.records.Credential != nil || metadata.records.Gateway != nil {
			return nil, ErrAdmissionResponse
		}
	} else if wire.FormatVersion < 5 && ((wire.FormatVersion == 4) != (metadata.plan.TunnelID != "") || metadata.format >= 3) ||
		wire.FormatVersion == 5 && (metadata.format < 3 || metadata.format == 4 && (!credentialReleasePath(path) || path == "rdp")) {
		return nil, ErrAdmissionResponse
	}
	state := material.account
	result := &UnverifiedCredentialRelease{metadata: metadata, profile: material.profile, account: state}
	holder := state.Encryption
	columns := 23
	if wire.FormatVersion == 5 {
		columns = 24
		if enrollment != nil {
			if len(*enrollment) == 0 || len(*enrollment) > vault.MaxUserEnrollmentCertificateBytes*2 {
				return nil, ErrAdmissionResponse
			}
			raw, e := hex.DecodeString(*enrollment)
			if e != nil {
				return nil, ErrAdmissionResponse
			}
			c, e := vault.DecodeUserEnrollmentCertificate(raw)
			if e != nil || c.Manifest.Context.WorkspaceID != request.WorkspaceID || c.Manifest.Context.UserID != request.UserID {
				return nil, ErrAdmissionResponse
			}
			result.enrollment = &c
			holder = vault.KeyRef{ID: c.Rekey.EncryptionKeyID, Version: c.Rekey.KeyVersion}
		}
	}
	manifests := make(map[uuid.UUID]vault.BoundaryManifest, len(metadata.manifests))
	for _, m := range metadata.manifests {
		manifests[m.BoundaryID] = m
	}
	type profile struct {
		role, kind      string
		owner, boundary uuid.UUID
		fields          []vaultstore.CredentialField
	}
	var profiles []profile
	if metadata.plan.Credential.Kind == "inline" {
		if (wire.FormatVersion != 3 && wire.FormatVersion != 4 && wire.FormatVersion != 5) || metadata.plan.Credential.NodeID != node.String() || metadata.records.Credential != nil {
			return nil, ErrAdmissionResponse
		}
		row, e := snapshotOptionalRow(nodeFields, columns)
		if e != nil || row == nil {
			return nil, ErrAdmissionResponse
		}
		r, a, e := parseSelectionProjection([][][]byte{row}, request, sharedcatalog.SelectionScope{Kind: "node-fields", Subject: node}, epoch, sequence)
		if e != nil {
			return nil, e
		}
		leaf := metadata.records.Chain[0].Node
		if r.Boundary != leaf.Boundary || r.Seal.Revision != leaf.Seal.Revision {
			return nil, ErrAdmissionResponse
		}
		record := r.Record.(sharedcatalog.NodeFieldsRecord)
		result.inline = &UnverifiedSelectionRecord{Selection: *r, Author: *a}
		profiles = append(profiles, profile{"inline", "node", node, r.Boundary, record.Fields})
	} else if len(nodeFields) > 0 && !bytes.Equal(bytes.TrimSpace(nodeFields), []byte("null")) {
		return nil, ErrAdmissionResponse
	}
	for i, r := range []*UnverifiedCredentialRecord{metadata.records.Credential, metadata.records.Gateway} {
		if r == nil {
			continue
		}
		roles := []string{"primary", "gateway"}
		profiles = append(profiles, profile{roles[i], "credential", uuid.MustParse(r.Credential.Record.Metadata.ID), r.Credential.Boundary, r.Credential.Record.Fields})
	}
	if r := metadata.records.Tunnel; r != nil && rdpPath != "rdp-gateway" {
		tunnel := r.Selection.Record.(sharedcatalog.TunnelRecord)
		profiles = append(profiles, profile{"tunnel", "tunnel", uuid.MustParse(tunnel.Metadata.ID), r.Selection.Boundary, []vaultstore.CredentialField{{Field: "settings", Version: tunnel.ConfigurationVersion, Present: !tunnel.Deleted}}})
	}
	rootRefs := make(map[vault.KeyRef]bool)
	// A DEK belongs to one secret. Primary and gateway may legitimately select
	// the exact same credential/field, but distinct secrets cannot share its DEK.
	type owner struct{ kind, id, field string }
	dekOwners := make(map[vault.KeyRef]owner)
	d := json.NewDecoder(bytes.NewReader(wire.Accounts))
	token, e := d.Token()
	if e != nil || token != json.Delim('[') {
		return nil, ErrAdmissionResponse
	}
	for _, profile := range profiles {
		if !d.More() {
			return nil, ErrAdmissionResponse
		}
		var section json.RawMessage
		if d.Decode(&section) != nil {
			return nil, ErrAdmissionResponse
		}
		var w credentialReleaseAccountWire
		if _, e := strictCatalogObject(section, w); e != nil {
			return nil, e
		}
		if json.Unmarshal(section, &w) != nil || w.Account != profile.role {
			return nil, ErrAdmissionResponse
		}
		rows, e := snapshotRows(w.Values, 4, 9)
		if e != nil {
			return nil, e
		}
		values, e := parseManifestValues(rows, request, profile.kind, profile.owner, profile.fields, epoch, sequence)
		if e != nil {
			return nil, e
		}
		rows, e = snapshotRows(w.Copies, 4, columns)
		if e != nil || len(rows) != len(values) {
			return nil, ErrAdmissionResponse
		}
		account := credentialReleaseAccount{role: w.Account, boundary: profile.boundary, values: values}
		m := manifests[account.boundary]
		for j, value := range values {
			holder, e := releaseKeyRef(rows[j], 5)
			if e != nil || (holder != m.Secret.Key && (m.PreviousSecret == nil || holder != m.PreviousSecret.Key)) {
				return nil, ErrAdmissionResponse
			}
			copy, e := parseKeyCopyProjection([][][]byte{rows[j]}, request, value.Binding.DEK, holder, epoch, sequence)
			if e != nil {
				return nil, e
			}
			who := owner{value.Binding.OwnerKind, value.Binding.OwnerID.String(), value.Binding.Field}
			if old, ok := dekOwners[value.Binding.DEK]; ok && old != who {
				return nil, ErrAdmissionResponse
			}
			dekOwners[value.Binding.DEK] = who
			rootRefs[holder] = true
			account.copies = append(account.copies, *copy)
		}
		result.accounts = append(result.accounts, account)
	}
	if token, e = d.Token(); e != nil || token != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return nil, ErrAdmissionResponse
	}
	if len(rootRefs) > 6 {
		return nil, ErrAdmissionResponse
	}
	refs := make([]vault.KeyRef, 0, len(rootRefs))
	for ref := range rootRefs {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return releaseRootLabel(refs[i]) < releaseRootLabel(refs[j]) })
	result.roots, e = parseBoundaryRootCopies(wire.Roots, request, refs, holder, epoch, sequence, columns)
	if e != nil {
		return nil, e
	}
	return result, nil
}

// VerifiedCredentialRelease is a verified ciphertext graph, never a release
// capability. The owning operation must commit the returned TrustState BEFORE
// any private-key operation, and independently authorize/audit its connection.
// No mutable response data is exposed to its callers.
type VerifiedCredentialRelease struct {
	graph      *UnverifiedCredentialRelease
	trust      TrustState
	plan       resolver.Plan
	used       atomic.Bool
	rdpGateway *VerifiedCredentialRelease
}

// VerifyCredentialRelease authenticates the account, all steering metadata,
// manifests and copy issuers as one coherent observation. A nonzero returned
// state must be persisted even on error. No prepared graph is returned on error.
func (s TrustState) VerifyCredentialRelease(ctx context.Context, node uuid.UUID, graph *UnverifiedCredentialRelease) (observed TrustState, verified *VerifiedCredentialRelease, err error) {
	if graph != nil && graph.pairedRDP && graph.rdpGateway != nil {
		return s.verifyRDPRelease(ctx, node, graph)
	}
	return s.verifyCredentialPathRelease(ctx, node, graph)
}

func (s TrustState) verifyCredentialPathRelease(ctx context.Context, node uuid.UUID, graph *UnverifiedCredentialRelease) (observed TrustState, verified *VerifiedCredentialRelease, err error) {
	if ctx == nil || graph == nil || graph.metadata == nil || node == uuid.Nil {
		return TrustState{}, nil, ErrConfiguration
	}
	if !s.valid() || s.Account == nil || !s.Account.Active {
		return TrustState{}, nil, ErrTrustState
	}
	observed = cloneTrustState(s)
	changed := false
	defer func() {
		if changed {
			observed.Revision = s.Revision + 1
		}
		if err == nil {
			// Detach the exported unverified container: its caller may replace
			// the whole value after verification. Nested fields remain private.
			frozen := *graph
			verified = &VerifiedCredentialRelease{graph: &frozen, trust: cloneTrustState(observed), plan: graph.metadata.plan}
		}
	}()
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
	}
	next, _, e := observed.verifyConnectionMaterial(ctx, node, graph.metadata, graph.profile, graph.account)
	absorb(next)
	if e != nil {
		return observed, nil, e
	}
	// Native enrollment pins are established by the protected join flow, never
	// first-use SQL. A current source chain must match that existing final pair.
	if graph.enrollment != nil {
		if s.Enrollment == nil || observed.Account.Encryption != s.Account.Encryption || observed.Account.Signing != s.Account.Signing {
			return observed, nil, vault.ErrAuthentication
		}
		next, e := observed.AdvanceEnrollment(*graph.enrollment, observed.WrappingRevision)
		absorb(next)
		if e != nil {
			return observed, nil, e
		}
	} else if s.Enrollment != nil {
		return observed, nil, vault.ErrAuthentication
	}
	if graph.inline != nil {
		next, e := observed.AdvanceSelection(graph.inline.Selection, graph.inline.Author)
		absorb(next)
		if e != nil {
			return observed, nil, e
		}
	}
	authors := map[uuid.UUID]uint64{s.UserID: graph.account.Sequence}
	inconsistent := false
	remember := func(a *UnverifiedNodeAuthor) {
		if a == nil {
			return // Independently pinned org copy.
		}
		user, sequence := a.State.UserID, a.State.Sequence
		if old, ok := authors[user]; ok && old != sequence {
			inconsistent = true
		}
		authors[user] = sequence
	}
	if graph.inline != nil {
		remember(&graph.inline.Author)
	}
	for _, r := range graph.metadata.records.Chain {
		remember(&r.Author)
	}
	for _, r := range []*UnverifiedSelectionRecord{graph.metadata.records.Override, graph.metadata.records.Slot, graph.metadata.records.SlotValue, graph.metadata.records.Tunnel} {
		if r != nil {
			remember(&r.Author)
		}
	}
	for _, r := range []*UnverifiedCredentialRecord{graph.metadata.records.Credential, graph.metadata.records.Gateway} {
		if r != nil {
			remember(&r.Author)
		}
	}
	verifyCopy := func(copy UnverifiedKeyCopy) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		next, e := observed.AdvanceKeyCopy(copy.Binding, copy.Copy, copy.Author)
		absorb(next)
		if e == nil {
			remember(copy.Author)
		}
		return e
	}
	for _, copy := range graph.roots {
		if e := ctx.Err(); e != nil {
			return observed, nil, e
		}
		next, e := observed.advanceBoundaryRootCopy(copy)
		absorb(next)
		if e != nil {
			return observed, nil, e
		}
		remember(copy.Author)
	}
	for _, account := range graph.accounts {
		for _, copy := range account.copies {
			if e := verifyCopy(copy); e != nil {
				return observed, nil, e
			}
		}
	}
	if e := ctx.Err(); e != nil {
		return observed, nil, e
	}
	if inconsistent {
		return observed, nil, ErrTreeSnapshotChanged
	}
	if observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		return observed, nil, vault.ErrAuthentication
	}
	return observed, nil, nil
}
