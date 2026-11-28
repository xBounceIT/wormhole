package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const nodeOverrideSignature = "wormhole_api_v1.node_credential_override(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,bigint,bigint,bigint,uuid,bytea)"
const nodeOverrideSQL = `SELECT status,epoch::text,change_seq::text,node_chain::text,override_row::text,credential_row::text
 FROM wormhole_api_v1.node_credential_override(` + serverCAArguments + `,$10::uuid,$11,$12,$13::bigint,$14::bigint,$15::bigint,$16::uuid,pg_catalog.decode($17,'hex'))`

type NodeOverrideChoice struct {
	NodeID       string `json:"nodeId"`
	NodeName     string `json:"nodeName"`
	UserID       string `json:"userId"`
	Protocol     string `json:"protocol"`
	Scope        string `json:"scope"`
	Name         string `json:"credentialName"`
	CredentialID string `json:"credentialId"`
	Provider     string `json:"provider"`
	Epoch        string `json:"epoch"`
	Sequence     string `json:"changeSeq"`
	Revision     string `json:"overrideRevision"`
}

type NodeOverrideReview struct {
	Choice                          NodeOverrideChoice
	workspace, user, node, boundary uuid.UUID
	scope, name, current, selected  string
	epoch, sequence, revision       uint64
	overrideSeal, credentialSeal    []byte
	confirmation                    string
}

func (r *NodeOverrideReview) Unchanged() bool { return r.current == r.selected }

func (r *NodeOverrideReview) Confirmation() string { return r.confirmation }

func (s *Session) NodeOverrideSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, "SELECT (pg_catalog.to_regprocedure('"+nodeOverrideSignature+"') IS NOT NULL)::text")
}

func (s *Session) ReadNodeOverride(ctx context.Context, t TrustState, tls *VerifiedTLSBundle, node uuid.UUID, scope, name string) (TrustState, *NodeOverrideReview, string, error) {
	if ctx == nil || node == uuid.Nil || (scope != "personal" && scope != "shared" && scope != "inherit") || (scope == "inherit") != (name == "") || (name != "" && !adminGroupText(name, 1024)) {
		return t, nil, "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(t, tls); err != nil {
		return t, nil, "", err
	}
	return s.queryNodeOverride(ctx, t, node, scope, name, "review", [][]byte{nil, nil, nil, nil, nil})
}

func (s *Session) queryNodeOverride(ctx context.Context, t TrustState, node uuid.UUID, scope, name, expected string, write [][]byte) (TrustState, *NodeOverrideReview, string, error) {
	args := append([][]byte{[]byte(node.String()), []byte(scope), []byte(name)}, write...)
	var review *NodeOverrideReview
	var status string
	err := s.queryServerCA(ctx, t, nodeOverrideSQL, args, MaxConnectionSnapshotBytes+2*adminSlotPageMaxBytes, 1, 6, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 6 {
			return ErrAdmissionResponse
		}
		var err error
		t, review, status, err = verifyNodeOverride(ctx, t, node, scope, name, expected, rows[0])
		return err
	})
	return t, review, status, err
}

func verifyNodeOverride(ctx context.Context, t TrustState, node uuid.UUID, scope, name, expected string, row [][]byte) (observed TrustState, review *NodeOverrideReview, status string, err error) {
	if len(row) != 6 {
		return t, nil, "", ErrAdmissionResponse
	}
	status = string(row[0])
	if status != expected {
		if (status == "unavailable" || status == "stale" || status == "busy") && row[1] == nil && row[2] == nil && row[3] == nil && row[4] == nil && row[5] == nil {
			return t, nil, status, nil
		}
		return t, nil, "", ErrAdmissionResponse
	}
	epoch, eok := treeNumber(row[1], 1, math.MaxInt64)
	seq, sok := treeNumber(row[2], 0, math.MaxInt64)
	if !eok || !sok || (row[5] == nil) != (scope == "inherit") || len(row[3]) > MaxConnectionSnapshotBytes {
		return t, nil, "", ErrAdmissionResponse
	}
	request := AdmissionRequest{WorkspaceID: t.WorkspaceID, UserID: t.UserID, DeviceID: t.DeviceID}
	chain, err := snapshotNodeChain(row[3], 24, request, epoch, seq)
	if err != nil {
		return t, nil, "", err
	}
	observed, plan, err := t.resolveCatalogChain(ctx, node, chain, "", true)
	if err != nil {
		return observed, nil, "", err
	}
	family := resolver.CredentialProtocol(plan.Protocol)
	if family == "" {
		return observed, nil, "", ErrAdmissionResponse
	}
	r := &NodeOverrideReview{workspace: t.WorkspaceID, user: t.UserID, node: node, boundary: chain[0].Node.Boundary, scope: scope, name: name, epoch: epoch, sequence: seq}
	r.Choice = NodeOverrideChoice{NodeID: node.String(), NodeName: chain[0].Node.Metadata.Name, UserID: t.UserID.String(), Protocol: family, Scope: scope, Name: name, Epoch: string(row[1]), Sequence: string(row[2]), Revision: "0"}
	// Each independently signed row belongs to one snapshot and one durable trust update.
	changed := observed.Revision != t.Revision
	observed.Revision = t.Revision
	defer func() {
		if changed {
			observed.Revision = t.Revision + 1
		}
	}()
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != t.Revision
			next.Revision = t.Revision
			observed = next
		}
	}
	authors := make(map[uuid.UUID]uint64)
	for _, item := range chain {
		authors[item.Author.State.UserID] = item.Author.State.Sequence
	}
	consistent := func(a *UnverifiedNodeAuthor) bool {
		user, sequence := a.State.UserID, a.State.Sequence
		old, seen := authors[user]
		authors[user] = sequence
		return !seen || old == sequence
	}
	if row[4] == nil {
		if _, seen := observed.Catalog["override/"+node.String()+"/"+t.UserID.String()]; seen || expected == "saved" {
			return observed, nil, "", ErrAdmissionResponse
		}
	} else {
		wire, err := snapshotOptionalRow(row[4], 24)
		if err != nil {
			return observed, nil, "", err
		}
		input, author, err := parseSelectionProjection([][][]byte{wire}, request, sharedcatalog.SelectionScope{Kind: "override", Subject: node, User: t.UserID}, epoch, seq)
		if err != nil {
			return observed, nil, "", err
		}
		record := input.Record.(sharedcatalog.OverrideRecord)
		next, err := observed.AdvanceSelection(*input, *author)
		absorb(next)
		if err != nil && !(record.Deleted && errors.Is(err, vaultstore.ErrMissing)) {
			return observed, nil, "", err
		}
		if !consistent(author) {
			return observed, nil, "", ErrTreeSnapshotChanged
		}
		r.revision, r.boundary = input.Seal.Revision, input.Boundary
		r.overrideSeal = input.Seal.Signature
		r.Choice.Revision = strconv.FormatUint(r.revision, 10)
		if !record.Deleted {
			r.current = record.CredentialID
		}
	}
	if row[5] != nil {
		wire, err := snapshotOptionalRow(row[5], 24)
		if err != nil || len(wire) != 24 {
			return observed, nil, "", ErrAdmissionResponse
		}
		id, ok := treeID(wire[1])
		if !ok {
			return observed, nil, "", ErrAdmissionResponse
		}
		c, author, err := parseCredentialProjection([][][]byte{wire}, request, id, epoch, seq)
		if err != nil {
			return observed, nil, "", err
		}
		next, err := observed.AdvanceCredential(*c, *author)
		absorb(next)
		if err != nil {
			return observed, nil, "", err
		}
		meta := c.Record.Metadata
		if !consistent(author) || meta.Name != name || meta.Protocol != family ||
			(scope == "personal" && (meta.OwnerUserID != t.UserID.String() || (meta.Provider != "local" && meta.Provider != "bitwarden"))) ||
			(scope == "shared" && (meta.OwnerUserID != "" || meta.Provider != "local")) {
			return observed, nil, "", ErrAdmissionResponse
		}
		r.Choice.CredentialID, r.Choice.Provider = meta.ID, meta.Provider
		r.selected, r.credentialSeal = meta.ID, c.Seal.Signature
	}
	if expected == "review" && r.revision >= math.MaxInt64 {
		return observed, nil, "unavailable", nil
	}
	// Bind the user's confirmation to every signed input, including ancestor
	// changes that leave the displayed connection and credential names intact.
	encoded, err := json.Marshal(r.Choice)
	if err != nil {
		return observed, nil, "", err
	}
	digest := sha256.New()
	digest.Write(t.WorkspaceID[:])
	digest.Write(encoded)
	for _, item := range chain {
		digest.Write(item.Node.Seal.Signature)
	}
	digest.Write(r.overrideSeal)
	digest.Write(r.credentialSeal)
	r.confirmation = hex.EncodeToString(digest.Sum(nil))
	return observed, r, status, nil
}

func (s *Session) CommitNodeOverride(ctx context.Context, t TrustState, tls *VerifiedTLSBundle, r *NodeOverrideReview, keys *vault.UserKeys) (TrustState, string, error) {
	if ctx == nil || r == nil || r.workspace != t.WorkspaceID || r.user != t.UserID || r.node == uuid.Nil || r.boundary == uuid.Nil || r.revision >= math.MaxInt64 || keys == nil {
		return t, "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(t, tls); err != nil {
		return t, "", err
	}
	pub, err := keys.Public()
	if err != nil {
		return t, "", err
	}
	digest := enrollmentPublicDigest(pub)
	if !bytes.Equal(digest[:], t.Enrollment.PublicDigest) {
		return t, "", vault.ErrAuthentication
	}
	if r.Unchanged() {
		return t, "unchanged", nil
	}
	record := sharedcatalog.OverrideRecord{UserID: t.UserID.String(), NodeID: r.node.String(), CredentialID: r.selected, Deleted: r.selected == ""}
	key := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignSelection(t.WorkspaceID, r.boundary, record, r.revision+1, t.Enrollment.Signing, key)
	if err != nil {
		return t, "", err
	}
	var id []byte
	if r.selected != "" {
		id = []byte(r.selected)
	}
	write := [][]byte{strconv.AppendUint(nil, r.epoch, 10), strconv.AppendUint(nil, r.sequence, 10), strconv.AppendUint(nil, r.revision, 10), id, hex.AppendEncode(nil, seal.Signature)}
	next, receipt, status, err := s.queryNodeOverride(ctx, t, r.node, r.scope, r.name, "saved", write)
	if err == nil && receipt != nil && (receipt.current != r.selected || receipt.revision != r.revision+1 || receipt.boundary != r.boundary || !bytes.Equal(receipt.credentialSeal, r.credentialSeal) ||
		receipt.epoch != r.epoch || receipt.sequence <= r.sequence || !bytes.Equal(receipt.overrideSeal, seal.Signature)) {
		return next, "", vault.ErrAuthentication
	}
	return next, status, err
}
