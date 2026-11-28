package sharedpg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type groupBoundaryCopy struct {
	manifest vault.GroupKeyManifest
	copy     UnverifiedKeyCopy
}

type groupBoundaryWire struct {
	GroupID   string          `json:"groupId"`
	Manifest  string          `json:"manifest"`
	GroupCopy json.RawMessage `json:"groupCopy"`
	RootCopy  json.RawMessage `json:"rootCopy"`
}

func parseBoundaryRootCopies(raw []byte, request AdmissionRequest, roots []vault.KeyRef, holder vault.KeyRef,
	epoch, sequence uint64, columns int) ([]UnverifiedKeyCopy, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrAdmissionResponse
	}
	var result []UnverifiedKeyCopy
	for _, key := range roots {
		if !d.More() {
			return nil, ErrAdmissionResponse
		}
		var item json.RawMessage
		if err := d.Decode(&item); err != nil {
			return nil, ErrAdmissionResponse
		}
		copy, err := parseBoundaryRootCopy(item, request, key, holder, epoch, sequence, columns)
		if err != nil {
			return nil, err
		}
		result = append(result, *copy)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return nil, ErrAdmissionResponse
	}
	return result, nil
}

func parseBoundaryRootCopy(raw []byte, request AdmissionRequest, key, holder vault.KeyRef, epoch, sequence uint64, columns int) (*UnverifiedKeyCopy, error) {
	raw = bytes.TrimSpace(raw)
	parse := func(raw []byte, key, holder vault.KeyRef) (*UnverifiedKeyCopy, error) {
		row, err := snapshotOptionalRow(raw, columns)
		if err != nil || row == nil {
			return nil, ErrAdmissionResponse
		}
		return parseKeyCopyProjection([][][]byte{row}, request, key, holder, epoch, sequence)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return parse(raw, key, holder)
	}
	if columns != 24 {
		return nil, ErrAdmissionResponse
	}
	var wire groupBoundaryWire
	if _, err := strictCatalogObject(raw, wire); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.Manifest) > 2*vault.MaxGroupKeyManifestBytes {
		return nil, ErrAdmissionResponse
	}
	id, ok := treeID([]byte(wire.GroupID))
	if !ok {
		return nil, ErrAdmissionResponse
	}
	body, err := hex.DecodeString(wire.Manifest)
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	m, err := vault.DecodeGroupKeyManifest(body)
	if err != nil || m.WorkspaceID != request.WorkspaceID || m.GroupID != id ||
		m.Key.Key.ID == key.ID || m.Key.Key.ID == holder.ID {
		return nil, ErrAdmissionResponse
	}
	memberCopy, err := parse(wire.GroupCopy, m.Key.Key, holder)
	if err != nil {
		return nil, err
	}
	root, err := parse(wire.RootCopy, key, m.Key.Key)
	if err != nil {
		return nil, err
	}
	if memberCopy.Author != nil || root.Author != nil || memberCopy.Binding.Issuer != m.Signer || root.Binding.Issuer != m.Signer {
		return nil, vault.ErrAuthentication
	}
	root.group = &groupBoundaryCopy{m, *memberCopy}
	return root, nil
}

func (copy UnverifiedKeyCopy) boundaryRecipient() vault.KeyRef {
	if copy.group != nil {
		return copy.group.copy.Binding.Holder
	}
	return copy.Binding.Holder
}

func (s TrustState) advanceBoundaryRootCopy(copy UnverifiedKeyCopy) (TrustState, error) {
	if copy.group == nil {
		return s.AdvanceKeyCopy(copy.Binding, copy.Copy, copy.Author)
	}
	g := copy.group
	if s.Enrollment == nil || g.copy.Binding.Holder != s.Enrollment.Encryption ||
		copy.Binding.Holder != g.manifest.Key.Key || g.copy.Binding.Key != g.manifest.Key.Key ||
		copy.Author != nil || g.copy.Author != nil || copy.Binding.Issuer != g.manifest.Signer || g.copy.Binding.Issuer != g.manifest.Signer {
		return s, vault.ErrAuthentication
	}
	next, err := s.AdvanceGroupKey(g.manifest.GroupID, g.manifest)
	if err != nil {
		return next, err
	}
	pin, err := s.accountTrust()
	if err != nil {
		return next, err
	}
	if err := vault.VerifyKeyCopy(g.copy.Binding, g.copy.Copy, pin.Organisation); err != nil {
		return next, err
	}
	return next, vault.VerifyKeyCopy(copy.Binding, copy.Copy, pin.Organisation)
}

func openBoundaryReleaseRoot(private []byte, copy UnverifiedKeyCopy, issuer vault.KeyCopyTrust,
	manifest vault.BoundaryManifest, trust vault.BoundaryTrust, purpose vault.BoundaryPurpose, committed TrustState) ([]byte, error) {
	if g := copy.group; g != nil {
		if manifest.OwnerUserID != uuid.Nil || committed.Enrollment == nil || g.copy.Binding.Holder != committed.Enrollment.Encryption {
			return nil, vault.ErrAuthentication
		}
		minimum := uint32(committed.Catalog["group-key/"+g.manifest.GroupID.String()].Revision)
		if minimum == 0 {
			return nil, ErrTrustState
		}
		groupSeed, err := vault.OpenGroupKeyCopy(g.manifest, trust.WorkspaceID, g.manifest.GroupID, trust.Signer,
			trust.Organisation, minimum, g.copy.Binding.Holder, private, g.copy.Copy)
		if err != nil {
			return nil, err
		}
		defer vault.Wipe(groupSeed)
		private = groupSeed
	}
	return vault.OpenBoundaryKeyCopy(private, copy.Binding, copy.Copy, issuer, manifest, trust, purpose)
}
