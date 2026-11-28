package sharedpg

import (
	"bytes"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxTransportSnapshotBytes = 2 * 1024 * 1024

// transportSnapshot is public metadata, not proof of provenance. Persist only
// inside a protected device setup record. Never accept it from the renderer or
// use its organisation identity as a first-use pin.
type transportSnapshot struct {
	FormatVersion uint16        `json:"formatVersion"`
	Endpoints     []Endpoint    `json:"endpoints"`
	Database      string        `json:"database"`
	DeviceRole    string        `json:"deviceRole"`
	TLS           TLSMode       `json:"tls"`
	Profile       vault.Profile `json:"profile"`
	CAPEM         []byte        `json:"caPem"`
	Bundle        []byte        `json:"bundle"`
	Changes       *ChangePolicy `json:"changes,omitempty"`
}

// EncodeTransportSnapshot retains the actual managed TLS document, which the
// ordinary Settings JSON representation intentionally omits. The trust state
// must already contain its durably accepted TLS high-water mark. No network I/O.
func EncodeTransportSnapshot(s Settings, trust TrustState, osFloor, userFloor vault.Profile, api int32) ([]byte, error) {
	prepared, err := trust.PrepareTransport(s, osFloor, userFloor, api)
	if err != nil {
		return nil, err
	}
	record := transportSnapshot{FormatVersion: 2, Changes: &prepared.Changes, Endpoints: prepared.Endpoints, Database: prepared.Database, DeviceRole: prepared.DeviceRole, TLS: prepared.TLS, Profile: prepared.Profile, CAPEM: prepared.CAPEM}
	if prepared.TLSBundle != nil {
		if trust.TLSSequence == 0 {
			return nil, ErrTrustState
		}
		record.Bundle = prepared.TLSBundle.Encode()
		// Managed roots are obtained solely from the signed bundle.
		record.CAPEM = nil
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > MaxTransportSnapshotBytes {
		return nil, ErrConfiguration
	}
	return raw, nil
}

// DecodeTransportSnapshot authenticates signed TLS against independent trust,
// then reapplies current workspace/OS/user floors. A stale bundle fails closed;
// the setup owner must supply a durably updated snapshot, never silently discard
// the managed bundle or downgrade to unmanaged CA settings.
func DecodeTransportSnapshot(raw []byte, trust TrustState, osFloor, userFloor vault.Profile, api int32) (Settings, error) {
	return decodeTransportSnapshot(raw, trust, osFloor, userFloor, api, nil)
}

// AdvanceTransportSnapshotTLS preserves the enrolled endpoints and role when
// the protected startup anchor adopts a newer, durably accepted managed bundle.
func AdvanceTransportSnapshotTLS(raw []byte, trust TrustState, bundle *VerifiedTLSBundle) ([]byte, error) {
	if bundle == nil {
		return nil, ErrTLSRequired
	}
	settings, err := decodeTransportSnapshot(raw, trust, vault.Default, vault.Default, 1, bundle)
	if err != nil {
		return nil, err
	}
	return EncodeTransportSnapshot(settings, trust, vault.Default, vault.Default, 1)
}

// Parse the persisted format without applying environment-dependent transport
// policy. Rewrapping and opening share the same canonical format boundary.
func decodeTransportSnapshotRecord(raw []byte) (transportSnapshot, error) {
	if len(raw) == 0 || len(raw) > MaxTransportSnapshotBytes {
		return transportSnapshot{}, ErrConfiguration
	}
	var record transportSnapshot
	if json.Unmarshal(raw, &record) != nil ||
		(record.FormatVersion != 1 && record.FormatVersion != 2) ||
		(record.FormatVersion == 1 && record.Changes != nil) ||
		(record.FormatVersion == 2 && record.Changes == nil) {
		return transportSnapshot{}, ErrConfiguration
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return transportSnapshot{}, ErrConfiguration
	}
	return record, nil
}

func decodeTransportSnapshot(raw []byte, trust TrustState, osFloor, userFloor vault.Profile, api int32, replacement *VerifiedTLSBundle) (Settings, error) {
	record, err := decodeTransportSnapshotRecord(raw)
	if err != nil {
		return Settings{}, err
	}
	s := Settings{Endpoints: record.Endpoints, Database: record.Database, DeviceRole: record.DeviceRole, TLS: record.TLS, Profile: record.Profile, CAPEM: record.CAPEM}
	// Legacy records have no pooler metadata: use polling until a native
	// deployment update supplies an explicit policy.
	s.Changes = ChangePolicy{TransactionPooler: true}
	if record.Changes != nil {
		s.Changes = *record.Changes
	}
	if len(record.Bundle) != 0 {
		if len(record.CAPEM) != 0 || record.TLS != TLSVerified || trust.TLSSequence == 0 {
			return Settings{}, ErrConfiguration
		}
		// VerifyTLS checks the organisation, exact sequence/digest floor and signature.
		if replacement != nil {
			record.Bundle, err = replaceHistoricalTransportTLS(record.Bundle, trust, replacement)
			if err != nil {
				return Settings{}, err
			}
		}
		s.TLSBundle, err = trust.VerifyTLS(record.Bundle)
		if err != nil {
			return Settings{}, err
		}
	} else if replacement != nil {
		return Settings{}, ErrConfiguration
	}
	return trust.PrepareTransport(s, osFloor, userFloor, api)
}

// Only a strictly older, genuinely signed managed snapshot can use the current
// cached bundle. Equal-sequence equivocation and unaccepted future sequences must
// not be repaired by discarding evidence. Endpoints and every other setting stay.
func replaceHistoricalTransportTLS(raw []byte, trust TrustState, replacement *VerifiedTLSBundle) ([]byte, error) {
	if !trust.valid() {
		return nil, ErrTrustState
	}
	anchor, err := trust.accountTrust()
	if err != nil {
		return nil, err
	}
	old, err := DecodeTLSTrustBundle(raw)
	if err != nil {
		return nil, err
	}
	if _, err := VerifyTLSTrustBundle(old, TLSTrustPin{WorkspaceID: trust.WorkspaceID, Signer: anchor.Signer, Organisation: anchor.Organisation, MinimumSequence: 1}); err != nil {
		return nil, err
	}
	if old.Sequence >= trust.TLSSequence {
		return nil, vault.ErrRollback
	}
	return replacement.Encode(), nil
}

// transportSetupBinding separates protected connection configuration from trust and
// pending-enrollment ciphertext. The independent native binding is mandatory.
func transportSetupBinding(b TrustBinding) (vault.Binding, error) {
	binding, err := b.binding()
	binding.Table = "SharedConnectionSetup"
	binding.Field += "/transport"
	return binding, err
}

// SealTransportSetup does not establish trust, create a root or persist a file.
// The root and binding come from native unlocked device storage. The caller must
// durably store this ciphertext before an invitation commit can be dispatched.
func SealTransportSetup(root []byte, b TrustBinding, s Settings, trust TrustState, osFloor, userFloor vault.Profile, api int32) ([]byte, error) {
	_, err := transportSetupBinding(b)
	if err != nil || !trust.matches(b) {
		return nil, ErrTrustState
	}
	raw, err := EncodeTransportSnapshot(s, trust, osFloor, userFloor, api)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(raw)
	return sealTransportSetupPayload(root, b, raw)
}

func sealTransportSetupPayload(root []byte, b TrustBinding, raw []byte) ([]byte, error) {
	binding, err := transportSetupBinding(b)
	if err != nil {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(key)
	envelope, err := vault.Seal(key, binding, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// OpenTransportSetup accepts no stored identity as a pin. Binding and current
// trust are supplied independently by the authenticated local device owner.
func OpenTransportSetup(root []byte, b TrustBinding, raw []byte, trust TrustState, osFloor, userFloor vault.Profile, api int32) (Settings, error) {
	return openTransportSetup(root, b, raw, trust, osFloor, userFloor, api, nil)
}

// OpenTransportSetupWithTLS preserves an authenticated historical configuration
// while using the separately cached bundle matching the current durable floor.
// It cannot upgrade an unmanaged setup or accept an uncommitted TLS observation.
func OpenTransportSetupWithTLS(root []byte, b TrustBinding, raw []byte, trust TrustState, osFloor, userFloor vault.Profile, api int32, replacement *VerifiedTLSBundle) (Settings, error) {
	if replacement == nil {
		return Settings{}, ErrConfiguration
	}
	return openTransportSetup(root, b, raw, trust, osFloor, userFloor, api, replacement)
}

func openTransportSetup(root []byte, b TrustBinding, raw []byte, trust TrustState, osFloor, userFloor vault.Profile, api int32, replacement *VerifiedTLSBundle) (Settings, error) {
	if !trust.matches(b) {
		return Settings{}, ErrTrustState
	}
	plain, err := openTransportSetupPayload(root, b, raw)
	if err != nil {
		return Settings{}, err
	}
	defer vault.Wipe(plain)
	return decodeTransportSnapshot(plain, trust, osFloor, userFloor, api, replacement)
}

func openTransportSetupPayload(root []byte, b TrustBinding, raw []byte) ([]byte, error) {
	binding, err := transportSetupBinding(b)
	if err != nil || len(raw) == 0 || len(raw) > MaxTransportSnapshotBytes*2 {
		return nil, ErrTrustState
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return nil, ErrTrustState
	}
	return plain, nil
}
