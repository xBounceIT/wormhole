package sharedpg

import (
	"bytes"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// PrepareTransport authenticates the cached profile before a connection can
// exchange a login proof. It cannot relax any workspace, OS, user or caller floor.
// The receiver must come from authenticated OpenTrustState or NewTrustState;
// signature verification cannot establish the provenance of a caller-supplied pin.
// Endpoints and CA metadata still require authenticated enrollment; this method
// enforces the transport subset, not complete Hardened/Paranoid runtime policy.
func (s TrustState) PrepareTransport(requested Settings, osFloor, userFloor vault.Profile, api int32) (Settings, error) {
	policy, err := s.Policy()
	if err != nil {
		return Settings{}, err
	}
	if api < 1 {
		return Settings{}, ErrConfiguration
	}
	if uint32(api) < policy.MinAPI || uint32(api) > policy.MaxAPI {
		return Settings{}, ErrAPIVersion
	}
	if s.TLSSequence != 0 && requested.TLS == TLSVerified && requested.TLSBundle == nil {
		return Settings{}, ErrConfiguration
	}
	if bundle := requested.TLSBundle; bundle != nil {
		pin := bundle.Pin()
		if pin.WorkspaceID != s.WorkspaceID || pin.Signer.ID.String() != s.SignerKeyID || pin.Signer.Version != s.SignerKeyVersion || !bytes.Equal(pin.Organisation, s.PublicKey) {
			return Settings{}, ErrConfiguration
		}
		if s.TLSSequence != 0 && (pin.MinimumSequence != s.TLSSequence || !bytes.Equal(pin.Digest, s.TLSDigest)) {
			return Settings{}, ErrTrustRollback
		}
	}
	personal := vault.EffectiveProfile(s.PersonalProfile(), userFloor, requested.Profile)
	requested.Profile = vault.EffectiveProfile(osFloor, policy.Profile, personal)
	requested.CAPEM = bytes.Clone(requested.CAPEM)
	requested.Endpoints = append([]Endpoint(nil), requested.Endpoints...)
	if _, err := Config(requested); err != nil {
		return Settings{}, err
	}
	return requested, nil
}
