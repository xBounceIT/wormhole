package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

// UserKeyState is the organisation's signed current account key selection. A
// revoked state remains signed and keeps its key references for audit/history.
// Sequence is independent of certificate and password-wrapping revisions.
type UserKeyState struct {
	FormatVersion                uint16    `json:"formatVersion"`
	WorkspaceID                  uuid.UUID `json:"workspaceId"`
	UserID                       uuid.UUID `json:"userId"`
	Sequence                     uint64    `json:"sequence"`
	Active                       bool      `json:"active"`
	Encryption                   KeyRef    `json:"encryption"`
	Signing                      KeyRef    `json:"signing"`
	MinimumEncryptionCertificate uint64    `json:"minimumEncryptionCertificate"`
	MinimumSigningCertificate    uint64    `json:"minimumSigningCertificate"`
	Signer                       KeyRef    `json:"signer"`
	Signature                    []byte    `json:"signature"`
}

// UserKeyTrust must come from independently pinned identity and durable local
// high-water state, not from a database response being verified.
type UserKeyTrust struct {
	WorkspaceID             uuid.UUID
	UserID                  uuid.UUID
	Signer                  KeyRef
	Organisation            ed25519.PublicKey
	MinimumSequence         uint64
	MinimumWrappingRevision uint64
}

func (s UserKeyState) signingBytes() ([]byte, error) {
	if s.FormatVersion > FormatVersion {
		return nil, ErrNewerFormat
	}
	if s.FormatVersion != FormatVersion || s.WorkspaceID == uuid.Nil || s.UserID == uuid.Nil || s.Sequence == 0 || s.Sequence > math.MaxInt64 || s.MinimumEncryptionCertificate == 0 || s.MinimumEncryptionCertificate > math.MaxInt64 || s.MinimumSigningCertificate == 0 || s.MinimumSigningCertificate > math.MaxInt64 {
		return nil, ErrFormat
	}
	if s.Encryption.ID == s.Signing.ID || s.Encryption.ID == s.Signer.ID || s.Signing.ID == s.Signer.ID {
		return nil, ErrFormat
	}
	for _, key := range []KeyRef{s.Encryption, s.Signing, s.Signer} {
		if key.ID == uuid.Nil || key.Version == 0 || key.Version > math.MaxInt32 {
			return nil, ErrFormat
		}
	}
	s.Signature = nil
	body, err := json.Marshal(s)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/user-key-state", body), nil
}

func SignUserKeyState(state UserKeyState, organisation ed25519.PrivateKey) (UserKeyState, error) {
	if len(organisation) != ed25519.PrivateKeySize {
		return UserKeyState{}, ErrFormat
	}
	body, err := state.signingBytes()
	if err != nil {
		return UserKeyState{}, err
	}
	state.Signature = ed25519.Sign(organisation, body)
	return state, nil
}

// VerifyUserKeyState authenticates selection, sequence and active status, including
// valid revocations which callers must persist before refusing unlock. A client
// cannot detect an unseen newer state without an independent freshness source;
// persisting MinimumSequence prevents replay of states it has already superseded.
func VerifyUserKeyState(state UserKeyState, trust UserKeyTrust) error {
	body, err := state.signingBytes()
	if err != nil {
		return err
	}
	if len(trust.Organisation) != ed25519.PublicKeySize || state.WorkspaceID != trust.WorkspaceID || state.UserID != trust.UserID || state.Signer != trust.Signer || !ed25519.Verify(trust.Organisation, body, state.Signature) {
		return ErrAuthentication
	}
	if state.Sequence < trust.MinimumSequence {
		return ErrRollback
	}
	return nil
}

// OpenCurrentUserKeys requires signed current selection in addition to both key
// certificates. The caller must durably advance trusted high-water marks before
// publishing unlocked state, including the sequence of an authentic revocation.
func OpenCurrentUserKeys(master []byte, binding UserKeyBinding, envelope Envelope, encryption, signing UserKeyCertificate, state UserKeyState, trust UserKeyTrust) (*UserKeys, error) {
	if err := VerifyUserKeyState(state, trust); err != nil {
		return nil, err
	}
	if !state.Active {
		return nil, ErrPolicy
	}
	if binding.WorkspaceID != state.WorkspaceID || binding.UserID != state.UserID || binding.Encryption != state.Encryption || binding.Signing != state.Signing {
		return nil, ErrAuthentication
	}
	if binding.Revision < trust.MinimumWrappingRevision {
		return nil, ErrRollback
	}
	return OpenCertifiedUserKeys(master, binding, envelope, encryption, signing, trust.Signer, trust.Organisation, state.MinimumEncryptionCertificate, state.MinimumSigningCertificate)
}
