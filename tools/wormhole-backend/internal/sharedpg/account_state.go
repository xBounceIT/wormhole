package sharedpg

import (
	"context"
	"encoding/hex"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountKeyStateSQL = `SELECT pg_catalog.encode(signed_state,'hex'),state_sequence::text FROM wormhole_api_v1.account_key_state(pg_catalog.decode($1,'hex'))`

// The first 24 columns exactly match the existing certificate/capsule decoder.
const accountUnlockMaterialSQL = accountKeyMaterialColumns + `,pg_catalog.encode(signed_state,'hex'),state_sequence::text FROM wormhole_api_v1.account_unlock_material(pg_catalog.decode($1,'hex'))`

// AccountKeyState can retrieve an authenticated user's signed revocation even if
// its old capsule/certificates are unavailable. The signature is still unverified.
func (s *Session) AccountKeyState(ctx context.Context) (*vault.UserKeyState, error) {
	result, err := s.accountKeys(ctx, accountStateOnly)
	if err != nil {
		return nil, err
	}
	return result.State, nil
}

// AccountUnlockMaterial retrieves state, certificates and capsule in one server
// transaction. No fallback occurs when provisioning is incomplete.
func (s *Session) AccountUnlockMaterial(ctx context.Context) (*UnverifiedAccountKeys, error) {
	return s.accountKeys(ctx, accountUnlock)
}

func parseAccountKeyState(rows [][][]byte, request AdmissionRequest) (*vault.UserKeyState, error) {
	if len(rows) != 1 || len(rows[0]) != 2 || len(rows[0][0]) == 0 || len(rows[0][0]) > 2*vault.MaxUserKeyStateBytes {
		return nil, ErrAdmissionResponse
	}
	raw, err := hex.DecodeString(string(rows[0][0]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	state, err := vault.DecodeUserKeyState(raw)
	if err != nil || state.WorkspaceID != request.WorkspaceID || state.UserID != request.UserID || strconv.FormatUint(state.Sequence, 10) != string(rows[0][1]) {
		return nil, ErrAdmissionResponse
	}
	return &state, nil
}

func parseAccountUnlockMaterial(rows [][][]byte, request AdmissionRequest, epoch uint64) (*UnverifiedAccountKeys, error) {
	if len(rows) != 1 || len(rows[0]) != 26 {
		return nil, ErrAdmissionResponse
	}
	material, err := parseAccountKeyMaterial([][][]byte{rows[0][:24]}, request, epoch)
	if err != nil {
		return nil, err
	}
	state, err := parseAccountKeyState([][][]byte{rows[0][24:]}, request)
	if err != nil {
		return nil, err
	}
	if state.Encryption != material.Binding.Encryption || state.Signing != material.Binding.Signing || state.Signer != material.EncryptionCertificate.Signer {
		return nil, ErrAdmissionResponse
	}
	material.State = state
	return material, nil
}
