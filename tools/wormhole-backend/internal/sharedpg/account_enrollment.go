package sharedpg

import (
	"context"
	"encoding/hex"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountEnrollmentMaterialSQL = `SELECT workspace_id::text,user_id::text,encryption_key_id::text,encryption_key_version::text,
signing_key_id::text,signing_key_version::text,wrap_revision::text,kdf_preset,ask_required::text,
pg_catalog.encode(nonce,'hex'),pg_catalog.encode(ciphertext,'hex'),auth_epoch::text,
pg_catalog.encode(signed_state,'hex'),state_sequence::text,pg_catalog.encode(enrollment_certificate,'hex')
FROM wormhole_api_v1.account_enrollment_material(pg_catalog.decode($1,'hex'))`

// AccountEnrollmentMaterial retrieves the committed final capsule and bootstrap
// certification together. Parsing checks bindings only; signatures still require
// independently pinned trust and floors before any private material is opened.
func (s *Session) AccountEnrollmentMaterial(ctx context.Context) (*UnverifiedAccountKeys, error) {
	return s.accountKeys(ctx, accountEnrollment)
}

func parseAccountEnrollmentMaterial(rows [][][]byte, request AdmissionRequest, epoch uint64) (*UnverifiedAccountKeys, error) {
	if len(rows) != 1 || len(rows[0]) != 15 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	material, err := parseAccountKeys([][][]byte{row[:12]}, request, epoch)
	if err != nil {
		return nil, err
	}
	state, err := parseAccountKeyState([][][]byte{row[12:14]}, request)
	if err != nil {
		return nil, err
	}
	if len(row[14]) == 0 || len(row[14]) > 2*vault.MaxUserEnrollmentCertificateBytes {
		return nil, ErrAdmissionResponse
	}
	raw, err := hex.DecodeString(string(row[14]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	certificate, err := vault.DecodeUserEnrollmentCertificate(raw)
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	c := certificate.Manifest.Context
	p := certificate.Rekey
	if c.WorkspaceID != request.WorkspaceID || c.UserID != request.UserID || state.Encryption != (vault.KeyRef{ID: c.KeyID, Version: c.KeyVersion}) ||
		certificate.BootstrapEncryption.Key != state.Encryption || certificate.BootstrapSigning.Key != state.Signing ||
		certificate.BootstrapEncryption.Signer != state.Signer || certificate.BootstrapSigning.Signer != state.Signer ||
		material.Binding.Encryption != (vault.KeyRef{ID: p.EncryptionKeyID, Version: p.KeyVersion}) ||
		material.Binding.Signing != (vault.KeyRef{ID: p.SigningKeyID, Version: p.KeyVersion}) {
		return nil, ErrAdmissionResponse
	}
	material.State = state
	material.EnrollmentCertificate = &certificate
	return material, nil
}
