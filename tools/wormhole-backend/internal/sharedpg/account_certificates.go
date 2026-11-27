package sharedpg

import (
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountKeyMaterialColumns = `SELECT workspace_id::text,user_id::text,encryption_key_id::text,encryption_key_version::text,
signing_key_id::text,signing_key_version::text,wrap_revision::text,kdf_preset,ask_required::text,
pg_catalog.encode(nonce,'hex'),pg_catalog.encode(ciphertext,'hex'),auth_epoch::text,
enc_suite::text,pg_catalog.encode(enc_public,'hex'),enc_signer_id::text,enc_signer_version::text,enc_cert_revision::text,pg_catalog.encode(enc_signature,'hex'),
sign_suite::text,pg_catalog.encode(sign_public,'hex'),sign_signer_id::text,sign_signer_version::text,sign_cert_revision::text,pg_catalog.encode(sign_signature,'hex')`

const accountKeyMaterialSQL = accountKeyMaterialColumns + ` FROM wormhole_api_v1.account_key_material(pg_catalog.decode($1,'hex'))`

func parseAccountKeyMaterial(rows [][][]byte, request AdmissionRequest, epoch uint64) (*UnverifiedAccountKeys, error) {
	if len(rows) != 1 || len(rows[0]) != 24 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	result, err := parseAccountKeys([][][]byte{row[:12]}, request, epoch)
	if err != nil {
		return nil, err
	}
	certificates, err := parseUserKeyCertificates(row[12:], result.Binding)
	if err != nil {
		return nil, err
	}
	result.EncryptionCertificate, result.SigningCertificate = certificates[0], certificates[1]
	return result, nil
}

// Binding is structural until the caller verifies the organisation signatures.
func parseUserKeyCertificates(row [][]byte, binding vault.UserKeyBinding) ([2]*vault.UserKeyCertificate, error) {
	certificates := [2]*vault.UserKeyCertificate{}
	if len(row) != 12 {
		return certificates, ErrAdmissionResponse
	}
	for i, start := range []int{0, 6} {
		suite := uint16(vault.SuiteX25519HKDFSHA256AES256GCM)
		kind := "user-enc"
		key := binding.Encryption
		if i == 1 {
			suite = 1
			kind = "user-sign"
			key = binding.Signing
		}
		if string(row[start]) != strconv.FormatUint(uint64(suite), 10) {
			return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
		}
		if len(row[start+1]) != 64 || len(row[start+5]) != 128 {
			return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
		}
		public, e := hex.DecodeString(string(row[start+1]))
		signature, e2 := hex.DecodeString(string(row[start+5]))
		if e != nil || e2 != nil {
			return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
		}
		signer, e := uuid.Parse(string(row[start+2]))
		if e != nil || signer == uuid.Nil || signer == key.ID || signer.String() != string(row[start+2]) {
			return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
		}
		version, e := strconv.ParseUint(string(row[start+3]), 10, 32)
		revision, e2 := strconv.ParseUint(string(row[start+4]), 10, 64)
		if e != nil || e2 != nil || version == 0 || version > math.MaxInt32 || revision == 0 || revision > math.MaxInt64 || strconv.FormatUint(version, 10) != string(row[start+3]) || strconv.FormatUint(revision, 10) != string(row[start+4]) {
			return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
		}
		certificates[i] = &vault.UserKeyCertificate{FormatVersion: vault.FormatVersion, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: key, Kind: kind, Suite: suite, PublicKey: public, Revision: revision, Signer: vault.KeyRef{ID: signer, Version: uint32(version)}, Signature: signature}
	}
	if certificates[0].Signer != certificates[1].Signer {
		return [2]*vault.UserKeyCertificate{}, ErrAdmissionResponse
	}
	return certificates, nil
}
