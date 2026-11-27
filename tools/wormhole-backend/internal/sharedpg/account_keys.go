package sharedpg

import (
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// UnverifiedAccountKeys contains ciphertext and server metadata, not certified
// keys or trusted policy. Before decrypting, the caller must compare Binding to
// its independently authenticated key graph and KDF/ASK to signed policy. Never
// use these unverified fields to weaken derivation requirements.
type UnverifiedAccountKeys struct {
	Binding               vault.UserKeyBinding
	Envelope              vault.Envelope
	KDF                   vault.KDFPreset
	ASKRequired           bool
	EncryptionCertificate *vault.UserKeyCertificate
	SigningCertificate    *vault.UserKeyCertificate
	State                 *vault.UserKeyState
	EnrollmentCertificate *vault.UserEnrollmentCertificate
}

const accountKeysSQL = `SELECT workspace_id::text,user_id::text,encryption_key_id::text,encryption_key_version::text,
signing_key_id::text,signing_key_version::text,wrap_revision::text,kdf_preset,ask_required::text,
pg_catalog.encode(nonce,'hex'),pg_catalog.encode(ciphertext,'hex'),auth_epoch::text
FROM wormhole_api_v1.account_keys(pg_catalog.decode($1,'hex'))`

// AccountKeys fetches the current account's encrypted capsule using its audited
// native capability. It never accepts another user's ID or releases private keys.
func (s *Session) AccountKeys(ctx context.Context) (*UnverifiedAccountKeys, error) {
	return s.accountKeys(ctx, accountCapsule)
}

// AccountKeyMaterial fetches the capsule and both certificates under one server
// transaction. It never falls back to the uncertified schema-6 endpoint. Returned
// signatures still require an independent organisation pin and revision floors.
func (s *Session) AccountKeyMaterial(ctx context.Context) (*UnverifiedAccountKeys, error) {
	return s.accountKeys(ctx, accountCertificates)
}

type accountReadKind uint8

const (
	accountCapsule accountReadKind = iota
	accountCertificates
	accountUnlock
	accountStateOnly
	accountEnrollment
)

func (s *Session) accountKeys(ctx context.Context, kind accountReadKind) (*UnverifiedAccountKeys, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return nil, err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return nil, ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return nil, ErrQuery
	}
	var rows [][][]byte
	statement := accountKeysSQL
	switch kind {
	case accountCapsule:
	case accountCertificates:
		statement = accountKeyMaterialSQL
	case accountUnlock:
		statement = accountUnlockMaterialSQL
	case accountStateOnly:
		statement = accountKeyStateSQL
	case accountEnrollment:
		statement = accountEnrollmentMaterialSQL
	default:
		return nil, ErrConfiguration
	}
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		var e error
		rows, e = s.queryLeased(opCtx, conn, statement, [][]byte{encoded})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	var result *UnverifiedAccountKeys
	switch kind {
	case accountCapsule:
		result, err = parseAccountKeys(rows, s.admission, s.authEpoch)
	case accountCertificates:
		result, err = parseAccountKeyMaterial(rows, s.admission, s.authEpoch)
	case accountUnlock:
		result, err = parseAccountUnlockMaterial(rows, s.admission, s.authEpoch)
	case accountEnrollment:
		result, err = parseAccountEnrollmentMaterial(rows, s.admission, s.authEpoch)
	case accountStateOnly:
		var state *vault.UserKeyState
		state, err = parseAccountKeyState(rows, s.admission)
		if err == nil {
			result = &UnverifiedAccountKeys{State: state}
		}
	}
	if err != nil {
		s.discardConnection(conn)
	}
	return result, err
}

func parseAccountKeys(rows [][][]byte, request AdmissionRequest, epoch uint64) (*UnverifiedAccountKeys, error) {
	if len(rows) != 1 || len(rows[0]) != 12 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	ids := [4]uuid.UUID{}
	for i, col := range []int{0, 1, 2, 4} {
		id, e := uuid.Parse(string(row[col]))
		if e != nil || id == uuid.Nil || id.String() != string(row[col]) {
			return nil, ErrAdmissionResponse
		}
		ids[i] = id
	}
	if ids[0] != request.WorkspaceID || ids[1] != request.UserID || ids[2] == ids[3] {
		return nil, ErrAdmissionResponse
	}
	numbers := [4]uint64{}
	for i, col := range []int{3, 5, 6, 11} {
		value, e := strconv.ParseUint(string(row[col]), 10, 64)
		limit := uint64(math.MaxInt64)
		if i < 2 {
			limit = math.MaxInt32
		}
		if e != nil || value == 0 || value > limit || strconv.FormatUint(value, 10) != string(row[col]) {
			return nil, ErrAdmissionResponse
		}
		numbers[i] = value
	}
	if numbers[3] != epoch {
		return nil, ErrAdmissionResponse
	}
	preset := vault.KDFPreset(row[7])
	if _, err := vault.Parameters(preset); err != nil {
		return nil, ErrAdmissionResponse
	}
	if string(row[8]) != "true" && string(row[8]) != "false" {
		return nil, ErrAdmissionResponse
	}
	if len(row[9]) != 24 || len(row[10]) != 162 {
		return nil, ErrAdmissionResponse
	}
	nonce, e := hex.DecodeString(string(row[9]))
	ciphertext, e2 := hex.DecodeString(string(row[10]))
	if e != nil || e2 != nil {
		return nil, ErrAdmissionResponse
	}
	return &UnverifiedAccountKeys{
		Binding:  vault.UserKeyBinding{WorkspaceID: ids[0], UserID: ids[1], Encryption: vault.KeyRef{ID: ids[2], Version: uint32(numbers[0])}, Signing: vault.KeyRef{ID: ids[3], Version: uint32(numbers[1])}, Revision: numbers[2]},
		Envelope: vault.Envelope{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteAES256GCM, KeyID: ids[2].String(), KeyVersion: uint32(numbers[0]), Nonce: nonce, Ciphertext: ciphertext},
		KDF:      preset, ASKRequired: string(row[8]) == "true",
	}, nil
}
