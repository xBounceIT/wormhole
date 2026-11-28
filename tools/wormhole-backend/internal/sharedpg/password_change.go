package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrPasswordChangeUncertain = errors.New("workspace password change outcome is uncertain; reconciliation is required")

// PreparedPasswordChange is a short-lived, caller-owned native request. It retains
// a credential verifier and ciphertext, never either account master or private
// keys. Do not log it or share it with concurrent Wipe/use operations.
type PreparedPasswordChange struct {
	binding  vault.UserKeyBinding
	envelope vault.Envelope
	verifier []byte
}

// PreparePasswordChange accepts account masters after the same required ASK mix.
// The caller verifies signed policy and preserves its KDF preset/ASK. The old
// capsule must open against independently certified public keys before anything
// can be submitted to PostgreSQL.
func PreparePasswordChange(oldMaster, newMaster []byte, binding vault.UserKeyBinding, envelope vault.Envelope, public vault.UserPublicKeys) (*PreparedPasswordChange, error) {
	next, wrapped, err := vault.RewrapUserKeys(oldMaster, newMaster, binding, envelope, public)
	if err != nil {
		return nil, err
	}
	material, err := vault.DeriveKey(newMaster, nil, vault.PurposeLogin)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(material)
	verifier, err := NewSCRAMVerifier(material)
	if err != nil {
		return nil, err
	}
	return &PreparedPasswordChange{binding: next, envelope: wrapped, verifier: verifier}, nil
}

func (p *PreparedPasswordChange) Wipe() {
	if p == nil {
		return
	}
	vault.Wipe(p.verifier)
	vault.Wipe(p.envelope.Nonce)
	vault.Wipe(p.envelope.Ciphertext)
	p.verifier = nil
	p.envelope = vault.Envelope{}
	p.binding = vault.UserKeyBinding{}
}

func (p *PreparedPasswordChange) validate() error {
	if p == nil || p.binding.Revision < 2 || p.binding.Revision > math.MaxInt64 || p.envelope.FormatVersion != vault.FormatVersion || p.envelope.SuiteID != vault.SuiteAES256GCM || p.envelope.KeyID != p.binding.Encryption.ID.String() || p.envelope.KeyVersion != p.binding.Encryption.Version || len(p.envelope.Nonce) != 12 || len(p.envelope.Ciphertext) != 81 || ValidateSCRAMVerifier(p.verifier) != nil {
		return ErrPasswordChangePayload
	}
	return nil
}

type PasswordChangeReceipt struct {
	WrappingRevision uint64
	AuthEpoch        uint64
}

const changePasswordSQL = `SELECT wrap_revision::text,auth_epoch::text FROM wormhole_api_v1.change_password(
pg_catalog.decode($1,'hex'),$2::bigint,$3::text,pg_catalog.decode($4,'hex'),pg_catalog.decode($5,'hex'),$6::text)`

// ChangePassword submits one autocommit mutation, never retries, and retires the
// owner on committed/uncertain outcomes. A receipt proves the checked committed
// response even when an accompanying ErrSessionCleanup requires Close retries.
// Without a receipt, ErrPasswordChangeUncertain must be reconciled, not resubmitted.
// Known SQL rejections preserve the owner unless identity was invalidated.
func (s *Session) ChangePassword(ctx context.Context, p *PreparedPasswordChange, source string) (receipt *PasswordChangeReceipt, err error) {
	if ctx == nil || (source != "ui" && source != "mcp") {
		return nil, ErrConfiguration
	}
	if err = p.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = take(ctx, s.control); err != nil {
		return nil, err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return nil, ErrAuthentication
	}
	if p.binding.WorkspaceID != s.admission.WorkspaceID || p.binding.UserID != s.admission.UserID {
		return nil, ErrPasswordChangePayload
	}
	if s.authEpoch >= math.MaxInt64 {
		return nil, ErrAccountRevision
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
	if conn.TxStatus() != 'I' {
		return nil, ErrConfiguration
	}
	retire := false
	defer func() {
		if retire || s.lifetime.Err() != nil {
			s.discardConnection(conn)
			s.admission = AdmissionRequest{}
			s.authEpoch = 0
			s.administrator = false
			if s.capability != nil {
				if s.capability.Close() != nil {
					if err != ErrPasswordChangeUncertain {
						err = ErrSessionCleanup
					}
				} else {
					s.capability = nil
				}
			}
		}
	}()
	var rows [][][]byte
	sent := false
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		nonce := hex.AppendEncode(nil, p.envelope.Nonce)
		defer vault.Wipe(nonce)
		ciphertext := hex.AppendEncode(nil, p.envelope.Ciphertext)
		defer vault.Wipe(ciphertext)
		sent = true
		var e error
		rows, e = s.queryLeased(opCtx, conn, changePasswordSQL, [][]byte{encoded, []byte(strconv.FormatUint(p.binding.Revision-1, 10)), p.verifier, nonce, ciphertext, []byte(source)})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		if sent && !knownPasswordChangeRejection(err) {
			retire = true
			return nil, ErrPasswordChangeUncertain
		}
		return nil, err
	}
	retire = true
	if conn.TxStatus() != 'I' || len(rows) != 1 || len(rows[0]) != 2 {
		return nil, ErrPasswordChangeUncertain
	}
	values := [2]uint64{}
	for i := range values {
		value, e := strconv.ParseUint(string(rows[0][i]), 10, 64)
		if e != nil || strconv.FormatUint(value, 10) != string(rows[0][i]) {
			return nil, ErrPasswordChangeUncertain
		}
		values[i] = value
	}
	if values[0] != p.binding.Revision || values[1] != s.authEpoch+1 {
		return nil, ErrPasswordChangeUncertain
	}
	return &PasswordChangeReceipt{WrappingRevision: values[0], AuthEpoch: values[1]}, nil
}

func knownPasswordChangeRejection(err error) bool {
	return err == ErrPasswordChangePayload || err == ErrDeviceCredentials || err == ErrAccountRevision || err == ErrAuditUnavailable || err == ErrChangeInProgress || err == ErrIdentityUnavailable || err == ErrAuthentication || err == ErrTransactionIsolation
}
