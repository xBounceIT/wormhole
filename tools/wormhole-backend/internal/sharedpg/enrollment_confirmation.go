package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrEnrollmentConfirmationUncertain = errors.New("device confirmation outcome is uncertain; reconnect and verify enrollment")

const confirmEnrollmentSQL = `SELECT device_id::text,confirmed::text FROM wormhole_api_v1.confirm_enrollment(pg_catalog.decode($1,'hex'),pg_catalog.decode($2,'hex'))`

// ConfirmEnrollment makes this device's finite login permanent after a fresh
// audited session. The caller must first authenticate the committed certificate
// and capsule and pass the digest of that exact public certificate. No first-use
// trust is established here. There are no automatic retries: uncertain outcomes
// retire the owner; reconnect, reauthenticate and reverify before retrying the
// server's idempotent confirmation with the same certificate digest.
func (s *Session) ConfirmEnrollment(ctx context.Context, certificateDigest []byte) (err error) {
	if ctx == nil || len(certificateDigest) != sha256.Size {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrQuery
	}
	if conn.TxStatus() != 'I' {
		return ErrConfiguration
	}
	var rows [][][]byte
	sent := false
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		digest := hex.AppendEncode(nil, certificateDigest)
		defer vault.Wipe(digest)
		sent = true
		var e error
		rows, e = s.queryLeased(opCtx, conn, confirmEnrollmentSQL, [][]byte{encoded, digest})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		if sent && !knownEnrollmentConfirmationRejection(err) {
			s.discardConnection(conn)
			return ErrEnrollmentConfirmationUncertain
		}
		return err
	}
	if conn.TxStatus() != 'I' || !validEnrollmentConfirmation(rows, s.admission.DeviceID) {
		s.discardConnection(conn)
		return ErrEnrollmentConfirmationUncertain
	}
	return nil
}

func validEnrollmentConfirmation(rows [][][]byte, device uuid.UUID) bool {
	return device != uuid.Nil && len(rows) == 1 && len(rows[0]) == 2 && string(rows[0][0]) == device.String() && string(rows[0][1]) == "true"
}

func knownEnrollmentConfirmationRejection(err error) bool {
	return err == ErrDeviceCredentials || err == ErrAccountRevision || err == ErrAuditUnavailable || err == ErrChangeInProgress || err == ErrIdentityUnavailable || err == ErrAuthentication || err == ErrTransactionIsolation
}
