package sharedpg

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// queryConnection serves fixed typed connection operations only. Keep receipt
// decoding inside the same control/connection lease; malformed or ambiguous
// responses retire the owner. No automatic retries, even for metadata planning.
func (s *Session) queryConnection(ctx context.Context, node uuid.UUID, statement string, extra [][]byte, payloadLimit, columns int, decode func([][][]byte, AdmissionRequest) error) error {
	return s.queryAuthenticated(ctx, statement, append([][]byte{[]byte(node.String())}, extra...), payloadLimit, columns, decode)
}

// Only fixed, typed APIs call this capability-bound transport.
func (s *Session) queryAuthenticated(ctx context.Context, statement string, args [][]byte, payloadLimit, columns int, decode func([][][]byte, AdmissionRequest) error) error {
	return s.queryAuthenticatedRows(ctx, statement, args, payloadLimit, 1, columns, decode)
}

func (s *Session) queryAuthenticatedRows(ctx context.Context, statement string, args [][]byte, payloadLimit, rowLimit, columns int, decode func([][][]byte, AdmissionRequest) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := take(ctx, s.control); e != nil {
		return e
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return ErrAuthentication
	}
	owned, opCtx, release, e := s.lease(ctx, 0)
	if e != nil {
		return e
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrQuery
	}
	if conn.TxStatus() != 'I' {
		return ErrConfiguration
	}
	conn.Frontend().SetMaxBodyLen(payloadLimit + 1024)
	defer conn.Frontend().SetMaxBodyLen(maxProtocolBodyBytes)
	params := append([][]byte{nil}, args...)
	var rows [][][]byte
	e = s.capability.With(func(capability []byte) error {
		params[0] = hex.AppendEncode(nil, capability)
		defer vault.Wipe(params[0])
		var err error
		rows, err = s.queryLeasedWithLimits(opCtx, conn, statement, params, payloadLimit+512, rowLimit, columns)
		return err
	})
	defer wipeQueryRows(rows)
	if e == ErrImportedConnectionPins && len(rows) == 0 && conn.TxStatus() == 'I' && opCtx.Err() == nil {
		return e
	}
	if e == nil && conn.TxStatus() != 'I' {
		e = ErrAdmissionResponse
	}
	if e == nil {
		e = decode(rows, s.admission)
	}
	if e == nil {
		e = opCtx.Err()
	}
	if e != nil {
		s.discardConnection(conn)
	}
	return e
}
