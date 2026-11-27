package sharedpg

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const nodePermissionsSQL = `SELECT wormhole_api_v1.node_permissions(pg_catalog.decode($1,'hex'),$2::uuid)::text`

// NodePermissions reports the server's current grant union for the admitted
// user. It is not a release ticket or cryptographic authorization: begin_use,
// fetch_secret and verification of the complete signed chain remain mandatory.
func (s *Session) NodePermissions(ctx context.Context, node uuid.UUID) (permissions.Mask, error) {
	if ctx == nil || node == uuid.Nil {
		return 0, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return 0, err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return 0, ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return 0, err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return 0, ErrQuery
	}
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		var e error
		rows, e = s.queryLeased(opCtx, conn, nodePermissionsSQL, [][]byte{encoded, []byte(node.String())})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return 0, err
	}
	result, err := parseNodePermissions(rows)
	if err != nil {
		s.discardConnection(conn)
	}
	return result, err
}

func parseNodePermissions(rows [][][]byte) (permissions.Mask, error) {
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, ErrAdmissionResponse
	}
	value, err := strconv.ParseUint(string(rows[0][0]), 10, 8)
	if err != nil || value > uint64(permissions.All) || strconv.FormatUint(value, 10) != string(rows[0][0]) {
		return 0, ErrAdmissionResponse
	}
	return permissions.Mask(value), nil
}
