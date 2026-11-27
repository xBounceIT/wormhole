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

const catalogChangesSQL = `SELECT workspace_id::text,user_id::text,epoch::text,change_seq::text,
resolver_version::text,reset_required::text,node_id::text
FROM wormhole_api_v1.get_changes_since(pg_catalog.decode($1,'hex'),$2::bigint,$3::bigint)`

// CatalogChanges is an invalidation hint, not signed metadata or authorization.
// Reset discards the old projection. Nodes must be fetched and verified afresh.
type CatalogChanges struct {
	Epoch, ChangeSeq uint64
	Reset            bool
	Nodes            []uuid.UUID
}

func (s *Session) ChangesSince(ctx context.Context, epoch, since uint64) (*CatalogChanges, error) {
	if ctx == nil || epoch > math.MaxInt64 || since > math.MaxInt64 || (epoch == 0 && since != 0) {
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
	params := [][]byte{nil, []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(since, 10))}
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		params[0] = hex.AppendEncode(nil, capability)
		defer vault.Wipe(params[0])
		var e error
		rows, e = s.queryLeased(opCtx, conn, catalogChangesSQL, params)
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	result, err := parseCatalogChanges(rows, s.admission, epoch, since)
	if err != nil {
		s.discardConnection(conn)
	}
	return result, err
}

func parseCatalogChanges(rows [][][]byte, request AdmissionRequest, epoch, since uint64) (*CatalogChanges, error) {
	if len(rows) == 0 || len(rows) > MaxTreePage {
		return nil, ErrAdmissionResponse
	}
	result := &CatalogChanges{}
	previous := ""
	for i, row := range rows {
		if len(row) != 7 || string(row[0]) != request.WorkspaceID.String() || string(row[1]) != request.UserID.String() || string(row[4]) != "1" {
			return nil, ErrAdmissionResponse
		}
		e, ok := treeNumber(row[2], 1, math.MaxInt64)
		seq, ok2 := treeNumber(row[3], 0, math.MaxInt64)
		if !ok || !ok2 || e < epoch || (e == epoch && seq < since) || (string(row[5]) != "true" && string(row[5]) != "false") {
			return nil, ErrAdmissionResponse
		}
		reset := string(row[5]) == "true"
		if e != epoch && !reset {
			return nil, ErrAdmissionResponse
		}
		if i == 0 {
			result.Epoch = e
			result.ChangeSeq = seq
			result.Reset = reset
		} else if result.Epoch != e || result.ChangeSeq != seq || result.Reset != reset {
			return nil, ErrAdmissionResponse
		}
		if row[6] == nil {
			if len(rows) != 1 {
				return nil, ErrAdmissionResponse
			}
		} else {
			id, ok := treeID(row[6])
			if !ok || reset || (e == epoch && seq == since) || id.String() <= previous {
				return nil, ErrAdmissionResponse
			}
			result.Nodes = append(result.Nodes, id)
			previous = id.String()
		}
	}
	return result, nil
}
