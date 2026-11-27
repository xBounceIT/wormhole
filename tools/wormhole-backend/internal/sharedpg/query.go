package sharedpg

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	maxQueryBytes     = 32 * 1024
	maxParameterBytes = 1024 * 1024
	maxResultBytes    = 8 * 1024 * 1024
	maxResultRows     = 1024
	maxResultColumns  = 64
)

var (
	ErrQuery               = errors.New("shared PostgreSQL operation failed")
	ErrResultLimit         = errors.New("shared PostgreSQL result exceeds safe limits")
	ErrChangeInProgress    = errors.New("another workspace change is in progress")
	ErrTreeSnapshotChanged = errors.New("shared tree snapshot changed")
	ErrUseTicket           = errors.New("shared use ticket is unavailable")
	ErrTreeMetadata        = errors.New("shared tree metadata is unavailable")
)

// Query is a native-only transport primitive for the upcoming typed SQL API.
// Never expose arbitrary statement text through IPC. Parameters use PostgreSQL
// text encoding; callers must encode ciphertext appropriately. Results are
// independent copies, preserve SQL NULL, and belong to the native caller.
func (s *Session) Query(ctx context.Context, statement string, params [][]byte) (rows [][][]byte, err error) {
	if ctx == nil || len(statement) == 0 || len(statement) > maxQueryBytes || !utf8.ValidString(statement) || strings.IndexByte(statement, 0) >= 0 || len(params) > 64 {
		return nil, ErrConfiguration
	}
	parameterBytes := 0
	for _, value := range params {
		if len(value) > maxParameterBytes-parameterBytes {
			return nil, ErrConfiguration
		}
		parameterBytes += len(value)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return nil, ErrQuery
	}
	return s.queryLeased(opCtx, conn, statement, params)
}

// queryLeased is for fixed native statements while the caller owns query slot 0.
// It must not acquire another lease or let a result stream escape that lease.
func (s *Session) queryLeased(opCtx context.Context, conn *pgconn.PgConn, statement string, params [][]byte) (rows [][][]byte, err error) {
	return s.queryLeasedWithLimits(opCtx, conn, statement, params, maxResultBytes, maxResultRows, maxResultColumns)
}

// Fixed typed operations may use narrower row/column bounds and a separately
// bounded ciphertext payload. Query's general limits remain unchanged.
func (s *Session) queryLeasedWithLimits(opCtx context.Context, conn *pgconn.PgConn, statement string, params [][]byte, byteLimit, rowLimit, columnLimit int) (rows [][][]byte, err error) {
	defer func() {
		if err != nil {
			for _, row := range rows {
				for _, value := range row {
					clear(value)
				}
			}
			rows = nil
		}
		s.invalidateIfClosed(conn)
	}()
	// Close the stream immediately on an invalid/oversized response. Draining it
	// could otherwise accept arbitrarily many rows from an untrusted server.
	reject := func(reason error) error {
		s.discardConnection(conn)
		return reason
	}
	r := conn.ExecParams(opCtx, statement, params, nil, nil, nil)
	resultBytes := 0
	for r.NextRow() {
		values := r.Values()
		if len(rows) >= rowLimit || len(values) > columnLimit {
			return rows, reject(ErrResultLimit)
		}
		if len(values) == 0 || len(values) != len(r.FieldDescriptions()) {
			return rows, reject(ErrQuery)
		}
		for _, value := range values {
			if len(value) > byteLimit-resultBytes {
				return rows, reject(ErrResultLimit)
			}
			resultBytes += len(value)
		}
		row := make([][]byte, len(values))
		for i, value := range values {
			if value != nil {
				row[i] = make([]byte, len(value))
				copy(row[i], value)
			}
		}
		rows = append(rows, row)
	}
	if len(r.FieldDescriptions()) > columnLimit {
		return rows, reject(ErrResultLimit)
	}
	if _, queryErr := r.Close(); queryErr != nil {
		if opCtx.Err() != nil {
			return rows, opCtx.Err()
		}
		mapped := workspaceQueryError(queryErr)
		if mapped == ErrIdentityUnavailable || mapped == ErrAuthentication {
			s.discardConnection(conn)
		}
		return rows, mapped
	}
	if opCtx.Err() != nil {
		return rows, opCtx.Err()
	}
	return rows, nil
}
