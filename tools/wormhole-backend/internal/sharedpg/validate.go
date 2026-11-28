package sharedpg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var errServerState = errors.New("shared PostgreSQL server did not meet the connection policy")

const readWriteQuery = "show transaction_read_only"
const privateReadWriteQuery = "SELECT pg_catalog.current_setting('transaction_read_only') WHERE pg_catalog.current_setting('log_statement') = 'none'"

// Stream a single bounded row instead of pgx's read-write validator, which
// indexes ReadAll()[0].Rows[0][0] without validating the server's response shape.
func validateServerState(ctx context.Context, conn *pgconn.PgConn, query string) (err error) {
	defer func() {
		if err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = conn.Close(closeCtx)
		}
	}()
	r := conn.ExecParams(ctx, query, nil, nil, nil, nil)
	if !r.NextRow() {
		return errServerState
	}
	values := r.Values()
	if len(values) != 1 || string(values[0]) != "off" {
		return errServerState
	}
	if r.NextRow() {
		return errServerState
	}
	if _, err := r.Close(); err != nil {
		return errServerState
	}
	return nil
}
