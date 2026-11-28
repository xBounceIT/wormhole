package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const connectionDeadline = 30 * time.Second

var (
	ErrConnection      = errors.New("shared PostgreSQL connection failed")
	ErrConnectionLimit = errors.New("the workspace server is at its connection limit")
	ErrAuthentication  = errors.New("shared PostgreSQL authentication failed")
)

// Connect opens one native connection with an overall deadline covering DNS,
// every fallback, TLS, authentication, and read-write server validation. The
// caller owns the returned connection and must close it on workspace lock.
// secret is borrowed, not consumed; it must be a native-derived device login
// secret, never a renderer-supplied database password. pgx retains a Go string
// copy while connecting: this API does not claim zeroizable password memory.
// Returned errors are fixed messages without server text, hostnames, or secrets.
func Connect(ctx context.Context, s Settings, secret []byte) (*pgconn.PgConn, error) {
	return connect(ctx, s, secret, pgconn.ConnectConfig)
}

func connect(ctx context.Context, s Settings, secret []byte, dial func(context.Context, *pgconn.Config) (*pgconn.PgConn, error)) (*pgconn.PgConn, error) {
	if ctx == nil || len(secret) == 0 || len(secret) > 1024 || !utf8.Valid(secret) || bytes.IndexByte(secret, 0) >= 0 {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := Config(s)
	if err != nil {
		return nil, err
	}
	c.Password = string(secret)
	defer func() { c.Password = "" }()
	connectCtx, cancel := context.WithTimeout(ctx, connectionDeadline)
	defer cancel()
	conn, err := dial(connectCtx, c)
	if err != nil {
		// Never wrap driver errors: PostgreSQL may put arbitrary sensitive text
		// in Message, Detail, Hint, Where, or authentication failure fields.
		if contextErr := connectCtx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if hasSQLState(err, "53300", 0) {
			return nil, ErrConnectionLimit
		}
		if hasSQLState(err, "28P01", 0) || hasSQLState(err, "28000", 0) {
			return nil, ErrAuthentication
		}
		return nil, ErrConnection
	}
	return conn, nil
}

// pgx aggregates failures from multiple hosts. Inspect all of them instead of
// letting an unrelated first host hide a later device-limit rejection.
func hasSQLState(err error, code string, depth int) bool {
	return hasConnectionCause(err, depth, func(cause error) bool {
		pgErr, ok := cause.(*pgconn.PgError)
		return ok && pgErr.Code == code
	})
}

func hasConnectionCause(err error, depth int, match func(error) bool) bool {
	if err == nil || depth > 32 {
		return false
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			if hasConnectionCause(child, depth+1, match) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return hasConnectionCause(e.Unwrap(), depth+1, match)
	default:
		return match(err)
	}
	return false
}
