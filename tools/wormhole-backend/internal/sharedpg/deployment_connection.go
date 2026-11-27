package sharedpg

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
)

// Read a single bounded receipt from a temporary deployment connection. The
// caller always closes the connection, including on malformed server replies.
func readDeploymentResponse(ctx context.Context, conn *pgconn.PgConn, statement string, params [][]byte, limit int) ([]byte, error) {
	result := conn.ExecParams(ctx, statement, params, nil, nil, nil)
	if !result.NextRow() {
		_, err := result.Close()
		var rejected *pgconn.PgError
		if errors.As(err, &rejected) && rejected.Severity == "ERROR" && !conn.IsClosed() && conn.TxStatus() == 'I' {
			return nil, ErrDeploymentRejected
		}
		return nil, ErrDeploymentUncertain
	}
	values := result.Values()
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > limit {
		return nil, ErrDeploymentUncertain
	}
	raw := bytes.Clone(values[0])
	if result.NextRow() {
		return nil, ErrDeploymentUncertain
	}
	if _, err := result.Close(); err != nil || conn.TxStatus() != 'I' {
		return nil, ErrDeploymentUncertain
	}
	return raw, nil
}

type DeploymentConnectionStage string

const (
	DeploymentDNS            DeploymentConnectionStage = "dns"
	DeploymentTCP            DeploymentConnectionStage = "tcp"
	DeploymentTLS            DeploymentConnectionStage = "tls"
	DeploymentSCRAM          DeploymentConnectionStage = "scram"
	DeploymentChannelBinding DeploymentConnectionStage = "channel-binding"
	DeploymentDatabase       DeploymentConnectionStage = "database"
	DeploymentReadWrite      DeploymentConnectionStage = "read-write"
)

// DeploymentConnectionError exposes a fixed stage and a sanitized cause. It
// never contains server text, connection coordinates or the deployer password.
type DeploymentConnectionError struct {
	Stage DeploymentConnectionStage
	cause error
}

func (e *DeploymentConnectionError) Error() string {
	return "PostgreSQL deployment check failed at " + string(e.Stage)
}
func (e *DeploymentConnectionError) Unwrap() error { return e.cause }

func connectForDeploymentCheck(ctx context.Context, settings Settings, password []byte) (*pgconn.PgConn, error) {
	stage := DeploymentDNS
	conn, err := connect(ctx, settings, password, func(ctx context.Context, config *pgconn.Config) (*pgconn.PgConn, error) {
		// Preflight and Check deployment report logging settings through fixed
		// diagnostic queries. Neither connection admits a device session.
		config.ValidateConnect = func(ctx context.Context, conn *pgconn.PgConn) error {
			return validateServerState(ctx, conn, readWriteQuery)
		}
		var openedTCP, verifiedTLS bool
		dial := config.DialFunc
		config.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			// pgx resolves all configured endpoints before calling its dialer.
			if stage == DeploymentDNS {
				stage = DeploymentTCP
			}
			conn, err := dial(ctx, network, address)
			openedTCP = openedTCP || err == nil
			return conn, err
		}
		trackTLS := func(config *tls.Config) {
			if config == nil {
				return
			}
			verify := config.VerifyConnection
			config.VerifyConnection = func(state tls.ConnectionState) error {
				if verify != nil {
					if err := verify(state); err != nil {
						return err
					}
				}
				verifiedTLS = true
				return nil
			}
		}
		trackTLS(config.TLSConfig)
		for _, fallback := range config.Fallbacks {
			trackTLS(fallback.TLSConfig)
		}
		conn, err := pgconn.ConnectConfig(ctx, config)
		switch {
		case err == nil:
		case hasSQLState(err, "3D000", 0) || hasSQLState(err, "42501", 0):
			stage = DeploymentDatabase
		case errors.Is(err, errServerState):
			stage = DeploymentReadWrite
		case verifiedTLS && hasConnectionCause(err, 0, missingSCRAMPlus):
			stage = DeploymentChannelBinding
		case verifiedTLS || (openedTCP && settings.TLS == TLSOff):
			stage = DeploymentSCRAM
		case openedTCP:
			stage = DeploymentTLS
		}
		return conn, err
	})
	if err != nil && !errors.Is(err, ErrConfiguration) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, &DeploymentConnectionError{Stage: stage, cause: err}
	}
	return conn, err
}

// pgx 5.12 returns a local, untyped error when the SASL list lacks PLUS.
// Match only that exact leaf. A server ErrorResponse or a password rejection
// must never be reported as the absence of channel binding.
func missingSCRAMPlus(err error) bool {
	if _, fromServer := err.(*pgconn.PgError); fromServer {
		return false
	}
	return err.Error() == "channel binding required but server does not support SCRAM-SHA-256-PLUS"
}
