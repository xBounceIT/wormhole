package sharedpg

import (
	"context"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type DeploymentChecks struct {
	DeploymentLogging
	PlainStartup string `json:"plainStartup"`
}

type DeploymentInspection struct {
	SchemaDeployment
	Checks DeploymentChecks `json:"checks"`
}

// Probe the same server from the same local IP as the authenticated DBA
// connection. The only outbound message contains public startup fields. Never
// supply a password, respond to an authentication challenge or execute SQL.
func checkPlainStartup(ctx context.Context, verified net.Conn, database, roleTag string) string {
	local, ok := verified.LocalAddr().(*net.TCPAddr)
	peer, tcp := verified.RemoteAddr().(*net.TCPAddr)
	if !ok || !tcp {
		return "unconfirmed"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dial := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.IP, Zone: local.Zone}}
	conn, err := dial.DialContext(ctx, "tcp", peer.String())
	if err != nil {
		return "unconfirmed"
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	wire := pgproto3.NewFrontend(conn, conn)
	wire.SetMaxBodyLen(8192)
	wire.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"database": database, "user": "wh_" + roleTag + "_deployer"}})
	if err := wire.Flush(); err != nil {
		return "unconfirmed"
	}
	message, err := wire.Receive()
	if err != nil {
		return "unconfirmed"
	}
	switch m := message.(type) {
	case *pgproto3.ErrorResponse:
		// Other failures, including an exhausted connection budget, give no
		// evidence about the server's plaintext authentication policy.
		if m.Code == "28000" {
			return "refused"
		}
	case *pgproto3.AuthenticationOk, *pgproto3.AuthenticationSASL, *pgproto3.AuthenticationCleartextPassword,
		*pgproto3.AuthenticationMD5Password, *pgproto3.AuthenticationGSS:
		return "offered"
	}
	return "unconfirmed"
}
