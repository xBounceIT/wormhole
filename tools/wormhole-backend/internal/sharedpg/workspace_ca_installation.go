package sharedpg

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"
)

func (v *VerifiedTLSBundle) verifyRotatedServerInstallation(ctx context.Context, settings Settings) error {
	config, err := v.Config(settings)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, connectionDeadline)
	defer cancel()
	leaf := v.bundle.WorkspaceCA.ServerCertificate
	dial := new(net.Dialer)
	if err := checkPostgresRotatedLeaf(ctx, dial, config.Host, config.Port, config.TLSConfig, leaf); err != nil {
		return err
	}
	for _, fallback := range config.Fallbacks {
		if err := checkPostgresRotatedLeaf(ctx, dial, fallback.Host, fallback.Port, fallback.TLSConfig, leaf); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Use PostgreSQL's TLS negotiation and stop after the verified handshake.
// Reading exactly one byte prevents pre-handshake response bytes from being
// buffered and discarded; the check never sends a StartupMessage or credentials.
func checkPostgresRotatedLeaf(ctx context.Context, dial *net.Dialer, host string, port uint16, config *tls.Config, leaf []byte) error {
	conn, err := dial.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return ErrWorkspaceCARotation
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return ErrWorkspaceCARotation
	}
	if _, err := conn.Write(request); err != nil {
		return ErrWorkspaceCARotation
	}
	var accepted [1]byte
	if _, err := io.ReadFull(conn, accepted[:]); err != nil || accepted[0] != 'S' {
		return ErrWorkspaceCARotation
	}
	secured := tls.Client(conn, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		return ErrWorkspaceCARotation
	}
	state := secured.ConnectionState()
	if len(state.PeerCertificates) == 0 || !bytes.Equal(leaf, state.PeerCertificates[0].Raw) {
		return ErrWorkspaceCARotation
	}
	return nil
}
