package sharedpg

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestDeploymentDistinguishesMissingChannelBinding(t *testing.T) {
	dir := t.TempDir()
	s := settings()
	s.TLS, s.CAPEM = TLSVerified, postgresTestCertificate(t, dir)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s.Endpoints = []Endpoint{{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := listener.(*net.TCPListener).SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := CheckDeploymentPrerequisites(ctx, s, []byte("synthetic-test-factor"))
		result <- err
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	wire := pgproto3.NewBackend(conn, conn)
	message, err := wire.ReceiveStartupMessage()
	if _, ok := message.(*pgproto3.SSLRequest); err != nil || !ok {
		t.Fatal("expected TLS negotiation", err)
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		t.Fatal(err)
	}
	secured := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	wire = pgproto3.NewBackend(secured, secured)
	if _, err := wire.ReceiveStartupMessage(); err != nil {
		t.Fatal(err)
	}
	wire.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := wire.Flush(); err != nil {
		t.Fatal(err)
	}
	var stage *DeploymentConnectionError
	if err := <-result; !errors.As(err, &stage) || stage.Stage != DeploymentChannelBinding {
		t.Fatal("missing PLUS was not distinguished from a password rejection", err)
	}
	// Server text cannot impersonate a locally detected negotiation failure.
	if missingSCRAMPlus(&pgconn.PgError{Message: "channel binding required but server does not support SCRAM-SHA-256-PLUS"}) {
		t.Fatal("server text was treated as mechanism negotiation")
	}
}

func TestDeploymentPlainStartupSendsNoAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response pgproto3.BackendMessage
		want     string
	}{
		{"refusal", &pgproto3.ErrorResponse{Code: "28000"}, "refused"},
		{"connection limit", &pgproto3.ErrorResponse{Code: "53300"}, "unconfirmed"},
		{"password request", &pgproto3.AuthenticationCleartextPassword{}, "offered"},
		{"already authenticated", &pgproto3.AuthenticationOk{}, "offered"},
		{"unexpected response", &pgproto3.ReadyForQuery{TxStatus: 'I'}, "unconfirmed"},
		{"connection lost", nil, "unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			verified, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer verified.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				server := pgproto3.NewBackend(conn, conn)
				message, err := server.ReceiveStartupMessage()
				start, ok := message.(*pgproto3.StartupMessage)
				if err != nil || !ok || len(start.Parameters) != 2 || start.Parameters["database"] != "vault" || start.Parameters["user"] != "wh_testscope_deployer" {
					done <- errors.New("unexpected plaintext startup fields")
					return
				}
				if tc.response != nil {
					server.Send(tc.response)
					if err := server.Flush(); err != nil {
						done <- err
						return
					}
					var unexpected [1]byte
					if n, err := conn.Read(unexpected[:]); n != 0 || !errors.Is(err, io.EOF) {
						done <- errors.New("probe continued after initial response")
						return
					}
				}
				done <- nil
			}()
			if got := checkPlainStartup(context.Background(), verified, "vault", "testscope"); got != tc.want {
				t.Errorf("probe returned %q, want %q", got, tc.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if got := checkPlainStartup(context.Background(), local, "vault", "testscope"); got != "unconfirmed" {
		t.Fatal("non-TCP transport reported", got)
	}
}
