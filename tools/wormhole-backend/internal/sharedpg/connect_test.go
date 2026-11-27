package sharedpg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestConnectBoundsAndSecretLifetime(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	secret := []byte("native-device-secret")
	var captured *pgconn.Config
	var dialCtx context.Context
	marker := new(pgconn.PgConn)
	before := time.Now()
	conn, err := connect(context.Background(), settings(), secret, func(ctx context.Context, c *pgconn.Config) (*pgconn.PgConn, error) {
		captured, dialCtx = c, ctx
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(before.Add(29*time.Second)) || deadline.After(time.Now().Add(connectionDeadline)) {
			t.Fatal("missing overall deadline")
		}
		if c.Password != string(secret) || c.RequireAuth != "scram-sha-256" {
			t.Fatal("missing credential/auth policy")
		}
		return marker, nil
	})
	if err != nil || conn != marker || captured.Password != "" || string(secret) != "native-device-secret" || dialCtx.Err() != context.Canceled {
		t.Fatal("ownership/lifetime violation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = connect(ctx, settings(), secret, func(actual context.Context, _ *pgconn.Config) (*pgconn.PgConn, error) {
		want, _ := ctx.Deadline()
		got, _ := actual.Deadline()
		if !got.Equal(want) {
			t.Fatal("extended caller deadline")
		}
		return nil, errors.New("server-controlled confidential detail")
	})
	if err != ErrConnection || errors.Unwrap(err) != nil {
		t.Fatal("raw driver error escaped")
	}
}

func TestConnectRejectsInvalidInputsWithoutDialing(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	never := func(context.Context, *pgconn.Config) (*pgconn.PgConn, error) {
		t.Fatal("unexpected dial")
		return nil, nil
	}
	for _, secret := range [][]byte{nil, {}, make([]byte, 1025), {'a', 0, 'b'}, {0xff}} {
		if _, err := connect(context.Background(), settings(), secret, never); err != ErrConfiguration {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if _, err := connect(nil, settings(), []byte("secret"), never); err != ErrConfiguration {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = "prefer"
	if _, err := connect(context.Background(), s, []byte("secret"), never); err != ErrConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connect(ctx, settings(), []byte("secret"), never); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestConnectSanitizesAllHostErrors(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, tc := range []struct {
		input error
		want  error
	}{
		{&pgconn.PgError{Code: "53300", Message: "secret"}, ErrConnectionLimit},
		{&pgconn.PgError{Code: "28P01", Detail: "secret"}, ErrAuthentication},
		{&pgconn.PgError{Code: "28000", Hint: "secret"}, ErrAuthentication},
		{&pgconn.PgError{Code: "08006", Where: "secret"}, ErrConnection},
		{errors.Join(&pgconn.PgError{Code: "08006"}, fmt.Errorf("secret: %w", &pgconn.PgError{Code: "53300"})), ErrConnectionLimit},
		{errors.Join(errors.New("secret"), &pgconn.PgError{Code: "28P01"}), ErrAuthentication},
	} {
		var captured *pgconn.Config
		_, err := connect(context.Background(), settings(), []byte("secret"), func(_ context.Context, c *pgconn.Config) (*pgconn.PgConn, error) { captured = c; return nil, tc.input })
		if err != tc.want || captured.Password != "" || errors.Unwrap(err) != nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe result: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := connect(ctx, settings(), []byte("secret"), func(context.Context, *pgconn.Config) (*pgconn.PgConn, error) {
		cancel()
		return nil, &pgconn.PgError{Code: "53300"}
	})
	if err != context.Canceled {
		t.Fatal(err)
	}
	if hasSQLState(nil, "53300", 0) || hasSQLState(&pgconn.PgError{Code: "53300"}, "53300", 33) {
		t.Fatal("invalid traversal boundary")
	}
}

func TestConnectMapsRealServerLimitRejection(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b := pgproto3.NewBackend(conn, conn)
		if _, err = b.ReceiveStartupMessage(); err != nil {
			done <- err
			return
		}
		b.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "53300", Message: "secret server message", Detail: "secret database detail"})
		done <- b.Flush()
	}()
	s := settings()
	s.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Connect(ctx, s, []byte("native-device-secret"))
	if conn != nil || err != ErrConnectionLimit {
		t.Fatalf("unexpected result %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectDeadlineClosesUnresponsiveServer(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b := pgproto3.NewBackend(conn, conn)
		if _, err = b.ReceiveStartupMessage(); err != nil {
			done <- err
			return
		}
		close(started)
		var response [1]byte
		n, err := conn.Read(response[:])
		if n != 0 || err != io.EOF {
			done <- fmt.Errorf("connection not closed: bytes=%d error=%v", n, err)
			return
		}
		done <- nil
	}()
	s := settings()
	s.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := Connect(ctx, s, []byte("native-device-secret"))
	if conn != nil || err != context.DeadlineExceeded {
		t.Fatalf("unexpected timeout: %v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("never reached server handshake")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
