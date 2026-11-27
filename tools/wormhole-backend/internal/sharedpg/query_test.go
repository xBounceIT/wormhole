package sharedpg

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestChangeDeliveryPolicy(t *testing.T) {
	for _, count := range []uint32{0, 1, 300, 301, ^uint32(0)} {
		for _, pooler := range []bool{false, true} {
			p := ChangePolicy{ConcurrentDevices: count, TransactionPooler: pooler}
			want := !pooler && count <= 300
			if p.UseNotifications() != want {
				t.Fatal("wrong delivery mode")
			}
			interval := 30 * time.Second
			if want {
				interval = 0
			}
			if p.PollInterval() != interval {
				t.Fatal("wrong polling interval")
			}
		}
	}
}

func TestQueryInputBounds(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	for _, q := range []string{"", strings.Repeat("q", maxQueryBytes+1), "select\x00bad", string([]byte{0xff})} {
		if _, err := s.Query(context.Background(), q, nil); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.Query(nil, "select 1", nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.Query(context.Background(), "select 1", make([][]byte, 65)); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.Query(context.Background(), "select 1", [][]byte{make([]byte, maxParameterBytes), {1}}); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.Query(context.Background(), "select 1", nil); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	if _, err := fake.Query(context.Background(), "select 1", nil); err != ErrQuery {
		t.Fatal(err)
	}
}

func TestQueriesAgainstAuthenticatedServer(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, scenario := range []string{"rows", "empty", "late-error", "busy", "capacity", "revoked", "credential-expired", "too-many-rows", "too-many-columns", "too-many-bytes", "bad-shape"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			secret := []byte("native-query-test-secret")
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if err := initializeWritableTestConnection(b, secret); err != nil {
					done <- err
					return
				}
				query, params, err := receiveTestQuery(b)
				if err != nil {
					done <- err
					return
				}
				if query != "select $1" || len(params) != 1 || string(params[0]) != "native-parameter" {
					done <- fmt.Errorf("parameters not preserved")
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				columns := 1
				if scenario == "rows" {
					columns = 3
				}
				if scenario == "too-many-columns" {
					columns = 65
				}
				fields := make([]pgproto3.FieldDescription, columns)
				for i := range fields {
					fields[i] = pgproto3.FieldDescription{Name: []byte("value"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
				}
				b.Send(&pgproto3.RowDescription{Fields: fields})
				switch scenario {
				case "rows":
					b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("first"), nil, []byte{}}})
					b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("later"), nil, []byte{}}})
				case "late-error", "revoked", "credential-expired":
					b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("sensitive-partial-result")}})
				case "too-many-rows":
					for i := 0; i <= maxResultRows; i++ {
						b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("x")}})
					}
				case "too-many-bytes":
					b.Send(&pgproto3.DataRow{Values: [][]byte{make([]byte, maxResultBytes+1)}})
				case "bad-shape":
					b.Send(&pgproto3.DataRow{Values: nil})
				}
				if scenario == "late-error" || scenario == "busy" || scenario == "capacity" || scenario == "revoked" || scenario == "credential-expired" {
					code := "XX000"
					if scenario == "busy" {
						code = "55P03"
					}
					if scenario == "capacity" {
						code = "53300"
					}
					if scenario == "revoked" {
						code = "WH001"
					}
					if scenario == "credential-expired" {
						code = "WH007"
					}
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: "private server detail", Detail: "native-parameter"})
				} else {
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := b.Flush(); err != nil {
					done <- err
					return
				}
				msg, err := b.Receive()
				if err != nil {
					done <- err
					return
				}
				if _, ok := msg.(*pgproto3.Terminate); !ok {
					done <- fmt.Errorf("expected termination, got %T", msg)
					return
				}
				done <- nil
			}()
			settings := settings()
			settings.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			s := NewSession()
			defer s.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			policy := ChangePolicy{TransactionPooler: true}
			if scenario == "empty" {
				policy = ChangePolicy{ConcurrentDevices: 301}
			}
			if err := s.Open(ctx, settings, secret, policy); err != nil {
				t.Fatal(err)
			}
			rows, err := s.Query(ctx, "select $1", [][]byte{[]byte("native-parameter")})
			switch scenario {
			case "rows":
				if err != nil || len(rows) != 2 || string(rows[0][0]) != "first" || string(rows[1][0]) != "later" || rows[0][1] != nil || rows[0][2] == nil {
					t.Fatalf("invalid copied result: %v", err)
				}
			case "empty":
				if err != nil || len(rows) != 0 {
					t.Fatal("invalid empty result")
				}
			default:
				want := ErrQuery
				if strings.HasPrefix(scenario, "too-many-") {
					want = ErrResultLimit
				}
				if scenario == "busy" {
					want = ErrChangeInProgress
				}
				if scenario == "capacity" {
					want = ErrConnectionLimit
				}
				if scenario == "revoked" || scenario == "credential-expired" {
					want = ErrIdentityUnavailable
					if scenario == "credential-expired" {
						want = ErrAuthentication
					}
					select {
					case <-s.Done():
					default:
						t.Fatal("revocation did not notify the owning controller")
					}
					if _, nextErr := s.Query(ctx, "select 1", nil); nextErr != ErrSessionClosed {
						t.Fatal("revoked owner accepted another operation")
					}
				}
				if err != want || rows != nil {
					t.Fatalf("unsafe error/result: %v", err)
				}
				if scenario == "bad-shape" || strings.HasPrefix(scenario, "too-many-") {
					if _, _, _, err := s.lease(ctx, 0); err != ErrSessionClosed {
						t.Fatal("invalid stream left session usable")
					}
				}
			}
			if err := s.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func receiveTestQuery(b *pgproto3.Backend) (string, [][]byte, error) {
	var query string
	var params [][]byte
	for {
		msg, err := b.Receive()
		if err != nil {
			return "", nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.Parse:
			query = m.Query
		case *pgproto3.Bind:
			params = m.Parameters
		case *pgproto3.Sync:
			return query, params, nil
		}
	}
}

func TestQueryCancellationCleansNativeConnection(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	secret := []byte("native-cancel-test-secret")
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		b := pgproto3.NewBackend(conn, conn)
		if err := initializeWritableTestConnection(b, secret); err != nil {
			done <- err
			return
		}
		if _, _, err := receiveTestQuery(b); err != nil {
			done <- err
			return
		}
		cancelConn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer cancelConn.Close()
		_ = cancelConn.SetDeadline(time.Now().Add(5 * time.Second))
		msg, err := pgproto3.NewBackend(cancelConn, cancelConn).ReceiveStartupMessage()
		if err != nil {
			done <- err
			return
		}
		if _, ok := msg.(*pgproto3.CancelRequest); !ok {
			done <- fmt.Errorf("expected cancel request, got %T", msg)
			return
		}
		_ = cancelConn.Close()
		b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "private canceled operation"})
		b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		done <- b.Flush()
	}()
	settings := settings()
	settings.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
	s := NewSession()
	defer s.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	queryCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stop()
	rows, err := s.Query(queryCtx, "select pg_sleep(60)", nil)
	if err != context.DeadlineExceeded || rows != nil {
		t.Fatalf("unsafe cancellation result: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
