package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
)

func secretReleaseFixture(t *testing.T) ([][][]byte, AdmissionRequest, UseIntent, TrustState) {
	t.Helper()
	f, w := releaseGraphFixture(t, "saved", true, false)
	raw, _ := json.Marshal(w)
	request := admissionRequest()
	intent := UseIntent{Node: f.node(), Ticket: uuid.New(), Epoch: 1, ChangeSeq: 7, ExpiresAt: 1800000000}
	return [][][]byte{{[]byte(request.WorkspaceID.String()), []byte(request.UserID.String()), []byte(request.DeviceID.String()), []byte(intent.Node.String()), []byte(intent.Ticket.String()), []byte("1"), []byte("7"), raw}}, request, intent, f.s
}

func TestSecretReleaseReceipt(t *testing.T) {
	rows, request, intent, trust := secretReleaseFixture(t)
	g, e := parseSecretRelease(rows, request, intent)
	if e != nil {
		t.Fatal(e)
	}
	pathIntent := intent
	pathIntent.Path = "ssh"
	if g, e := parseSecretRelease(rows, request, pathIntent); g != nil || e != ErrAdmissionResponse {
		t.Fatal("a path ticket accepted a path-less release", e)
	}
	wipeQueryRows(rows)
	if _, v, e := trust.VerifyCredentialRelease(context.Background(), intent.Node, g); e != nil || v == nil {
		t.Fatal("wire lifetime", e)
	}
	for column := 0; column < 8; column++ {
		rows, r, intent, _ := secretReleaseFixture(t)
		rows[0][column] = []byte("bad")
		if g, e := parseSecretRelease(rows, r, intent); g != nil || e == nil {
			t.Fatal("receipt substitution", column, e)
		}
	}
	for _, shape := range [][][][]byte{nil, {{}}, {{[]byte("x")}, {[]byte("x")}}} {
		if _, e := parseSecretRelease(shape, request, intent); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
}

func TestFetchSecretValidation(t *testing.T) {
	_, _, intent, _ := secretReleaseFixture(t)
	s := NewSession()
	defer s.Close(context.Background())
	if _, e := s.FetchSecret(nil, intent); e != ErrConfiguration {
		t.Fatal(e)
	}
	for _, mutate := range []func(*UseIntent){func(i *UseIntent) { i.Node = uuid.Nil }, func(i *UseIntent) { i.Ticket = uuid.Nil }, func(i *UseIntent) { i.Epoch = 0 }, func(i *UseIntent) { i.Epoch = math.MaxUint64 }, func(i *UseIntent) { i.ChangeSeq = math.MaxUint64 }, func(i *UseIntent) { i.ExpiresAt = 0 }, func(i *UseIntent) { i.Path = "reveal" }} {
		i := intent
		mutate(&i)
		if _, e := s.FetchSecret(context.Background(), i); e != ErrConfiguration {
			t.Fatal(e)
		}
	}
	if _, e := s.FetchSecret(context.Background(), intent); e != ErrAuthentication {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.FetchSecret(ctx, intent); e != context.Canceled {
		t.Fatal(e)
	}
	seedPasswordSession(t, s)
	if _, e := s.FetchSecret(context.Background(), intent); e != ErrSessionClosed {
		t.Fatal(e)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, e := fake.FetchSecret(context.Background(), intent); e != ErrQuery {
		t.Fatal(e)
	}
}

func TestFetchSecretTransport(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []string{"valid", "large-valid", "receipt", "graph", "uncommitted", "ticket-error", "disconnect", "rows", "columns", "oversize", "caller-transaction"} {
		t.Run(mode, func(t *testing.T) {
			rows, _, intent, trust := secretReleaseFixture(t)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
			done := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				// This fake serves one connection. Refuse pgx's asynchronous
				// cancellation connection instead of leaving it unhandled.
				_ = listener.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if e := initializeWritableTestConnection(b, []byte("fetch-test-secret")); e != nil {
					done <- e
					return
				}
				query, params, e := receiveTestQuery(b)
				if e != nil {
					done <- e
					return
				}
				if mode == "caller-transaction" {
					if query != "BEGIN" {
						done <- fmt.Errorf("expected transaction")
						return
					}
					b.Send(&pgproto3.ParseComplete{})
					b.Send(&pgproto3.BindComplete{})
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
					b.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
				} else {
					if query != fetchSecretSQL || len(params) != 3 || string(params[0]) != strings.Repeat("00", 32) || string(params[1]) != intent.Node.String() || string(params[2]) != intent.Ticket.String() {
						done <- fmt.Errorf("unexpected fetch parameters")
						return
					}
					if mode == "disconnect" {
						done <- nil
						return
					}
					b.Send(&pgproto3.ParseComplete{})
					b.Send(&pgproto3.BindComplete{})
					if mode == "ticket-error" {
						b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "WH015", Message: "private ticket detail"})
					} else {
						values := rows[0]
						switch mode {
						case "receipt":
							values[4] = []byte(uuid.NewString())
						case "graph":
							values[7] = []byte("{}")
						case "large-valid":
							values[7] = append(values[7], bytes.Repeat([]byte(" "), 17*1024*1024)...)
						case "oversize":
							values[7] = bytes.Repeat([]byte("x"), MaxCredentialReleaseBytes+513)
						case "columns":
							values = append(values, []byte("extra"))
						}
						fields := make([]pgproto3.FieldDescription, len(values))
						for i := range fields {
							fields[i] = pgproto3.FieldDescription{Name: []byte("v"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
						}
						b.Send(&pgproto3.RowDescription{Fields: fields})
						b.Send(&pgproto3.DataRow{Values: values})
						if mode == "rows" {
							b.Send(&pgproto3.DataRow{Values: values})
						}
						b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
					}
					status := byte('I')
					if mode == "uncommitted" {
						status = 'T'
					}
					b.Send(&pgproto3.ReadyForQuery{TxStatus: status})
				}
				if e := b.Flush(); e != nil {
					done <- e
					return
				}
				if mode == "large-valid" {
					query, _, e := receiveTestQuery(b)
					if e != nil || query != "SELECT 'cap-probe'" {
						done <- fmt.Errorf("missing restored-cap probe: %v", e)
						return
					}
					b.Send(&pgproto3.ParseComplete{})
					b.Send(&pgproto3.BindComplete{})
					b.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("v"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
					if e := b.Flush(); e != nil {
						done <- e
						return
					}
					// Body length 16 MiB+1. No body is sent: the restored protocol
					// cap must reject this header before trying to read/allocate it.
					if _, e := conn.Write([]byte{'D', 1, 0, 0, 5}); e != nil {
						done <- e
						return
					}
				}
				msg, e := b.Receive()
				if e == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						e = fmt.Errorf("automatic retry or extra operation")
					}
				}
				if errors.Is(e, io.EOF) {
					e = nil
				}
				done <- e
			}()
			config := settings()
			config.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			s := NewSession()
			defer s.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if e := s.Open(ctx, config, []byte("fetch-test-secret"), ChangePolicy{TransactionPooler: true}); e != nil {
				t.Fatal(e)
			}
			seedPasswordSession(t, s)
			if mode == "caller-transaction" {
				if _, e := s.Query(ctx, "BEGIN", nil); e != nil {
					t.Fatal(e)
				}
			}
			g, e := s.FetchSecret(ctx, intent)
			if mode == "valid" || mode == "large-valid" {
				if e != nil || g == nil {
					t.Fatal("valid fetch", e)
				}
				if _, v, e := trust.VerifyCredentialRelease(ctx, intent.Node, g); e != nil || v == nil {
					t.Fatal("verification", e)
				}
				if mode == "large-valid" {
					if rows, e := s.Query(ctx, "SELECT 'cap-probe'", nil); e != ErrQuery || rows != nil {
						t.Fatal("protocol cap was not restored", e)
					}
				}
			} else {
				if e == nil || g != nil || strings.Contains(e.Error(), "private ticket detail") {
					t.Fatal("unsafe release", e)
				}
				if mode == "ticket-error" && e != ErrUseTicket {
					t.Fatal(e)
				}
				if (mode == "rows" || mode == "columns" || mode == "oversize") && e != ErrResultLimit {
					t.Fatal(e)
				}
				if mode == "caller-transaction" && e != ErrConfiguration {
					t.Fatal(e)
				}
				if mode != "caller-transaction" {
					select {
					case <-s.Done():
					default:
						t.Fatal("ambiguous release retained session")
					}
				}
			}
			if e := s.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
