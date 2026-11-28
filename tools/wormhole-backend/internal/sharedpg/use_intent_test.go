package sharedpg

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func useIntentRows() [][][]byte {
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte(testHintID), []byte(treeFirstID), []byte(treeSecondID), []byte("1"), []byte("0"), []byte("1800000000")}}
}
func TestUseIntentParsing(t *testing.T) {
	id := uuid.MustParse(treeFirstID)
	rows := useIntentRows()
	got, err := parseUseIntent(rows, admissionRequest(), id)
	if err != nil || got.Ticket.String() != treeSecondID || got.Node != id || got.Epoch != 1 || got.ChangeSeq != 0 || got.ExpiresAt != 1800000000 {
		t.Fatal("receipt", err)
	}
	wipeQueryRows(rows)
	if got.Ticket.String() != treeSecondID {
		t.Fatal("wire alias")
	}
	for _, bad := range [][][][]byte{nil, {{}}, append(useIntentRows(), useIntentRows()...)} {
		if _, err := parseUseIntent(bad, admissionRequest(), id); err != ErrAdmissionResponse {
			t.Fatal("shape", err)
		}
	}
	for i := 0; i < 8; i++ {
		for _, v := range [][]byte{nil, {}, []byte("bad"), []byte("0"), []byte("01"), []byte("-1"), []byte("9223372036854775808")} {
			if i == 6 && string(v) == "0" {
				continue
			}
			rows := useIntentRows()
			rows[0][i] = v
			if _, err := parseUseIntent(rows, admissionRequest(), id); err != ErrAdmissionResponse {
				t.Fatal("field", i, err)
			}
		}
	}
	rows = useIntentRows()
	rows[0][4] = []byte(uuid.Nil.String())
	if _, err := parseUseIntent(rows, admissionRequest(), id); err != ErrAdmissionResponse {
		t.Fatal("nil ticket", err)
	}
}
func TestUseIntentValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	id := uuid.MustParse(treeFirstID)
	for _, path := range []string{"", "unknown", "rdp-gateway", "reveal"} {
		if _, err := s.BeginUsePath(context.Background(), id, "ui", path); err != ErrConfiguration {
			t.Fatal("unsupported credential release path", err)
		}
	}
	if _, err := s.BeginUse(nil, id, "ui"); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, v := range []struct {
		id     uuid.UUID
		source string
	}{{uuid.Nil, "ui"}, {id, ""}, {id, "UI"}, {id, "mcp\x00"}} {
		if _, err := s.BeginUse(context.Background(), v.id, v.source); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.BeginUse(context.Background(), id, "ui"); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginUse(ctx, id, "ui"); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.BeginUse(context.Background(), id, "ui"); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.BeginUse(context.Background(), id, "ui"); err != ErrQuery {
		t.Fatal(err)
	}
}

func TestUseIntentResponseRetiresSession(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []string{"malformed", "uncommitted", "audit-failure", "disconnect", "path-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
			secret := []byte("test-use-intent")
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
				validQuery := mode == "path-mismatch" && query == beginUsePathSQL && len(params) == 4 && string(params[3]) == "ssh" ||
					mode != "path-mismatch" && query == beginUseSQL && len(params) == 3
				if err != nil || !validQuery || string(params[0]) != strings.Repeat("00", 32) || string(params[1]) != treeFirstID || string(params[2]) != "ui" {
					done <- fmt.Errorf("unexpected use parameters")
					return
				}
				if mode == "disconnect" {
					done <- nil
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				if mode == "audit-failure" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "WH005", Message: "private audit detail"})
				} else {
					values := useIntentRows()[0]
					if mode == "malformed" {
						values[2] = []byte(uuid.NewString())
					}
					if mode == "path-mismatch" {
						values = append(values, []byte("sftp"))
					}
					fields := make([]pgproto3.FieldDescription, len(values))
					for i := range fields {
						fields[i] = pgproto3.FieldDescription{Name: []byte("value"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
					}
					b.Send(&pgproto3.RowDescription{Fields: fields})
					b.Send(&pgproto3.DataRow{Values: values})
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				}
				status := byte('I')
				if mode == "uncommitted" {
					status = 'T'
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: status})
				if err := b.Flush(); err != nil {
					done <- err
					return
				}
				msg, err := b.Receive()
				if err == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						err = fmt.Errorf("automatic retry")
					}
				}
				if errors.Is(err, io.EOF) {
					err = nil
				}
				done <- err
			}()
			config := settings()
			config.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			session := NewSession()
			defer session.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := session.Open(ctx, config, secret, ChangePolicy{TransactionPooler: true}); err != nil {
				t.Fatal(err)
			}
			seedPasswordSession(t, session)
			var result *UseIntent
			if mode == "path-mismatch" {
				result, err = session.BeginUsePath(ctx, uuid.MustParse(treeFirstID), "ui", "ssh")
			} else {
				result, err = session.BeginUse(ctx, uuid.MustParse(treeFirstID), "ui")
			}
			if result != nil || err == nil || strings.Contains(err.Error(), "private audit detail") {
				t.Fatal("unsafe failed receipt", err)
			}
			if mode == "audit-failure" && err != ErrAuditUnavailable {
				t.Fatal(err)
			}
			if (mode == "malformed" || mode == "uncommitted" || mode == "path-mismatch") && err != ErrAdmissionResponse {
				t.Fatal(err)
			}
			select {
			case <-session.Done():
			default:
				t.Fatal("failed session retained")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
