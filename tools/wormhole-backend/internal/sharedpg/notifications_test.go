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

const testHintID = "12345678-1234-4234-8234-123456789abc"

func TestChangeHintValidation(t *testing.T) {
	if !validChangeHint(testHintID) {
		t.Fatal("valid ID rejected")
	}
	for _, value := range []string{"", strings.ToUpper(testHintID), "00000000-0000-0000-0000-000000000000", strings.Repeat("x", 36), "{\"id\":\"" + testHintID + "\"}", testHintID + "\n"} {
		if validChangeHint(value) {
			t.Fatal("invalid hint accepted")
		}
	}
	s := NewSession()
	defer s.Close(context.Background())
	if err := s.SubscribeChanges(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := s.SubscribeChanges(context.Background()); err != ErrSessionClosed {
		t.Fatal(err)
	}
	if _, err := s.NextChangeHint(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	fake, _ := readySession(t, true)
	if err := fake.SubscribeChanges(context.Background()); err != ErrNotifications {
		t.Fatal(err)
	}
	if _, err := fake.NextChangeHint(context.Background()); err != ErrNotifications {
		t.Fatal(err)
	}
}

func TestNativeChangeSubscriptions(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, scenario := range []string{"valid", "filtered", "noise", "unexpected", "row", "wrong-tag", "sql-error", "timeout-reuse", "lock-wait"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
			secret := []byte("native-notification-test-secret")
			done := make(chan error, 2)
			sendAfterTimeout := make(chan struct{})
			go func() {
				queryConn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				go func() { done <- serveWritableSessionConnection(queryConn, secret) }()
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
				if query != "listen "+changeChannel || len(params) != 0 {
					done <- fmt.Errorf("unexpected subscription command")
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				switch scenario {
				case "row":
					b.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("bad"), DataTypeOID: 25, DataTypeSize: -1}}})
					b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("private")}})
				case "sql-error":
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "private notification diagnostic"})
				default:
					b.Send(&pgproto3.NoData{})
				}
				if scenario != "sql-error" {
					tag := "LISTEN"
					if scenario == "wrong-tag" {
						tag = "SELECT 0"
					}
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := b.Flush(); err != nil {
					done <- err
					return
				}
				switch scenario {
				case "filtered":
					b.Send(&pgproto3.NoticeResponse{Severity: "NOTICE", Message: "untrusted notice"})
					b.Send(&pgproto3.ParameterStatus{Name: "application_name", Value: "server value"})
					b.Send(&pgproto3.NotificationResponse{Channel: "other", Payload: testHintID})
					b.Send(&pgproto3.NotificationResponse{Channel: changeChannel, Payload: "private malformed payload"})
				case "noise":
					for i := 0; i < 64; i++ {
						b.Send(&pgproto3.NotificationResponse{Channel: changeChannel, Payload: "not an ID"})
					}
				case "unexpected":
					b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				case "timeout-reuse":
					select {
					case <-sendAfterTimeout:
					case <-time.After(5 * time.Second):
						done <- fmt.Errorf("timeout test did not resume")
						return
					}
				}
				if scenario == "valid" || scenario == "filtered" || scenario == "timeout-reuse" {
					b.Send(&pgproto3.NotificationResponse{Channel: changeChannel, Payload: testHintID})
				}
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
			if err := s.Open(ctx, settings, secret, ChangePolicy{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.NextChangeHint(ctx); err != ErrNotSubscribed {
				t.Fatal(err)
			}
			err = s.SubscribeChanges(ctx)
			if scenario == "row" || scenario == "wrong-tag" || scenario == "sql-error" {
				if err != ErrNotifications {
					t.Fatalf("invalid subscription accepted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SubscribeChanges(ctx); err != nil {
					t.Fatal("subscription not idempotent")
				}
				if scenario == "timeout-reuse" {
					waitCtx, stop := context.WithTimeout(ctx, 30*time.Millisecond)
					id, err := s.NextChangeHint(waitCtx)
					stop()
					if err != context.DeadlineExceeded || id != "" {
						t.Fatalf("invalid wait timeout: %v", err)
					}
					close(sendAfterTimeout)
				}
				var closeDone chan error
				if scenario == "lock-wait" {
					closeDone = make(chan error, 1)
					go func() {
						ticker := time.NewTicker(time.Millisecond)
						defer ticker.Stop()
						for {
							if len(s.slots[1].gate) == 1 {
								closeDone <- s.Close(ctx)
								return
							}
							select {
							case <-ticker.C:
							case <-ctx.Done():
								closeDone <- ctx.Err()
								return
							}
						}
					}()
				}
				id, err := s.NextChangeHint(ctx)
				switch scenario {
				case "lock-wait":
					if id != "" || (err != context.Canceled && err != ErrSessionClosed) {
						t.Fatalf("lock did not cancel wait: %v", err)
					}
					if err := <-closeDone; err != nil {
						t.Fatal(err)
					}
				case "noise":
					if err != ErrNotificationNoise || id != "" {
						t.Fatal("invalid noise handling")
					}
				case "unexpected":
					if err != ErrNotifications || id != "" {
						t.Fatal("unexpected protocol message accepted")
					}
				default:
					if err != nil || id != testHintID {
						t.Fatalf("valid hint missing: %v", err)
					}
				}
			}
			if err := s.Close(ctx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("missing termination")
				}
			}
		})
	}
}
