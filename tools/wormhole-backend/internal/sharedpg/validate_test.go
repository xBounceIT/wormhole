package sharedpg

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/pbkdf2"
)

func TestAuthenticatedServerStateValidation(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, state := range []string{"off", "on", "empty", "null", "extra-row", "query-error", "late-query-error"} {
		t.Run(state, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			secret := []byte("native-device-test-secret")
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
				if err = authenticateTestClient(b, secret); err != nil {
					done <- err
					return
				}
				for {
					msg, err := b.Receive()
					if err != nil {
						done <- err
						return
					}
					if parse, ok := msg.(*pgproto3.Parse); ok && parse.Query != "show transaction_read_only" {
						done <- fmt.Errorf("unexpected validation query")
						return
					}
					if _, ok := msg.(*pgproto3.Sync); ok {
						break
					}
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				b.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("transaction_read_only"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
				if state == "query-error" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "XX000", Message: "private diagnostic"})
				} else {
					if state != "empty" {
						value := []byte("off")
						if state == "on" {
							value = []byte("on")
						}
						if state == "null" {
							value = nil
						}
						b.Send(&pgproto3.DataRow{Values: [][]byte{value}})
						if state == "extra-row" {
							b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("off")}})
						}
					}
					if state == "late-query-error" {
						b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "XX000", Message: "private diagnostic"})
					} else {
						b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SHOW")})
					}
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
					done <- fmt.Errorf("expected connection termination, got %T", msg)
					return
				}
				done <- nil
			}()
			s := settings()
			s.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := Connect(ctx, s, secret)
			if state == "off" {
				if err != nil || conn == nil {
					t.Fatalf("valid SCRAM connection failed: %v", err)
				}
				if err := conn.Close(ctx); err != nil {
					t.Fatal(err)
				}
			} else if conn != nil || err != ErrConnection {
				t.Fatalf("invalid server state accepted: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Complete both SCRAM proofs so the tests reach real post-authentication
// validation instead of passing because authentication was rejected earlier.
func authenticateTestClient(b *pgproto3.Backend, secret []byte) error {
	b.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := b.Flush(); err != nil {
		return err
	}
	b.SetAuthType(pgproto3.AuthTypeSASL)
	msg, err := b.Receive()
	if err != nil {
		return err
	}
	initial, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok {
		return fmt.Errorf("expected SCRAM initial, got %T", msg)
	}
	first := strings.TrimPrefix(string(initial.Data), "n,,")
	parts := strings.Split(first, ",r=")
	if len(parts) != 2 {
		return fmt.Errorf("missing client nonce")
	}
	serverFirst := "r=" + parts[1] + "server,s=c2FsdA==,i=4096"
	b.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := b.Flush(); err != nil {
		return err
	}
	b.SetAuthType(pgproto3.AuthTypeSASLContinue)
	msg, err = b.Receive()
	if err != nil {
		return err
	}
	final, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return fmt.Errorf("expected SCRAM final, got %T", msg)
	}
	proofParts := strings.Split(string(final.Data), ",p=")
	if len(proofParts) != 2 {
		return fmt.Errorf("missing proof")
	}
	auth := first + "," + serverFirst + "," + proofParts[0]
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(value))
		return h.Sum(nil)
	}
	salted := pbkdf2.Key(secret, []byte("salt"), 4096, 32, sha256.New)
	clientKey := mac(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	signature := mac(storedKey[:], auth)
	for i := range clientKey {
		clientKey[i] ^= signature[i]
	}
	proof, err := base64.StdEncoding.DecodeString(proofParts[1])
	if err != nil || !hmac.Equal(proof, clientKey) {
		return fmt.Errorf("invalid client proof")
	}
	serverSignature := mac(mac(salted, "Server Key"), auth)
	b.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte("v=" + base64.StdEncoding.EncodeToString(serverSignature))})
	b.Send(&pgproto3.AuthenticationOk{})
	b.Send(&pgproto3.BackendKeyData{ProcessID: 123, SecretKey: []byte{1, 2, 3, 4}})
	b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return b.Flush()
}
