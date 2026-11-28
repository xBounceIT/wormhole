package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func challengeRows() [][][]byte {
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte(testHintID), []byte("1"), []byte("42"), []byte("1900000000"), []byte(strings.Repeat("01", 32)), []byte(strings.Repeat("02", 32)), []byte("4096"), []byte("42")}}
}

func TestParseSessionChallenge(t *testing.T) {
	nonce := NewSessionProofNonce()
	commitment := sha256.Sum256(NewSessionProofNonce())
	rows := challengeRows()
	c, err := parseSessionChallenge(rows, admissionRequest(), nonce, commitment)
	if err != nil || c.Binding.CapabilityHash != commitment || c.Binding.BackendPID != 42 {
		t.Fatal("valid challenge rejected")
	}
	wipeQueryRows(rows)
	if c.ServerNonce[0] != 1 || c.Salt[0] != 2 {
		t.Fatal("challenge aliases rows")
	}
	for _, rows := range [][][][]byte{nil, {{}}, {challengeRows()[0], challengeRows()[0]}} {
		if _, err := parseSessionChallenge(rows, admissionRequest(), nonce, commitment); err != ErrAdmissionResponse {
			t.Fatal("invalid shape accepted")
		}
	}
	for _, bad := range []struct {
		column int
		value  string
	}{
		{0, "bad"}, {1, ""}, {2, "00000000-0000-0000-0000-000000000000"}, {3, "0"}, {3, "9223372036854775808"}, {3, "01"}, {4, "2147483648"}, {4, "-1"}, {5, "0"}, {8, "4095"}, {8, "1000001"}, {9, "43"},
		{6, "00"}, {6, strings.Repeat("zz", 32)}, {7, ""}, {7, strings.Repeat("00", 65)}, {7, strings.Repeat("0", 33)}, {7, strings.Repeat("zz", 32)},
	} {
		rows := challengeRows()
		rows[0][bad.column] = []byte(bad.value)
		if _, err := parseSessionChallenge(rows, admissionRequest(), nonce, commitment); err != ErrAdmissionResponse {
			t.Fatalf("bad column %d accepted", bad.column)
		}
	}
	if _, err := parseSessionChallenge(challengeRows(), admissionRequest(), nil, commitment); err != ErrAdmissionResponse {
		t.Fatal("missing nonce accepted")
	}
	if _, err := parseSessionChallenge(challengeRows(), admissionRequest(), nonce, [32]byte{}); err != ErrAdmissionResponse {
		t.Fatal("missing commitment accepted")
	}
}

func TestAuthenticateSessionValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := s.AuthenticateSession(ctx, admissionRequest(), nil); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.AuthenticateSession(ctx, admissionRequest(), make([]byte, 32)); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateSession(context.Background(), admissionRequest(), make([]byte, 32)); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	if _, err := fake.AuthenticateSession(context.Background(), admissionRequest(), make([]byte, 32)); err != ErrQuery {
		t.Fatal(err)
	}
}

func TestAuthenticateSessionAgainstServer(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, scenario := range []string{"success", "begin-error", "begin-state", "begin-rows", "challenge-error", "challenge-shape", "proof-error", "proof-shape", "proof-signature", "proof-encoding", "admit-error", "admit-shape", "commit-error", "commit-state", "commit-rows"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
			material := bytes.Repeat([]byte{7}, 32)
			login, _ := EncodeLoginSecret(material)
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
				if err := initializeWritableTestConnection(b, login); err != nil {
					done <- err
					return
				}
				var challenge SessionProofChallenge
				for step, expected := range []string{"BEGIN", sessionChallengeSQL, sessionProveSQL, authenticatedSessionStartSQL, "COMMIT"} {
					query, params, err := receiveTestQuery(b)
					if err != nil {
						done <- err
						return
					}
					if query != expected {
						done <- fmt.Errorf("unexpected statement at step %d", step)
						return
					}
					b.Send(&pgproto3.ParseComplete{})
					b.Send(&pgproto3.BindComplete{})
					var rows [][][]byte
					status := byte('T')
					if step == 4 {
						status = 'I'
					}
					failure := strings.HasPrefix(scenario, []string{"begin-", "challenge-", "proof-", "admit-", "commit-"}[step])
					if step == 1 {
						if len(params) != 2 {
							done <- fmt.Errorf("bad challenge parameters")
							return
						}
						nonce, e := hex.DecodeString(string(params[0]))
						hash, e2 := hex.DecodeString(string(params[1]))
						if e != nil || e2 != nil || len(hash) != 32 {
							done <- fmt.Errorf("bad challenge encoding")
							return
						}
						var commitment [32]byte
						copy(commitment[:], hash)
						rows = challengeRows()
						challenge, err = parseSessionChallenge(rows, admissionRequest(), nonce, commitment)
						if err != nil {
							done <- err
							return
						}
					}
					if step == 2 {
						if len(params) != 1 {
							done <- fmt.Errorf("bad proof parameters")
							return
						}
						proof, e := hex.DecodeString(string(params[0]))
						if e != nil {
							done <- e
							return
						}
						verifier := buildSCRAMVerifier(login, challenge.Salt)
						server, e := VerifySessionProof(verifier, challenge.Binding, challenge, proof)
						if e != nil {
							done <- e
							return
						}
						rows = [][][]byte{{hex.AppendEncode(nil, server)}}
					}
					if step == 3 {
						if len(params) != 4 {
							done <- fmt.Errorf("missing capability")
							return
						}
						capability, e := hex.DecodeString(string(params[3]))
						if e != nil || len(capability) != 32 || sha256.Sum256(capability) != challenge.Binding.CapabilityHash {
							done <- fmt.Errorf("capability commitment mismatch")
							return
						}
						rows = admissionRows()
					}
					if failure {
						switch {
						case strings.HasSuffix(scenario, "-error"):
							b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "WH005", Message: "private detail"})
							rows = nil
						case strings.HasSuffix(scenario, "-state"):
							if step == 0 {
								status = 'I'
							} else {
								status = 'T'
							}
						case strings.HasSuffix(scenario, "-rows"):
							rows = [][][]byte{{[]byte("unexpected")}}
						case strings.HasSuffix(scenario, "-shape"):
							rows = [][][]byte{{[]byte("bad")}}
						case scenario == "proof-signature":
							rows = [][][]byte{{[]byte(strings.Repeat("00", 32))}}
						case scenario == "proof-encoding":
							rows = [][][]byte{{[]byte(strings.Repeat("zz", 32))}}
						}
					}
					if len(rows) > 0 {
						fields := make([]pgproto3.FieldDescription, len(rows[0]))
						for i := range fields {
							fields[i] = pgproto3.FieldDescription{Name: []byte("value"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
						}
						b.Send(&pgproto3.RowDescription{Fields: fields})
						for _, row := range rows {
							b.Send(&pgproto3.DataRow{Values: row})
						}
					}
					if !failure || !strings.HasSuffix(scenario, "-error") {
						b.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
					}
					b.Send(&pgproto3.ReadyForQuery{TxStatus: status})
					if e := b.Flush(); e != nil {
						done <- e
						return
					}
					if failure {
						break
					}
				}
				msg, e := b.Receive()
				if e == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						e = fmt.Errorf("expected terminate")
					}
				}
				done <- e
			}()
			settings := settings()
			settings.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			s := NewSession()
			defer s.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
				t.Fatal(err)
			}
			result, err := s.AuthenticateSession(ctx, admissionRequest(), material)
			if scenario == "success" {
				if err != nil || result == nil || s.capability == nil || !s.capability.Locked() {
					t.Fatalf("admission failed: %v", err)
				}
				if _, err := s.AuthenticateSession(ctx, admissionRequest(), material); err != ErrSessionStarted {
					t.Fatal("repeated admission accepted")
				}
			} else {
				if err == nil || result != nil || s.capability != nil {
					t.Fatal("failed exchange retained result or credential")
				}
				select {
				case <-s.Done():
				default:
					t.Fatal("failed exchange left owner active")
				}
			}
			if err := s.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if s.capability != nil {
				t.Fatal("capability not released")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
