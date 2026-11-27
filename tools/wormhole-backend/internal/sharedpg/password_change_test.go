package sharedpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func passwordChangeFixture(t *testing.T) (*PreparedPasswordChange, []byte, []byte, vault.UserKeyBinding, vault.Envelope, vault.UserPublicKeys) {
	t.Helper()
	oldMaster, newMaster := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	keys := &vault.UserKeys{EncryptionPrivate: NewSessionProofNonce(), SigningSeed: NewSessionProofNonce()}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.UserKeyBinding{WorkspaceID: uuid.MustParse(testHintID), UserID: uuid.MustParse(testHintID), Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, Revision: 1}
	envelope, err := vault.SealUserKeys(oldMaster, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PreparePasswordChange(oldMaster, newMaster, binding, envelope, public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Wipe)
	return p, oldMaster, newMaster, binding, envelope, public
}

func TestPreparePasswordChange(t *testing.T) {
	p, oldMaster, newMaster, binding, envelope, public := passwordChangeFixture(t)
	if p.validate() != nil || p.binding.Revision != 2 {
		t.Fatal("invalid prepared change")
	}
	oldKeys, err := vault.OpenUserKeys(oldMaster, binding, envelope, public)
	if err != nil {
		t.Fatal(err)
	}
	defer oldKeys.Wipe()
	newKeys, err := vault.OpenUserKeys(newMaster, p.binding, p.envelope, public)
	if err != nil {
		t.Fatal(err)
	}
	defer newKeys.Wipe()
	if !bytes.Equal(oldKeys.EncryptionPrivate, newKeys.EncryptionPrivate) || !bytes.Equal(oldKeys.SigningSeed, newKeys.SigningSeed) {
		t.Fatal("private keys changed")
	}
	if !bytes.Equal(oldMaster, bytes.Repeat([]byte{1}, 32)) || !bytes.Equal(newMaster, bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("borrowed master modified")
	}
	material, _ := vault.DeriveKey(newMaster, nil, vault.PurposeLogin)
	defer vault.Wipe(material)
	// Recompute using the verifier's random salt and the independently derived login.
	login, _ := EncodeLoginSecret(material)
	defer vault.Wipe(login)
	salt, err := base64.StdEncoding.DecodeString(strings.Split(strings.Split(string(p.verifier), "$")[1], ":")[1])
	if err != nil || !bytes.Equal(p.verifier, buildSCRAMVerifier(login, salt)) {
		t.Fatal("verifier does not authenticate the new login")
	}
	encoded, err := json.Marshal(p)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("prepared secrets exposed to JSON")
	}
	for _, bad := range [][]byte{nil, oldMaster[:31], newMaster} {
		result, err := PreparePasswordChange(bad, newMaster, binding, envelope, public)
		if err == nil || result != nil {
			t.Fatal("invalid old master accepted")
		}
	}
	if result, err := PreparePasswordChange(oldMaster, nil, binding, envelope, public); err == nil || result != nil {
		t.Fatal("invalid new master accepted")
	}
	wrong := public
	wrong.Encryption = bytes.Clone(public.Encryption)
	wrong.Encryption[0] ^= 1
	if result, err := PreparePasswordChange(oldMaster, newMaster, binding, envelope, wrong); err == nil || result != nil {
		t.Fatal("uncertified keys accepted")
	}
	verifier, nonce, ciphertext := p.verifier, p.envelope.Nonce, p.envelope.Ciphertext
	p.Wipe()
	p.Wipe()
	(*PreparedPasswordChange)(nil).Wipe()
	for _, value := range [][]byte{verifier, nonce, ciphertext} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("retained alias not wiped")
		}
	}
	if p.validate() != ErrPasswordChangePayload {
		t.Fatal("wiped plan accepted")
	}
}

func seedPasswordSession(t *testing.T, s *Session) {
	t.Helper()
	var err error
	s.capability, err = securemem.New(32, false)
	if err != nil {
		t.Fatal(err)
	}
	s.admission = admissionRequest()
	s.authEpoch = 1
}

func TestChangePasswordValidation(t *testing.T) {
	p, _, _, _, _, _ := passwordChangeFixture(t)
	s := NewSession()
	defer s.Close(context.Background())
	for _, test := range []struct {
		ctx    context.Context
		p      *PreparedPasswordChange
		source string
		want   error
	}{
		{nil, p, "ui", ErrConfiguration}, {context.Background(), p, "bad", ErrConfiguration}, {context.Background(), nil, "ui", ErrPasswordChangePayload}, {context.Background(), p, "ui", ErrAuthentication},
	} {
		if r, e := s.ChangePassword(test.ctx, test.p, test.source); r != nil || e != test.want {
			t.Fatalf("unexpected validation: %v", e)
		}
	}
	seedPasswordSession(t, s)
	p.binding.UserID = uuid.New()
	if _, e := s.ChangePassword(context.Background(), p, "ui"); e != ErrPasswordChangePayload {
		t.Fatal(e)
	}
	p.binding.UserID = s.admission.UserID
	s.authEpoch = math.MaxInt64
	if _, e := s.ChangePassword(context.Background(), p, "ui"); e != ErrAccountRevision {
		t.Fatal(e)
	}
	s.authEpoch = 1
	if _, e := s.ChangePassword(context.Background(), p, "ui"); e != ErrSessionClosed {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.ChangePassword(ctx, p, "ui"); e != context.Canceled {
		t.Fatal(e)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, e := fake.ChangePassword(context.Background(), p, "ui"); e != ErrQuery {
		t.Fatal(e)
	}
}

func TestChangePasswordWireOutcomes(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, scenario := range []string{"success", "disconnect", "shape", "revision", "epoch", "noncanonical", "invalid-number", "transaction", "WH008", "WH009", "WH010", "WH005", "55P03", "WH001", "WH007", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			p, _, _, _, _, _ := passwordChangeFixture(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
			secret := []byte("native-password-change-test")
			done := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if e = initializeWritableTestConnection(b, secret); e != nil {
					done <- e
					return
				}
				query, params, e := receiveTestQuery(b)
				if e != nil {
					done <- e
					return
				}
				if query != changePasswordSQL || len(params) != 6 || string(params[0]) != strings.Repeat("00", 32) || string(params[1]) != "1" || !bytes.Equal(params[2], p.verifier) || string(params[3]) != hex.EncodeToString(p.envelope.Nonce) || string(params[4]) != hex.EncodeToString(p.envelope.Ciphertext) || string(params[5]) != "mcp" {
					done <- fmt.Errorf("password change parameters differ")
					return
				}
				if scenario == "disconnect" {
					_ = listener.Close()
					done <- nil
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				code := scenario
				if scenario == "unknown" {
					code = "XX000"
				}
				if strings.HasPrefix(code, "WH") || code == "55P03" || code == "XX000" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: "private detail must not escape"})
				} else {
					values := [][]byte{[]byte("2"), []byte("2")}
					switch scenario {
					case "shape":
						values = values[:1]
					case "revision":
						values[0] = []byte("3")
					case "epoch":
						values[1] = []byte("3")
					case "noncanonical":
						values[0] = []byte("02")
					case "invalid-number":
						values[1] = []byte("bad")
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
				if scenario == "transaction" {
					status = 'T'
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: status})
				if e = b.Flush(); e != nil {
					done <- e
					return
				}
				msg, e := b.Receive()
				if e == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						e = fmt.Errorf("request unexpectedly retried")
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
			if err := s.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
				t.Fatal(err)
			}
			// Admission itself is covered by the full exchange and real PostgreSQL tests.
			seedPasswordSession(t, s)
			receipt, err := s.ChangePassword(ctx, p, "mcp")
			known := map[string]error{"WH008": ErrPasswordChangePayload, "WH009": ErrDeviceCredentials, "WH010": ErrAccountRevision, "WH005": ErrAuditUnavailable, "55P03": ErrChangeInProgress, "WH001": ErrIdentityUnavailable, "WH007": ErrAuthentication}
			expected := ErrPasswordChangeUncertain
			if scenario == "success" {
				expected = nil
			} else if e, ok := known[scenario]; ok {
				expected = e
			}
			if err != expected {
				t.Fatalf("got %v want %v", err, expected)
			}
			if scenario == "success" {
				if receipt == nil || receipt.WrappingRevision != 2 || receipt.AuthEpoch != 2 {
					t.Fatal("missing committed receipt")
				}
			} else if receipt != nil {
				t.Fatal("failure returned committed receipt")
			}
			retired := expected == nil || expected == ErrPasswordChangeUncertain || expected == ErrIdentityUnavailable || expected == ErrAuthentication
			select {
			case <-s.Done():
				if !retired {
					t.Fatal("known rejection retired session")
				}
			default:
				if retired {
					t.Fatal("uncertain or committed session retained")
				}
			}
			if retired && (s.capability != nil || s.authEpoch != 0 || s.admission != (AdmissionRequest{})) {
				t.Fatal("retired session retained authority")
			}
			if err := s.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
