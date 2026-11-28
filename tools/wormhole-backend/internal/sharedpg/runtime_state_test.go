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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func runtimeFixture(t *testing.T) (connectionFixture, map[string]any, *UnverifiedRuntimeState) {
	t.Helper()
	f, plan := connectionPlanFixture(t, "saved")
	wire := map[string]any{"formatVersion": 1, "profile": plan["profile"], "account": plan["account"]}
	raw, _ := json.Marshal(wire)
	input, err := DecodeRuntimeState(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID})
	if err != nil {
		t.Fatal(err)
	}
	vault.Wipe(raw)
	return f, wire, input
}

func TestRuntimeStateVerificationAndRetention(t *testing.T) {
	for _, mode := range []string{"current", "advance-account", "revoked", "rotated", "old-account", "forged-account", "policy", "policy-rollback", "policy-fork", "forged-policy", "cancel", "max-revision"} {
		t.Run(mode, func(t *testing.T) {
			f, _, input := runtimeFixture(t)
			ctx := context.Background()
			var want error
			switch mode {
			case "advance-account", "revoked", "rotated", "old-account", "forged-account":
				input.account.Sequence++
				if mode == "revoked" {
					input.account.Active = false
					want = vault.ErrPolicy
				}
				if mode == "rotated" {
					input.account.Encryption.ID = uuid.New()
					want = vault.ErrAuthentication
				}
				if mode == "old-account" {
					input.account.Sequence -= 2
					want = vault.ErrRollback
				}
				input.account, _ = vault.SignUserKeyState(input.account, f.org)
				if mode == "forged-account" {
					input.account.Signature = make([]byte, 64)
					want = vault.ErrAuthentication
				}
			case "policy", "policy-rollback", "policy-fork", "forged-policy":
				p, _ := vault.DecodeSignedPolicy(input.profile)
				if mode == "policy" {
					p.Policy.Sequence++
					p.Policy.Profile = vault.Standard
					want = ErrProfileChanged
				}
				if mode == "policy-rollback" {
					p.Policy.Sequence--
					want = ErrProfileRollback
				}
				if mode == "policy-fork" {
					p.Policy.OrgEscrow = false
					p.Policy.Profile = vault.Paranoid
					p.Policy.KDF = vault.KDFV3
					p.Policy.ASKRequired = true
					want = ErrProfileEquivocation
				}
				p, err := vault.SignPolicy(p.Policy, p.SignerKeyID, p.SignerKeyVersion, f.org)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "forged-policy" {
					p.Signature[0] ^= 1
					want = ErrProfileAuthentication
				}
				input.profile, _ = vault.EncodeSignedPolicy(p)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "max-revision":
				f.s.Revision = math.MaxUint64
			}
			next, err := f.s.VerifyRuntimeState(ctx, input)
			if err != want || next.Revision == 0 {
				t.Fatal(mode, err, want)
			}
			if next.Revision != f.s.Revision && f.s.ValidateAdvance(next) != nil {
				t.Fatal("invalid retained state")
			}
			if mode == "policy" && (next.PolicySequence != f.s.PolicySequence+1 || bytes.Equal(next.SignedProfile, f.s.SignedProfile)) {
				t.Fatal("higher policy lost")
			}
			if mode == "revoked" && (next.Account.Active || next.Account.Sequence != input.account.Sequence) {
				t.Fatal("revocation lost")
			}
			if want == nil {
				again, err := next.VerifyRuntimeState(ctx, input)
				if err != nil || !reflect.DeepEqual(again, next) {
					t.Fatal("unstable state", err)
				}
			}
		})
	}
	f, _, input := runtimeFixture(t)
	if _, err := f.s.VerifyRuntimeState(nil, input); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := f.s.VerifyRuntimeState(context.Background(), nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := (TrustState{}).VerifyRuntimeState(context.Background(), input); err != ErrTrustState {
		t.Fatal(err)
	}
}

func TestRuntimeStateWireBounds(t *testing.T) {
	f, wire, _ := runtimeFixture(t)
	request := AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}
	for _, raw := range [][]byte{nil, {255}, []byte("null"), []byte("[]"), []byte("{}"), bytes.Repeat([]byte("x"), MaxRuntimeStateBytes+1)} {
		if _, err := DecodeRuntimeState(raw, request); err == nil {
			t.Fatal("malformed state accepted")
		}
	}
	for _, mode := range []string{"version", "future", "profile-empty", "profile-long", "profile-hex", "account-null", "account-row", "account-scope", "account-hex", "account-sequence", "extra", "missing", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			copy := make(map[string]any)
			for k, v := range wire {
				copy[k] = v
			}
			switch mode {
			case "version":
				copy["formatVersion"] = 0
			case "future":
				copy["formatVersion"] = 2
			case "profile-empty":
				copy["profile"] = ""
			case "profile-long":
				copy["profile"] = strings.Repeat("00", 65537)
			case "profile-hex":
				copy["profile"] = "zz"
			case "account-null":
				copy["account"] = nil
			case "account-row":
				copy["account"] = []any{"1"}
			case "account-scope":
				request.UserID = uuid.New()
				defer func() { request.UserID = f.s.UserID }()
			case "account-hex":
				copy["account"] = []any{"1", "zz"}
			case "account-sequence":
				copy["account"] = []any{"01", wire["account"].([]any)[1]}
			case "extra":
				copy["keys"] = []any{}
			case "missing":
				delete(copy, "account")
			}
			raw, _ := json.Marshal(copy)
			if mode == "duplicate" {
				raw = append([]byte(`{"formatVersion":1,`), raw[1:]...)
			}
			input, err := DecodeRuntimeState(raw, request)
			if err == nil || input != nil {
				t.Fatal("invalid wrapper accepted")
			}
			if mode == "future" && err != vault.ErrNewerFormat {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeStateSessionGuards(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.RuntimeState(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.RuntimeState(context.Background()); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.RuntimeState(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.RuntimeState(context.Background()); err != ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestRuntimeStateTransport(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []string{"valid", "logged", "logging-changed", "logging-invalid", "workspace", "user", "device", "epoch", "sequence", "payload", "oversize", "columns", "extra-row", "error", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f, wire, _ := runtimeFixture(t)
			payload, _ := json.Marshal(wire)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
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
				_ = listener.Close()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if e := initializeWritableTestConnection(b, []byte("runtime-test")); e != nil {
					done <- e
					return
				}
				query, params, e := receiveTestQuery(b)
				if e != nil || query != runtimeStateSQL || len(params) != 1 || string(params[0]) != strings.Repeat("00", 32) {
					done <- fmt.Errorf("unexpected runtime query: %v", e)
					return
				}
				if mode == "disconnect" {
					done <- nil
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				if mode == "error" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "WH007", Message: "private runtime detail"})
				} else {
					values := [][]byte{[]byte(testHintID), []byte(testHintID), []byte(testHintID), []byte("1"), []byte("7"), payload, []byte("true")}
					if mode == "logged" || mode == "logging-changed" {
						values[6] = []byte("false")
					}
					if mode == "logging-invalid" {
						values[6] = nil
					}
					if i, ok := map[string]int{"workspace": 0, "user": 1, "device": 2, "epoch": 3, "sequence": 4, "payload": 5}[mode]; ok {
						values[i] = []byte("bad")
					}
					if mode == "oversize" {
						values[5] = append(values[5], bytes.Repeat([]byte(" "), MaxRuntimeStateBytes)...)
					}
					if mode == "columns" {
						values = values[:5]
					}
					fields := make([]pgproto3.FieldDescription, len(values))
					for i := range fields {
						fields[i] = pgproto3.FieldDescription{Name: []byte("v"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
					}
					b.Send(&pgproto3.RowDescription{Fields: fields})
					b.Send(&pgproto3.DataRow{Values: values})
					if mode == "extra-row" {
						b.Send(&pgproto3.DataRow{Values: values})
					}
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if e := b.Flush(); e != nil {
					done <- e
					return
				}
				msg, e := b.Receive()
				if e == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						e = errors.New("retry or unexpected query")
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
			if e := s.Open(ctx, config, []byte("runtime-test"), ChangePolicy{TransactionPooler: true}); e != nil {
				t.Fatal(e)
			}
			seedPasswordSession(t, s)
			s.requirePrivateStatements = mode == "logging-changed"
			input, e := s.RuntimeState(ctx)
			if mode == "logging-changed" && !errors.Is(e, ErrProfileChanged) {
				t.Fatalf("changed statement logging under Standard: %v", e)
			}
			if mode == "valid" || mode == "logged" {
				if e != nil || input == nil || input.StatementsPrivate() != (mode == "valid") {
					t.Fatal(e)
				}
				if _, e = f.s.VerifyRuntimeState(ctx, input); e != nil {
					t.Fatal(e)
				}
			} else if e == nil || input != nil || strings.Contains(e.Error(), "private runtime") {
				t.Fatal("invalid runtime result", e)
			}
			if e := s.Close(ctx); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-ctx.Done():
				t.Fatal("runtime transport did not stop")
			}
		})
	}
}
