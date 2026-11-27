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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func connectionPlanFixture(t *testing.T, kind string) (connectionFixture, map[string]any) {
	t.Helper()
	f, w := releaseGraphFixture(t, kind, true, false)
	return f, map[string]any{"formatVersion": 1, "profile": w["profile"], "account": w["account"], "metadata": w["metadata"]}
}
func decodePlanFixture(t *testing.T, f connectionFixture, w map[string]any) (*UnverifiedConnectionPlan, error) {
	t.Helper()
	raw, _ := json.Marshal(w)
	return DecodeConnectionPlan(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
}

func pathPlanFixture(t *testing.T) (connectionFixture, map[string]any) {
	t.Helper()
	f, w := connectionPlanFixture(t, "saved")
	metadata := w["metadata"].(map[string]any)
	metadata["formatVersion"], metadata["path"], metadata["importedData"], metadata["tunnel"] = 4, "ssh", nil, nil
	chain := metadata["chain"].([]any)
	for i := range chain {
		chain[i] = append(chain[i].([]any), nil)
	}
	metadata["credential"] = append(metadata["credential"].([]any), nil)
	return f, w
}

func TestConnectionPathPlanRejectsInvalidAttachmentWire(t *testing.T) {
	f, w := pathPlanFixture(t)
	m := w["metadata"].(map[string]any)
	for _, invalid := range []any{"", "0", "invalid hex", strings.Repeat("00", workspaceimport.MaxNodeDataBytes+1)} {
		m["importedData"] = invalid
		if plan, err := decodePlanFixture(t, f, w); plan != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid attachment reached native verification", err)
		}
	}
	m["importedData"] = "7b7d" // An ordinary node has no signed attachment anchor.
	untrusted, err := decodePlanFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, plan, err := f.s.VerifyConnectionPlan(context.Background(), f.node(), untrusted); plan != (ResolvedConnectionPlan{}) || err != vault.ErrFormat {
		t.Fatal("an attachment was accepted without a signed anchor", err)
	}
	m["importedData"], m["path"] = nil, "rdp"
	untrusted, err = decodePlanFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, plan, err := f.s.VerifyConnectionPlan(context.Background(), f.node(), untrusted); plan != (ResolvedConnectionPlan{}) || err == nil {
		t.Fatal("a path outside the leaf's protocol family was accepted")
	}
	m["path"] = "SSH"
	if plan, err := decodePlanFixture(t, f, w); plan != nil || err != ErrAdmissionResponse {
		t.Fatal("path-aware plan accepted a noncanonical path", err)
	}
	delete(m, "path")
	if plan, err := decodePlanFixture(t, f, w); plan != nil || err != ErrAdmissionResponse {
		t.Fatal("path-aware plan omitted its path", err)
	}
}

func TestConnectionPlanVerification(t *testing.T) {
	for _, kind := range []string{"saved", "slot", "override", "gateway", "none"} {
		f, w := connectionPlanFixture(t, kind)
		raw, _ := json.Marshal(w)
		input, e := DecodeConnectionPlan(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
		if e != nil {
			t.Fatal(e)
		}
		vault.Wipe(raw)
		next, p, e := f.s.VerifyConnectionPlan(context.Background(), f.node(), input)
		if e != nil || len(p.Revision) != 64 || p.Plan != input.metadata.plan || f.s.ValidateAdvance(next) != nil {
			t.Fatal(kind, e)
		}
		again, p2, e := next.VerifyConnectionPlan(context.Background(), f.node(), input)
		if e != nil || p2 != p || !reflect.DeepEqual(again, next) {
			t.Fatal("plan stability", e)
		}
		// Any authenticated parent change invalidates pending host confirmation,
		// even if the effective host/account and visible fingerprint stay equal.
		last := len(input.metadata.records.Chain) - 1
		r := &input.metadata.records.Chain[last]
		r.Node.Metadata.Name = "Updated parent"
		r.Node.Seal, e = sharedcatalog.SignNode(f.s.WorkspaceID, r.Node.Boundary, r.Node.Metadata, r.Node.Seal.Revision+1, r.Author.Key, f.key)
		if e != nil {
			t.Fatal(e)
		}
		updated, p3, e := next.VerifyConnectionPlan(context.Background(), f.node(), input)
		if e != nil || p3.Plan != p.Plan || p3.Revision == p.Revision || next.ValidateAdvance(updated) != nil {
			t.Fatal("resolution revision", e)
		}
	}
}

func TestConnectionPlanBoundaries(t *testing.T) {
	for _, mode := range []string{"format", "future", "profile", "account", "metadata", "unknown", "missing", "null", "type", "old-state", "new-state", "redirect", "revocation", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f, w := connectionPlanFixture(t, "saved")
			switch mode {
			case "format":
				w["formatVersion"] = 0
			case "future":
				w["formatVersion"] = 2
			case "profile":
				w["profile"] = "zz"
			case "account":
				w["account"] = []any{"4"}
			case "metadata":
				w["metadata"] = map[string]any{}
			case "unknown":
				w["values"] = []any{}
			case "missing":
				delete(w, "account")
			case "null":
				w["account"] = nil
			case "type":
				w["formatVersion"] = "1"
			}
			input, e := decodePlanFixture(t, f, w)
			if mode == "future" {
				if e != vault.ErrNewerFormat {
					t.Fatal(e)
				}
				return
			}
			if mode == "format" || mode == "profile" || mode == "account" || mode == "metadata" || mode == "unknown" || mode == "missing" || mode == "null" || mode == "type" {
				if e == nil || input != nil {
					t.Fatal("invalid wire", mode, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			want := error(ErrTreeSnapshotChanged)
			switch mode {
			case "old-state":
				input.account.Sequence--
				input.account, _ = vault.SignUserKeyState(input.account, f.org)
				want = vault.ErrRollback
			case "new-state":
				input.account.Sequence++
				input.account, _ = vault.SignUserKeyState(input.account, f.org)
				want = vault.ErrRollback
			case "redirect":
				input.metadata.plan.Host = "redirect.example"
				want = ErrAdmissionResponse
			case "revocation":
				input.account.Sequence++
				input.account.Active = false
				input.account, _ = vault.SignUserKeyState(input.account, f.org)
				want = vault.ErrPolicy
			case "policy":
				policy, _ := vault.DecodeSignedPolicy(input.profile)
				policy.Policy.Sequence++
				policy, _ = vault.SignPolicy(policy.Policy, policy.SignerKeyID, policy.SignerKeyVersion, f.org)
				input.profile, _ = vault.EncodeSignedPolicy(policy)
				want = ErrProfileChanged
			}
			next, p, e := f.s.VerifyConnectionPlan(context.Background(), f.node(), input)
			if e != want || p != (ResolvedConnectionPlan{}) || next.Revision == 0 {
				t.Fatal("invalid plan", mode, e, want)
			}
			if next.Revision != f.s.Revision && f.s.ValidateAdvance(next) != nil {
				t.Fatal("lost observation")
			}
		})
	}
	f, w := connectionPlanFixture(t, "saved")
	input, _ := decodePlanFixture(t, f, w)
	for _, raw := range [][]byte{nil, {255}, []byte("[]"), []byte("{}"), bytes.Repeat([]byte("x"), MaxConnectionPlanBytes+1)} {
		if _, e := DecodeConnectionPlan(raw, AdmissionRequest{}, uuid.Nil, 0, 0); e == nil {
			t.Fatal("bad raw")
		}
	}
	for _, ctx := range []context.Context{nil, &cancelResolutionContext{Context: context.Background(), after: 0}} {
		if _, _, e := f.s.VerifyConnectionPlan(ctx, f.node(), input); e == nil {
			t.Fatal("bad context")
		}
	}
	if _, _, e := f.s.VerifyConnectionPlan(context.Background(), f.node(), nil); e != ErrConfiguration {
		t.Fatal(e)
	}
	if _, _, e := (TrustState{}).VerifyConnectionPlan(context.Background(), f.node(), input); e != ErrTrustState {
		t.Fatal(e)
	}
	f.s.Revision = math.MaxUint64 - 1
	next, _, e := f.s.VerifyConnectionPlan(context.Background(), f.node(), input)
	if e != nil || next.Revision != math.MaxUint64 {
		t.Fatal(e)
	}
	if _, _, e := next.VerifyConnectionPlan(context.Background(), f.node(), input); e != nil {
		t.Fatal("max idempotence", e)
	}
}

func TestConnectionPlanSessionValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	n := uuid.New()
	if _, e := s.ConnectionPlanPath(context.Background(), n, "unknown"); e != ErrConfiguration {
		t.Fatal(e)
	}
	if _, e := s.ConnectionPlan(nil, n); e != ErrConfiguration {
		t.Fatal(e)
	}
	if _, e := s.ConnectionPlan(context.Background(), uuid.Nil); e != ErrConfiguration {
		t.Fatal(e)
	}
	if _, e := s.ConnectionPlan(context.Background(), n); e != ErrAuthentication {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.ConnectionPlan(ctx, n); e != context.Canceled {
		t.Fatal(e)
	}
	seedPasswordSession(t, s)
	if _, e := s.ConnectionPlan(context.Background(), n); e != ErrSessionClosed {
		t.Fatal(e)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, e := fake.ConnectionPlan(context.Background(), n); e != ErrQuery {
		t.Fatal(e)
	}
}

func TestConnectionPlanTransport(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []string{"valid", "large", "workspace", "user", "device", "node", "epoch", "sequence", "payload", "columns", "extra-row", "error", "disconnect", "path-valid", "path-mismatch", "path-in-legacy"} {
		t.Run(mode, func(t *testing.T) {
			f, w := connectionPlanFixture(t, "saved")
			path := ""
			if strings.HasPrefix(mode, "path-") {
				f, w = pathPlanFixture(t)
				switch mode {
				case "path-valid":
					path = "ssh"
				case "path-mismatch":
					path = "sftp"
				}
			}
			payload, _ := json.Marshal(w)
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
				_ = listener.Close()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if e := initializeWritableTestConnection(b, []byte("plan-test")); e != nil {
					done <- e
					return
				}
				query, params, e := receiveTestQuery(b)
				validQuery := path == "" && query == connectionPlanSQL && len(params) == 2 ||
					path != "" && query == connectionPlanPathSQL && len(params) == 3 && string(params[2]) == path
				if e != nil || !validQuery || string(params[0]) != strings.Repeat("00", 32) || string(params[1]) != f.node().String() {
					done <- fmt.Errorf("unexpected metadata query: %v", e)
					return
				}
				if mode == "disconnect" {
					done <- nil
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				if mode == "error" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "WH007", Message: "private plan detail"})
				} else {
					values := [][]byte{[]byte(testHintID), []byte(testHintID), []byte(testHintID), []byte(f.node().String()), []byte("1"), []byte("7"), payload}
					col := map[string]int{"workspace": 0, "user": 1, "device": 2, "node": 3, "epoch": 4, "sequence": 5, "payload": 6}
					if n, ok := col[mode]; ok {
						values[n] = []byte("bad")
					}
					if mode == "large" {
						values[6] = append(values[6], bytes.Repeat([]byte(" "), 17*1024*1024)...)
					}
					if mode == "columns" {
						values = values[:6]
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
						e = fmt.Errorf("automatic retry or extra request")
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
			if e := s.Open(ctx, config, []byte("plan-test"), ChangePolicy{TransactionPooler: true}); e != nil {
				t.Fatal(e)
			}
			seedPasswordSession(t, s)
			var input *UnverifiedConnectionPlan
			if path == "" {
				input, e = s.ConnectionPlan(ctx, f.node())
			} else {
				input, e = s.ConnectionPlanPath(ctx, f.node(), path)
			}
			if mode == "valid" || mode == "large" || mode == "path-valid" {
				if e != nil || input == nil {
					t.Fatal(e)
				}
				if _, _, e := f.s.VerifyConnectionPlan(ctx, f.node(), input); e != nil {
					t.Fatal(e)
				}
			} else {
				if e == nil || input != nil || strings.Contains(e.Error(), "private plan detail") {
					t.Fatal("unsafe metadata response", e)
				}
				select {
				case <-s.Done():
				default:
					t.Fatal("failed session retained")
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
