package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func sealedSAMLServer(t *testing.T, mode string) ([]byte, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "fail" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/saml_login" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || !strings.Contains(body["bytes"], "UID=") || !strings.Contains(body["bytes"], "REDIRECT_PORT=") {
				t.Error("missing native attempt")
			}
			_, _ = w.Write([]byte(`window.location="/saml?fixture=1";`))
			return
		}
		w.WriteHeader(404)
	}))
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	raw, _ := json.Marshal(map[string]any{"Host": "127.0.0.1", "SamlPort": port, "PreSharedKey": "synthetic-key", "UserAuth": 3, "Username": "stale-user", "Password": "stale-factor", "TrustServerCertificate": mode != "certificate"})
	return raw, server.Close
}
func TestSealedTunnelBrowserLifecycle(t *testing.T) {
	for _, mode := range []string{"ready", "close", "lock", "bad-cipher", "wrong-purpose", "fail", "certificate"} {
		t.Run(mode, func(t *testing.T) {
			cfg, closeServer := sealedSAMLServer(t, mode)
			defer closeServer()
			b := sealedTunnelBinding()
			b.Kind = 9
			p := testSealedTunnelProcess("127.0.0.1:12345")
			calls := 0
			c := startSealedTunnelTestChild(t, func(ctx context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				calls++
				exe, sidecar, err := sealedTunnelBrowserConfig(ctx, got, raw)
				defer vault.Wipe(sidecar)
				if err != nil || exe != "wormhole-fortiipsecproxy" || !bytes.Contains(sidecar, []byte(`"saml_token":"`+strings.Repeat("aB", 16)+`"`)) || bytes.Contains(sidecar, []byte("stale-factor")) {
					t.Error("invalid authorized native launch", err)
				}
				if _, _, err := sealedTunnelBrowserConfig(context.Background(), got, raw); err == nil {
					t.Error("missing witness accepted")
				}
				changed := append(bytes.Clone(raw), ' ')
				if _, _, err := sealedTunnelBrowserConfig(ctx, got, changed); err == nil {
					t.Error("changed launch accepted")
				}
				return p, nil
			})
			c.send(t, sealedTunnelPacket(t, c.public, b, cfg))
			if mode == "fail" || mode == "certificate" {
				if c.wait(t) == nil || calls != 0 {
					t.Fatal("failed negotiation started")
				}
				return
			}
			var greeting struct {
				Type, SessionID, ChallengeID, StartURL, CallbackURL string
				PublicKey                                           []byte
				IgnoreCertificateErrors                             bool
			}
			if json.Unmarshal(c.line(t), &greeting) != nil || greeting.Type != "browser-authentication-required" {
				t.Fatal("challenge")
			}
			// Go retains the callback port until the same native attempt is retired.
			callback, _ := url.Parse(greeting.CallbackURL)
			listener, err := net.Listen("tcp4", callback.Host)
			if err == nil {
				listener.Close()
				t.Fatal("callback not reserved")
			}
			switch mode {
			case "close", "lock":
				kind := "close"
				if mode == "lock" {
					kind = "app-lock"
				}
				c.send(t, vaultInput(t, map[string]any{"type": kind, "sessionId": b.SessionID}))
			default:
				binding := vault.TunnelBrowserBinding{Route: b, ChallengeID: greeting.ChallengeID, StartURL: greeting.StartURL, CallbackURL: greeting.CallbackURL, IgnoreCertificateErrors: greeting.IgnoreCertificateErrors}
				sealed, e := vault.SealTunnelBrowserToken(greeting.PublicKey, binding, bytes.Repeat([]byte("aB"), 16))
				if e != nil {
					t.Fatal(e)
				}
				if mode == "bad-cipher" {
					sealed.Ciphertext[0] ^= 1
				}
				if mode == "wrong-purpose" {
					sealed, _ = vault.SealTunnelAuthentication(greeting.PublicKey, vault.TunnelAuthenticationBinding{Route: b, ChallengeID: greeting.ChallengeID}, nil, []byte("not-a-token"))
				}
				c.send(t, vaultInput(t, map[string]any{"type": "browser-authentication", "sessionId": b.SessionID, "challengeId": greeting.ChallengeID, "envelope": sealed}))
				if mode == "ready" {
					var ready struct{ Type string }
					if json.Unmarshal(c.line(t), &ready) != nil || ready.Type != "ready" {
						t.Fatal("not ready")
					}
					c.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
				}
			}
			err = c.wait(t)
			if mode == "ready" && (err != nil || calls != 1 || p.alive()) {
				t.Fatal("live native route", err)
			}
			if mode != "ready" && calls != 0 {
				t.Fatal("unauthorized launch")
			}
			listener, err = net.Listen("tcp4", callback.Host)
			if err != nil {
				t.Fatal("callback leaked", err)
			}
			listener.Close()
		})
	}
	// Constructor gates and failure paths never enter legacy authentication.
	if a, err := newSealedTunnelBrowser(sealedTunnelBinding(), nil); err != nil || a != nil {
		t.Fatal("wrong provider")
	}
	b := sealedTunnelBinding()
	b.Kind = 9
	for _, raw := range []string{`{}`, `{"Host":"vpn.test","PreSharedKey":"p","UserAuth":3,"FallbackTunnelId":"bad"}`} {
		if a, err := newSealedTunnelBrowser(b, []byte(raw)); err == nil || a != nil {
			t.Fatal("invalid browser config")
		}
	}
	ctx := context.WithValue(context.Background(), sealedTunnelBrowserKey{}, sealedTunnelBrowserPermit{b, sha256.Sum256([]byte("bad"))})
	if _, _, err := sealedTunnelBrowserConfig(ctx, b, []byte("bad")); err == nil {
		t.Fatal("bad permitted config")
	}
}
