package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"strings"
	"testing"
)

func TestSealedTunnelCookieLifecycle(t *testing.T) {
	testSealedTunnelCookieLifecycle(t, false)
}

func TestSealedFallbackCookieLifecycle(t *testing.T) {
	testSealedTunnelCookieLifecycle(t, true)
}

func testSealedTunnelCookieLifecycle(t *testing.T, fallback bool) {
	for _, mode := range []string{"ready", "callback", "max", "close", "lock", "eof", "wrong-cipher", "wrong-purpose", "replay"} {
		t.Run(mode, func(t *testing.T) {
			b := sealedTunnelBinding()
			b.Kind = 2
			pair := sealedFallbackBinding()
			if fallback {
				b = pair.Fallback
			}
			p := testSealedTunnelProcess("127.0.0.1:12345")
			calls := 0
			cookie := []byte("one-use-cookie+/=")
			callback := mode == "callback"
			ready := callback || mode == "ready" || mode == "max"
			if callback {
				cookie = []byte("opaque,callback")
			}
			if mode == "max" {
				cookie = bytes.Repeat([]byte("c"), vault.MaxTunnelCookieBytes)
			}
			child := startSealedTunnelTestChildMode(t, func(ctx context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				calls++
				if got != b {
					t.Error("cookie launch changed active source")
				}
				exe, cfg, err := sealedTunnelBrowserConfig(ctx, got, raw)
				defer vault.Wipe(cfg)
				if err != nil || exe != "wormhole-fortiproxy" || !bytes.Contains(cfg, cookie) || bytes.Contains(cfg, []byte("stale")) {
					t.Error("invalid cookie launch", err)
				}
				if callback && !bytes.Contains(cfg, []byte(`"saml_auth_id":"opaque,callback"`)) {
					t.Error("missing callback credential")
				}
				if _, _, err := sealedTunnelBrowserConfig(context.Background(), got, raw); err == nil {
					t.Error("missing witness")
				}
				return p, nil
			}, fallback)
			original := []byte(`{"Host":"vpn.test","UseSingleSignOn":true,"Realm":"staff/a","Username":"stale-user","Password":"stale-password","SvpnCookie":"stale-cookie","SamlAuthId":"stale-auth"}`)
			if callback {
				original = bytes.Replace(original, []byte(`"Realm":"staff/a"`), []byte(`"UseSamlCallback":true`), 1)
			}
			if fallback {
				child.send(t, sealedFallbackPacket(t, child.public, pair, original))
			} else {
				child.send(t, sealedTunnelPacket(t, child.public, b, original))
			}
			var g struct {
				Type, SessionID, ChallengeID, StartURL, CookieName, Completion string
				PublicKey                                                      []byte
				IgnoreCertificateErrors                                        bool
			}
			name, completion, query := "SVPNCOOKIE", "", "realm=staff%2Fa"
			if callback {
				name, completion, query = "", "fortinet-ssl", "redirect=1"
			}
			if json.Unmarshal(child.line(t), &g) != nil || g.Type != "cookie-authentication-required" || g.CookieName != name || g.Completion != completion || g.StartURL != "https://vpn.test:443/remote/saml/start?"+query {
				t.Fatalf("challenge type=%s start=%s cookie=%s", g.Type, g.StartURL, g.CookieName)
			}
			switch mode {
			case "close", "lock":
				kind := "close"
				if mode == "lock" {
					kind = "app-lock"
				}
				child.send(t, vaultInput(t, map[string]any{"type": kind, "sessionId": b.SessionID}))
			case "eof":
				child.input.Close()
			default:
				binding := vault.TunnelCookieBinding{Route: b, ChallengeID: g.ChallengeID, StartURL: g.StartURL, UseSamlCallback: callback, IgnoreCertificateErrors: g.IgnoreCertificateErrors}
				sealed, err := vault.SealTunnelCookie(g.PublicKey, binding, cookie)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "wrong-cipher" {
					sealed.Ciphertext[0] ^= 1
				}
				if mode == "wrong-purpose" {
					sealed, _ = vault.SealTunnelBundle(g.PublicKey, b, []byte("not-cookie"))
				}
				packet := vaultInput(t, map[string]any{"type": "cookie-authentication", "sessionId": b.SessionID, "challengeId": g.ChallengeID, "envelope": sealed})
				child.send(t, packet)
				if ready || mode == "replay" {
					var ready struct{ Type string }
					if json.Unmarshal(child.line(t), &ready) != nil || ready.Type != "ready" {
						t.Fatal("not ready")
					}
					if mode == "replay" {
						child.send(t, packet)
					} else {
						child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
					}
				}
			}
			err := child.wait(t)
			if ready && (err != nil || calls != 1 || p.alive()) {
				t.Fatal("route cleanup", err)
			}
			if (mode == "wrong-cipher" || mode == "wrong-purpose" || mode == "replay") && err == nil {
				t.Fatal("invalid control accepted")
			}
			if !ready && mode != "replay" && calls != 0 {
				t.Fatal("unexpected start")
			}
		})
	}
}
func TestSealedTunnelCookieGates(t *testing.T) {
	b := sealedTunnelBinding()
	b.Kind = 2
	if a, err := newSealedTunnelCookie(sealedTunnelBinding(), nil); err != nil || a != nil {
		t.Fatal("other provider")
	}
	if a, err := newSealedTunnelCookie(b, []byte(`{"Host":"vpn.test","UseSingleSignOn":false}`)); err != nil || a != nil {
		t.Fatal("noninteractive")
	}
	for _, cfg := range []string{`{`, `{"UseSingleSignOn":true}`, `{"Host":"vpn.test","UseSingleSignOn":true,"ServerCertSha256Pin":"` + strings.Repeat("ab", 32) + `"}`, `{"Host":"vpn.test","UseSingleSignOn":true,"Realm":"` + strings.Repeat("é", 1000) + `"}`} {
		if a, err := newSealedTunnelCookie(b, []byte(cfg)); err == nil || a != nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, cfg := range []string{`{`, `{}`, `{"Host":"vpn.test","UseSingleSignOn":true,"SvpnCookie":"bad value"}`, `{"Host":"vpn.test","UseSingleSignOn":true,"SvpnCookie":"valid","SamlAuthId":"old"}`, `{"UseSingleSignOn":true,"SvpnCookie":"valid"}`} {
		raw := []byte(cfg)
		ctx := context.WithValue(context.Background(), sealedTunnelBrowserKey{}, sealedTunnelBrowserPermit{b, sha256.Sum256(raw)})
		if _, _, err := sealedTunnelBrowserConfig(ctx, b, raw); err == nil {
			t.Fatal("malformed permitted launch")
		}
	}
}
