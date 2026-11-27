package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"testing"
	"time"
)

type tunnelAuthGreeting struct {
	Type, SessionID, ChallengeID string
	PublicKey                    []byte
	UsernameRequired             bool
}

func tunnelAuthReply(t *testing.T, g tunnelAuthGreeting, b vault.TunnelBundleBinding, name, password []byte) []byte {
	t.Helper()
	sealed, err := vault.SealTunnelAuthentication(g.PublicKey, vault.TunnelAuthenticationBinding{Route: b, ChallengeID: g.ChallengeID, UsernameRequired: g.UsernameRequired}, name, password)
	if err != nil {
		t.Fatal(err)
	}
	return vaultInput(t, map[string]any{"type": "authentication", "sessionId": b.SessionID, "challengeId": g.ChallengeID, "envelope": sealed})
}
func TestSealedTunnelAuthenticationUsesFreshFactor(t *testing.T) {
	for _, required := range []bool{true, false} {
		b := sealedTunnelBinding()
		b.Kind = 9
		p := testSealedTunnelProcess("127.0.0.1:12345")
		var borrowed []byte
		calls := 0
		c := startSealedTunnelTestChild(t, func(ctx context.Context, _ vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
			calls++
			borrowed = raw
			settings, err := decodeVaultTunnelSettings(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer clearTunnelSettingsMap(settings)
			want := "fixed"
			if required {
				want = "new-user"
			}
			if tunnelSettingString(settings, "Username") != want || tunnelSettingString(settings, "Password") != "fresh-factor" || fortinetUserAuth(settings) != 2 {
				t.Error("wrong transient factor")
			}
			return p, nil
		})
		config := `{"Host":"vpn.test","PreSharedKey":"private-fixture","UserAuth":1,"Password":"stale-factor"}`
		if !required {
			config = `{"Host":"vpn.test","PreSharedKey":"private-fixture","UserAuth":1,"Username":"fixed","Password":"stale-factor"}`
		}
		original := []byte(config)
		c.send(t, sealedTunnelPacket(t, c.public, b, original))
		var greeting tunnelAuthGreeting
		raw := c.line(t)
		if bytes.Contains(raw, []byte("stale-factor")) || json.Unmarshal(raw, &greeting) != nil || greeting.Type != "authentication-required" || greeting.UsernameRequired != required {
			t.Fatal("invalid native challenge")
		}
		var name []byte
		if required {
			name = []byte("new-user")
		}
		c.send(t, tunnelAuthReply(t, greeting, b, name, []byte("fresh-factor")))
		var ready struct{ Type string }
		if json.Unmarshal(c.line(t), &ready) != nil || ready.Type != "ready" {
			t.Fatal("not ready")
		}
		if calls != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) || !bytes.Equal(original, []byte(config)) {
			t.Fatal("configuration ownership changed")
		}
		c.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
		if err := c.wait(t); err != nil || p.alive() {
			t.Fatal("not closed", err)
		}
	}
}
func TestSealedTunnelAuthenticationCancellationAndRejection(t *testing.T) {
	for _, mode := range []string{"close", "app-lock", "eof", "wrong-session", "wrong-challenge", "unknown-field", "wrong-cipher", "duplicate", "bad-frame", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			b := sealedTunnelBinding()
			b.Kind = 9
			started := make(chan struct{})
			p := testSealedTunnelProcess("127.0.0.1:12345")
			calls := 0
			c := startSealedTunnelTestChild(t, func(ctx context.Context, _ vault.TunnelBundleBinding, _ []byte) (*tunnelProcess, error) {
				calls++
				close(started)
				<-ctx.Done()
				return p, nil
			})
			config := []byte(`{"Host":"vpn.test","PreSharedKey":"private","UserAuth":1}`)
			if mode == "unsupported" {
				config = []byte(`{"Host":"vpn.test","PreSharedKey":"private","UserAuth":1,"FallbackTunnelId":"` + uuid.NewString() + `"}`)
			}
			c.send(t, sealedTunnelPacket(t, c.public, b, config))
			if mode == "unsupported" {
				if c.wait(t) == nil || calls != 0 {
					t.Fatal("unsupported auth started")
				}
				return
			}
			var g tunnelAuthGreeting
			if json.Unmarshal(c.line(t), &g) != nil {
				t.Fatal("challenge")
			}
			switch mode {
			case "close", "app-lock":
				c.send(t, vaultInput(t, map[string]any{"type": mode, "sessionId": b.SessionID}))
			case "eof":
				c.input.Close()
			case "bad-frame":
				c.send(t, []byte(`[]`))
			default:
				packet := tunnelAuthReply(t, g, b, []byte("u"), []byte("p"))
				var frame map[string]any
				_ = json.Unmarshal(packet, &frame)
				if mode == "wrong-session" {
					frame["sessionId"] = uuid.NewString()
				}
				if mode == "wrong-challenge" {
					frame["challengeId"] = uuid.NewString()
				}
				if mode == "unknown-field" {
					frame["password"] = "never-accepted"
				}
				if mode == "wrong-cipher" {
					frame["envelope"].(map[string]any)["ciphertext"] = "AAAA"
				}
				c.send(t, vaultInput(t, frame))
				if mode == "duplicate" {
					select {
					case <-started:
					case <-time.After(5 * time.Second):
						t.Fatal("start not reached")
					}
					c.send(t, packet)
				}
			}
			err := c.wait(t)
			if mode != "close" && mode != "app-lock" && mode != "eof" && err == nil {
				t.Fatal("unsafe command accepted")
			}
			if calls > 0 && mode != "duplicate" {
				t.Fatal("unexpected native start")
			}
			if mode == "duplicate" && p.alive() {
				t.Fatal("replay retained process")
			}
		})
	}
}
