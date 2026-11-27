package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func primaryTunnelConfiguration(t *testing.T, target string, auth int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"Host": "vpn.test", "PreSharedKey": "test-profile", "UserAuth": auth, "FallbackTunnelId": target})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertFallbackRequired(t *testing.T, c sealedSSHTestChild, b vault.TunnelBundleBinding) {
	t.Helper()
	var marker map[string]any
	if raw := c.line(t); json.Unmarshal(raw, &marker) != nil || len(marker) != 3 || marker["type"] != "fallback-required" || marker["sessionId"] != b.SessionID || marker["requestId"] != b.RequestID {
		t.Fatal("invalid fallback eligibility marker")
	}
}

func assertNoFallbackRequired(t *testing.T, c sealedSSHTestChild) {
	t.Helper()
	select {
	case raw, ok := <-c.lines:
		if ok {
			t.Fatal("unexpected native output after failure", string(raw))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native output did not close")
	}
}

func TestPrimaryTunnelConfigurationKeepsLogicalSourceAndGuards(t *testing.T) {
	b := sealedTunnelBinding()
	b.Kind = 9
	for _, target := range []string{"", uuid.NewString()} {
		raw := primaryTunnelConfiguration(t, target, 0)
		original := bytes.Clone(raw)
		prepared, eligible, err := prepareSealedPrimaryTunnel(b, raw)
		if err != nil || eligible != (target != "") || !bytes.Equal(raw, original) {
			t.Fatal("invalid primary preparation", err)
		}
		var settings map[string]json.RawMessage
		if json.Unmarshal(prepared, &settings) != nil || tunnelSettingString(settings, "PreSharedKey") != "test-profile" || tunnelSettingString(settings, "FallbackTunnelId") != "" {
			t.Fatal("provider control not isolated")
		}
		if _, _, err := sealedTunnelSidecarConfig(9, prepared); err != nil {
			t.Fatal("sanitized primary refused", err)
		}
		if target != "" {
			if _, _, err := sealedTunnelSidecarConfig(9, original); err == nil {
				t.Fatal("ordinary saved-fallback guard relaxed")
			}
		}
		vault.Wipe(prepared)
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{`), primaryTunnelConfiguration(t, "invalid", 0), primaryTunnelConfiguration(t, b.TunnelConfigID, 0), []byte(`{"Host":"vpn.test","PreSharedKey":"key","Unknown":true}`)} {
		if value, eligible, err := prepareSealedPrimaryTunnel(b, raw); err == nil || eligible || value != nil {
			t.Fatal("invalid settings authorized fallback")
		}
	}
	b.Kind = 2
	if value, eligible, err := prepareSealedPrimaryTunnel(b, primaryTunnelConfiguration(t, uuid.NewString(), 0)); err == nil || eligible || value != nil {
		t.Fatal("wrong primary provider")
	}
}

func TestPrimaryFallbackMarkerWaitsForOriginalExitAndWiping(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "startup-error", true: "cancel-during-retirement"}[cancelled], func(t *testing.T) {
			b := sealedTunnelBinding()
			b.Kind = 9
			proof := make(chan struct{})
			closer := &sealedTunnelTestCloser{done: make(chan struct{})}
			process := &tunnelProcess{stdin: closer, exited: proof}
			contextReady := make(chan context.Context, 1)
			var borrowed []byte
			c := startSealedTunnelTestChildOperation(t, func(ctx context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				if got != b || bytes.Contains(raw, []byte("FallbackTunnelId")) {
					t.Error("primary source changed or recursive field retained")
				}
				borrowed = raw
				contextReady <- ctx
				return process, vault.ErrPolicy
			}, "tunnel-primary-sealed")
			c.send(t, sealedTunnelPacket(t, c.public, b, primaryTunnelConfiguration(t, uuid.NewString(), 0)))
			ctx := <-contextReady
			select {
			case <-closer.done:
			case <-time.After(3 * time.Second):
				t.Fatal("no original shutdown request")
			}
			if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("secret retained during uncertain retirement")
			}
			select {
			case <-c.lines:
				t.Fatal("eligibility before OS exit proof")
			default:
			}
			select {
			case <-c.done:
				t.Fatal("controller acknowledged uncertain retirement")
			default:
			}
			if cancelled {
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
				select {
				case <-ctx.Done():
				case <-time.After(3 * time.Second):
					t.Fatal("cancellation not observed")
				}
			}
			close(proof)
			if !cancelled {
				assertFallbackRequired(t, c, b)
			}
			if c.wait(t) == nil {
				t.Fatal("startup failure lost")
			}
			assertNoFallbackRequired(t, c)
		})
	}
}

func TestPrimaryFallbackDoesNotConvertSuccessOrInvalidInput(t *testing.T) {
	for _, mode := range []string{"ready", "runtime-exit", "missing-reference", "invalid-config", "wrong-provider", "cancelled", "format-error", "auth-error", "protocol-error"} {
		t.Run(mode, func(t *testing.T) {
			b := sealedTunnelBinding()
			b.Kind = 9
			cfg := primaryTunnelConfiguration(t, uuid.NewString(), 0)
			if mode == "missing-reference" {
				cfg = primaryTunnelConfiguration(t, "", 0)
			}
			if mode == "invalid-config" {
				cfg = []byte(`{}`)
			}
			if mode == "wrong-provider" {
				b.Kind = 2
			}
			p := testSealedTunnelProcess("127.0.0.1:12345")
			calls := 0
			c := startSealedTunnelTestChildOperation(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
				calls++
				switch mode {
				case "ready", "runtime-exit":
					return p, nil
				case "cancelled":
					return p, context.Canceled
				case "format-error":
					return p, vault.ErrFormat
				case "auth-error":
					return p, vault.ErrAuthentication
				case "protocol-error":
					return p, vaultwire.ErrProtocol
				default:
					return p, vault.ErrPolicy
				}
			}, "tunnel-primary-sealed")
			c.send(t, sealedTunnelPacket(t, c.public, b, cfg))
			if mode == "ready" || mode == "runtime-exit" {
				var ready struct{ Type string }
				if json.Unmarshal(c.line(t), &ready) != nil || ready.Type != "ready" {
					t.Fatal("no primary readiness")
				}
				if mode == "runtime-exit" {
					p.close()
				} else {
					c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
				}
			}
			err := c.wait(t)
			if mode == "ready" && err != nil {
				t.Fatal(err)
			}
			if mode != "ready" && err == nil {
				t.Fatal("invalid primary result accepted")
			}
			if (mode == "invalid-config" || mode == "wrong-provider") && calls != 0 {
				t.Fatal("invalid source reached launcher")
			}
			assertNoFallbackRequired(t, c)
		})
	}
}

func TestPrimaryFallbackOperationalFailureWithoutOwnedSidecar(t *testing.T) {
	b := sealedTunnelBinding()
	b.Kind = 9
	c := startSealedTunnelTestChildOperation(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
		return nil, errors.New("provider unavailable")
	}, "tunnel-primary-sealed")
	c.send(t, sealedTunnelPacket(t, c.public, b, primaryTunnelConfiguration(t, uuid.NewString(), 0)))
	assertFallbackRequired(t, c, b)
	if c.wait(t) == nil {
		t.Fatal("provider failure lost")
	}
	assertNoFallbackRequired(t, c)
}

func TestPrimaryFallbackAuthenticationDeclineNeverStartsSecondary(t *testing.T) {
	for _, mode := range []string{"cancel", "bad-envelope"} {
		t.Run(mode, func(t *testing.T) {
			b := sealedTunnelBinding()
			b.Kind = 9
			calls := 0
			c := startSealedTunnelTestChildOperation(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
				calls++
				return nil, vault.ErrPolicy
			}, "tunnel-primary-sealed")
			c.send(t, sealedTunnelPacket(t, c.public, b, primaryTunnelConfiguration(t, uuid.NewString(), 1)))
			var g tunnelAuthGreeting
			if json.Unmarshal(c.line(t), &g) != nil || g.Type != "authentication-required" {
				t.Fatal("no fresh authentication")
			}
			if mode == "cancel" {
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
			} else {
				c.send(t, vaultInput(t, map[string]any{"type": "authentication", "sessionId": b.SessionID, "challengeId": g.ChallengeID, "envelope": vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: bytes.Repeat([]byte{1}, 32), Ciphertext: bytes.Repeat([]byte{1}, 32)}}))
			}
			_ = c.wait(t)
			if calls != 0 {
				t.Fatal("declined or invalid authentication reached launcher")
			}
			assertNoFallbackRequired(t, c)
		})
	}
}

func TestPrimaryFallbackSAMLNegotiationFailureAndUserDecline(t *testing.T) {
	for _, mode := range []string{"fail", "certificate", "ready"} {
		t.Run(mode, func(t *testing.T) {
			config, closeServer := sealedSAMLServer(t, mode)
			defer closeServer()
			var settings map[string]json.RawMessage
			_ = json.Unmarshal(config, &settings)
			settings["FallbackTunnelId"], _ = json.Marshal(uuid.NewString())
			config, _ = json.Marshal(settings)
			b := sealedTunnelBinding()
			b.Kind = 9
			calls := 0
			c := startSealedTunnelTestChildOperation(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
				calls++
				return nil, vault.ErrPolicy
			}, "tunnel-primary-sealed")
			c.send(t, sealedTunnelPacket(t, c.public, b, config))
			if mode == "ready" {
				var g struct{ Type string }
				if json.Unmarshal(c.line(t), &g) != nil || g.Type != "browser-authentication-required" {
					t.Fatal("no browser challenge")
				}
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
			} else {
				assertFallbackRequired(t, c, b)
			}
			_ = c.wait(t)
			if calls != 0 {
				t.Fatal("negotiation failure reached launcher")
			}
			assertNoFallbackRequired(t, c)
		})
	}
}

func TestPrimaryFallbackRealSidecarExitPrecedesReceipt(t *testing.T) {
	b := sealedTunnelBinding()
	b.Kind = 9
	var owned *tunnelProcess
	var borrowed []byte
	c := startSealedTunnelTestChildOperation(t, func(ctx context.Context, _ vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
		borrowed = raw
		cmd := exec.Command(os.Args[0], "-test.run=^TestSealedTunnelSidecarFixture$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "WORMHOLE_TEST_SEALED_TUNNEL=slow-shutdown")
		var err error
		owned, err = launchSealedTunnel(ctx, cmd, raw)
		if err != nil {
			return owned, err
		}
		return owned, vault.ErrPolicy
	}, "tunnel-primary-sealed")
	c.send(t, sealedTunnelPacket(t, c.public, b, primaryTunnelConfiguration(t, uuid.NewString(), 0)))
	assertFallbackRequired(t, c, b)
	if owned == nil || owned.command.ProcessState == nil || owned.alive() || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("receipt lacks original OS exit or wiped configuration")
	}
	if c.wait(t) == nil {
		t.Fatal("original startup failure lost")
	}
	assertNoFallbackRequired(t, c)
}

func TestPrimaryFallbackCLIAndOutputFailureAreGeneric(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if runBackendCLI([]string{"--operation", "tunnel-primary-sealed"}, strings.NewReader("invalid\n"), &out, &diagnostics) != 1 || !strings.Contains(out.String(), "recipient") || diagnostics.String() != "sealed_tunnel_stopped\n" {
		t.Fatal("primary CLI accepted plaintext or exposed diagnostics")
	}
	if err := writeSealedFallbackRequired(json.NewEncoder(failSealedTunnelWriter{}), sealedTunnelBinding()); err != vaultwire.ErrProtocol {
		t.Fatal("lost output failure", err)
	}
	if err := writeSealedFallbackRequired(json.NewEncoder(io.Discard), sealedTunnelBinding()); err != nil {
		t.Fatal(err)
	}
}
