package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sealedFallbackBinding() vault.TunnelFallbackBinding {
	p := sealedTunnelBinding()
	p.Kind = 9
	f := p
	f.Kind, f.TunnelConfigID, f.RequestID = 2, uuid.NewString(), uuid.NewString()
	f.RowVersion, f.ConfigurationVersion = 4, 3
	return vault.TunnelFallbackBinding{Primary: p, Fallback: f}
}

func sealedFallbackPacket(t *testing.T, public []byte, b vault.TunnelFallbackBinding, configurations ...[]byte) []byte {
	t.Helper()
	configuration := []byte(`{"Host":"ssl.test","Username":"native-user","Password":"native-fallback-secret"}`)
	if len(configurations) > 0 {
		configuration = configurations[0]
	}
	sealed, err := vault.SealTunnelFallback(public, b, configuration)
	if err != nil {
		t.Fatal(err)
	}
	return vaultInput(t, map[string]any{"binding": b, "bundle": sealed})
}

func TestSealedFallbackLifecycle(t *testing.T) {
	for _, action := range []string{"close", "app-lock", "eof", "replay", "wrong-session", "exit"} {
		t.Run(action, func(t *testing.T) {
			b := sealedFallbackBinding()
			process := testSealedTunnelProcess("127.0.0.1:12345")
			var borrowed []byte
			c := startSealedTunnelTestChildMode(t, func(_ context.Context, active vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				if active != b.Fallback || !bytes.Contains(raw, []byte("native-fallback-secret")) {
					t.Error("wrong active SSL source or configuration")
				}
				borrowed = raw
				return process, nil
			}, true)
			packet := sealedFallbackPacket(t, c.public, b)
			c.send(t, packet)
			var ready map[string]any
			line := c.line(t)
			if json.Unmarshal(line, &ready) != nil || len(ready) != 3 || ready["type"] != "ready" || ready["sessionId"] != b.Fallback.SessionID || ready["endpoint"] != process.socks || bytes.Contains(line, []byte("native-fallback-secret")) {
				t.Fatal("invalid secondary readiness")
			}
			switch action {
			case "eof":
				_ = c.input.Close()
			case "replay":
				c.send(t, packet)
			case "wrong-session":
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": uuid.NewString()}))
			case "exit":
				process.close()
			default:
				c.send(t, vaultInput(t, map[string]any{"type": action, "sessionId": b.Fallback.SessionID}))
			}
			err := c.wait(t)
			if (action == "replay" || action == "wrong-session" || action == "exit") && err == nil {
				t.Fatal("invalid secondary control accepted")
			}
			if process.alive() || len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("secondary process or plaintext retained")
			}
		})
	}
}

func TestSealedFallbackRejectsRetaggingAndMalformedPackets(t *testing.T) {
	for _, mode := range []string{"ordinary-shape", "ordinary-purpose", "primary", "fallback", "same-attempt", "provider", "outer-extra", "pair-extra", "primary-shape", "fallback-shape", "envelope-extra", "malformed", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			b := sealedFallbackBinding()
			calls := 0
			c := startSealedTunnelTestChildMode(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
				calls++
				return nil, errors.New("must not start")
			}, true)
			var packet map[string]any
			if json.Unmarshal(sealedFallbackPacket(t, c.public, b), &packet) != nil {
				t.Fatal("packet fixture")
			}
			pair := packet["binding"].(map[string]any)
			switch mode {
			case "ordinary-shape":
				packet["binding"] = b.Fallback
			case "ordinary-purpose":
				sealed, err := vault.SealTunnelBundle(c.public, b.Fallback, []byte(`{"Host":"ssl.test"}`))
				if err != nil {
					t.Fatal(err)
				}
				packet["bundle"] = sealed
			case "primary", "fallback":
				pair[mode].(map[string]any)["rowVersion"] = "5"
			case "same-attempt":
				pair["fallback"].(map[string]any)["requestId"] = b.Primary.RequestID
			case "provider":
				pair["fallback"].(map[string]any)["kind"] = 9
			case "outer-extra":
				packet["extra"] = true
			case "pair-extra":
				pair["extra"] = true
			case "primary-shape":
				pair["primary"] = nil
			case "fallback-shape":
				pair["fallback"] = nil
			case "envelope-extra":
				packet["bundle"].(map[string]any)["extra"] = true
			case "ciphertext":
				packet["bundle"].(map[string]any)["ciphertext"] = "AAAA"
			}
			if mode == "malformed" {
				c.send(t, []byte(`{"binding":`))
			} else {
				c.send(t, vaultInput(t, packet))
			}
			if c.wait(t) == nil || calls != 0 {
				t.Fatal("invalid packet reached starter")
			}
		})
	}
	// The ordinary recipient also refuses the new purpose, including when the
	// caller replaces the pair wrapper with its active ordinary binding.
	for _, pairShape := range []bool{false, true} {
		c := startSealedTunnelTestChild(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
			t.Error("fallback reached ordinary starter")
			return nil, vault.ErrPolicy
		})
		b := sealedFallbackBinding()
		var packet map[string]any
		_ = json.Unmarshal(sealedFallbackPacket(t, c.public, b), &packet)
		if !pairShape {
			packet["binding"] = b.Fallback
		}
		c.send(t, vaultInput(t, packet))
		if c.wait(t) == nil {
			t.Fatal("fallback accepted as ordinary packet")
		}
	}
}

func TestSealedFallbackCancellationAndExitProof(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "startup-error", true: "cancelled"}[cancelled], func(t *testing.T) {
			b := sealedFallbackBinding()
			exitProof := make(chan struct{})
			closer := &sealedTunnelTestCloser{done: make(chan struct{})}
			process := &tunnelProcess{stdin: closer, exited: exitProof, socks: "127.0.0.1:12345"}
			entered := make(chan struct{})
			var borrowed []byte
			c := startSealedTunnelTestChildMode(t, func(ctx context.Context, active vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				borrowed = raw
				close(entered)
				if cancelled {
					<-ctx.Done()
				}
				return process, vault.ErrPolicy
			}, true)
			c.send(t, sealedFallbackPacket(t, c.public, b))
			<-entered
			if cancelled {
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.Fallback.SessionID}))
			}
			select {
			case <-closer.done:
			case <-time.After(3 * time.Second):
				t.Fatal("no shutdown request")
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("secret retained while waiting for exit")
			}
			select {
			case <-c.done:
				t.Fatal("cleanup acknowledged before exit")
			default:
			}
			close(exitProof)
			if c.wait(t) == nil {
				t.Fatal("startup error lost")
			}
		})
	}
}

func TestSealedFallbackCLIRejectsUnsealedInput(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if runBackendCLI([]string{"--operation", "tunnel-fallback-sealed"}, strings.NewReader("invalid\n"), &out, &diagnostics) != 1 || !strings.Contains(out.String(), "recipient") || diagnostics.String() != "sealed_tunnel_stopped\n" {
		t.Fatal("fallback CLI exposed diagnostic or admitted unsealed input")
	}
}

// Actual native sidecar and Cmd.Wait, with a synthetic SSL configuration over
// stdin. No VPN/network: the fixture delays exit after EOF to expose early ack.
func TestSealedFallbackRealSidecarExit(t *testing.T) {
	for _, startupError := range []bool{false, true} {
		name := "ready"
		if startupError {
			name = "startup-error"
		}
		t.Run(name, func(t *testing.T) {
			b := sealedFallbackBinding()
			started := make(chan struct{})
			var owned *tunnelProcess
			var borrowed []byte
			c := startSealedTunnelTestChildMode(t, func(ctx context.Context, active vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				if active != b.Fallback {
					return nil, vault.ErrAuthentication
				}
				borrowed = raw
				command := exec.Command(os.Args[0], "-test.run=^TestSealedTunnelSidecarFixture$", "-test.timeout=20s")
				command.Env = append(os.Environ(), "WORMHOLE_TEST_SEALED_TUNNEL=slow-shutdown")
				var err error
				owned, err = launchSealedTunnel(ctx, command, raw)
				close(started)
				if err == nil && startupError {
					return owned, vault.ErrPolicy
				}
				return owned, err
			}, true)
			c.send(t, sealedFallbackPacket(t, c.public, b, []byte(`{"Host":"ssl.test","Password":"test-profile"}`)))
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("secondary did not start")
			}
			if !startupError {
				var ready struct{ Type string }
				if json.Unmarshal(c.line(t), &ready) != nil || ready.Type != "ready" {
					t.Fatal("no ready response")
				}
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.Fallback.SessionID}))
			}
			err := c.wait(t)
			if (err != nil) != startupError || owned == nil || owned.command.ProcessState == nil || owned.alive() {
				t.Fatal("secondary shutdown lacks actual OS exit proof", err)
			}
			if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("borrowed configuration retained")
			}
		})
	}
}
