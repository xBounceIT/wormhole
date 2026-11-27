package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func sealedTunnelBinding() vault.TunnelBundleBinding {
	b := sealedSSHFixtureBinding()
	b.TunnelConfigID = uuid.NewString()
	return vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 1, RowVersion: 2, ConfigurationVersion: 1}
}
func sealedTunnelPacket(t *testing.T, public []byte, b vault.TunnelBundleBinding, configurations ...[]byte) []byte {
	t.Helper()
	raw := []byte(`{"ProfileOvpn":"native-profile","Password":"native-secret"}`)
	if len(configurations) > 0 {
		raw = configurations[0]
	}
	s, err := vault.SealTunnelBundle(public, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	return vaultInput(t, map[string]any{"binding": b, "bundle": s})
}
func startSealedTunnelTestChild(t *testing.T, start sealedTunnelStart) sealedSSHTestChild {
	return startSealedTunnelTestChildMode(t, start, false)
}

func startSealedTunnelTestChildMode(t *testing.T, start sealedTunnelStart, fallback bool) sealedSSHTestChild {
	operation := "tunnel-sealed"
	if fallback {
		operation = "tunnel-fallback-sealed"
	}
	return startSealedTunnelTestChildOperation(t, start, operation)
}

func startSealedTunnelTestChildOperation(t *testing.T, start sealedTunnelStart, operation string) sealedSSHTestChild {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done, lines := make(chan error, 1), make(chan []byte, 8)
	c := sealedSSHTestChild{input: inW, done: done, lines: lines}
	go func() {
		if start == nil {
			var diagnostics bytes.Buffer
			code := runBackendCLI([]string{"--operation", operation}, inR, outW, &diagnostics)
			if code != 0 {
				done <- errors.New("native route stopped")
			} else {
				done <- nil
			}
		} else if operation == "tunnel-fallback-sealed" {
			done <- serveSealedTunnelWithOpener(inR, outW, start, openSealedTunnelFallbackConfiguration)
		} else if operation == "tunnel-primary-sealed" {
			done <- serveSealedTunnelActor(inR, outW, start, openSealedTunnelConfiguration, true)
		} else {
			done <- serveSealedTunnel(inR, outW, start)
		}
		outW.Close()
	}()
	go func() {
		defer close(lines)
		s := bufio.NewScanner(outR)
		for s.Scan() {
			lines <- bytes.Clone(s.Bytes())
		}
	}()
	t.Cleanup(func() { inW.Close(); outR.Close() })
	var greeting struct {
		Type      string
		PublicKey []byte
	}
	if json.Unmarshal(c.line(t), &greeting) != nil || greeting.Type != "recipient" || len(greeting.PublicKey) != 32 {
		t.Fatal("recipient")
	}
	c.public = greeting.PublicKey
	return c
}

type sealedTunnelTestCloser struct {
	done chan struct{}
	once sync.Once
}

func (c *sealedTunnelTestCloser) Write(v []byte) (int, error) { return len(v), nil }
func (c *sealedTunnelTestCloser) Close() error                { c.once.Do(func() { close(c.done) }); return nil }
func testSealedTunnelProcess(endpoint string) *tunnelProcess {
	c := &sealedTunnelTestCloser{done: make(chan struct{})}
	return &tunnelProcess{stdin: c, exited: c.done, socks: endpoint}
}

func TestSealedTunnelLifecycle(t *testing.T) {
	for _, action := range []string{"close", "app-lock", "eof", "replay", "wrong-session", "exit"} {
		t.Run(action, func(t *testing.T) {
			b := sealedTunnelBinding()
			process := testSealedTunnelProcess("127.0.0.1:12345")
			var borrowed []byte
			c := startSealedTunnelTestChild(t, func(_ context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				if got != b || !bytes.Contains(raw, []byte("native-secret")) {
					t.Error("wrong context/configuration")
				}
				borrowed = raw
				return process, nil
			})
			packet := sealedTunnelPacket(t, c.public, b)
			c.send(t, packet)
			var ready map[string]any
			line := c.line(t)
			if json.Unmarshal(line, &ready) != nil || len(ready) != 3 || ready["type"] != "ready" || ready["sessionId"] != b.SessionID || ready["endpoint"] != process.socks || bytes.Contains(line, []byte("native-secret")) {
				t.Fatal("invalid ready", string(line))
			}
			switch action {
			case "eof":
				c.input.Close()
			case "replay":
				c.send(t, packet)
			case "wrong-session":
				c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": uuid.NewString()}))
			case "exit":
				process.close()
			default:
				c.send(t, vaultInput(t, map[string]any{"type": action, "sessionId": b.SessionID}))
			}
			err := c.wait(t)
			if (action == "replay" || action == "wrong-session" || action == "exit") && err == nil {
				t.Fatal("invalid state accepted")
			}
			if process.alive() || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("route or secrets retained")
			}
		})
	}
}

func TestSealedTunnelCancelledStartup(t *testing.T) {
	for _, late := range []bool{false, true} {
		entered := make(chan struct{})
		process := testSealedTunnelProcess("127.0.0.1:12345")
		var borrowed []byte
		c := startSealedTunnelTestChild(t, func(ctx context.Context, _ vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
			borrowed = raw
			close(entered)
			<-ctx.Done()
			if late {
				return process, nil
			}
			return process, ctx.Err()
		})
		c.send(t, sealedTunnelPacket(t, c.public, sealedTunnelBinding()))
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("start blocked")
		}
		c.input.Close()
		if c.wait(t) == nil || process.alive() || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("late route escaped")
		}
	}
}

func TestSealedTunnelRetainsControllerUntilOriginalSidecarExit(t *testing.T) {
	for _, failedStartup := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "startup-error"}[failedStartup], func(t *testing.T) {
			process := testSealedTunnelProcess("127.0.0.1:12345")
			// Model a prior bounded close that completed without OS exit proof.
			// A repeated close is idempotent; it must not count as termination.
			process.closeOnce.Do(func() {})
			var exitOnce sync.Once
			exit := func() { exitOnce.Do(func() { close(process.exited) }) }
			defer exit()
			entered := make(chan context.Context, 1)
			var borrowed []byte
			c := startSealedTunnelTestChild(t, func(ctx context.Context, _ vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
				borrowed = raw
				entered <- ctx
				if failedStartup {
					return process, vault.ErrPolicy
				}
				return process, nil
			})
			c.send(t, sealedTunnelPacket(t, c.public, sealedTunnelBinding()))
			ctx := <-entered
			if !failedStartup {
				_ = c.line(t)
				_ = c.input.Close()
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("controller did not receive cancellation")
				}
			}
			select {
			case <-c.done:
				t.Fatal("controller exited while original sidecar exit was unconfirmed")
			case <-time.After(50 * time.Millisecond):
			}
			exit()
			err := c.wait(t)
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("configuration retained after sidecar retirement")
			}
			if failedStartup && err == nil {
				t.Fatal("startup failure lost", err)
			}
		})
	}
}

type sealedTunnelWipeCloser struct {
	check func()
	done  chan struct{}
}

func (c sealedTunnelWipeCloser) Write(raw []byte) (int, error) { return len(raw), nil }
func (c sealedTunnelWipeCloser) Close() error {
	c.check()
	close(c.done)
	return nil
}

func TestSealedTunnelWipesConfigurationBeforeNativeRetirement(t *testing.T) {
	c := startSealedTunnelTestChild(t, func(_ context.Context, _ vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
		closer := sealedTunnelWipeCloser{done: make(chan struct{}), check: func() {
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Error("borrowed configuration reached retirement before wiping")
			}
		}}
		return &tunnelProcess{stdin: closer, exited: closer.done}, vault.ErrPolicy
	})
	c.send(t, sealedTunnelPacket(t, c.public, sealedTunnelBinding()))
	if c.wait(t) == nil {
		t.Fatal("startup failure lost")
	}
}

func TestSealedTunnelExitRequiresOSWaitState(t *testing.T) {
	retireSealedTunnel(nil)
	process := &tunnelProcess{command: exec.Command("unused-not-started"), exited: make(chan struct{})}
	waitSealedTunnel(process)
	select {
	case <-process.exited:
		t.Fatal("failed wait without OS state acknowledged exit")
	default:
	}
}

func TestSealedTunnelRejectsPacketsAndUnsafeRoutes(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { return []byte("{}") },
		func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"rowVersion":"2"`), []byte(`"rowVersion":"02"`), 1)
		},
		func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"configurationVersion":"1"`), []byte(`"configurationVersion":1`), 1)
		},
		func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"host":"127.0.0.1"`), []byte(`"host":"attacker"`), 1)
		},
		func(p []byte) []byte { return bytes.Replace(p, []byte(`"suiteId":2`), []byte(`"suiteId":1`), 1) },
		func(p []byte) []byte { return bytes.Replace(p, []byte(`"kind":1`), []byte(`"kind":1,"kind":2`), 1) },
		func(p []byte) []byte { return bytes.Repeat([]byte("x"), vaultwire.MaxFrameBytes+1) },
	} {
		c := startSealedTunnelTestChild(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) {
			t.Error("unauthenticated start")
			return nil, io.EOF
		})
		// Oversized frames may close the reader before the write completes.
		_, _ = c.input.Write(append(mutate(sealedTunnelPacket(t, c.public, sealedTunnelBinding())), '\n'))
		if c.wait(t) == nil {
			t.Fatal("invalid packet accepted")
		}
	}
	for _, endpoint := range []string{"", "10.0.0.1:22", "127.0.0.1:0"} {
		p := testSealedTunnelProcess(endpoint)
		c := startSealedTunnelTestChild(t, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) { return p, nil })
		c.send(t, sealedTunnelPacket(t, c.public, sealedTunnelBinding()))
		if c.wait(t) == nil || p.alive() {
			t.Fatal("unsafe route retained")
		}
	}
	if serveSealedTunnel(io.NopCloser(strings.NewReader("")), io.Discard, nil) == nil {
		t.Fatal("empty handshake")
	}
	if serveSealedTunnel(io.NopCloser(strings.NewReader("")), failSealedTunnelWriter{}, nil) == nil {
		t.Fatal("failed output")
	}
}

type failSealedTunnelWriter struct{}

func (failSealedTunnelWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type failSealedTunnelReadyWriter struct{ public chan []byte }

func (w failSealedTunnelReadyWriter) Write(raw []byte) (int, error) {
	var greeting struct {
		Type      string
		PublicKey []byte
	}
	if json.Unmarshal(raw, &greeting) == nil && greeting.Type == "recipient" {
		w.public <- greeting.PublicKey
		return len(raw), nil
	}
	return 0, io.ErrClosedPipe
}
func TestSealedTunnelLostReadyOutputClosesSidecar(t *testing.T) {
	inR, inW := io.Pipe()
	defer inW.Close()
	writer := failSealedTunnelReadyWriter{public: make(chan []byte, 1)}
	p := testSealedTunnelProcess("127.0.0.1:12345")
	done := make(chan error, 1)
	go func() {
		done <- serveSealedTunnel(inR, writer, func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error) { return p, nil })
	}()
	var public []byte
	select {
	case public = <-writer.public:
	case <-time.After(5 * time.Second):
		t.Fatal("no recipient")
	}
	if _, err := inW.Write(append(sealedTunnelPacket(t, public, sealedTunnelBinding()), '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || p.alive() {
			t.Fatal("orphan after output failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("output failure deadlock")
	}
}

func TestSealedTunnelProviderGate(t *testing.T) {
	for kind, raw := range map[uint16]string{
		0: `{"InterfacePrivateKey":"key","InterfaceAddress":"10.0.0.2/24","PeerPublicKey":"pub","PeerEndpoint":"vpn:123"}`,
		1: `{"ProfileOvpn":"profile","Password":"secret"}`,
		2: `{"Host":"vpn","Username":"u","Password":"secret","UseSingleSignOn":false}`,
		6: `{"Host":"vpn","Username":"u","Password":"secret"}`,
	} {
		exe, config, err := sealedTunnelSidecarConfig(kind, []byte(raw))
		if err != nil || exe == "" || !json.Valid(config) {
			t.Fatal(kind, err)
		}
		vault.Wipe(config)
	}
	for _, kind := range []uint16{3, 4, 5, 7, 8, 9} {
		if _, _, err := sealedTunnelSidecarConfig(kind, []byte(`{}`)); err != vault.ErrPolicy {
			t.Fatal(kind, err)
		}
	}
	for _, raw := range []string{"", "null", "[]", "{}", `{"UseSingleSignOn":true}`, `{"UseSingleSignOn":true,"UseSingleSignOn":false}`, `{"UseSingleSignOn":"true"}`, `{"Host":"vpn","Username":"u","Password":"secret","SamlAuthId":"old-token"}`, `{"Host":"vpn","Username":"u","Password":"secret","SvpnCookie":"old-cookie"}`} {
		if _, _, err := sealedTunnelSidecarConfig(2, []byte(raw)); err == nil {
			t.Fatal("unsafe provider settings", raw)
		}
	}
}

func TestSealedTunnelNativeLauncher(t *testing.T) {
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "yes")
	t.Setenv("WORMHOLE_OVPNPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_CISCOPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_FORTIIPSECPROXY_PATH", os.Args[0])
	// Exercise the real CLI dispatch without supplying any database path.
	c := startSealedTunnelTestChild(t, nil)
	binding := sealedTunnelBinding()
	c.send(t, sealedTunnelPacket(t, c.public, binding))
	var ready struct{ Type, SessionID, Endpoint string }
	if json.Unmarshal(c.line(t), &ready) != nil || ready.Type != "ready" || ready.SessionID != binding.SessionID || ready.Endpoint != "127.0.0.1:32123" {
		t.Fatal("native CLI readiness")
	}
	c.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": binding.SessionID}))
	if err := c.wait(t); err != nil {
		t.Fatal(err)
	}
	for kind, configuration := range map[uint16]string{1: `{"ProfileOvpn":"test-profile"}`, 6: `{"Host":"vpn","Username":"u","Password":"secret"}`, 9: `{"Host":"vpn.test","PreSharedKey":"native-psk-fixture","UserAuth":0}`} {
		b := sealedTunnelBinding()
		b.Kind = kind
		p, err := startSealedTunnel(context.Background(), b, []byte(configuration))
		if err != nil {
			t.Fatal(err)
		}
		if p.socks != "127.0.0.1:32123" {
			t.Fatal("wrong endpoint")
		}
		p.close()
	}

	ipsec := startSealedTunnelTestChild(t, nil)
	ipsecBinding := sealedTunnelBinding()
	ipsecBinding.Kind = 9
	ipsec.send(t, sealedTunnelPacket(t, ipsec.public, ipsecBinding, []byte(`{"Host":"vpn.test","PreSharedKey":"native-psk-fixture","UserAuth":2,"Username":"u","Password":"native-password-fixture"}`)))
	var ipsecReady struct{ Type, Endpoint string }
	if json.Unmarshal(ipsec.line(t), &ipsecReady) != nil || ipsecReady.Type != "ready" || ipsecReady.Endpoint != "127.0.0.1:32123" {
		t.Fatal("IPsec sealed native readiness")
	}
	ipsec.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": ipsecBinding.SessionID}))
	if err := ipsec.wait(t); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "no")
	if _, err := startSealedTunnel(context.Background(), sealedTunnelBinding(), []byte(`{"ProfileOvpn":"test-profile"}`)); !errors.Is(err, errOpenVPNUnavailable) {
		t.Fatal("capability bypass", err)
	}
	if _, err := startSealedTunnel(context.Background(), sealedTunnelBinding(), []byte(`{}`)); err != vault.ErrFormat {
		t.Fatal("invalid config", err)
	}
}

// Real pipes and a subprocess exercise blocked writes, EOF and readiness. This
// helper contains no network access and receives a synthetic profile via stdin.
func TestSealedTunnelSidecarFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_SEALED_TUNNEL")
	if mode == "" {
		t.Skip("subprocess fixture")
	}
	if mode == "stall" {
		time.Sleep(30 * time.Second)
		os.Exit(2)
	}
	s := bufio.NewScanner(os.Stdin)
	if !s.Scan() || !bytes.Contains(s.Bytes(), []byte("test-profile")) {
		os.Exit(3)
	}
	_, _ = os.Stderr.WriteString("private-diagnostic-never-publish\n")
	switch mode {
	case "bad":
		_, _ = os.Stdout.WriteString("READY 0\n")
	case "exit":
		os.Exit(4)
	case "wait-ready":
		time.Sleep(30 * time.Second)
	default:
		_, _ = os.Stdout.WriteString("READY 12345\n")
	}
	if mode == "flood" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("ignored output"), 256*1024))
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if mode == "slow-shutdown" {
		time.Sleep(2400 * time.Millisecond)
	}
	os.Exit(0)
}
func TestSealedTunnelLaunch(t *testing.T) {
	for _, mode := range []string{"ready", "flood", "bad", "exit", "stall", "wait-ready"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.Command(os.Args[0], "-test.run=^TestSealedTunnelSidecarFixture$")
			command.Env = append(os.Environ(), "WORMHOLE_TEST_SEALED_TUNNEL="+mode)
			config := []byte(`{"ProfileOvpn":"test-profile"}`)
			if mode == "stall" {
				config = bytes.Repeat([]byte("x"), vault.MaxSecretBytes)
			}
			p, err := launchSealedTunnel(ctx, command, config)
			if mode == "ready" || mode == "flood" {
				if err != nil || p.socks != "127.0.0.1:12345" || !p.alive() {
					t.Fatal("ready", err)
				}
				p.close()
				if p.alive() {
					t.Fatal("orphan")
				}
			} else {
				if err == nil || p == nil {
					t.Fatal("startup failure lost original process ownership", err)
				}
				retireSealedTunnel(p)
				if p.alive() {
					t.Fatal("failed native startup escaped cleanup")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := launchSealedTunnel(ctx, exec.Command("unused"), nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := launchSealedTunnel(context.Background(), exec.Command("wormhole-nonexistent-test-sidecar"), nil); err == nil {
		t.Fatal("missing executable")
	}
	var out, diagnostic bytes.Buffer
	if runBackendCLI([]string{"--operation", "tunnel-sealed"}, strings.NewReader("invalid\n"), &out, &diagnostic) != 1 || !strings.Contains(diagnostic.String(), "sealed_tunnel_stopped") || !strings.Contains(out.String(), "recipient") {
		t.Fatal("CLI branch", diagnostic.String())
	}
}
