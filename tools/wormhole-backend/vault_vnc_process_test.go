package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sealedVNCBinding() vault.BundleBinding {
	b := sealedSSHFixtureBinding()
	b.Protocol = "vnc"
	return b
}
func startSealedVNCTestChild(t *testing.T, dial sealedVNCDial, manualMode ...bool) sealedSSHTestChild {
	manual := len(manualMode) > 0 && manualMode[0]
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	lines := make(chan []byte, 32)
	go func() {
		if dial == nil {
			var diagnostics bytes.Buffer
			operation := "vnc-sealed"
			if manual {
				operation = "vnc-manual-sealed"
			}
			code := runBackendCLI([]string{"--operation", operation}, inR, outW, &diagnostics)
			if code != 0 {
				done <- errors.New("sealed VNC child stopped")
			} else {
				done <- nil
			}
		} else {
			done <- serveSealedVNCMode(inR, outW, dial, manual)
		}
		outW.Close()
	}()
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(outR)
		scanner.Buffer(make([]byte, 4096), 32*1024*1024)
		for scanner.Scan() {
			lines <- bytes.Clone(scanner.Bytes())
		}
	}()
	t.Cleanup(func() { inW.Close(); outR.Close() })
	child := sealedSSHTestChild{input: inW, lines: lines, done: done}
	var greeting struct {
		Type      string
		PublicKey []byte
	}
	if json.Unmarshal(child.line(t), &greeting) != nil || greeting.Type != "recipient" || len(greeting.PublicKey) != 32 {
		t.Fatal("invalid VNC recipient greeting")
	}
	child.public = greeting.PublicKey
	return child
}
func sealedVNCPacket(t *testing.T, public []byte, b vault.BundleBinding) []byte {
	t.Helper()
	plain, err := vault.EncodeVNCBundle(vault.VNCBundlePayload{Password: []byte("native-password"), PasswordProvided: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	bundle, err := vault.SealBundle(public, b, plain)
	if err != nil {
		t.Fatal(err)
	}
	return vaultInput(t, map[string]any{"binding": b, "bundle": bundle})
}
func vncChildEvent(t *testing.T, child sealedSSHTestChild, status string) backendEvent {
	t.Helper()
	var event backendEvent
	if json.Unmarshal(child.line(t), &event) != nil {
		t.Fatal("invalid native event")
	}
	if status == "frame" {
		if event.Type != "vnc.frame" {
			t.Fatal(event)
		}
	} else if event.Type != "vnc.status" || event.Status != status {
		t.Fatal(event)
	}
	return event
}

func TestSealedVNCProcessRealCLIFramesAndInput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	inputs := make(chan string, 2)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveFakeVncWithFormat(listener, inputs, [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, "native-password")
	}()
	child := startSealedVNCTestChild(t, nil)
	b := sealedVNCBinding()
	b.Host = "127.0.0.1"
	b.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	child.send(t, sealedVNCPacket(t, child.public, b))
	vncChildEvent(t, child, "connecting")
	vncChildEvent(t, child, "connected")
	frame := vncChildEvent(t, child, "frame")
	if frame.SessionID != b.SessionID || frame.Width != 1 || frame.Height != 1 || !strings.HasPrefix(frame.Image, "data:image/png;base64,") {
		t.Fatal("invalid frame")
	}
	child.send(t, vaultInput(t, map[string]any{"type": "pointer", "sessionId": b.SessionID, "x": 0, "y": 0, "buttons": 1}))
	child.send(t, vaultInput(t, map[string]any{"type": "key", "sessionId": b.SessionID, "keysym": 0xff0d, "down": true}))
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case key := <-inputs:
			seen[key] = true
		case <-time.After(time.Second):
			t.Fatal("input lost")
		}
	}
	child.wait(t)
}

func TestSealedVNCProcessCancellationAndRouteBinding(t *testing.T) {
	for _, stop := range []string{"close", "app-lock", "eof", "replay", "wrong-session", "secret", "oversized"} {
		for _, routed := range []bool{false, true} {
			t.Run(stop+map[bool]string{false: "/direct", true: "/route"}[routed], func(t *testing.T) {
				b := sealedVNCBinding()
				endpoint := ""
				if routed {
					b.TunnelConfigID = uuid.NewString()
					endpoint = "127.0.0.1:2345"
				}
				entered := make(chan struct{})
				child := startSealedVNCTestChild(t, func(ctx context.Context, route, address string) (net.Conn, error) {
					if route != endpoint || address != net.JoinHostPort(b.Host, "22") {
						t.Error("authenticated destination lost")
					}
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				})
				var raw []byte
				if routed {
					route := vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 1, ConfigurationVersion: 1}
					plain, _ := vault.EncodeVNCBundle(vault.VNCBundlePayload{Password: []byte("native-password"), PasswordProvided: true})
					defer vault.Wipe(plain)
					bundle, err := vault.SealRoutedBundle(child.public, route, endpoint, plain)
					if err != nil {
						t.Fatal(err)
					}
					raw = vaultInput(t, map[string]any{"binding": route, "bundle": bundle, "endpoint": endpoint})
				} else {
					raw = sealedVNCPacket(t, child.public, b)
				}
				child.send(t, raw)
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("dial did not start")
				}
				switch stop {
				case "eof":
					child.input.Close()
				case "replay":
					child.send(t, raw)
				case "wrong-session":
					child.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": uuid.NewString()}))
				case "secret":
					child.send(t, vaultInput(t, map[string]any{"type": "key", "sessionId": b.SessionID, "password": "injected"}))
				case "oversized":
					_, _ = child.input.Write(bytes.Repeat([]byte("x"), sealedVNCFrameLimit+3))
				default:
					child.send(t, vaultInput(t, map[string]any{"type": stop, "sessionId": b.SessionID}))
				}
				err := child.wait(t)
				if (stop == "replay" || stop == "wrong-session" || stop == "secret" || stop == "oversized") && err == nil {
					t.Fatal("malformed control accepted")
				}
			})
		}
	}
}

func TestSealedVNCProcessRejectsTamperingBeforeDial(t *testing.T) {
	for _, mode := range []string{"host", "session", "ciphertext", "payload", "route-endpoint", "route-strip", "opening", "eof"} {
		t.Run(mode, func(t *testing.T) {
			child := startSealedVNCTestChild(t, func(context.Context, string, string) (net.Conn, error) {
				t.Error("invalid opening reached network")
				return nil, io.EOF
			})
			b := sealedVNCBinding()
			var packet map[string]any
			if mode == "route-endpoint" || mode == "route-strip" {
				b.TunnelConfigID = uuid.NewString()
				route := vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 1, ConfigurationVersion: 1}
				bundle, err := vault.SealRoutedBundle(child.public, route, "127.0.0.1:2345", []byte("invalid"))
				if err != nil {
					t.Fatal(err)
				}
				packet = map[string]any{"binding": route, "bundle": bundle, "endpoint": "127.0.0.1:2346"}
				if mode == "route-strip" {
					delete(packet, "endpoint")
				}
			} else {
				if err := json.Unmarshal(sealedVNCPacket(t, child.public, b), &packet); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "host":
					b.Host = "attacker.invalid"
					packet["binding"] = b
				case "session":
					b.SessionID = uuid.NewString()
					packet["binding"] = b
				case "ciphertext":
					packet["bundle"] = map[string]any{"formatVersion": 1, "suiteId": 2, "enc": make([]byte, 32), "ciphertext": make([]byte, 16)}
				case "payload":
					bundle, err := vault.SealBundle(child.public, b, []byte("invalid"))
					if err != nil {
						t.Fatal(err)
					}
					packet["bundle"] = bundle
				case "opening":
					packet["password"] = "injected"
				}
			}
			if mode == "eof" {
				child.input.Close()
			} else {
				child.send(t, vaultInput(t, packet))
			}
			if child.wait(t) == nil {
				t.Fatal("invalid opening accepted")
			}
		})
	}
}

func TestSealedVNCStrictSchemas(t *testing.T) {
	b := sealedVNCBinding()
	base := map[string]any{"binding": b, "bundle": vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, 16)}}
	if _, err := decodeSealedVNCOpening(vaultInput(t, base)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"binding", "bundle"} {
		p := map[string]any{}
		for k, v := range base {
			if k != field {
				p[k] = v
			}
		}
		if _, err := decodeSealedVNCOpening(vaultInput(t, p)); err == nil {
			t.Fatal("missing", field)
		}
	}
	for _, change := range []func(*vault.BundleBinding){func(b *vault.BundleBinding) { b.Protocol = "ssh" }, func(b *vault.BundleBinding) { b.NodeID = "bad" }, func(b *vault.BundleBinding) { b.WorkspaceID = uuid.Nil.String() }, func(b *vault.BundleBinding) { b.Host = "bad host" }, func(b *vault.BundleBinding) { b.Host = strings.Repeat("x", 1025) }, func(b *vault.BundleBinding) { b.UseExternalClient = true }, func(b *vault.BundleBinding) { b.Epoch = 0 }, func(b *vault.BundleBinding) { b.Port = 0 }, func(b *vault.BundleBinding) { b.TunnelConfigID = uuid.NewString() }} {
		bad := b
		change(&bad)
		base["binding"] = bad
		if _, err := decodeSealedVNCOpening(vaultInput(t, base)); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	for _, packet := range []map[string]any{
		{"type": "pointer", "sessionId": b.SessionID, "x": 0, "y": 65535, "buttons": 255},
		{"type": "key", "sessionId": b.SessionID, "down": false, "keysym": 4294967295},
		{"type": "close", "sessionId": b.SessionID}, {"type": "app-lock", "sessionId": b.SessionID},
	} {
		if _, err := decodeSealedVNCCommand(vaultInput(t, packet), b.SessionID); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"type", "sessionId", "password"} {
			copy := map[string]any{}
			for k, v := range packet {
				copy[k] = v
			}
			if field == "password" {
				copy[field] = "injected"
			} else {
				delete(copy, field)
			}
			if _, err := decodeSealedVNCCommand(vaultInput(t, copy), b.SessionID); err == nil {
				t.Fatal("invalid control accepted")
			}
		}
	}
	for _, raw := range []string{`{"type":"pointer","sessionId":"ID","x":-1,"y":0,"buttons":0}`, `{"type":"pointer","sessionId":"ID","x":65536,"y":0,"buttons":0}`, `{"type":"key","sessionId":"ID","down":true}`, `{"type":"open","sessionId":"ID"}`, `{"type":"close","sessionId":"ID","x":0}`} {
		if _, err := decodeSealedVNCCommand([]byte(strings.ReplaceAll(raw, "ID", b.SessionID)), b.SessionID); err == nil {
			t.Fatal("invalid bounds/schema")
		}
	}
	if err := serveSealedVNC(io.NopCloser(strings.NewReader("")), io.Discard, nil); err == nil {
		t.Fatal("empty opening accepted")
	}
	writer := sealedSSHTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := serveSealedVNC(io.NopCloser(strings.NewReader("")), writer, nil); err == nil {
		t.Fatal("greeting failure ignored")
	}
}

func TestSealedVNCSessionCancellationAndAuthFailure(t *testing.T) {
	for _, mode := range []string{"stopped", "cancel-dial", "cancel-handshake", "auth-failure", "late-dial"} {
		t.Run(mode, func(t *testing.T) {
			var output synchronizedBuffer
			manager := newVncManager(nil, newBackendLineWriter(&output))
			b := sealedVNCBinding()
			raw := []byte("native-password")
			entered, release := make(chan struct{}), make(chan struct{})
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			session := newVncSession(b.SessionID, manager.output, manager)
			session.sealed = &sealedVNCSession{binding: b, auth: &sealedVNCAuth{password: raw, provided: true}, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(entered)
				if mode == "cancel-dial" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if mode == "late-dial" {
					<-release
				}
				return client, nil
			}}
			if mode == "stopped" {
				session.close()
				session.start(backendCommand{}, nil)
				session.closeAndWait()
				if session.sealed.auth.password != nil || !bytes.Equal(raw, make([]byte, len(raw))) {
					t.Fatal("stopped session retained password")
				}
				return
			}
			session.start(backendCommand{}, nil)
			<-entered
			if mode == "auth-failure" {
				_ = server.Close()
				select {
				case <-session.done:
				case <-time.After(time.Second):
					t.Fatal("auth failure did not retire session")
				}
			} else {
				session.close()
			}
			if mode == "late-dial" {
				close(release)
			}
			session.closeAndWait()
			if !bytes.Equal(raw, make([]byte, len(raw))) || session.sealed.auth.password != nil {
				t.Fatal("session retained password")
			}
			if mode == "auth-failure" && !strings.Contains(output.String(), `"message":"VNC connection failed"`) {
				t.Fatal("missing sanitized auth error")
			}
		})
	}
}

func TestSealedVNCCLIFixedErrors(t *testing.T) {
	var output, diagnostics bytes.Buffer
	code := runBackendCLI([]string{"--operation", "vnc-sealed"}, strings.NewReader("invalid\n"), &output, &diagnostics)
	if code != 1 || strings.TrimSpace(diagnostics.String()) != "sealed_vnc_stopped" {
		t.Fatal("CLI leaked or omitted error", code, diagnostics.String())
	}
}

func TestSealedVNCRouteFailureNeverFallsBackDirect(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := proxy.Addr().String()
	_ = proxy.Close()
	b := sealedVNCBinding()
	b.Host = "127.0.0.1"
	b.Port = uint16(target.Addr().(*net.TCPAddr).Port)
	b.TunnelConfigID = uuid.NewString()
	route := vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 1, ConfigurationVersion: 1}
	child := startSealedVNCTestChild(t, nil)
	plain, err := vault.EncodeVNCBundle(vault.VNCBundlePayload{PasswordProvided: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	bundle, err := vault.SealRoutedBundle(child.public, route, endpoint, plain)
	if err != nil {
		t.Fatal(err)
	}
	child.send(t, vaultInput(t, map[string]any{"binding": route, "bundle": bundle, "endpoint": endpoint}))
	vncChildEvent(t, child, "connecting")
	event := vncChildEvent(t, child, "failed")
	if event.Message != "VNC connection failed" || event.SessionID != b.SessionID {
		t.Fatal("unsanitized route failure")
	}
	child.wait(t)
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	unexpected, err := target.Accept()
	if err == nil {
		unexpected.Close()
		t.Fatal("VPN failure fell back to direct")
	}
	if network, ok := err.(net.Error); !ok || !network.Timeout() {
		t.Fatal("unexpected listener error", err)
	}
}

func TestSealedVNCConnectedLockJoinsReader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serveFakeVnc(listener, make(chan string, 2)) }()
	b := sealedVNCBinding()
	b.Host = "127.0.0.1"
	b.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	child := startSealedVNCTestChild(t, nil)
	child.send(t, sealedVNCPacket(t, child.public, b))
	vncChildEvent(t, child, "connecting")
	vncChildEvent(t, child, "connected")
	vncChildEvent(t, child, "frame")
	child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
	if err := child.wait(t); err != nil {
		t.Fatal("connected lock failed", err)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("server did not observe socket close")
		}
	case <-time.After(time.Second):
		t.Fatal("reader/socket leaked on lock")
	}
}

func TestSealedVNCAbsentPasswordSignal(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	b := sealedVNCBinding()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = server.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(server, "RFB 003.008\n")
		var version [12]byte
		_, _ = io.ReadFull(server, version[:])
		_, _ = server.Write([]byte{1, 2})
		var selected [1]byte
		_, _ = io.ReadFull(server, selected[:])
		_, _ = io.Copy(io.Discard, server)
	}()
	child := startSealedVNCTestChild(t, func(context.Context, string, string) (net.Conn, error) { return client, nil })
	plain, err := vault.EncodeVNCBundle(vault.VNCBundlePayload{})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	bundle, err := vault.SealBundle(child.public, b, plain)
	if err != nil {
		t.Fatal(err)
	}
	child.send(t, vaultInput(t, map[string]any{"binding": b, "bundle": bundle}))
	vncChildEvent(t, child, "connecting")
	failed := vncChildEvent(t, child, "failed")
	if !failed.PasswordRequired || failed.Message != "VNC connection failed" {
		t.Fatal("missing native password requirement")
	}
	child.wait(t)
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("failed auth leaked socket")
	}
}

func TestSealedVNCDestinationNormalizationAfterAuthentication(t *testing.T) {
	for _, tc := range []struct{ host, address string }{
		{"server.example", "server.example:5900"}, {"server.example:5911", "server.example:5900"},
		{"[::1]", "[::1]:5900"}, {"[::1]:5911", "[::1]:5900"}, {"::1", "[::1]:5900"},
		{"server:invalid", ""}, {"[broken", ""}, {":5911", ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			var output synchronizedBuffer
			manager := newVncManager(nil, newBackendLineWriter(&output))
			b := sealedVNCBinding()
			b.Host = tc.host
			b.Port = 5900
			password := []byte("private-password")
			called := false
			session := newVncSession(b.SessionID, manager.output, manager)
			session.sealed = &sealedVNCSession{binding: b, auth: &sealedVNCAuth{password: password, provided: true}, dial: func(_ context.Context, endpoint, address string) (net.Conn, error) {
				called = true
				if endpoint != "" || address != tc.address {
					t.Errorf("wrong normalized destination %q", address)
				}
				return nil, io.EOF
			}}
			session.start(backendCommand{}, nil)
			<-session.done
			if called != (tc.address != "") {
				t.Fatal("malformed host reached dial or valid host rejected")
			}
			if !bytes.Equal(password, make([]byte, len(password))) {
				t.Fatal("failed destination retained secret")
			}
		})
	}
}
