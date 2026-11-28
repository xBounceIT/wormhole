package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"golang.org/x/crypto/ssh"
)

func sealedSSHFixtureBinding() vault.BundleBinding {
	return vault.BundleBinding{WorkspaceID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: uuid.NewString(), Protocol: "ssh", Host: "127.0.0.1", Port: 22, Epoch: 1}
}
func sealedSSHFixturePayload() vault.SSHBundlePayload {
	return vault.SSHBundlePayload{Username: "alice", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), Password: []byte("sealed-password")}
}
func sealedSSHPacket(t *testing.T, public []byte, binding vault.BundleBinding, payload vault.SSHBundlePayload) []byte {
	t.Helper()
	plain, err := vault.EncodeSSHBundle(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	bundle, err := vault.SealBundle(public, binding, plain)
	if err != nil {
		t.Fatal(err)
	}
	return vaultInput(t, map[string]any{"binding": binding, "bundle": bundle, "columns": 80, "rows": 24})
}

func TestVaultSSHBundleHandler(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	p := sealedSSHFixturePayload()
	protocol, mode := 0, 2
	c, err := h.owner.PutCredential(ctx, vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "account", Protocol: "ssh", Kind: "password", Provider: "local", Username: p.Username}, []localvault.SecretChange{{Field: "password", Value: p.Password}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: id, Name: "host", Kind: 1, Host: &[]string{"localhost"}[0], Protocol: &protocol, CredentialID: &c.ID, CredentialMode: &mode, SshKnownHostFingerprint: &p.Fingerprint}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	q := map[string]any{"nodeId": n.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1", "publicKey": key.PublicKey().Bytes()}
	if answer, err := h.Handle(ctx, "ssh-bitwarden-prepare", vaultInput(t, q)); err != nil || string(answer) != `{"required":false}` {
		t.Fatal("local SSH credential did not retain its native path", err)
	}
	raw, err := h.Handle(ctx, "ssh-bundle", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, p.Password) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(p.Password))) {
		t.Fatal("secret in relay")
	}
	var sealed localvault.SSHConnectionBundle
	if json.Unmarshal(raw, &sealed) != nil {
		t.Fatal("invalid response")
	}
	plain, err := vault.OpenBundle(key.Bytes(), sealed.Binding, sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	decoded, err := vault.DecodeSSHBundle(plain)
	if err != nil || !bytes.Equal(decoded.Password, p.Password) {
		t.Fatal(err)
	}

	tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"vpn","Username":"u","Password":"route-password"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	m := n.NodeMetadata
	enabled := true
	m.TunnelEnabled = &enabled
	m.TunnelConfigID = &tunnel.ID
	if _, err = h.owner.PutNode(ctx, m, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	planQuery := map[string]any{"nodeId": q["nodeId"], "credentialOverride": "", "sessionId": q["sessionId"], "requestId": q["requestId"], "epoch": "1"}
	routeRaw, err := h.Handle(ctx, "connection-route", vaultInput(t, planQuery))
	if err != nil {
		t.Fatal(err)
	}
	var route vault.TunnelBundleBinding
	if json.Unmarshal(routeRaw, &route) != nil {
		t.Fatal("route")
	}
	routedQuery := map[string]any{}
	for k, v := range q {
		routedQuery[k] = v
	}
	routedQuery["route"] = route
	routedQuery["endpoint"] = "127.0.0.1:12345"
	routedRaw, err := h.Handle(ctx, "ssh-route-bundle", vaultInput(t, routedQuery))
	if err != nil {
		t.Fatal(err)
	}
	var routed localvault.RoutedSSHConnectionBundle
	if json.Unmarshal(routedRaw, &routed) != nil {
		t.Fatal("routed response")
	}
	routedPlain, err := vault.OpenRoutedBundle(key.Bytes(), routed.Binding, routed.Endpoint, routed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(routedPlain, p.Password) {
		t.Fatal("wrong routed credential")
	}
	vault.Wipe(routedPlain)
	for _, change := range []map[string]any{{"endpoint": "10.0.0.1:22"}, {"epoch": "01"}, {"epoch": "0"}, {"publicKey": []byte{}}, {"route": nil}, {"route": map[string]any{"unknown": true}}, {"extra": true}} {
		bad := map[string]any{}
		for k, v := range routedQuery {
			bad[k] = v
		}
		for k, v := range change {
			bad[k] = v
		}
		if _, err := h.sshRouteBundle(ctx, vaultInput(t, bad)); err == nil {
			t.Fatal("bad route request")
		}
	}
	if _, err := h.sshRouteBundle(ctx, bytes.Repeat([]byte("x"), 8193)); err == nil {
		t.Fatal("oversized route")
	}
	if _, err := (&vaultFoundationHandler{}).sshRouteBundle(ctx, vaultInput(t, routedQuery)); err == nil {
		t.Fatal("locked route")
	}
	wrong := route
	wrong.ConfigurationVersion++
	routedQuery["route"] = wrong
	if _, err := h.sshRouteBundle(ctx, vaultInput(t, routedQuery)); err == nil {
		t.Fatal("stale route")
	}
	for _, epoch := range []string{"01", "-1", "bad", "0", "9007199254740992"} {
		q["epoch"] = epoch
		if _, err := h.Handle(ctx, "ssh-bundle", vaultInput(t, q)); err == nil {
			t.Fatal("epoch accepted", epoch)
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{"nodeId":null}`), []byte(strings.Repeat("x", 2049))} {
		if _, err := h.sshBundle(ctx, raw); err == nil {
			t.Fatal("bad request")
		}
	}
	if _, err := (&vaultFoundationHandler{}).sshBundle(ctx, vaultInput(t, q)); err == nil {
		t.Fatal("locked owner")
	}
}

type sealedSSHTestChild struct {
	input  *io.PipeWriter
	lines  <-chan []byte
	done   <-chan error
	public []byte
}

type sealedSSHTestWriter func([]byte) (int, error)

func (w sealedSSHTestWriter) Write(p []byte) (int, error) { return w(p) }

func TestVaultSSHSealedOutputFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		writer := sealedSSHTestWriter(func([]byte) (int, error) {
			if short {
				return 0, nil
			}
			return 0, io.ErrClosedPipe
		})
		if _, err := (sealedSSHOutput{writer: writer, cancel: cancel}).Write([]byte("event")); err == nil || ctx.Err() == nil {
			t.Fatal("output failure did not retire child")
		}
		if err := serveSealedSSH(io.NopCloser(strings.NewReader("")), writer, nil); err == nil {
			t.Fatal("greeting failure ignored")
		}
	}
	if err := serveSealedSSH(io.NopCloser(strings.NewReader("")), io.Discard, nil); err == nil {
		t.Fatal("missing first packet")
	}
	child := startSealedSSHTestChild(t, func(context.Context, sshTarget, uint16, uint16) (*sshNativeSession, string, error) {
		t.Error("invalid payload reached dial")
		return nil, "", io.EOF
	})
	b := sealedSSHFixtureBinding()
	bundle, err := vault.SealBundle(child.public, b, []byte("invalid SSH payload"))
	if err != nil {
		t.Fatal(err)
	}
	child.send(t, vaultInput(t, map[string]any{"binding": b, "bundle": bundle, "columns": 80, "rows": 24}))
	if child.wait(t) == nil {
		t.Fatal("invalid binary payload accepted")
	}
}

func startSealedSSHTestChild(t *testing.T, dial sealedSSHDial, editOptions ...sealedSFTPEditOptions) sealedSSHTestChild {
	return startSealedSSHModeTestChild(t, dial, "", editOptions...)
}

func startSealedSSHModeTestChild(t *testing.T, dial sealedSSHDial, mode string, editOptions ...sealedSFTPEditOptions) sealedSSHTestChild {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	lines := make(chan []byte, 32)
	go func() {
		if dial == nil {
			var diagnostics bytes.Buffer
			args := []string{"--operation", "ssh-sealed"}
			if mode != "" {
				args[1] = "ssh-manual-" + mode + "-sealed"
			}
			if len(editOptions) > 0 {
				args = append(args, "--database", filepath.Join(filepath.Dir(editOptions[0].SettingsPath), "workspace.db"), "--electron-user-data", editOptions[0].UserDataPath)
			}
			code := runBackendCLI(args, inR, outW, &diagnostics)
			if code != 0 {
				done <- errors.New("sealed child stopped")
			} else {
				done <- nil
			}
		} else {
			done <- serveSealedSSHMode(inR, outW, dial, mode, editOptions...)
		}
		outW.Close()
	}()
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(outR)
		scanner.Buffer(make([]byte, 4096), 8*1024*1024)
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
		t.Fatal("first stdout line must announce recipient")
	}
	child.public = greeting.PublicKey
	return child
}
func (c sealedSSHTestChild) line(t *testing.T) []byte {
	t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			t.Fatal("unexpected child EOF")
		}
		return line
	case <-time.After(5 * time.Second):
		t.Fatal("child output timeout")
		return nil
	}
}
func (c sealedSSHTestChild) send(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := c.input.Write(append(bytes.Clone(raw), '\n')); err != nil {
		t.Fatal(err)
	}
}
func (c sealedSSHTestChild) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("child did not retire")
		return nil
	}
}

func TestVaultSSHSealedCancellationAndInvalidMessages(t *testing.T) {
	for _, command := range []string{"eof", "close", "app-lock", "replay", "credential", "wrong-session"} {
		t.Run(command, func(t *testing.T) {
			entered := make(chan struct{})
			var borrowed []byte
			child := startSealedSSHTestChild(t, func(ctx context.Context, target sshTarget, cols, rows uint16) (*sshNativeSession, string, error) {
				if target.password != "sealed-password" || target.knownHostFingerprint == "" || cols != 80 || rows != 24 || target.socksEndpoint != "" {
					t.Error("wrong target")
				}
				borrowed = target.privateKey
				close(entered)
				<-ctx.Done()
				return nil, "", ctx.Err()
			})
			b := sealedSSHFixtureBinding()
			p := sealedSSHFixturePayload()
			p.PrivateKey = []byte("borrowed-private-key")
			packet := sealedSSHPacket(t, child.public, b, p)
			child.send(t, packet)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no dial")
			}
			switch command {
			case "eof":
				child.input.Close()
			case "replay":
				child.send(t, packet)
			case "credential":
				child.send(t, vaultInput(t, map[string]any{"type": "input", "sessionId": b.SessionID, "password": "forbidden"}))
			case "wrong-session":
				child.send(t, vaultInput(t, map[string]any{"type": "input", "sessionId": uuid.NewString()}))
			default:
				child.send(t, vaultInput(t, map[string]any{"type": command, "sessionId": b.SessionID}))
			}
			child.wait(t)
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("decrypted frame retained")
			}
		})
	}
	child := startSealedSSHTestChild(t, func(context.Context, sshTarget, uint16, uint16) (*sshNativeSession, string, error) {
		t.Error("unauthenticated dial")
		return nil, "", errors.New("forbidden")
	})
	b := sealedSSHFixtureBinding()
	packet := sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload())
	packet = bytes.Replace(packet, []byte(`"host":"127.0.0.1"`), []byte(`"host":"attacker"`), 1)
	child.send(t, packet)
	if child.wait(t) == nil {
		t.Fatal("altered binding accepted")
	}
}

func TestVaultSSHSealedLateDialCannotOutliveCancellation(t *testing.T) {
	entered := make(chan struct{})
	native := &sshNativeSession{done: make(chan struct{})}
	child := startSealedSSHTestChild(t, func(ctx context.Context, _ sshTarget, _, _ uint16) (*sshNativeSession, string, error) {
		close(entered)
		<-ctx.Done()
		return native, "", nil
	})
	b := sealedSSHFixtureBinding()
	child.send(t, sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload()))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dial not entered")
	}
	child.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
	if !native.isClosed() {
		t.Fatal("late dial escaped cancellation")
	}
}

func TestVaultSSHSealedStrictDecoding(t *testing.T) {
	b := sealedSSHFixtureBinding()
	for _, mutate := range []func(*vault.BundleBinding){func(b *vault.BundleBinding) { b.NodeID = "bad" }, func(b *vault.BundleBinding) { b.TunnelConfigID = uuid.NewString() }, func(b *vault.BundleBinding) { b.UseExternalClient = true }, func(b *vault.BundleBinding) { b.Protocol = "rdp" }, func(b *vault.BundleBinding) { b.Epoch = 0 }, func(b *vault.BundleBinding) { b.Epoch = 1 << 53 }, func(b *vault.BundleBinding) { b.Host = "bad host" }, func(b *vault.BundleBinding) { b.Port = 0 }} {
		copy := b
		mutate(&copy)
		if validSealedSSHBinding(copy) {
			t.Fatal("unsafe binding")
		}
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	raw := sealedSSHPacket(t, key.PublicKey().Bytes(), b, sealedSSHFixturePayload())
	for _, bad := range [][]byte{nil, []byte(`{}`), bytes.Replace(raw, []byte(`"epoch":1`), []byte(`"epoch":1,"epoch":1`), 1), bytes.Replace(raw, []byte(`"suiteId":`), []byte(`"unknown":`), 1), bytes.Replace(raw, []byte(`"columns":80`), []byte(`"columns":0`), 1), bytes.Replace(raw, []byte(`"rows":24`), []byte(`"rows":501`), 1)} {
		if _, err := decodeSealedSSHOpening(bad); err == nil {
			t.Fatal("invalid open")
		}
	}
	for _, kind := range []string{"input", "resize", "snapshot", "terminal-ack", "auto-sudo-cancel", "close", "app-lock"} {
		if _, err := decodeSealedSSHCommand(vaultInput(t, map[string]any{"type": kind, "sessionId": b.SessionID}), b.SessionID); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"open", "host-key-trust", "sftp-edit", "mcp.start", "app-lock-all", "unknown"} {
		if _, err := decodeSealedSSHCommand(vaultInput(t, map[string]any{"type": kind, "sessionId": b.SessionID}), b.SessionID); err == nil {
			t.Fatal("unsafe command")
		}
	}
	var out, diagnostics bytes.Buffer
	if runBackendCLI([]string{"--operation", "ssh-sealed"}, strings.NewReader("{}\n"), &out, &diagnostics) != 1 || strings.Contains(diagnostics.String(), "database") || !strings.Contains(out.String(), "recipient") {
		t.Fatal("sealed entrypoint used legacy startup", diagnostics.String())
	}
}

// Real SSH handshake: the test server sees the password, the stdio relay sees
// only the recipient key, sealed bundle and public terminal events.
func TestVaultSSHSealedNativeHandshake(t *testing.T) {
	for _, mode := range []string{"connected", "mismatch", "remote-close"} {
		t.Run(mode, func(t *testing.T) { testSealedSSHNativeHandshake(t, mode) })
	}
}

func testSealedSSHNativeHandshake(t *testing.T, mode string) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authenticated := make(chan bool, 1)
	serverDone := make(chan struct{})
	remoteExit := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ok := meta.User() == "alice" && bytes.Equal(password, []byte("sealed-password"))
			authenticated <- ok
			if !ok {
				return nil, errors.New("denied")
			}
			return nil, nil
		}}
		config.AddHostKey(signer)
		native, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer native.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for r := range requests {
					if r.WantReply {
						_ = r.Reply(true, nil)
					}
					if r.Type == "shell" {
						if mode == "remote-close" {
							<-remoteExit
							_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							channel.Close()
							native.Close()
							return
						}
						_, _ = channel.Write([]byte("sealed-ready\r\n"))
						go io.Copy(channel, channel)
					}
				}
			}()
		}
	}()
	options := sealedEditOptions(t)
	child := startSealedSSHTestChild(t, nil, options)
	b := sealedSSHFixtureBinding()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	b.Port = uint16(number)
	p := sealedSSHFixturePayload()
	if mode != "mismatch" {
		p.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	}
	h := vaultCredentialFixture(t)
	protocol, portValue := 0, int(b.Port)
	node, err := h.owner.PutNode(context.Background(), vaultstore.NodeMetadata{ID: b.NodeID, Name: "SSH fixture", Kind: 1, Protocol: &protocol, Host: &b.Host, Port: &portValue, Username: &p.Username, UseInlinePassword: &[]bool{true}[0], SshKnownHostFingerprint: &p.Fingerprint}, []localvault.SecretChange{{Field: "inlinePassword", Value: p.Password}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.Handle(context.Background(), "ssh-bundle", vaultInput(t, map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": b.SessionID, "requestId": b.RequestID, "epoch": "1", "publicKey": child.public}))
	if err != nil {
		t.Fatal(err)
	}
	var packet map[string]any
	if json.Unmarshal(response, &packet) != nil {
		t.Fatal("invalid vault response")
	}
	packet["columns"], packet["rows"] = json.RawMessage("80"), json.RawMessage("24")
	child.send(t, vaultInput(t, packet))
	var event sshWireEvent
	if mode != "connected" {
		if mode == "remote-close" {
			if json.Unmarshal(child.line(t), &event) != nil || event.Type != "connected" {
				t.Fatal("remote close did not follow established session", event)
			}
			close(remoteExit)
		}
		for line := range child.lines {
			if mode == "mismatch" && (bytes.Contains(line, p.Password) || bytes.Contains(line, []byte("SHA256:"))) {
				t.Fatal("unsafe error response")
			}
		}
		child.wait(t)
		if mode == "mismatch" {
			select {
			case <-authenticated:
				t.Fatal("password sent to wrong host")
			default:
			}
		}
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Fatal("SSH transport leaked")
		}
		return
	}
	if json.Unmarshal(child.line(t), &event) != nil || event.Type != "connected" || event.Fingerprint != p.Fingerprint {
		t.Fatal("handshake failed", event)
	}
	if !<-authenticated {
		t.Fatal("wrong SSH credential")
	}
	child.send(t, vaultInput(t, map[string]any{"type": "sftp-edit", "sessionId": b.SessionID, "operation": "list", "request_id": "editor-list"}))
	if event := waitSealedSFTPEvent(t, child, "sftp.edit", "editor-list"); event.Error != "" || len(event.Edits) != 0 {
		t.Fatal("native CLI did not receive trusted editor paths", event)
	}
	var actualBinding vault.BundleBinding
	if json.Unmarshal(vaultInput(t, packet["binding"].(map[string]any)), &actualBinding) != nil {
		t.Fatal("invalid binding fixture")
	}
	if _, err := os.Stat(filepath.Join(options.UserDataPath, "vault-sftp-edit", actualBinding.WorkspaceID, b.NodeID, "sftp-edit")); err != nil {
		t.Fatal("CLI did not scope editing to the authenticated handoff", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(options.SettingsPath), "workspace.db")); !os.IsNotExist(err) {
		t.Fatal("sealed CLI opened a legacy database", err)
	}
	child.send(t, vaultInput(t, map[string]any{"type": "resize", "sessionId": b.SessionID, "columns": 100, "rows": 30}))
	child.send(t, vaultInput(t, map[string]any{"type": "input", "sessionId": b.SessionID, "data": base64.StdEncoding.EncodeToString([]byte("echo-fixture\r"))}))
	child.send(t, vaultInput(t, map[string]any{"type": "snapshot", "sessionId": b.SessionID}))
	child.send(t, vaultInput(t, map[string]any{"type": "close", "sessionId": b.SessionID}))
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH transport leaked")
	}
}
