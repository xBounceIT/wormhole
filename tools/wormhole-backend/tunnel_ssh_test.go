package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const jumpNodeID = "11111111-1111-4111-8111-111111111111"
const jumpCredentialID = "22222222-2222-4222-8222-222222222222"
const jumpFolderID = "33333333-3333-4333-8333-333333333333"

func jumpTestServer(t *testing.T) (string, int, string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				server, channels, requests, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					_ = ch.Reject(ssh.Prohibited, "probe only")
				}
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
}

func jumpFixture(t *testing.T, host string, port int) (string, tunnelDetails) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jump.db")
	db := openBackupTestDatabase(t, path)
	for _, entry := range []struct {
		table   string
		columns []backupColumn
		values  map[string]any
	}{
		{"Nodes", backupNodeColumns, map[string]any{"id": jumpFolderID, "name": "Inherited identity", "kind": 0, "sortOrder": 0, "protocol": 0, "credentialId": jumpCredentialID, "credentialMode": 2, "createdAt": "now", "updatedAt": "now"}},
		{"Nodes", backupNodeColumns, map[string]any{"id": jumpNodeID, "parentId": jumpFolderID, "name": "Bastion", "kind": 1, "sortOrder": 0, "protocol": 0, "host": host, "port": port, "createdAt": "now", "updatedAt": "now"}},
		{"CredentialProfiles", backupCredentialColumns, map[string]any{"id": jumpCredentialID, "name": "Jump credential", "username": "ops", "kind": 0, "protocol": 0, "secretProvider": 0, "createdAt": "now", "updatedAt": "now"}},
	} {
		if err := insertBackupObject(db, entry.table, entry.columns, backupTestObject(entry.values)); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	secret, encoding, err := storeCredentialSecret(path, jumpCredentialID, "secret")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO CredentialSecrets (Id,Secret,Encoding,UpdatedAt) VALUES (?,?,?,'now');", jumpCredentialID, secret, encoding); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	raw, _ := json.Marshal(map[string]any{"Mode": "connection", "JumpConnectionId": jumpNodeID, "KeepaliveSeconds": 30})
	details, err := createTunnel(path, tunnelWriteRequest{Name: "Jump", Kind: 8, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	return path, details
}

func jumpExec(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
func jumpSnapshot(t *testing.T, path, id string) tunnelConfigSnapshot {
	t.Helper()
	snapshot, err := loadTunnelSnapshot(path, id)
	if err != nil {
		t.Fatal(err)
	}
	details, err := readTunnel(path, tunnelReadRequest{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.settings = details.Settings
	return snapshot
}

func TestSSHJumpValidation(t *testing.T) {
	valid := map[string]any{"Mode": "manual", "Host": "bastion.test", "Port": 22, "Username": "ops", "CredentialId": jumpCredentialID}
	for _, input := range []map[string]any{valid, {"Mode": "connection", "JumpConnectionId": jumpNodeID}} {
		raw, _ := json.Marshal(input)
		request := tunnelWriteRequest{Name: "Jump", Kind: 8, Settings: raw}
		if err := validateTunnelWriteRequest(&request, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []map[string]any{{"Mode": "bad"}, {"Host": "bad\n"}, {"Port": 0}, {"Port": 65536}, {"Username": ""}, {"Username": "bad\x00"}, {"CredentialId": "bad"}, {"HostKeySha256": "bad"}, {"KeepaliveSeconds": 0}, {"KeepaliveSeconds": 3601}, {"Password": "secret"}, {"HostKeySha256": map[string]any{"Password": "secret"}}, {"Username": nil}, {"JumpConnectionId": jumpNodeID}} {
		input := map[string]any{}
		for k, v := range valid {
			input[k] = v
		}
		for k, v := range change {
			input[k] = v
		}
		raw, _ := json.Marshal(input)
		var settings map[string]json.RawMessage
		_ = json.Unmarshal(raw, &settings)
		if validateTunnelSettings(8, settings) == nil {
			t.Fatalf("accepted invalid setting %v", change)
		}
	}
	for _, raw := range []string{`{"Mode":"connection","JumpConnectionId":"bad"}`, fmt.Sprintf(`{"Mode":"connection","JumpConnectionId":%q,"Host":"override"}`, jumpNodeID)} {
		var settings map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &settings)
		if validateTunnelSettings(8, settings) == nil {
			t.Fatal("accepted invalid connection mode")
		}
	}
	request := tunnelWriteRequest{Name: "Jump", Kind: 9, Settings: []byte(`{}`)}
	if validateTunnelWriteRequest(&request, false) == nil {
		t.Fatal("unknown tunnel kind accepted")
	}
	request.Kind = 8
	request.ForgetJumpHostKeySha256 = "bad"
	if validateTunnelWriteRequest(&request, false) == nil {
		t.Fatal("bad pin reset accepted")
	}
	raw, _ := json.Marshal(valid)
	if endpoint := tunnelEndpointSummary(8, raw); endpoint != "ops@bastion.test:22" {
		t.Fatal(endpoint)
	}
}

func TestSSHJumpTrustResolutionAndPinReset(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	snapshot := jumpSnapshot(t, path, details.ID)
	target, err := resolveSSHJumpTarget(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "ops" || target.password != "secret" || target.credentialID != jumpCredentialID {
		t.Fatal("inherited credential not resolved")
	}
	if _, _, _, err := prepareSSHJump(context.Background(), snapshot); err == nil {
		t.Fatal("TOFU without prompt succeeded")
	}
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Confirmation || !strings.Contains(prompt.Message, pin) {
			t.Fatal("missing fingerprint confirmation")
		}
		return "reject", nil
	})
	if _, _, _, err := prepareSSHJump(ctx, snapshot); err == nil {
		t.Fatal("rejected TOFU succeeded")
	}
	ctx = withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "accept", nil })
	payload, upstream, _, err := prepareSSHJump(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(payload)
	if upstream != nil {
		t.Fatal("unexpected upstream")
	}
	var config map[string]any
	_ = json.Unmarshal(payload, &config)
	if config["host_key_sha256"] != pin || config["password"] != "secret" {
		t.Fatal("invalid sidecar payload")
	}
	details, err = readTunnel(path, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	if details.JumpHostKeySha256 != pin || details.Endpoint != "Bastion" || bytes.Contains(details.Settings, []byte("secret")) {
		t.Fatal("pin missing or secret in settings")
	}
	details, err = updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: details.Settings, ForgetJumpHostKeySha256: pin})
	if err != nil {
		t.Fatal(err)
	}
	if details.JumpHostKeySha256 != "" {
		t.Fatal("pin reset failed")
	}
	if _, err = updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: details.Settings, ForgetJumpHostKeySha256: pin}); err == nil {
		t.Fatal("stale reset accepted")
	}
	jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint = ? WHERE Id = ?;", "SHA256:"+strings.Repeat("A", 43), jumpNodeID)
	if _, _, _, err = prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID)); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
}

func TestSSHJumpManualAndPassphrase(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("phrase"))
	keyBytes := pem.EncodeToMemory(block)
	if err := protectFile(credentialPrivateKeyPath(path, jumpCredentialID), keyBytes); err != nil {
		t.Fatal(err)
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET Kind=1 WHERE Id=?;", jumpCredentialID)
	jumpExec(t, path, "DELETE FROM CredentialSecrets WHERE Id=?;", jumpCredentialID)
	raw, _ := json.Marshal(map[string]any{"Mode": "manual", "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
	details, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	prompts := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		prompts++
		if prompt.Confirmation {
			return "accept", nil
		}
		if !prompt.Secret {
			t.Fatal("non-secret passphrase")
		}
		return "phrase", nil
	})
	payload, _, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(payload)
	if prompts != 2 || !bytes.Contains(payload, []byte(`"key_passphrase":"phrase"`)) {
		t.Fatal("missing passphrase prompt")
	}
	details, err = readTunnel(path, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(details.Settings, []byte(pin)) || bytes.Contains(details.Settings, []byte("phrase")) {
		t.Fatal("trust or protected settings invalid")
	}
	bad := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "wrong", nil })
	if _, _, _, err := prepareSSHJump(bad, jumpSnapshot(t, path, details.ID)); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET SecretProvider=1 WHERE Id=?;", jumpCredentialID)
	if _, err := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID)); err == nil || !strings.Contains(err.Error(), "Bitwarden credentials are not yet supported") {
		t.Fatalf("Bitwarden: %v", err)
	}
	jumpExec(t, path, "DELETE FROM CredentialProfiles WHERE Id=?;", jumpCredentialID)
	if _, err := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID)); err == nil || !strings.Contains(err.Error(), "Bitwarden credentials are not yet supported") {
		t.Fatalf("missing or virtual credential: %v", err)
	}
}

func TestSSHJumpCyclesDepthInvalidationAndReferences(t *testing.T) {
	path, details := jumpFixture(t, "bastion.test", 22)
	initial, err := sshJumpIdentity(path, details.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET Username='rotated' WHERE Id=?;", jumpCredentialID)
	changed, err := sshJumpIdentity(path, details.ID, nil)
	if err != nil || initial == changed {
		t.Fatal("credential change did not invalidate pool identity")
	}
	if err := deleteCredential(path, credentialDeleteRequest{ID: jumpCredentialID}); err == nil || !strings.Contains(err.Error(), "used by SSH tunnel Jump") {
		t.Fatalf("credential deletion: %v", err)
	}
	if _, err := deleteWorkspaceNodes(path, workspaceNodesRequest{NodeIDs: []string{jumpFolderID}}); err == nil || !strings.Contains(err.Error(), "used by SSH tunnel Jump") {
		t.Fatalf("subtree deletion: %v", err)
	}
	jumpExec(t, path, "UPDATE Nodes SET TunnelEnabled=1,TunnelConfigId=? WHERE Id=?;", details.ID, jumpNodeID)
	if _, err := sshJumpIdentity(path, details.ID, nil); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
	if _, err := sshJumpIdentity(path, details.ID, []string{"a", "b", "c"}); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("depth: %v", err)
	}
	if _, err := startTunnelRuntime(context.WithValue(context.Background(), sshJumpPathKey{}, []string{details.ID}), path, details.ID); err == nil {
		t.Fatal("runtime cycle accepted")
	}
	if _, err := startTunnelRuntime(context.WithValue(context.Background(), sshJumpPathKey{}, []string{"a", "b", "c"}), path, details.ID); err == nil {
		t.Fatal("runtime depth accepted")
	}
	jumpExec(t, path, "UPDATE Nodes SET TunnelEnabled=0,Protocol=1 WHERE Id=?;", jumpNodeID)
	if _, err := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID)); err == nil {
		t.Fatal("non-SSH accepted")
	}
	jumpExec(t, path, "DELETE FROM Nodes WHERE Id=?;", jumpNodeID)
	if _, err := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID)); err == nil {
		t.Fatal("missing jump accepted")
	}
}

func TestSSHJumpPoolSharesInvalidatesAndFailsClosed(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", pin, jumpNodeID)
	t.Setenv("WORMHOLE_SSHPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	previous := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(startTunnelProcess)
	processTunnelPool.loadSettings = true
	t.Cleanup(func() { processTunnelPool = previous })
	a, err := startTunnelRuntime(context.Background(), path, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	b, err := startTunnelRuntime(context.Background(), path, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if a.entry != b.entry || a.entry.refs != 2 {
		t.Fatal("sessions did not share one sidecar")
	}
	a.close()
	if !b.entry.process.alive() {
		t.Fatal("first release closed shared sidecar")
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET Username='rotated' WHERE Id=?;", jumpCredentialID)
	c, err := startTunnelRuntime(context.Background(), path, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if c.entry == b.entry {
		t.Fatal("rotated credential reused old sidecar")
	}
	if err := b.entry.process.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.exited():
	case <-time.After(3 * time.Second):
		t.Fatal("dropped sidecar did not notify dependents")
	}
	if conn, err := b.dialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
		conn.Close()
		t.Fatal("failed SOCKS dial fell back directly")
	}
	c.close()
	if c.entry.process.alive() {
		t.Fatal("last lease did not close sidecar")
	}
}

func TestSSHJumpPromptProtocolAndErrors(t *testing.T) {
	for _, test := range []struct {
		line      string
		answer    string
		wantError bool
	}{
		{"PROMPT {\"message\":\"OTP:\"}\nREADY 1234\n", "654321", false},
		{"READY 0\n", "", true}, {"bad\n", "", true}, {"PROMPT {}\nREADY 1234\n", "", true}, {"PROMPT {\"message\":\"bad\\n\"}\n", "", true},
		{"PROMPT {\"message\":\"OTP\"}\n", strings.Repeat("x", 16385), true},
	} {
		ready := make(chan string, 1)
		fail := make(chan error, 1)
		var out bytes.Buffer
		ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
			if !prompt.Secret {
				t.Fatal("non-secret OTP")
			}
			return test.answer, nil
		})
		readSSHJumpReady(ctx, bufio.NewReader(strings.NewReader(test.line)), &out, ready, fail)
		select {
		case <-ready:
			if test.wantError {
				t.Fatal("bad protocol accepted")
			}
		case <-fail:
			if !test.wantError {
				t.Fatal("good protocol rejected")
			}
		default:
			t.Fatal("no result")
		}
	}
	ready := make(chan string, 1)
	fail := make(chan error, 1)
	readSSHJumpReady(context.Background(), bufio.NewReader(strings.NewReader("PROMPT {\"message\":\"OTP\"}\n")), io.Discard, ready, fail)
	if <-fail == nil {
		t.Fatal("missing prompt handler accepted")
	}
	if _, _, _, err := prepareSSHJump(context.Background(), tunnelConfigSnapshot{settings: []byte("bad")}); err == nil {
		t.Fatal("invalid settings accepted")
	}
	if _, err := probeSSHJump(context.Background(), sshTarget{host: "127.0.0.1", port: 1}, nil); err == nil {
		t.Fatal("unreachable host accepted")
	}
	if _, err := resolveSSHJumpTarget(tunnelConfigSnapshot{settings: []byte(`{}`)}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestSSHJumpBackupPreservesReferences(t *testing.T) {
	path, details := jumpFixture(t, "bastion.test", 22)
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	if _, err := exportBackup(path, backupRequest{Path: backupPath, Password: "backup-passphrase"}); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if _, err := importBackup(restored, backupRequest{Path: backupPath, Password: "backup-passphrase"}); err != nil {
		t.Fatal(err)
	}
	copy, err := readTunnel(restored, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	if string(copy.Settings) != string(details.Settings) {
		t.Fatal("SSH reference ids changed on restore")
	}
	jumpExec(t, restored, "DELETE FROM Nodes WHERE Id=?;", jumpNodeID)
	if _, err := sshJumpIdentity(restored, details.ID, nil); err == nil {
		t.Fatal("dangling restored reference accepted")
	}
}

func jumpSocksProcess(t *testing.T) *tunnelProcess {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	process := newTestTunnelProcess()
	process.socks = ln.Addr().String()
	process.stdin = closeWriterFunc(func() error { ln.Close(); close(process.exited); return nil })
	t.Cleanup(process.close)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header := make([]byte, 3)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				header = make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				var host string
				if header[3] == 1 {
					address := make([]byte, 4)
					if _, err := io.ReadFull(conn, address); err != nil {
						return
					}
					host = net.IP(address).String()
				} else if header[3] == 3 {
					length := []byte{0}
					if _, err := io.ReadFull(conn, length); err != nil {
						return
					}
					address := make([]byte, int(length[0]))
					if _, err := io.ReadFull(conn, address); err != nil {
						return
					}
					host = string(address)
				} else {
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(conn, port); err != nil {
					return
				}
				remote, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
				if err != nil {
					return
				}
				defer remote.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				bridgeTunnelConnections(conn, remote)
			}()
		}
	}()
	return process
}

func TestSSHJumpChainingHoldsAndReleasesUpstream(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprint(drop), func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			vpn, err := createTunnel(path, tunnelWriteRequest{Name: "Upstream VPN", Kind: 0, Settings: []byte(`{"InterfacePrivateKey":"key","InterfaceAddress":"10.0.0.2/32","PeerPublicKey":"pub","PeerEndpoint":"vpn.test:51820"}`)})
			if err != nil {
				t.Fatal(err)
			}
			jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=?,TunnelEnabled=1,TunnelConfigId=? WHERE Id=?;", pin, vpn.ID, jumpNodeID)
			upstream := jumpSocksProcess(t)
			t.Setenv("WORMHOLE_SSHPROXY_PATH", os.Args[0])
			t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
			previous := processTunnelPool
			processTunnelPool = newTunnelRuntimePool(func(ctx context.Context, snapshot tunnelConfigSnapshot) (*tunnelProcess, error) {
				if snapshot.kind == 0 {
					return upstream, nil
				}
				return startTunnelProcess(ctx, snapshot)
			})
			processTunnelPool.loadSettings = true
			t.Cleanup(func() { processTunnelPool = previous })
			a, err := startTunnelRuntime(context.Background(), path, details.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			b, err := startTunnelRuntime(context.Background(), path, details.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			a.close()
			if !upstream.alive() {
				t.Fatal("upstream released before the downstream's last lease")
			}
			if drop {
				upstream.close()
				select {
				case <-b.exited():
				case <-time.After(3 * time.Second):
					t.Fatal("upstream failure did not close child")
				}
			} else {
				b.close()
			}
			waitForSSHTestCondition(t, "upstream released", func() bool { return !upstream.alive() })
		})
	}
}

func TestSSHJumpStaleEditorPreservesNewTrustAndGuardsReset(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	raw, _ := json.Marshal(map[string]any{"Mode": "manual", "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
	details, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "accept", nil })
	if _, _, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID)); err != nil {
		t.Fatal(err)
	}
	saved, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
	if err != nil || !bytes.Contains(saved.Settings, []byte(pin)) {
		t.Fatal("stale editor erased newly approved pin", err)
	}
	saved, err = updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw, ForgetJumpHostKeySha256: pin})
	if err != nil || bytes.Contains(saved.Settings, []byte(pin)) {
		t.Fatal("explicit reset failed", err)
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw, ForgetJumpHostKeySha256: pin}); err == nil {
		t.Fatal("stale manual reset accepted")
	}
	// The manual username is explicit; a password rotation must still invalidate the attempt.
	target, _ := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID))
	jumpExec(t, path, "UPDATE CredentialProfiles SET Username='changed' WHERE Id=?;", jumpCredentialID)
	target.password = "stale"
	if err := verifySSHJumpTargetCurrent(jumpSnapshot(t, path, details.ID), target); err == nil {
		t.Fatal("credential rotation accepted during authentication")
	}
}

func TestSSHJumpBrokerFailureNotifiesAndClosesVNC(t *testing.T) {
	process := newTestTunnelProcess()
	pool := newTunnelRuntimePool(nil)
	entry := &sharedTunnelEntry{key: "jump", refs: 1, process: process}
	pool.entries[entry.key] = entry
	lease := &tunnelRuntime{entry: entry, pool: pool, released: make(chan struct{})}
	output := &synchronizedBuffer{}
	manager := newVncManager(nil, newBackendLineWriter(output))
	manager.tunnelLeases["ssh-dependent"] = lease
	done := make(chan struct{})
	go func() { manager.watchTunnelLease("ssh-dependent", lease); close(done) }()
	process.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broker failure blocked")
	}
	if !strings.Contains(output.String(), `"type":"tunnel.failed"`) {
		t.Fatal("missing failure event")
	}
	session, m, _ := newTestVncSessionWithClosedTunnel("vnc-dependent")
	session.watchTunnel(session.tunnel)
	if !session.isStopped() || m.sessions[session.id] != nil {
		t.Fatal("VNC survived tunnel failure")
	}
}

func TestSSHJumpDeadOrReleasedLeaseNeverDialsAReusedProxyPort(t *testing.T) {
	for _, released := range []bool{false, true} {
		t.Run(fmt.Sprint(released), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			process := &tunnelProcess{socks: listener.Addr().String(), exited: make(chan struct{})}
			lease := &tunnelRuntime{entry: &sharedTunnelEntry{process: process}, released: make(chan struct{})}
			if released {
				close(lease.released)
			} else {
				close(process.exited)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if conn, err := lease.dialContext(ctx, "tcp", "reachable.example:22"); err == nil {
				conn.Close()
				t.Fatal("dead lease dial succeeded")
			}
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
			if conn, err := listener.Accept(); err == nil {
				conn.Close()
				t.Fatal("dead lease contacted a different process on its old SOCKS port")
			}
		})
	}
}

func TestSSHJumpTOFUDoesNotSplitAPendingSharedPassphrasePrompt(t *testing.T) {
	for _, chained := range []bool{false, true} {
		t.Run(fmt.Sprint(chained), func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			upstreamID := ""
			if chained {
				raw, _ := json.Marshal(map[string]any{"Mode": "manual", "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
				upstream, err := createTunnel(path, tunnelWriteRequest{Name: "SSH upstream", Kind: 8, Settings: raw})
				if err != nil {
					t.Fatal(err)
				}
				upstreamID = upstream.ID
				jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=?,TunnelEnabled=1,TunnelConfigId=? WHERE Id=?;", pin, upstreamID, jumpNodeID)
			}
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			block, _ := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("phrase"))
			if err := protectFile(credentialPrivateKeyPath(path, jumpCredentialID), pem.EncodeToMemory(block)); err != nil {
				t.Fatal(err)
			}
			jumpExec(t, path, "UPDATE CredentialProfiles SET Kind=1 WHERE Id=?;", jumpCredentialID)
			jumpExec(t, path, "DELETE FROM CredentialSecrets WHERE Id=?;", jumpCredentialID)
			t.Setenv("WORMHOLE_SSHPROXY_PATH", os.Args[0])
			t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
			var starts, prompts atomic.Int32
			previous := processTunnelPool
			processTunnelPool = newTunnelRuntimePool(func(ctx context.Context, snapshot tunnelConfigSnapshot) (*tunnelProcess, error) {
				starts.Add(1)
				if snapshot.id == upstreamID {
					payload, lease, _, err := prepareSSHJump(ctx, snapshot)
					clearBytes(payload)
					lease.close()
					if err != nil {
						return nil, err
					}
					return jumpSocksProcess(t), nil
				}
				return startTunnelProcess(ctx, snapshot)
			})
			processTunnelPool.loadSettings = true
			t.Cleanup(func() { processTunnelPool = previous })
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			entered, resume := make(chan struct{}, 1), make(chan struct{})
			ctx = withTunnelPromptHandler(ctx, func(ctx context.Context, prompt tunnelPrompt) (string, error) {
				if prompt.Confirmation {
					return "accept", nil
				}
				prompts.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-resume:
					return "phrase", nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			})
			type result struct {
				lease *tunnelRuntime
				err   error
			}
			results := make(chan result, 2)
			start := func() { lease, err := startTunnelRuntime(ctx, path, details.ID); results <- result{lease, err} }
			go start()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("passphrase prompt did not open")
			}
			go start()
			waitForSSHTestCondition(t, "second session joined pending SSH tunnel", func() bool {
				processTunnelPool.mu.Lock()
				defer processTunnelPool.mu.Unlock()
				for _, entry := range processTunnelPool.entries {
					if entry.refs == 2 && strings.HasSuffix(entry.key, details.ID) {
						return true
					}
				}
				return false
			})
			close(resume)
			first, second := <-results, <-results
			defer first.lease.close()
			defer second.lease.close()
			if first.err != nil || second.err != nil {
				t.Fatalf("shared start: %v, %v", first.err, second.err)
			}
			expected := int32(1)
			if chained {
				expected = 2
			}
			if first.lease.entry != second.lease.entry || starts.Load() != expected || prompts.Load() != expected {
				t.Fatal("TOFU split the shared establishment or duplicated its prompt")
			}
		})
	}
}

func TestSSHJumpTrustRefreshFailsOnlyTheRequiredPendingChain(t *testing.T) {
	pool := newTunnelRuntimePool(nil)
	changed := errors.New("jump credential changed")
	required := &sharedTunnelEntry{identity: "old", refreshTrustIdentity: func() (string, error) { return "", changed }}
	unrelated := &sharedTunnelEntry{identity: "unrelated", refreshTrustIdentity: func() (string, error) { return "", changed }}
	ready := &sharedTunnelEntry{process: &tunnelProcess{}, refreshTrustIdentity: func() (string, error) { t.Fatal("refreshed an established tunnel"); return "", nil }}
	pool.entries = map[string]*sharedTunnelEntry{"required": required, "other": unrelated, "ready": ready}
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	if err := pool.refreshPendingSSHTrust(required); !errors.Is(err, changed) {
		t.Fatalf("required chain error: %v", err)
	}
	required.refreshTrustIdentity = func() (string, error) { return "trusted", nil }
	if err := pool.refreshPendingSSHTrust(required); err != nil {
		t.Fatalf("unrelated invalid chain blocked trust: %v", err)
	}
	if required.identity != "trusted" || unrelated.identity != "unrelated" {
		t.Fatal("invalid trust refresh crossed chain ownership")
	}
}
