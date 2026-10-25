package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func jumpUseEncryptedKey(t *testing.T, path string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := protectFile(credentialPrivateKeyPath(path, jumpCredentialID), pem.EncodeToMemory(block)); err != nil {
		t.Fatal(err)
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET Kind=1 WHERE Id=?;", jumpCredentialID)
	jumpExec(t, path, "DELETE FROM CredentialSecrets WHERE Id=?;", jumpCredentialID)
}

func TestSSHJumpRejectsTrustChangedDuringAuthentication(t *testing.T) {
	for _, nextPin := range []string{"", "SHA256:" + strings.Repeat("A", 43)} {
		t.Run(nextPin, func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			jumpUseEncryptedKey(t, path)
			jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", pin, jumpNodeID)
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
				if !prompt.Secret {
					t.Fatal("expected a passphrase prompt")
				}
				jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", nextPin, jumpNodeID)
				return "phrase", nil
			})
			payload, upstream, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID))
			clearBytes(payload)
			upstream.close()
			if err == nil {
				t.Fatal("authentication continued after the jump host trust changed")
			}
		})
	}
}

func TestSSHJumpRejectsUpstreamChangedDuringAuthentication(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	jumpUseEncryptedKey(t, path)
	settings := json.RawMessage(`{"InterfacePrivateKey":"key","InterfaceAddress":"10.0.0.2/32","PeerPublicKey":"pub","PeerEndpoint":"vpn.test:51820"}`)
	vpn, err := createTunnel(path, tunnelWriteRequest{Name: "Upstream", Kind: 0, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=?,TunnelEnabled=1,TunnelConfigId=? WHERE Id=?;", pin, vpn.ID, jumpNodeID)
	previous := processTunnelPool
	process := jumpSocksProcess(t)
	processTunnelPool = newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) { return process, nil })
	processTunnelPool.loadSettings = true
	t.Cleanup(func() { processTunnelPool = previous })
	ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
		settings = json.RawMessage(strings.ReplaceAll(string(settings), "vpn.test", "new-vpn.test"))
		if _, err := updateTunnel(path, tunnelWriteRequest{ID: vpn.ID, Name: vpn.Name, Kind: 0, Settings: settings}); err != nil {
			t.Fatal(err)
		}
		return "phrase", nil
	})
	payload, upstream, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID))
	clearBytes(payload)
	upstream.close()
	if err == nil {
		t.Fatal("authentication continued on an upstream lease with an obsolete configuration")
	}
}

func TestSSHJumpDeletionUsesTheEffectiveInheritedCredential(t *testing.T) {
	path, details := jumpFixture(t, "bastion.test", 22)
	staleID := "44444444-4444-4444-8444-444444444444"
	jumpExec(t, path, "UPDATE Nodes SET CredentialMode=0,CredentialId=? WHERE Id=?;", staleID, jumpNodeID)
	target, err := resolveSSHJumpTarget(jumpSnapshot(t, path, details.ID))
	if err != nil || target.credentialID != jumpCredentialID {
		t.Fatalf("inherited credential: %s, %v", target.credentialID, err)
	}
	if err := rejectSSHJumpDeletion(path, nil, staleID); err != nil {
		t.Fatalf("unused stale credential was treated as effective: %v", err)
	}
	if err := deleteCredential(path, credentialDeleteRequest{ID: jumpCredentialID}); err == nil || !strings.Contains(err.Error(), "used by SSH tunnel") {
		t.Fatalf("the effective jump credential could be deleted: %v", err)
	}
}

func TestSSHJumpTrustRefreshDoesNotAdoptRotatedCredentials(t *testing.T) {
	path, details := jumpFixture(t, "bastion.test", 22)
	previous := processTunnelPool
	entered, resume := make(chan struct{}), make(chan struct{})
	processTunnelPool = newTunnelRuntimePool(func(ctx context.Context, _ tunnelConfigSnapshot) (*tunnelProcess, error) {
		close(entered)
		select {
		case <-resume:
			return nil, errors.New("test complete")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	processTunnelPool.loadSettings = true
	t.Cleanup(func() { processTunnelPool = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		lease, err := startTunnelRuntime(ctx, path, details.ID)
		lease.close()
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("pending establishment did not start")
	}
	jumpExec(t, path, "UPDATE CredentialProfiles SET Username='rotated' WHERE Id=?;", jumpCredentialID)
	processTunnelPool.mu.Lock()
	var entry *sharedTunnelEntry
	for _, pending := range processTunnelPool.entries {
		entry = pending
	}
	before := entry.identity
	processTunnelPool.mu.Unlock()
	tunnelMutationMu.Lock()
	err := processTunnelPool.refreshPendingSSHTrust(entry)
	tunnelMutationMu.Unlock()
	close(resume)
	<-done
	if err == nil || entry.identity != before {
		t.Fatal("trust refresh relabeled a pending authentication after credential rotation")
	}
}

func TestSSHJumpRejectsConfigurationChangedBeforeReady(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", pin, jumpNodeID)
	t.Setenv("WORMHOLE_SSHPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	ctx := withTunnelProgressHandler(context.Background(), func(_ context.Context, phase, _ string) error {
		if phase == "starting" {
			jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", "SHA256:"+strings.Repeat("A", 43), jumpNodeID)
		}
		return nil
	})
	process, err := startTunnelProcess(ctx, jumpSnapshot(t, path, details.ID))
	if process != nil {
		process.close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed while authentication") {
		t.Fatalf("obsolete authentication reported readiness: %v", err)
	}
}

func TestSSHJumpPromptHonorsEstablishmentCancellation(t *testing.T) {
	pool := newTunnelRuntimePool(nil)
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	entered := make(chan struct{})
	entry := &sharedTunnelEntry{}
	pool.subscribePromptLocked(entry, owner, func(ctx context.Context, _ tunnelPrompt) (string, error) {
		close(entered)
		<-ctx.Done()
		return "", ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := pool.prompt(entry)(ctx, tunnelPrompt{Secret: true}); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("prompt did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prompt cancellation: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		cancelOwner()
		<-done
		t.Fatal("prompt outlived the establishment context")
	}
}

func TestSSHJumpReleasedLeaseCancelsAnInFlightDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	process := newTestTunnelProcess()
	process.socks = listener.Addr().String()
	pool := newTunnelRuntimePool(nil)
	entry := &sharedTunnelEntry{key: "shared", refs: 2, process: process}
	pool.entries[entry.key] = entry
	lease := &tunnelRuntime{entry: entry, pool: pool, released: make(chan struct{})}
	defer pool.release(entry)
	defer lease.close()
	arrived := make(chan struct{})
	resume := make(chan struct{})
	defer close(resume)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(conn, make([]byte, 3)); err != nil {
			return
		}
		close(arrived)
		<-resume
		_, _ = conn.Write([]byte{5, 0})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := lease.dialContext(ctx, "tcp", "127.0.0.1:22")
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-arrived:
	case <-ctx.Done():
		t.Fatal("SOCKS handshake did not start")
	}
	lease.close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("released lease returned a connection")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("released lease left its SOCKS handshake running on the shared process")
	}
}

func TestSSHJumpRejectsMalformedPromptBeforeRequestingSecrets(t *testing.T) {
	for _, raw := range []string{`{}`, `{"message":null}`, `{"message":17}`, `[]`} {
		t.Run(raw, func(t *testing.T) {
			prompts := 0
			ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
				prompts++
				return "sensitive-answer", nil
			})
			ready, failures := make(chan string, 1), make(chan error, 1)
			var output bytes.Buffer
			// A valid READY after the malformed message prevents EOF from passing the test.
			readSSHJumpReady(ctx, bufio.NewReader(strings.NewReader("PROMPT "+raw+"\nREADY 1234\n")), &output, ready, failures)
			if prompts != 0 || output.Len() != 0 || len(ready) != 0 || len(failures) != 1 {
				t.Fatal("malformed sidecar message requested or forwarded an authentication secret")
			}
		})
	}
}

func TestSSHJumpSnapshotSettingsPreservesConfigurationAndErrors(t *testing.T) {
	if tunnelName(8) != "SSH tunnel (jump host)" {
		t.Fatal("backend kind label no longer matches the editor's SSH route catalog")
	}
	path, details := jumpFixture(t, "bastion.test", 22)
	snapshot, err := loadTunnelSnapshot(path, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTunnelSnapshotSettings(snapshot)
	defer clearBytes(loaded.settings)
	if err != nil || loaded.id != details.ID || loaded.updatedAt != snapshot.updatedAt || !bytes.Equal(loaded.settings, details.Settings) {
		t.Fatalf("configuration snapshot changed: %v", err)
	}
	for _, invalid := range []tunnelConfigSnapshot{
		{},
		{databasePath: filepath.Join(t.TempDir(), "missing.db"), id: details.ID},
		{databasePath: t.TempDir(), id: details.ID},
		{databasePath: path, id: "55555555-5555-4555-8555-555555555555"},
	} {
		loaded, err := loadTunnelSnapshotSettings(invalid)
		clearBytes(loaded.settings)
		if err == nil {
			t.Fatal("missing database, id or protected settings were accepted")
		}
	}
}

func TestSSHJumpIdentitySeparatesCredentialFieldsContainingNull(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	phrase := "phrase\x00\x00"
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(phrase))
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := pem.EncodeToMemory(block)
	if err := validateSshPrivateKey(keyBytes, phrase); err != nil {
		t.Fatalf("key fixture is not a supported credential: %v", err)
	}
	password := "\x00" + string(keyBytes) + "\x00phrase"
	if _, err := normalizeCredentialDraft(credentialCreateRequest{Name: "Password", Protocol: "ssh", Username: "ops", Password: password}, false); err != nil {
		t.Fatalf("password fixture is not a supported credential: %v", err)
	}
	snapshot := tunnelConfigSnapshot{id: "jump", kind: 8, settings: json.RawMessage(`{"Mode":"connection"}`)}
	passwordTarget := sshTarget{host: "bastion.test", port: 22, username: "ops", credentialID: jumpCredentialID, password: password}
	keyTarget := passwordTarget
	keyTarget.password, keyTarget.privateKey, keyTarget.keyPassphrase = "", keyBytes, phrase
	for _, includeTrust := range []bool{false, true} {
		before := sshJumpSnapshotIdentity(snapshot, &passwordTarget, "", includeTrust)
		after := sshJumpSnapshotIdentity(snapshot, &keyTarget, "", includeTrust)
		if before == after {
			t.Fatal("distinct supported password and key credentials have the same pool identity")
		}
	}
}

type jumpRetainingWriter struct {
	writes [][]byte
	failAt int
}

func (w *jumpRetainingWriter) Write(raw []byte) (int, error) {
	w.writes = append(w.writes, raw)
	if len(w.writes) == w.failAt {
		return 0, io.ErrClosedPipe
	}
	return len(raw), nil
}

func TestSSHJumpPromptScrubsWrittenAnswersAtAllocationBoundaries(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		writer := &jumpRetainingWriter{failAt: failAt}
		ready, failures := make(chan string, 1), make(chan error, 1)
		ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "123", nil })
		readSSHJumpReady(ctx, bufio.NewReader(strings.NewReader("PROMPT {\"message\":\"OTP\"}\nREADY 1234\n")), writer, ready, failures)
		for _, written := range writer.writes {
			for _, value := range bytes.TrimSuffix(written, []byte{'\n'}) {
				if value != 0 {
					t.Fatal("a written authentication buffer retained the answer after use")
				}
			}
		}
		if failAt == 0 && (len(ready) != 1 || len(failures) != 0) {
			t.Fatal("valid answer did not complete readiness")
		}
		if failAt != 0 && (len(ready) != 0 || len(failures) != 1) {
			t.Fatal("answer or newline write failure did not abort authentication")
		}
	}
}

func TestSSHJumpBrokerIgnoresReleasedAndSupersededLeases(t *testing.T) {
	for _, voluntary := range []bool{false, true} {
		t.Run(fmt.Sprint(voluntary), func(t *testing.T) {
			process := newTestTunnelProcess()
			pool := newTunnelRuntimePool(nil)
			entry := &sharedTunnelEntry{key: "jump", refs: 2, process: process}
			pool.entries[entry.key] = entry
			lease := &tunnelRuntime{entry: entry, pool: pool, released: make(chan struct{})}
			defer pool.release(entry)
			defer lease.close()
			output := &synchronizedBuffer{}
			manager := newVncManager(nil, newBackendLineWriter(output))
			manager.tunnelLeases["dependent"] = lease
			var replacement *tunnelRuntime
			if voluntary {
				manager.releaseTunnel(backendCommand{ID: "release", SessionID: "dependent"})
				manager.cleanup.Wait()
			} else {
				replacement = &tunnelRuntime{}
				manager.tunnelLeases["dependent"] = replacement
				process.close()
			}
			done := make(chan struct{})
			go func() { manager.watchTunnelLease("dependent", lease); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("stale or released watcher did not stop")
			}
			if strings.Contains(output.String(), `"type":"tunnel.failed"`) || manager.tunnelLeases["dependent"] != replacement {
				t.Fatal("old lease emitted a failure or detached its replacement")
			}
		})
	}
}

func TestSSHJumpStaleEditorCannotRestoreOrReplaceManualTrust(t *testing.T) {
	for _, retrust := range []bool{false, true} {
		t.Run(fmt.Sprint(retrust), func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			raw, _ := json.Marshal(map[string]any{"Mode": "manual", "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
			details, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
			if err != nil {
				t.Fatal(err)
			}
			ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "accept", nil })
			payload, upstream, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID))
			clearBytes(payload)
			upstream.close()
			if err != nil {
				t.Fatal(err)
			}
			editor, err := readTunnel(path, tunnelReadRequest{ID: details.ID})
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(editor.Settings)
			if _, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: editor.Settings, ForgetJumpHostKeySha256: pin}); err != nil {
				t.Fatal(err)
			}
			expected := ""
			if retrust {
				_, _, expected = jumpTestServer(t)
				snapshot := jumpSnapshot(t, path, details.ID)
				target, err := resolveSSHJumpTarget(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if err := persistSSHJumpPin(context.Background(), snapshot, target, expected); err != nil {
					t.Fatal(err)
				}
				if _, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: editor.Settings, ForgetJumpHostKeySha256: pin}); err == nil {
					t.Fatal("an old reset request cleared newly approved trust")
				}
			}
			saved, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: "Renamed", Kind: 8, Settings: editor.Settings})
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(saved.Settings)
			var settings map[string]json.RawMessage
			_ = json.Unmarshal(saved.Settings, &settings)
			defer clearTunnelSettingsMap(settings)
			if actual := tunnelSettingString(settings, "HostKeySha256"); actual != expected {
				t.Fatal("saving an old editor replaced the current manual trust")
			}
		})
	}
}

func TestSSHJumpClientCannotSeedOrMoveManualTrust(t *testing.T) {
	path, _ := jumpFixture(t, "bastion.test", 22)
	manual := map[string]any{"Mode": "manual", "Host": "bastion.test", "Port": 22, "Username": "ops", "CredentialId": jumpCredentialID, "HostKeySha256": "SHA256:" + strings.Repeat("A", 43)}
	raw, _ := json.Marshal(manual)
	details, err := createTunnel(path, tunnelWriteRequest{Name: "Manual", Kind: 8, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(details.Settings)
	if bytes.Contains(details.Settings, []byte("HostKeySha256")) {
		t.Fatal("client settings seeded a pin without the backend confirmation flow")
	}
	snapshot := jumpSnapshot(t, path, details.ID)
	target, err := resolveSSHJumpTarget(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSSHJumpPin(context.Background(), snapshot, target, manual["HostKeySha256"].(string)); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "manual-backup.json")
	if _, err := exportBackup(path, backupRequest{Path: backupPath, Password: "backup-passphrase"}); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if _, err := importBackup(restored, backupRequest{Path: backupPath, Password: "backup-passphrase"}); err != nil {
		t.Fatal(err)
	}
	restoredDetails, err := readTunnel(restored, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(restoredDetails.Settings)
	if !bytes.Contains(restoredDetails.Settings, []byte(manual["HostKeySha256"].(string))) {
		t.Fatal("restoring an encrypted backup lost backend-approved manual trust")
	}
	manual["Host"] = "another-bastion.test"
	raw, _ = json.Marshal(manual)
	details, err = updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(details.Settings)
	if bytes.Contains(details.Settings, []byte("HostKeySha256")) {
		t.Fatal("changing the endpoint carried a previously trusted pin to another host")
	}
}
