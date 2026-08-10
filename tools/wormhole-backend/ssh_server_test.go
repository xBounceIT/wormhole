package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestEncryptedSSHKeyWithoutPassphraseReturnsStablePromptError(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "test key", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = dialNativeSSH(context.Background(), sshTarget{
		host: "127.0.0.1", port: 22, username: "alice", privateKey: pem.EncodeToMemory(block),
	}, 80, 24)
	if err == nil || err.Error() != "SSH private key passphrase is required" {
		t.Fatalf("encrypted key error = %v", err)
	}
}

func TestLoadSSHTargetKeepsExplicitSSHProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, Username, UpdatedAt) VALUES
    ('folder', NULL, 'RDP folder', 0, 1, 'rdp.example', 3389, NULL, 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, 0, 'ssh.example', 2222, 'operator', 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTarget(databasePath, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "ssh.example" || target.port != 2222 || target.username != "operator" {
		t.Fatalf("unexpected SSH target: %#v", target)
	}
}

func TestLoadSSHTargetRejectsMissingProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Username TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username)
VALUES ('leaf', NULL, 'Protocol-less leaf', 1, NULL, 'ssh.example', 'operator');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = loadSSHTarget(databasePath, "leaf")
	if err == nil || !strings.Contains(err.Error(), "no protocol") {
		t.Fatalf("expected missing-protocol error, got %v", err)
	}
}

func TestLoadSSHTargetUsesInheritedSSHDefaults(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, Username, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, 'ssh.example', 2200, 'operator', 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, NULL, NULL, NULL, NULL, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTarget(databasePath, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "ssh.example" || target.port != 2200 || target.username != "operator" {
		t.Fatalf("unexpected inherited SSH target: %#v", target)
	}
}

func TestLoadSSHTargetUsesInheritedAutoSudoAndHonorsLeafOverride(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    Username TEXT NULL,
    SshAutoSudo INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, Username, SshAutoSudo, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, 'ssh.example', 22, 'operator', 1, 'now'),
    ('inherited', 'folder', 'Inherited auto sudo', 1, NULL, NULL, NULL, NULL, NULL, 'now'),
    ('disabled', 'folder', 'Disabled auto sudo', 1, NULL, NULL, NULL, NULL, 0, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	inherited, err := loadSSHTarget(databasePath, "inherited")
	if err != nil {
		t.Fatal(err)
	}
	if !inherited.autoSudo {
		t.Fatal("expected auto sudo to inherit from the folder")
	}

	disabled, err := loadSSHTarget(databasePath, "disabled")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.autoSudo {
		t.Fatal("expected an explicit false auto-sudo value to override the folder")
	}
}

func TestLoadSSHTargetExplicitNoneKeepsInheritedUsername(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username, CredentialMode, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, 'ssh.example', 'operator', NULL, 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, 0, NULL, NULL, 1, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTarget(databasePath, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "operator" {
		t.Fatalf("explicit no-credential mode suppressed inherited username: %#v", target)
	}
}

func TestLoadSSHTargetMissingSavedCredentialKeepsInheritedUsername(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username, CredentialMode, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, 'ssh.example', 'operator', NULL, 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, 0, NULL, NULL, 2, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTarget(databasePath, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "operator" {
		t.Fatalf("missing saved credential suppressed inherited username: %#v", target)
	}
}

func TestLoadSSHTargetUnknownCredentialModeStopsSavedCredentialInheritance(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username, CredentialId, CredentialMode, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, 'ssh.example', 'operator', 'parent-credential', 2, 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, 0, NULL, NULL, NULL, 99, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTarget(databasePath, "leaf")
	if err != nil {
		t.Fatalf("unknown credential mode inherited the parent credential: %v", err)
	}
	if target.username != "operator" || target.password != "" {
		t.Fatalf("unexpected SSH target: %#v", target)
	}
}

func TestLoadSSHTargetAcceptsTransientVirtualBitwardenCredential(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := bitwardenVirtualCredentialID("item-1", 0)
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, Name, Kind, Protocol, Host, CredentialId, CredentialMode, UpdatedAt)
VALUES ('leaf', 'SSH leaf', 1, 0, 'ssh.example', ?, 2, 'now');`, credentialID)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTargetWithOverrides(
		databasePath,
		"leaf",
		"vault-user",
		"vault-password",
		true,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "vault-user" || target.password != "vault-password" {
		t.Fatalf("virtual Bitwarden target = %#v", target)
	}
}

func TestExplicitSSHCredentialOverrideUsesSelectedIdentity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := "10000000-0000-4000-8000-000000000001"
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL, ParentId TEXT NULL, Name TEXT NOT NULL, Kind INTEGER NOT NULL,
    Protocol INTEGER NULL, Host TEXT NULL, Username TEXT NULL, CredentialId TEXT NULL,
    CredentialMode INTEGER NULL, UpdatedAt TEXT NOT NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL, Username TEXT NULL, Kind INTEGER NULL,
    Protocol INTEGER NULL, SecretProvider INTEGER NULL
);
INSERT INTO Nodes (Id, Name, Kind, Protocol, Host, Username, CredentialMode, UpdatedAt)
VALUES ('leaf', 'SSH leaf', 1, 0, 'ssh.example', 'connection-user', 0, 'now');
INSERT INTO CredentialProfiles (Id, Username, Kind, Protocol, SecretProvider)
VALUES (?, 'selected-user', 0, 0, 1);`, credentialID)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTargetWithCredentialOverrides(
		databasePath, "leaf", "selected-user", "selected-password", true, true, credentialID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "selected-user" || target.password != "selected-password" {
		t.Fatalf("selected SSH identity = %#v", target)
	}
}

func TestLoadSSHTargetKeepsExplicitUsernameOverBitwardenUsername(t *testing.T) {
	target := sshTarget{username: "connection-user"}
	if !applySSHCredentialOverride(&target, "vault-user", "vault-password", true, false) {
		t.Fatal("valid Bitwarden override was rejected")
	}
	if target.username != "connection-user" || target.password != "vault-password" {
		t.Fatalf("resolved SSH identity = %#v", target)
	}
}

func TestLoadSSHTargetAcceptsAuthoritativeManualUsernameAndEmptyPasswordOverride(t *testing.T) {
	target := sshTarget{username: "connection-user", password: "saved-password"}
	if !applySSHCredentialOverride(&target, "manual-user", "", true, true) {
		t.Fatal("explicit empty SSH password override was rejected")
	}
	if target.username != "manual-user" || target.password != "" {
		t.Fatalf("resolved SSH identity = %#v", target)
	}
}

func TestLoadSSHTargetAppliesManualCredentialsWithoutSavedBinding(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username, CredentialId, CredentialMode)
VALUES ('leaf', NULL, 'SSH leaf', 1, 0, 'ssh.example', NULL, NULL, 1);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	target, err := loadSSHTargetWithOverrides(
		databasePath,
		"leaf",
		"manual-user",
		"manual-password",
		true,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "manual-user" || target.password != "manual-password" {
		t.Fatalf("manual SSH target = %#v", target)
	}
}

func TestLoadSSHTargetRejectsInheritedVPNWithoutConfiguration(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    Username TEXT NULL,
    TunnelEnabled INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Username, TunnelEnabled, UpdatedAt) VALUES
    ('folder', NULL, 'VPN defaults', 0, 0, 'ssh.example', 'operator', 1, 'now'),
    ('leaf', 'folder', 'SSH leaf', 1, 0, NULL, NULL, NULL, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = loadSSHTarget(databasePath, "leaf")
	if err == nil || !strings.Contains(err.Error(), "VPN tunnel") {
		t.Fatalf("expected tunneled SSH connection to be rejected, got %v", err)
	}
}

func TestResolveDirectSSHTargetUsesTemporaryCredentialsAndDefaultsPort(t *testing.T) {
	const tunnelID = "11111111-2222-4333-8444-555555555555"
	target, err := resolveDirectSSHTarget(sshWireCommand{
		Host:           " [2001:db8::10] ",
		Username:       " operator ",
		Password:       "temporary-secret",
		TunnelConfigID: tunnelID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.nodeID != "" || target.host != "[2001:db8::10]" || target.port != 22 {
		t.Fatalf("unexpected direct SSH target: %#v", target)
	}
	if target.username != "operator" || target.password != "temporary-secret" {
		t.Fatalf("temporary SSH credential was not preserved: %#v", target)
	}
	if target.tunnelConfigID != tunnelID {
		t.Fatalf("unexpected direct SSH tunnel: %q", target.tunnelConfigID)
	}
}

func TestResolveDirectSSHTargetDefersIdentityToSelectedCredential(t *testing.T) {
	target, err := resolveDirectSSHTarget(sshWireCommand{
		Host: "ssh.example", CredentialID: "11111111-2222-4333-8444-555555555555", AutoSudo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.username != "" || !target.autoSudo {
		t.Fatalf("selected credential target was resolved prematurely: %#v", target)
	}
}

func TestResolveDirectSSHTargetRejectsInvalidTunnelAndBounds(t *testing.T) {
	_, err := resolveDirectSSHTarget(sshWireCommand{
		Host: "ssh.example", Username: "operator", Password: "secret",
		Port: 65536, TunnelConfigID: "not-a-tunnel",
	})
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected invalid port to be rejected, got %v", err)
	}
	_, err = resolveDirectSSHTarget(sshWireCommand{
		Host: "ssh.example", Username: "operator", Password: "secret",
		TunnelConfigID: "not-a-tunnel",
	})
	if err == nil || !strings.Contains(err.Error(), "tunnel") {
		t.Fatalf("expected invalid tunnel to be rejected, got %v", err)
	}
}

func TestNormalizeTerminalSizeAppliesSafeDefaultsAndBounds(t *testing.T) {
	columns, rows := normalizeTerminalSize(0, 1000)
	if columns != 80 || rows != sshMaxRows {
		t.Fatalf("unexpected terminal size: %d x %d", columns, rows)
	}
	columns, rows = normalizeTerminalSize(1200, 0)
	if columns != sshMaxColumns || rows != 24 {
		t.Fatalf("unexpected terminal size: %d x %d", columns, rows)
	}
}

func TestSSHAddressNormalizesBracketedIPv6Host(t *testing.T) {
	if got := normalizeSSHHost(" [2001:db8::10] "); got != "2001:db8::10" {
		t.Fatalf("unexpected normalized IPv6 host: %q", got)
	}
}

type blockingSSHInput struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

type recordingSSHInput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (input *recordingSSHInput) Write(data []byte) (int, error) {
	input.mu.Lock()
	defer input.mu.Unlock()
	return input.buffer.Write(data)
}

func (input *recordingSSHInput) Close() error { return nil }

func (input *recordingSSHInput) String() string {
	input.mu.Lock()
	defer input.mu.Unlock()
	return input.buffer.String()
}

func requireAutoSudoCommand(t *testing.T, value string) {
	t.Helper()
	if value != "sudo su\r" {
		t.Fatalf("auto sudo sent unexpected initial input: %q", value)
	}
}

func TestSSHAutoSudoDriverSendsPasswordOnlyAfterPrompt(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}

	driver.observe([]byte("operator@host:~$ "))
	initial := input.String()
	requireAutoSudoCommand(t, initial)

	// The PTY echoes the command. That echo is not the prompt and must not release the saved
	// password.
	driver.observe([]byte(initial))
	if got := input.String(); got != initial {
		t.Fatalf("auto sudo answered on its command echo: %q", got)
	}

	driver.observe([]byte("[sudo] password for operator: "))
	if got := input.String(); got != initial+"secret\r" {
		t.Fatalf("auto sudo sent password before the prompt: %q", got)
	}
	driver.dispose()
}

func TestSSHAutoSudoDriverStartsWithoutShellOutput(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	native.autoSudo = driver
	defer driver.dispose()

	driver.start()
	initial := input.String()
	requireAutoSudoCommand(t, initial)

	if err := native.write([]byte("whoami\r")); err != nil {
		t.Fatalf("buffering terminal input failed: %v", err)
	}
	if got := input.String(); got != initial {
		t.Fatalf("user input reached sudo before its password prompt: %q", got)
	}

	driver.observe([]byte("[sudo] password for operator: "))
	if got := input.String(); got != initial+"secret\r"+"whoami\r" {
		t.Fatalf("expected password before buffered user input, got %q", got)
	}
}

func TestSSHAutoSudoDriverUsesNonInteractiveSudoWithoutLoginPassword(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for an SSH key credential")
	}
	native.autoSudo = driver
	defer driver.dispose()

	if err := native.write([]byte("whoami\r")); err != nil {
		t.Fatalf("buffering terminal input failed: %v", err)
	}
	driver.start()
	if got := input.String(); got != "sudo -n su\rwhoami\r" {
		t.Fatalf("passwordless auto sudo input = %q", got)
	}
}

func TestSSHAutoSudoDriverStartIsIdempotent(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	defer driver.dispose()

	driver.start()
	initial := input.String()
	driver.start()
	driver.observe([]byte("operator@host:~$ "))
	if got := input.String(); got != initial {
		t.Fatalf("auto sudo start sent duplicate commands: %q", got)
	}
}

func TestSSHAutoSudoDriverBuffersUserInputUntilPrompt(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	native.autoSudo = driver
	defer driver.dispose()

	driver.observe([]byte("shell ready"))
	initial := input.String()
	if err := native.write([]byte("ls\r")); err != nil {
		t.Fatalf("buffering terminal input failed: %v", err)
	}
	if got := input.String(); got != initial {
		t.Fatalf("user input reached sudo before its password prompt: %q", got)
	}

	driver.observe([]byte("[sudo] password for operator: "))
	if got := input.String(); got != initial+"secret\r"+"ls\r" {
		t.Fatalf("expected password before buffered user input, got %q", got)
	}
}

func TestSSHAutoSudoDriverFlushesBufferedInputWhenCancelled(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	native.autoSudo = driver

	driver.observe([]byte("shell ready"))
	initial := input.String()
	if err := native.write([]byte("pwd\r")); err != nil {
		t.Fatalf("buffering terminal input failed: %v", err)
	}
	driver.dispose()
	if got := input.String(); got != initial+"pwd\r" {
		t.Fatalf("expected buffered input after cancellation without a password, got %q", got)
	}
}

func TestSSHAutoSudoDriverDoesNotSendPasswordAfterTimeout(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	defer driver.dispose()

	driver.observe([]byte("shell ready"))
	driver.onTimeout()
	driver.observe([]byte("[sudo] password for operator: "))
	requireAutoSudoCommand(t, input.String())
}

func TestSSHAutoSudoDriverClearsPasswordWhenCancelled(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}

	driver.observe([]byte("shell ready"))
	driver.dispose()
	driver.observe([]byte("[sudo] password for operator: "))
	requireAutoSudoCommand(t, input.String())
}

func TestSSHAutoSudoDriverHandlesPasswordPromptSplitAcrossChunks(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	defer driver.dispose()

	driver.observe([]byte("shell ready"))
	prompt := "[sudo] password for operator: "
	driver.observe([]byte(prompt[:len(prompt)-2]))
	requireAutoSudoCommand(t, input.String())
	driver.observe([]byte(prompt[len(prompt)-2:]))
	if got := input.String(); got != "sudo su\rsecret\r" {
		t.Fatalf("auto sudo did not answer a split password prompt: %q", got)
	}
}

func TestSSHAutoSudoDriverIgnoresUnrelatedPasswordText(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	defer driver.dispose()

	driver.observe([]byte("shell ready"))
	driver.observe([]byte("login password: \r\n"))
	driver.observe([]byte("sudo password: "))
	requireAutoSudoCommand(t, input.String())
}

func TestSSHAutoSudoDriverAcceptsLocalizedSudoPrompt(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input}
	driver := newSSHAutoSudoDriver(native, "secret")
	if driver == nil {
		t.Fatal("expected auto-sudo driver for a non-empty password")
	}
	defer driver.dispose()

	driver.observe([]byte("shell ready"))
	driver.observe([]byte("[sudo] password di operator: "))
	if got := input.String(); got != "sudo su\rsecret\r" {
		t.Fatalf("auto sudo did not answer the localized sudo prompt: %q", got)
	}
}

func TestSSHAutoSudoDriverRejectsLineBreakingPasswords(t *testing.T) {
	native := &sshNativeSession{stdin: &recordingSSHInput{}}
	if driver := newSSHAutoSudoDriver(native, "secret\nnot-a-password"); driver != nil {
		driver.dispose()
		t.Fatal("auto sudo accepted a password that could inject a shell line")
	}
}

func TestNormalizeSftpPathRejectsUnsafeInput(t *testing.T) {
	if got, err := normalizeSftpPath("/home/operator/../tmp"); err != nil || got != "/home/tmp" {
		t.Fatalf("unexpected normalized SFTP path: %q, %v", got, err)
	}
	for _, path := range []string{"relative", `\\server\share`, `/tmp\file`, "/tmp/" + "\x00"} {
		if _, err := normalizeSftpPath(path); err == nil {
			t.Fatalf("unsafe SFTP path was accepted: %q", path)
		}
	}
	if _, err := normalizeSftpPath(strings.Repeat("a", sshSftpMaxPathBytes+1)); err == nil {
		t.Fatal("overlong SFTP path was accepted")
	}
	if !isSafeSftpName("report:2026.txt") {
		t.Fatal("remote filename containing a colon was rejected")
	}
	if isSafeSftpName(`report\2026.txt`) {
		t.Fatal("remote filename containing a backslash was accepted")
	}
}

func TestLocalSftpNamesFollowHostFilesystemRules(t *testing.T) {
	wantPunctuation := runtime.GOOS != "windows"
	for _, name := range []string{"report:2026.txt", `report\2026.txt`} {
		if got := isSafeLocalSftpName(name); got != wantPunctuation {
			t.Fatalf("isSafeLocalSftpName(%q) = %v, want %v on %s", name, got, wantPunctuation, runtime.GOOS)
		}
	}
	for _, name := range []string{"", ".", "..", "nested/file", "bad\x00name"} {
		if isSafeLocalSftpName(name) {
			t.Fatalf("unsafe local SFTP name was accepted: %q", name)
		}
	}
	if !isSafeTransferName("local-to-remote", "report:2026.txt") {
		t.Fatal("valid remote destination name was rejected")
	}
	if isSafeTransferName("local-to-remote", `report\2026.txt`) {
		t.Fatal("unsupported remote destination backslash was accepted")
	}
}

func TestLocalSftpListingPreservesPosixPunctuation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filenames are not supported by the Windows test filesystem")
	}
	root := t.TempDir()
	names := []string{"report:2026.txt", `report\2026.txt`}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(root, name), []byte("report"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, _, err := readLocalDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool, len(entries))
	for _, entry := range entries {
		listed[entry.Name] = true
	}
	for _, name := range names {
		if !listed[name] {
			t.Fatalf("host-valid local filename was omitted: %q", name)
		}
	}
}

func TestSftpOperationsRejectFilesystemRoots(t *testing.T) {
	for _, operation := range []string{"delete", "rename"} {
		local := sshSftpOperationRootCommand("local", operation, filepath.VolumeName(t.TempDir())+string(filepath.Separator))
		if err := (&sshNativeSession{}).runSftpOperation(local); err == nil {
			t.Fatalf("local root %s was accepted", operation)
		}

		remote := sshSftpOperationRootCommand("remote", operation, "/")
		if err := (&sshNativeSession{}).runSftpOperation(remote); err == nil {
			t.Fatalf("remote root %s was accepted", operation)
		}
	}

	localRename := sshWireCommand{
		Pane:            "local",
		Operation:       "rename",
		Path:            filepath.Join(t.TempDir(), "report.txt"),
		DestinationPath: filepath.VolumeName(t.TempDir()) + string(filepath.Separator),
	}
	if err := (&sshNativeSession{}).runSftpOperation(localRename); err == nil {
		t.Fatal("local rename to the filesystem root was accepted")
	}

	remoteRename := sshWireCommand{
		Pane:            "remote",
		Operation:       "rename",
		Path:            "/home/operator/report.txt",
		DestinationPath: "/",
	}
	if err := (&sshNativeSession{}).runSftpOperation(remoteRename); err == nil {
		t.Fatal("remote rename to the filesystem root was accepted")
	}
}

func sshSftpOperationRootCommand(pane, operation, path string) sshWireCommand {
	return sshWireCommand{
		Pane:      pane,
		Operation: operation,
		Path:      path,
	}
}

func TestSftpReadyEventKeepsEmptyDirectoryFieldsOnTheWire(t *testing.T) {
	event, err := json.Marshal(sshWireEvent{
		Type:      "sftp.ready",
		SessionID: "session",
		Path:      "/home/operator",
		Entries:   []sshSftpEntry{},
		Truncated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(event)
	if !strings.Contains(encoded, `"entries":[]`) || !strings.Contains(encoded, `"truncated":false`) {
		t.Fatalf("SFTP ready event omitted empty-directory fields: %s", encoded)
	}
}

func TestReadLocalDirectoryCapsNativeEnumeration(t *testing.T) {
	directory := t.TempDir()
	for index := 0; index <= sshSftpMaxEntryCount; index++ {
		path := filepath.Join(directory, fmt.Sprintf("entry-%04d", index))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries, truncated, err := readLocalDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(entries) != sshSftpMaxEntryCount {
		t.Fatalf("bounded local listing returned %d entries, truncated=%v", len(entries), truncated)
	}
}

func TestSftpTransferBatchTerminalEventHasNoStaleItem(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}}
	command := sshWireCommand{
		SessionID:  "session",
		TransferID: "transfer",
		Direction:  "local-to-remote",
	}

	server.writeTransferBatchTerminal(command, "batch-completed")
	server.writeTransferBatchTerminal(command, "batch-cancelled")

	decoder := json.NewDecoder(&output)
	for _, expectedState := range []string{"batch-completed", "batch-cancelled"} {
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "sftp.transfer" || event.SessionID != command.SessionID ||
			event.TransferID != command.TransferID || event.Direction != command.Direction ||
			event.TransferState != expectedState || event.ItemID != "" || event.DisplayName != "" {
			t.Fatalf("unexpected terminal transfer event: %#v", event)
		}
	}
}

func TestSftpTransferItemIDsStayBoundedAndScoped(t *testing.T) {
	if got := sftpTransferItemID(0); got != "item-0" {
		t.Fatalf("unexpected first transfer item id: %q", got)
	}
	if got := sftpTransferItemID(4095); len(got) > 128 {
		t.Fatalf("transfer item id exceeded the renderer limit: %q", got)
	}
}

func TestServeSSHDispatchesInvalidAndDisconnectedCommands(t *testing.T) {
	commands := []sshWireCommand{
		{Type: "input", SessionID: ""},
		{Type: "unsupported", SessionID: "session"},
		{Type: "input", SessionID: "session", Data: "%%%"},
		{Type: "input", SessionID: "session", Data: "YQ=="},
		{Type: "resize", SessionID: "session", Columns: 80, Rows: 24},
		{Type: "snapshot", SessionID: "session"},
		{Type: "sftp-open", SessionID: "session", RequestID: "open"},
		{Type: "sftp-list", SessionID: "session", RequestID: "list", Path: "/"},
		{Type: "sftp-local-list", SessionID: "session", RequestID: "local", Path: t.TempDir()},
		{Type: "sftp-operation", SessionID: "session", RequestID: "operation", Pane: "local", Operation: "delete", Path: filepath.Join(t.TempDir(), "missing")},
		{Type: "sftp-transfer", SessionID: "session", TransferID: "transfer", Direction: "remote-to-local", DestinationPath: t.TempDir(), Items: []sshSftpTransferItem{{SourcePath: "/file", Name: "file"}}},
		{Type: "sftp-transfer-decision", SessionID: "session", TransferID: "missing", ItemID: "item", Decision: "skip"},
		{Type: "sftp-transfer-cancel", SessionID: "session", TransferID: "missing", ItemID: "item"},
		{Type: "sftp-close", SessionID: "session"},
		{Type: "auto-sudo-cancel", SessionID: "session"},
		{Type: "app-lock", SessionID: "session"},
		{Type: "close", SessionID: "session"},
		{Type: "open", SessionID: "session"},
	}
	var input strings.Builder
	input.WriteString("{\n")
	for _, command := range commands {
		encoded, err := json.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		input.Write(encoded)
		input.WriteByte('\n')
	}
	var output synchronizedBuffer
	if err := serveSSH("", strings.NewReader(input.String()), &output, "userdata"); err != nil {
		t.Fatalf("serveSSH returned %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	events := 0
	for {
		var event sshWireEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events++
	}
	if events < 10 {
		t.Fatalf("serveSSH emitted only %d events: %s", events, output.String())
	}
}

func TestSSHServerOpensFakeNativeSessionAndDispatchesConnectedCommands(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:     &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:   make(map[string]*sshNativeSession),
		pending:    make(map[string]context.CancelFunc),
		lifecycles: make(map[string]*sshReconnectState),
		transfers:  make(map[string]*sshSftpTransfer),
	}
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		inputQueue:       make(chan []byte, sshInputQueueCapacity),
		done:             make(chan struct{}),
		started:          true,
	}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		return native, sshTarget{host: "127.0.0.1", port: 22, username: "alice", title: "Test", knownHostFingerprint: "SHA256:test"}, nil
	}
	server.handle(sshWireCommand{Type: "open", SessionID: "session", Host: "127.0.0.1", Port: 22, Username: "alice", Password: "secret"})
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		connected := server.sessions["session"] == native
		server.mu.Unlock()
		if connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake SSH session did not connect: %s", output.String())
		}
		time.Sleep(time.Millisecond)
	}
	if !server.isActive(native) || server.session("session") != native {
		t.Fatal("connected SSH session was not active")
	}
	server.handle(sshWireCommand{Type: "input", SessionID: "session", Data: "aGVsbG8="})
	if len(native.inputQueue) != 1 {
		t.Fatalf("input queue length = %d", len(native.inputQueue))
	}
	server.handle(sshWireCommand{Type: "snapshot", SessionID: "session"})
	server.handle(sshWireCommand{Type: "auto-sudo-cancel", SessionID: "session"})
	server.handle(sshWireCommand{Type: "close", SessionID: "session"})
	if !native.isClosed() || server.session("session") != nil {
		t.Fatal("SSH close did not close and remove the native session")
	}
	if !strings.Contains(output.String(), `"type":"connected"`) || !strings.Contains(output.String(), `"type":"screen"`) || !strings.Contains(output.String(), `"type":"closed"`) {
		t.Fatalf("expected lifecycle events were not emitted: %s", output.String())
	}
}

func TestSSHServerReportsInitialHostKeyMismatch(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:     &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:   make(map[string]*sshNativeSession),
		pending:    make(map[string]context.CancelFunc),
		lifecycles: make(map[string]*sshReconnectState),
		transfers:  make(map[string]*sshSftpTransfer),
	}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		return nil, sshTarget{}, &sshHostKeyMismatchError{expected: "old", received: "new"}
	}
	server.open(sshWireCommand{Type: "open", SessionID: "session", Host: "127.0.0.1", Port: 22, Username: "alice", Password: "secret"})
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), `"type":"error"`) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var event sshWireEvent
	if err := json.NewDecoder(bytes.NewReader(output.Bytes())).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.HostKeyExpected != "old" || event.HostKeyReceived != "new" {
		t.Fatalf("mismatch event = %#v", event)
	}
}

func TestSSHServerRejectsDuplicateOpenStates(t *testing.T) {
	for name, configure := range map[string]func(*sshServer){
		"session": func(server *sshServer) { server.sessions["session"] = &sshNativeSession{} },
		"pending": func(server *sshServer) { server.pending["session"] = func() {} },
		"lifecycle": func(server *sshServer) {
			server.lifecycles["session"] = &sshReconnectState{command: sshWireCommand{SessionID: "session"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var output synchronizedBuffer
			server := &sshServer{
				output:     &sshEventWriter{encoder: json.NewEncoder(&output)},
				sessions:   make(map[string]*sshNativeSession),
				pending:    make(map[string]context.CancelFunc),
				lifecycles: make(map[string]*sshReconnectState),
				transfers:  make(map[string]*sshSftpTransfer),
			}
			configure(server)
			server.open(sshWireCommand{SessionID: "session", Host: "127.0.0.1", Port: 22, Username: "alice", Password: "secret"})
			if !strings.Contains(output.String(), `"type":"error"`) {
				t.Fatalf("duplicate %s state was accepted", name)
			}
		})
	}
}

func TestSftpTransferCancelsOnlySelectedItem(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	transfer := &sshSftpTransfer{
		itemCancels:    make(map[string]context.CancelFunc),
		cancelledItems: make(map[string]struct{}),
	}
	first := transfer.startItem(parent, "item-0")
	second := transfer.startItem(parent, "item-1")
	transfer.cancelItem("item-0")

	if !errors.Is(first.Err(), context.Canceled) {
		t.Fatalf("selected item was not cancelled: %v", first.Err())
	}
	if second.Err() != nil {
		t.Fatalf("cancelling one item cancelled another: %v", second.Err())
	}
	transfer.finishItem("item-0")
	transfer.finishItem("item-1")
}

type syntheticSftpFileInfo struct {
	mode os.FileMode
}

func (info syntheticSftpFileInfo) Name() string       { return "entry" }
func (info syntheticSftpFileInfo) Size() int64        { return 0 }
func (info syntheticSftpFileInfo) Mode() os.FileMode  { return info.mode }
func (info syntheticSftpFileInfo) ModTime() time.Time { return time.Time{} }
func (info syntheticSftpFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info syntheticSftpFileInfo) Sys() any           { return nil }

func TestSftpTransferDirectoryDetectionDoesNotFollowSymlinks(t *testing.T) {
	if !isSftpTransferDirectory(syntheticSftpFileInfo{mode: os.ModeDir}) {
		t.Fatal("directory metadata was not recognized")
	}
	if isSftpTransferDirectory(syntheticSftpFileInfo{mode: os.ModeDir | os.ModeSymlink}) {
		t.Fatal("symlink directory metadata was treated as a traversable directory")
	}
}

func TestSftpTransferDecisionIsScopedToItsConflict(t *testing.T) {
	decisions := make(chan sshSftpTransferDecision, 2)
	decisions <- sshSftpTransferDecision{itemID: "item-0", decision: "skip"}
	decisions <- sshSftpTransferDecision{itemID: "item-1", decision: "overwrite"}

	decision, err := awaitSftpTransferDecision(context.Background(), decisions, "item-1")
	if err != nil {
		t.Fatal(err)
	}
	if decision.itemID != "item-1" || decision.decision != "overwrite" {
		t.Fatalf("unexpected conflict decision: %#v", decision)
	}
}

func TestSftpRequestErrorEventCarriesRequestID(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}}
	server.writeSftpRequestError("session", "remote-7", "directory failed", "/home/operator")

	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "sftp.error" || event.RequestID != "remote-7" || event.Path != "/home/operator" {
		t.Fatalf("unexpected request-scoped SFTP error: %#v", event)
	}
}

func TestSftpOpenStateErrorsCarryRequestID(t *testing.T) {
	for name, native := range map[string]*sshNativeSession{
		"closed":  {id: "session", closed: true},
		"opening": {id: "session", sftpOpening: true},
	} {
		var output synchronizedBuffer
		server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}}
		native.server = server
		native.startSftpOpen("open-7")

		var event sshWireEvent
		if err := json.NewDecoder(&output).Decode(&event); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if event.Type != "sftp.error" || event.RequestID != "open-7" {
			t.Fatalf("%s: unexpected request-scoped open error: %#v", name, event)
		}
	}
}

func TestSftpLocalListWithoutSessionEmitsRequestScopedError(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
	}
	server.sftpLocalList(sshWireCommand{
		SessionID: "session",
		RequestID: "local-7",
		Path:      "",
	})

	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "sftp.local.error" || event.RequestID != "local-7" || event.Pane != "local" {
		t.Fatalf("unexpected missing-session local-list event: %#v", event)
	}
}

func TestSftpOperationWithoutSessionEmitsRequestScopedError(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
	}
	server.sftpOperation(sshWireCommand{
		SessionID: "session",
		RequestID: "operation-7",
		Pane:      "local",
		Operation: "delete",
		Path:      filepath.Join(t.TempDir(), "report.txt"),
	})

	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "sftp.operation" || event.RequestID != "operation-7" || event.Error == "" {
		t.Fatalf("unexpected missing-session operation event: %#v", event)
	}
}

func TestBuildLocalQuickPathsHasSafeShape(t *testing.T) {
	paths := buildLocalQuickPaths()
	if len(paths) == 0 {
		t.Fatal("expected at least the local home quick path")
	}

	seen := make(map[string]struct{})
	separators := 0
	for _, path := range paths {
		if path.Separator {
			separators++
			if path.DisplayName != "" || path.Path != "" {
				t.Fatalf("separator carried path data: %#v", path)
			}
			continue
		}
		if path.DisplayName == "" || path.Path == "" || !filepath.IsAbs(path.Path) {
			t.Fatalf("unsafe quick path: %#v", path)
		}
		key := strings.ToLower(filepath.Clean(path.Path))
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate quick path: %#v", path)
		}
		seen[key] = struct{}{}
	}
	if separators > 1 {
		t.Fatalf("expected at most one quick-path separator, got %d", separators)
	}
}

func TestBuildLocalQuickPathsFiltersUnreadyDrive(t *testing.T) {
	volume := filepath.VolumeName(t.TempDir())
	if volume == "" {
		t.Skip("drive-root quick paths are Windows-specific")
	}
	driveRoot := volume + string(filepath.Separator)
	folder := t.TempDir()
	paths := buildLocalQuickPathsFromCandidates(
		[]localQuickPathCandidate{{DisplayName: "Home", Path: folder, ProbeExists: true}},
		[]localQuickPathCandidate{{Path: driveRoot, ProbeExists: true}},
		func(path string) bool { return path == folder },
	)
	for _, path := range paths {
		if path.Path == driveRoot {
			t.Fatalf("unready drive was exposed as a quick path: %#v", path)
		}
	}
}

func TestLocalQuickPathCacheBuildsOnlyOnce(t *testing.T) {
	calls := 0
	cache := localQuickPathCache{
		build: func() []sshSftpQuickPath {
			calls++
			return []sshSftpQuickPath{{DisplayName: "Home", Path: t.TempDir()}}
		},
	}

	first := cache.get()
	second := cache.get()
	if calls != 1 {
		t.Fatalf("quick paths built %d times, want once", calls)
	}
	if len(first) != 1 || len(second) != 1 || first[0] != second[0] {
		t.Fatalf("cached quick paths changed: first=%#v second=%#v", first, second)
	}
}

func TestSftpLocalListingUsesQuickPathCache(t *testing.T) {
	var callsMu sync.Mutex
	calls := 0
	server := &sshServer{
		output: &sshEventWriter{encoder: json.NewEncoder(io.Discard)},
		localQuickPaths: localQuickPathCache{
			build: func() []sshSftpQuickPath {
				callsMu.Lock()
				defer callsMu.Unlock()
				calls++
				return nil
			},
		},
	}
	native := &sshNativeSession{id: "session", server: server}
	native.startLocalList(t.TempDir(), "local-1")

	deadline := time.Now().Add(time.Second)
	for {
		callsMu.Lock()
		observed := calls
		callsMu.Unlock()
		if observed > 0 {
			if observed != 1 {
				t.Fatalf("quick paths built %d times, want once", observed)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("local SFTP listing did not use the quick-path cache")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSftpTransferWithoutSessionEmitsBatchFailure(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
	}
	server.sftpTransfer(sshWireCommand{
		SessionID:       "session",
		TransferID:      "transfer",
		Direction:       "remote-to-local",
		DestinationPath: filepath.Join(t.TempDir(), "destination"),
		Items: []sshSftpTransferItem{{
			SourcePath: "/home/operator/report.txt",
			Name:       "report.txt",
		}},
	})

	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "sftp.transfer" || event.TransferID != "transfer" || event.TransferState != "batch-failed" {
		t.Fatalf("unexpected missing-session transfer event: %#v", event)
	}
}

func TestSftpTransferValidationSeparatesLocalAndRemotePaths(t *testing.T) {
	localRoot := t.TempDir()
	localFile := filepath.Join(localRoot, "report.txt")
	command := sshWireCommand{
		TransferID:      "transfer-1",
		Direction:       "local-to-remote",
		DestinationPath: "/home/operator",
		Items: []sshSftpTransferItem{{
			SourcePath:  localFile,
			Name:        "report.txt",
			IsDirectory: false,
			Size:        12,
		}},
	}
	if err := validateSftpTransferCommand(command); err != nil {
		t.Fatalf("valid local-to-remote transfer was rejected: %v", err)
	}
	command.Direction = "remote-to-local"
	command.Items[0].SourcePath = "/home/operator/report.txt"
	command.DestinationPath = localRoot
	if err := validateSftpTransferCommand(command); err != nil {
		t.Fatalf("valid remote-to-local transfer was rejected: %v", err)
	}
	command.Items[0].Name = "bad:name.txt"
	if err := validateSftpTransferCommand(command); err == nil {
		t.Fatal("unsafe transfer name was accepted")
	}
}

func TestAppendLocalTransferPlansPreservesEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "report.txt"), []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}

	plans := make([]sshSftpTransferPlan, 0)
	err := appendLocalTransferPlans("local-to-local", filepath.Join(root, "destination"), sshSftpTransferItem{
		SourcePath:  source,
		Name:        "source",
		IsDirectory: true,
	}, &plans, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 3 {
		t.Fatalf("expected root, empty directory, and file plans, got %d: %#v", len(plans), plans)
	}
	if !plans[1].isDirectory || plans[2].isDirectory {
		t.Fatalf("unexpected transfer plan ordering or directory metadata: %#v", plans)
	}
}

func TestAppendLocalTransferPlansRejectsFolderIntoItself(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	child := filepath.Join(source, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, destination := range []string{source, child} {
		plans := make([]sshSftpTransferPlan, 0)
		err := appendLocalTransferPlans("local-to-local", destination, sshSftpTransferItem{
			SourcePath:  source,
			Name:        "source",
			IsDirectory: true,
		}, &plans, context.Background())
		if err == nil || !strings.Contains(err.Error(), "copy a folder into itself") {
			t.Fatalf("expected self-copy rejection for %q, got %v", destination, err)
		}
	}
}

func TestLocalSftpSelfCopyGuardUsesFilesystemCaseSemantics(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "Project")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	alternateCase := filepath.Join(root, "project")
	target := filepath.Join(alternateCase, "Project")

	_, statErr := os.Stat(alternateCase)
	caseInsensitive := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		t.Fatal(statErr)
	}
	if got := sameLocalPath(source, alternateCase); got != caseInsensitive {
		t.Fatalf("sameLocalPath() = %v on case-insensitive=%v filesystem", got, caseInsensitive)
	}
	if got := localPathContains(source, filepath.Join(alternateCase, "nested")); got != caseInsensitive {
		t.Fatalf("localPathContains() = %v on case-insensitive=%v filesystem", got, caseInsensitive)
	}
	err := validateLocalTransferDestination(source, alternateCase, target, true)
	if caseInsensitive && (err == nil || !strings.Contains(err.Error(), "copy a folder into itself")) {
		t.Fatalf("case-insensitive self-copy was not rejected: %v", err)
	}
	if !caseInsensitive && err != nil {
		t.Fatalf("case-sensitive paths were treated as equivalent: %v", err)
	}
}

func TestLocalTransferRejectsSymlinkedDestinationParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(outside, linked); err != nil {
		t.Skipf("symbolic links are unavailable in this environment: %v", err)
	}

	if err := validateLocalTransferDestinationParents(filepath.Join(linked, "nested", "report.txt")); err == nil {
		t.Fatal("symlinked destination parent was accepted")
	}
}

func TestLocalTransferDestinationRejectsFilesystemAliasIntoSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "source-alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Skipf("symbolic links are unavailable in this environment: %v", err)
	}
	destination := filepath.Join(alias, "nested")
	target := filepath.Join(destination, filepath.Base(source))
	if err := validateLocalTransferDestination(source, destination, target, true); err == nil {
		t.Fatal("filesystem alias allowed a local folder copy back into its own source")
	}
}

func TestLocalTransferDoesNotTruncateItsOwnSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("preserve me"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := copyTransferFile(context.Background(), nil, "local-to-local", sshSftpTransferPlan{
		sourcePath:      source,
		destinationPath: source,
		incomingSize:    11,
		displayName:     "source.txt",
	}, func(int64) {})
	if err == nil {
		t.Fatal("same-file local transfer was accepted")
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "preserve me" {
		t.Fatalf("same-file transfer changed the source: %q", contents)
	}
}

func TestLocalSftpTransferCopiesDirectoryAndPublishesProgress(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(filepath.Join(source, "nested", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "report.txt"), []byte("report contents"), 0o644); err != nil {
		t.Fatal(err)
	}

	server, native, output := newLocalTransferTestServer()
	command := sshWireCommand{
		SessionID:       native.id,
		TransferID:      "copy-directory",
		Direction:       "local-to-local",
		DestinationPath: destination,
		Items: []sshSftpTransferItem{{
			SourcePath:  source,
			Name:        "copied",
			IsDirectory: true,
		}},
	}
	server.sftpTransfer(command)
	server.transferWG.Wait()

	contents, err := os.ReadFile(filepath.Join(destination, "copied", "nested", "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "report contents" {
		t.Fatalf("copied contents = %q", contents)
	}
	if info, err := os.Stat(filepath.Join(destination, "copied", "nested", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory was not copied: info=%v err=%v", info, err)
	}

	events := decodeSSHEvents(t, output.Bytes())
	states := make(map[string]bool)
	for _, event := range events {
		states[event.TransferState] = true
	}
	for _, state := range []string{"running", "progress", "completed", "batch-completed"} {
		if !states[state] {
			t.Fatalf("missing %q event in %#v", state, events)
		}
	}
}

func TestLocalSftpTransferAppliesConflictDecisionToAllItems(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.txt", "two.txt"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte("new "+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, name), []byte("old "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	server, native, output := newLocalTransferTestServer()
	command := sshWireCommand{
		SessionID:       native.id,
		TransferID:      "overwrite-all",
		Direction:       "local-to-local",
		DestinationPath: destination,
		Items: []sshSftpTransferItem{
			{SourcePath: filepath.Join(source, "one.txt"), Name: "one.txt"},
			{SourcePath: filepath.Join(source, "two.txt"), Name: "two.txt"},
		},
	}
	server.sftpTransfer(command)
	server.sftpTransferDecision(sshWireCommand{
		SessionID: native.id, TransferID: command.TransferID, ItemID: "item-0",
		Decision: "overwrite", ApplyToAll: true,
	})
	server.transferWG.Wait()

	for _, name := range []string{"one.txt", "two.txt"} {
		contents, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(contents) != "new "+name {
			t.Fatalf("%s contents = %q", name, contents)
		}
	}
	conflicts := 0
	for _, event := range decodeSSHEvents(t, output.Bytes()) {
		if event.Type == "sftp.conflict" {
			conflicts++
		}
	}
	if conflicts != 1 {
		t.Fatalf("conflict events = %d, want 1", conflicts)
	}
}

func TestLocalSftpTransferCanSkipConflictAndCancelBatch(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source.txt")
		destination := filepath.Join(root, "destination")
		if err := os.WriteFile(source, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(destination, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(destination, "source.txt")
		if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}

		server, native, _ := newLocalTransferTestServer()
		command := sshWireCommand{
			SessionID: native.id, TransferID: "skip", Direction: "local-to-local",
			DestinationPath: destination,
			Items:           []sshSftpTransferItem{{SourcePath: source, Name: "source.txt"}},
		}
		server.sftpTransfer(command)
		server.sftpTransferDecision(sshWireCommand{
			SessionID: native.id, TransferID: command.TransferID, ItemID: "item-0", Decision: "skip",
		})
		server.transferWG.Wait()
		contents, err := os.ReadFile(target)
		if err != nil || string(contents) != "old" {
			t.Fatalf("skipped target = %q, %v", contents, err)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source.txt")
		if err := os.WriteFile(source, []byte(strings.Repeat("x", 1024)), 0o644); err != nil {
			t.Fatal(err)
		}
		server, native, output := newLocalTransferTestServer()
		command := sshWireCommand{
			SessionID: native.id, TransferID: "cancel", Direction: "local-to-local",
			DestinationPath: filepath.Join(root, "destination"),
			Items:           []sshSftpTransferItem{{SourcePath: source, Name: "source.txt"}},
		}
		server.sftpTransfer(command)
		server.sftpTransferCancel(sshWireCommand{SessionID: native.id, TransferID: command.TransferID})
		server.transferWG.Wait()
		events := decodeSSHEvents(t, output.Bytes())
		if len(events) == 0 || events[len(events)-1].TransferState != "batch-cancelled" {
			t.Fatalf("unexpected cancellation events: %#v", events)
		}
	})
}

func TestSftpTransferRejectsDuplicateAndClosedRemoteSession(t *testing.T) {
	server, native, output := newLocalTransferTestServer()
	command := sshWireCommand{
		SessionID: native.id, TransferID: "duplicate", Direction: "local-to-local",
		DestinationPath: t.TempDir(),
		Items:           []sshSftpTransferItem{{SourcePath: filepath.Join(t.TempDir(), "missing"), Name: "missing"}},
	}
	server.transfers[command.TransferID] = &sshSftpTransfer{sessionID: native.id}
	server.sftpTransfer(command)
	delete(server.transfers, command.TransferID)

	server.runSftpTransfer(native, sshWireCommand{
		SessionID: native.id, TransferID: "remote", Direction: "remote-to-local",
	}, &sshSftpTransfer{}, context.Background())

	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 2 || events[0].TransferState != "batch-failed" || events[1].TransferState != "batch-failed" {
		t.Fatalf("unexpected transfer failures: %#v", events)
	}
}

func TestLocalSftpOperationsCreateRenameAndDelete(t *testing.T) {
	root := t.TempDir()
	native := &sshNativeSession{}
	directory := filepath.Join(root, "folder")
	file := filepath.Join(directory, "report.txt")
	renamed := filepath.Join(directory, "renamed.txt")
	commands := []sshWireCommand{
		{Pane: "local", Operation: "mkdir", Path: directory},
		{Pane: "local", Operation: "file", Path: file},
		{Pane: "local", Operation: "rename", Path: file, DestinationPath: renamed},
		{Pane: "local", Operation: "delete", Path: renamed},
	}
	for _, command := range commands {
		if err := native.runSftpOperation(command); err != nil {
			t.Fatalf("%s failed: %v", command.Operation, err)
		}
	}
	if _, err := os.Stat(renamed); !os.IsNotExist(err) {
		t.Fatalf("deleted local file still exists: %v", err)
	}
	for _, command := range []sshWireCommand{
		{Pane: "invalid", Operation: "mkdir", Path: directory},
		{Pane: "local", Operation: "invalid", Path: directory},
		{Pane: "remote", Operation: "open", Path: "/tmp/report.txt"},
		{Pane: "remote", Operation: "mkdir", Path: ""},
	} {
		if err := native.runSftpOperation(command); err == nil {
			t.Fatalf("invalid command was accepted: %#v", command)
		}
	}
}

func TestLocalTransferFilesystemHelpers(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "folder")
	file := filepath.Join(directory, "report.txt")
	if err := ensureTransferDirectory(nil, "local-to-local", directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}
	exists, isDirectory, size, err := transferDestinationInfo(nil, "local-to-local", file)
	if err != nil || !exists || isDirectory || size != 6 {
		t.Fatalf("file info = exists:%v directory:%v size:%d err:%v", exists, isDirectory, size, err)
	}
	exists, _, _, err = transferDestinationInfo(nil, "local-to-local", filepath.Join(root, "missing"))
	if err != nil || exists {
		t.Fatalf("missing info = exists:%v err:%v", exists, err)
	}
	if err := ensureTransferParent(nil, "local-to-local", filepath.Join(root, "nested", "report.txt")); err != nil {
		t.Fatal(err)
	}
	if err := removeTransferDestinationSymlink(nil, "local-to-local", filepath.Join(root, "missing")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteTransferBytesHandlesPartialAndFailedWriters(t *testing.T) {
	var output synchronizedBuffer
	partial := &partialSSHWriter{writer: &output, maximum: 2}
	if err := writeTransferBytes(partial, []byte("abcdef")); err != nil || output.String() != "abcdef" {
		t.Fatalf("partial write = %q, %v", output.String(), err)
	}
	if err := writeTransferBytes(backendFailingWriter{}, []byte("data")); err == nil {
		t.Fatal("writer failure was ignored")
	}
	if err := writeTransferBytes(zeroSSHWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write error = %v", err)
	}
}

type partialSSHWriter struct {
	writer  io.Writer
	maximum int
}

func (writer *partialSSHWriter) Write(data []byte) (int, error) {
	if len(data) > writer.maximum {
		data = data[:writer.maximum]
	}
	return writer.writer.Write(data)
}

type zeroSSHWriter struct{}

func (zeroSSHWriter) Write([]byte) (int, error) { return 0, nil }

func newLocalTransferTestServer() (*sshServer, *sshNativeSession, *synchronizedBuffer) {
	output := &synchronizedBuffer{}
	server := &sshServer{
		output:    &sshEventWriter{encoder: json.NewEncoder(output)},
		sessions:  make(map[string]*sshNativeSession),
		transfers: make(map[string]*sshSftpTransfer),
	}
	native := &sshNativeSession{id: "session", server: server}
	server.sessions[native.id] = native
	return server, native, output
}

func decodeSSHEvents(t *testing.T, data []byte) []sshWireEvent {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var events []sshWireEvent
	for {
		var event sshWireEvent
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			return events
		} else if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
}

func TestRemoteSftpOperationsAndDirectoryListing(t *testing.T) {
	client := newSftpTestClient(t)
	root := sftpTestPath(t.TempDir())
	if err := client.MkdirAll(root); err != nil {
		t.Fatal(err)
	}
	var output synchronizedBuffer
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}}
	native := &sshNativeSession{
		id: "remote-session", server: server, sftpClient: client,
		sftpGeneration: 1, sftpListSeq: 1,
	}

	directory := pathpkg.Join(root, "folder")
	file := pathpkg.Join(directory, "report.txt")
	renamed := pathpkg.Join(directory, "renamed.txt")
	for _, command := range []sshWireCommand{
		{Pane: "remote", Operation: "mkdir", Path: directory},
		{Pane: "remote", Operation: "file", Path: file},
		{Pane: "remote", Operation: "rename", Path: file, DestinationPath: renamed},
	} {
		if err := native.runSftpOperation(command); err != nil {
			t.Fatalf("remote %s failed: %v", command.Operation, err)
		}
	}
	writer, err := client.OpenFile(pathpkg.Join(directory, "zeta.txt"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("contents")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Mkdir(pathpkg.Join(directory, "alpha")); err != nil {
		t.Fatal(err)
	}

	resolved, entries, truncated, err := readSftpDirectory(client, directory)
	if err != nil || resolved != directory || truncated || len(entries) != 3 || !entries[0].IsDirectory {
		t.Fatalf("remote listing = path:%q entries:%#v truncated:%v err:%v", resolved, entries, truncated, err)
	}
	native.listSftp(directory, 1, 1, "list-request")
	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 1 || events[0].Type != "sftp.ready" || events[0].RequestID != "list-request" {
		t.Fatalf("remote listing events = %#v", events)
	}

	if err := native.runSftpOperation(sshWireCommand{Pane: "remote", Operation: "delete", Path: directory}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("remote directory still exists: %v", err)
	}
}

func TestSftpLifecyclePublishesRequestScopedEvents(t *testing.T) {
	client := newSftpTestClient(t)
	root := sftpTestPath(t.TempDir())
	if err := client.MkdirAll(root); err != nil {
		t.Fatal(err)
	}

	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(writer)}}
	native := &sshNativeSession{id: "lifecycle", server: server, sftpClient: client, done: make(chan struct{})}
	decoder := json.NewDecoder(reader)
	readEvent := func(wantType, wantRequest string) sshWireEvent {
		t.Helper()
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != wantType || event.RequestID != wantRequest || event.SessionID != native.id {
			t.Fatalf("SFTP event = %#v, want type=%q request=%q", event, wantType, wantRequest)
		}
		return event
	}

	go native.startSftpOpen("open")
	readEvent("sftp.opening", "open")
	ready := readEvent("sftp.ready", "open")
	if ready.Path == "" {
		t.Fatalf("initial SFTP path was empty: %#v", ready)
	}

	go native.startSftpList(root, 0, "list")
	if event := readEvent("sftp.ready", "list"); event.Path != root {
		t.Fatalf("listed path = %q, want %q", event.Path, root)
	}
	go native.startSftpList("relative", 0, "invalid-list")
	if event := readEvent("sftp.error", "invalid-list"); event.Path != "relative" {
		t.Fatalf("invalid-list event = %#v", event)
	}

	localDirectory := filepath.Join(t.TempDir(), "created")
	go native.startSftpOperation(sshWireCommand{
		RequestID: "operation", Pane: "local", Operation: "mkdir", Path: localDirectory,
	})
	if event := readEvent("sftp.operation", "operation"); event.Error != "" {
		t.Fatalf("local operation event = %#v", event)
	}
	if info, err := os.Stat(localDirectory); err != nil || !info.IsDir() {
		t.Fatalf("local directory was not created: %v", err)
	}

	go native.writeLocalSftpError("local-error", localDirectory, errors.New("private filesystem detail"))
	if event := readEvent("sftp.local.error", "local-error"); event.Error == "" || strings.Contains(event.Error, localDirectory) {
		t.Fatalf("local error event = %#v", event)
	}
	go native.closeSftp(true)
	readEvent("sftp.closed", "")
	go native.startSftpListWithGeneration(root, native.sftpGeneration, "closed-list")
	readEvent("sftp.error", "closed-list")
}

func TestSftpTransfersCopyBetweenLocalAndRemoteFilesystems(t *testing.T) {
	client := newSftpTestClient(t)
	remoteRoot := sftpTestPath(t.TempDir())
	if err := client.MkdirAll(remoteRoot); err != nil {
		t.Fatal(err)
	}
	server, native, output := newLocalTransferTestServer()
	native.sftpClient = client
	native.sftpGeneration = 1

	localRoot := t.TempDir()
	localSource := filepath.Join(localRoot, "upload.txt")
	if err := os.WriteFile(localSource, []byte("uploaded through SFTP"), 0o644); err != nil {
		t.Fatal(err)
	}
	upload := sshWireCommand{
		SessionID: native.id, TransferID: "upload", Direction: "local-to-remote",
		DestinationPath: pathpkg.Join(remoteRoot, "uploads"),
		Items:           []sshSftpTransferItem{{SourcePath: localSource, Name: "upload.txt", Size: 21}},
	}
	server.runSftpTransfer(native, upload, newSftpTransferForTest(upload), context.Background())
	remoteUpload := pathpkg.Join(upload.DestinationPath, "upload.txt")
	remoteContents, err := readSftpTestFile(client, remoteUpload)
	if err != nil || string(remoteContents) != "uploaded through SFTP" {
		t.Fatalf("remote upload = %q, %v", remoteContents, err)
	}

	remoteFolder := pathpkg.Join(remoteRoot, "download")
	if err := client.MkdirAll(pathpkg.Join(remoteFolder, "nested")); err != nil {
		t.Fatal(err)
	}
	if err := writeSftpTestFile(client, pathpkg.Join(remoteFolder, "nested", "report.txt"), []byte("downloaded through SFTP")); err != nil {
		t.Fatal(err)
	}
	localDestination := filepath.Join(localRoot, "downloads")
	download := sshWireCommand{
		SessionID: native.id, TransferID: "download", Direction: "remote-to-local",
		DestinationPath: localDestination,
		Items:           []sshSftpTransferItem{{SourcePath: remoteFolder, Name: "folder", IsDirectory: true}},
	}
	plans, err := buildSftpTransferPlans(client, download, context.Background())
	if err != nil || len(plans) != 3 {
		t.Fatalf("remote plans = %#v, %v", plans, err)
	}
	server.runSftpTransfer(native, download, newSftpTransferForTest(download), context.Background())
	downloaded, err := os.ReadFile(filepath.Join(localDestination, "folder", "nested", "report.txt"))
	if err != nil || string(downloaded) != "downloaded through SFTP" {
		t.Fatalf("local download = %q, %v", downloaded, err)
	}

	states := make(map[string]bool)
	for _, event := range decodeSSHEvents(t, output.Bytes()) {
		states[event.TransferState] = true
	}
	if !states["running"] || !states["progress"] || !states["completed"] || !states["batch-completed"] {
		t.Fatalf("transfer states = %#v", states)
	}
}

func TestRemoteSftpHelpersHandleMissingAndExistingDestinations(t *testing.T) {
	client := newSftpTestClient(t)
	root := sftpTestPath(t.TempDir())
	directory := pathpkg.Join(root, "nested")
	file := pathpkg.Join(directory, "report.txt")
	if err := ensureTransferDirectory(client, "local-to-remote", directory); err != nil {
		t.Fatal(err)
	}
	if err := ensureTransferParent(client, "local-to-remote", file); err != nil {
		t.Fatal(err)
	}
	if err := writeSftpTestFile(client, file, []byte("report")); err != nil {
		t.Fatal(err)
	}
	exists, isDirectory, size, err := transferDestinationInfo(client, "local-to-remote", file)
	if err != nil || !exists || isDirectory || size != 6 {
		t.Fatalf("remote destination = exists:%v directory:%v size:%d err:%v", exists, isDirectory, size, err)
	}
	exists, _, _, err = transferDestinationInfo(client, "local-to-remote", pathpkg.Join(root, "missing"))
	if err != nil || exists {
		t.Fatalf("missing remote destination = exists:%v err:%v", exists, err)
	}
	if err := removeTransferDestinationSymlink(client, "local-to-remote", pathpkg.Join(root, "missing")); err != nil {
		t.Fatal(err)
	}
	if err := removeTransferDestinationSymlink(client, "local-to-remote", file); err != nil {
		t.Fatal(err)
	}
}

func newSftpTransferForTest(command sshWireCommand) *sshSftpTransfer {
	return &sshSftpTransfer{
		id: command.TransferID, sessionID: command.SessionID,
		decisions:   make(chan sshSftpTransferDecision, 1),
		itemCancels: make(map[string]context.CancelFunc), cancelledItems: make(map[string]struct{}),
	}
}

func newSftpTestClient(t *testing.T) *sftp.Client {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	server, err := sftp.NewServer(serverConnection)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve() }()
	client, err := sftp.NewClientPipe(clientConnection, clientConnection)
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("SFTP fixture did not stop")
		}
	})
	return client
}

func sftpTestPath(localPath string) string {
	return "/" + filepath.ToSlash(localPath)
}

func writeSftpTestFile(client *sftp.Client, path string, contents []byte) error {
	file, err := client.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readSftpTestFile(client *sftp.Client, path string) ([]byte, error) {
	file, err := client.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func (input *blockingSSHInput) Write(data []byte) (int, error) {
	input.startOnce.Do(func() { close(input.started) })
	<-input.release
	return len(data), nil
}

func (input *blockingSSHInput) Close() error {
	input.releaseOnce.Do(func() { close(input.release) })
	return nil
}

func TestSSHInputQueueDoesNotBlockWhenRemoteStopsReading(t *testing.T) {
	input := &blockingSSHInput{started: make(chan struct{}), release: make(chan struct{})}
	native := &sshNativeSession{
		stdin:      input,
		inputQueue: make(chan []byte, 1),
		done:       make(chan struct{}),
	}
	native.startInputPump()

	if err := native.write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("input pump did not reach the blocking SSH writer")
	}
	if err := native.write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := native.write([]byte("third")); !errors.Is(err, errSSHInputFull) {
		t.Fatalf("expected bounded input queue error, got %v", err)
	}
	native.close(false)
}

func TestProtectedCredentialFileStemMatchesCredentialServiceAndRejectsPaths(t *testing.T) {
	stem, err := protectedCredentialFileStem("A1B2C3D4-E5F6-47A8-90B1-C2D3E4F56789")
	if err != nil {
		t.Fatal(err)
	}
	if stem != "a1b2c3d4e5f647a890b1c2d3e4f56789" {
		t.Fatalf("unexpected private-key filename stem: %q", stem)
	}
	if _, err := protectedCredentialFileStem("..\\outside"); err == nil {
		t.Fatal("path-like credential id was accepted")
	}
}

func TestPersistSSHFingerprintDoesNotOverwriteConcurrentTOFUPin(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, SshKnownHostFingerprint, UpdatedAt)
VALUES ('node', 'SHA256:already-pinned', 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	err = persistSSHFingerprint(databasePath, "node", "SHA256:attacker-key")
	if !errors.Is(err, errSSHHostFingerprintChanged) {
		t.Fatalf("expected concurrent TOFU pin conflict, got %v", err)
	}
}

func TestTrustSSHFingerprintReplacesOnlyTheExpectedPin(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, SshKnownHostFingerprint, UpdatedAt)
VALUES ('node', 'SHA256:KfNRucV0MaZ9lkCIfmHHZgcCsxJrf3frwycqo2/cw9k', 'now');
`)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}

	var request sshHostKeyTrustRequest
	if err := json.Unmarshal([]byte(`{"nodeId":"node","expected":"SHA256:KfNRucV0MaZ9lkCIfmHHZgcCsxJrf3frwycqo2/cw9k","received":"SHA256:rjnaNoqbDUI5dQiifXn9cdTeEZ0dRAD/TTLe6sBbOiw"}`), &request); err != nil {
		t.Fatal(err)
	}
	err = trustSSHFingerprint(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var fingerprint string
	if err := database.QueryRow("SELECT SshKnownHostFingerprint FROM Nodes WHERE Id = 'node';").Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint != "SHA256:rjnaNoqbDUI5dQiifXn9cdTeEZ0dRAD/TTLe6sBbOiw" {
		t.Fatalf("unexpected trusted fingerprint: %q", fingerprint)
	}
}

func TestTrustSSHFingerprintRejectsAStaleExpectedPin(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    SshKnownHostFingerprint TEXT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, SshKnownHostFingerprint, UpdatedAt)
VALUES ('node', 'SHA256:KfNRucV0MaZ9lkCIfmHHZgcCsxJrf3frwycqo2/cw9k', 'now');
`)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = trustSSHFingerprint(databasePath, sshHostKeyTrustRequest{
		NodeID:   "node",
		Expected: "SHA256:rjnaNoqbDUI5dQiifXn9cdTeEZ0dRAD/TTLe6sBbOiw",
		Received: "SHA256:KfNRucV0MaZ9lkCIfmHHZgcCsxJrf3frwycqo2/cw9k",
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint changed") {
		t.Fatalf("expected stale-pin rejection, got %v", err)
	}
}

func TestDialNativeSSHReportsStructuredHostKeyMismatch(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if connection.User() != "operator" || string(password) != "secret" {
				return nil, errors.New("invalid test credentials")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)
	serverDone := make(chan error, 1)
	go func() {
		rawConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer rawConnection.Close()
		_, _, _, handshakeErr := ssh.NewServerConn(rawConnection, serverConfig)
		serverDone <- handshakeErr
	}()

	_, _, err = dialNativeSSH(context.Background(), sshTarget{
		host:                 "127.0.0.1",
		port:                 listener.Addr().(*net.TCPAddr).Port,
		username:             "operator",
		password:             "secret",
		knownHostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, 80, 24)
	var mismatch *sshHostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected structured host-key mismatch, got %v", err)
	}
	if mismatch.expected != "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected expected fingerprint: %q", mismatch.expected)
	}
	if mismatch.received != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("unexpected received fingerprint: %q", mismatch.received)
	}
	if serverErr := <-serverDone; serverErr == nil {
		t.Fatal("expected the server handshake to be rejected")
	}
}

func TestSSHNativeSessionSnapshotPublishesAFullFrame(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	terminal, err := newSSHTerminalEmulator(8, 2)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id:       "session",
		server:   server,
		terminal: terminal,
		done:     make(chan struct{}),
	}
	server.sessions[native.id] = native

	native.snapshot()

	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "screen" || event.Frame == nil || !event.Frame.Full {
		t.Fatalf("snapshot did not publish a full screen frame: %#v", event)
	}
	if event.Frame.Columns != 8 || event.Frame.Rows != 2 || len(event.Frame.Cells) != 16 {
		t.Fatalf("unexpected snapshot dimensions: %#v", event.Frame)
	}
}

func TestSSHUnexpectedCloseRetriesThreeTimesBeforeTerminalFailure(t *testing.T) {
	reconnectDelay := time.Duration(0)

	var output synchronizedBuffer
	var callsMu sync.Mutex
	calls := 0
	server := &sshServer{
		output:                 &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:               make(map[string]*sshNativeSession),
		pending:                make(map[string]context.CancelFunc),
		lifecycles:             make(map[string]*sshReconnectState),
		reconnectDelayOverride: &reconnectDelay,
	}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		return nil, sshTarget{}, errors.New("network unavailable")
	}
	state := &sshReconnectState{
		command: sshWireCommand{SessionID: "session", Password: "retry-secret"}, connectedAt: time.Now(),
	}
	native := &sshNativeSession{id: "session", server: server}
	server.sessions[native.id] = native
	server.lifecycles[native.id] = state

	native.close(true)
	deadline := time.Now().Add(time.Second)
	for {
		server.output.mu.Lock()
		complete := strings.Contains(output.String(), `"type":"reconnect-failed"`)
		server.output.mu.Unlock()
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic reconnect did not exhaust its retry budget")
		}
		time.Sleep(time.Millisecond)
	}
	callsMu.Lock()
	actualCalls := calls
	callsMu.Unlock()
	if actualCalls != sshAutoReconnectMaxAttempts {
		t.Fatalf("automatic reconnect opened %d times, want %d", actualCalls, sshAutoReconnectMaxAttempts)
	}

	server.output.mu.Lock()
	snapshot := append([]byte(nil), output.Bytes()...)
	server.output.mu.Unlock()
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	for attempt := 1; attempt <= sshAutoReconnectMaxAttempts; attempt++ {
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "reconnecting" || event.Attempt != attempt ||
			event.MaxAttempts != sshAutoReconnectMaxAttempts {
			t.Fatalf("unexpected reconnect event for attempt %d: %#v", attempt, event)
		}
	}
	var terminal sshWireEvent
	if err := decoder.Decode(&terminal); err != nil {
		t.Fatal(err)
	}
	if terminal.Type != "reconnect-failed" || terminal.Attempt != sshAutoReconnectMaxAttempts ||
		terminal.Error != "network unavailable" {
		t.Fatalf("unexpected terminal reconnect event: %#v", terminal)
	}
	if state.commandSnapshot().Password != "" {
		t.Fatal("terminal reconnect failure retained the SSH password")
	}
}

func TestSSHExplicitCloseCancelsAPendingAutomaticReconnect(t *testing.T) {
	reconnectDelay := time.Hour

	var output synchronizedBuffer
	var callsMu sync.Mutex
	calls := 0
	server := &sshServer{
		output:                 &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:               make(map[string]*sshNativeSession),
		pending:                make(map[string]context.CancelFunc),
		lifecycles:             make(map[string]*sshReconnectState),
		transfers:              make(map[string]*sshSftpTransfer),
		reconnectDelayOverride: &reconnectDelay,
	}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		return nil, sshTarget{}, errors.New("must not run")
	}
	state := &sshReconnectState{
		command:     sshWireCommand{SessionID: "session", Password: "retry-secret"},
		connectedAt: time.Now().Add(-sshAutoReconnectStableWindow - time.Second),
		attempts:    sshAutoReconnectMaxAttempts,
	}
	native := &sshNativeSession{id: "session", server: server}
	server.sessions[native.id] = native
	server.lifecycles[native.id] = state

	native.close(true)
	if state.attempts != 1 {
		t.Fatalf("stable session did not reset its reconnect budget: %d", state.attempts)
	}
	server.close(native.id)
	time.Sleep(10 * time.Millisecond)
	callsMu.Lock()
	actualCalls := calls
	callsMu.Unlock()
	if actualCalls != 0 {
		t.Fatalf("explicit close allowed %d reconnect attempts", actualCalls)
	}
	server.mu.Lock()
	_, pending := server.pending[native.id]
	_, retained := server.lifecycles[native.id]
	server.mu.Unlock()
	if pending || retained {
		t.Fatal("explicit close retained automatic reconnect state")
	}
	if state.commandSnapshot().Password != "" {
		t.Fatal("explicit close retained the SSH password")
	}
}

func TestSSHAppLockClearsReconnectSecretsWithoutClosingAnActiveSession(t *testing.T) {
	var output synchronizedBuffer
	calls := 0
	server := &sshServer{
		output:     &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:   make(map[string]*sshNativeSession),
		pending:    make(map[string]context.CancelFunc),
		lifecycles: make(map[string]*sshReconnectState),
	}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		calls++
		return nil, sshTarget{}, errors.New("must not reconnect while locked")
	}
	state := &sshReconnectState{command: sshWireCommand{
		SessionID: "session", Password: "manual-secret", PasswordOverride: "vault-secret",
	}}
	native := &sshNativeSession{id: "session", server: server}
	server.sessions[native.id] = native
	server.lifecycles[native.id] = state

	server.prepareSessionForLock(native.id)
	command := state.commandSnapshot()
	if !state.reconnectDisabled || command.Password != "" || command.PasswordOverride != "" {
		t.Fatalf("application lock retained SSH reconnect secrets: %#v", command)
	}
	if server.sessions[native.id] != native {
		t.Fatal("application lock closed an active SSH session")
	}

	native.close(true)
	if calls != 0 {
		t.Fatalf("locked SSH session attempted %d reconnects", calls)
	}
	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "closed" || event.SessionID != native.id {
		t.Fatalf("locked SSH close emitted an unexpected event: %#v", event)
	}
}

func TestSSHSnapshotIgnoresAClosedSession(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}

	server.snapshot(sshWireCommand{SessionID: "closed-session"})
	if output.Len() != 0 {
		t.Fatalf("closed-session snapshot emitted an unexpected event: %s", output.String())
	}
}

func TestSSHNativeSessionDropsFramesAfterClose(t *testing.T) {
	var output synchronizedBuffer
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*sshNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	terminal, err := newSSHTerminalEmulator(8, 2)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id:       "session",
		server:   server,
		terminal: terminal,
		done:     make(chan struct{}),
	}
	server.sessions[native.id] = native

	native.close(true)
	native.publishTerminalFrame(terminal.initialFrame())

	decoder := json.NewDecoder(&output)
	var event sshWireEvent
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "closed" {
		t.Fatalf("unexpected close event: %#v", event)
	}
	var extra sshWireEvent
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("late terminal frame was published after close: event=%#v err=%v", extra, err)
	}
}

func TestDialNativeSSHHonorsContextCancellationDuringHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			close(accepted)
			<-serverDone
			_ = connection.Close()
			return
		}
		close(accepted)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-accepted
		cancel()
	}()
	start := time.Now()
	_, _, err = dialNativeSSH(ctx, sshTarget{
		host:     "127.0.0.1",
		port:     listener.Addr().(*net.TCPAddr).Port,
		username: "operator",
		password: "secret",
	}, 80, 24)
	close(serverDone)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("handshake cancellation took too long: %s", elapsed)
	}
}

func TestServeSSHRejectsMalformedAndUnsupportedCommands(t *testing.T) {
	input := strings.NewReader("not-json\n{" + `"type":"wat","session_id":"session"` + "}\n")
	var output synchronizedBuffer
	if err := serveSSH(filepath.Join(t.TempDir(), "wormhole.db"), input, &output); err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(&output)
	var first, second sshWireEvent
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if first.Type != "error" || first.Error != "invalid SSH command" {
		t.Fatalf("unexpected malformed-command response: %#v", first)
	}
	if second.Type != "error" || second.SessionID != "session" {
		t.Fatalf("unexpected unsupported-command response: %#v", second)
	}
}

func TestSSHNodeLoaderHandlesMissingOptionalColumns(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL
);
INSERT INTO Nodes (Id, Name, Kind, Protocol, Host) VALUES ('leaf', 'SSH leaf', 1, 0, 'ssh.example');
`)
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := loadSSHNodes(database)
	if err != nil {
		t.Fatal(err)
	}
	if nodes["leaf"] == nil || nodes["leaf"].host != "ssh.example" {
		t.Fatalf("optional-column node was not loaded: %#v", nodes)
	}
}

func TestLoadSSHCredentialCoversOverridesProvidersAndSecretFailures(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := loadSSHCredential(database, databasePath, "", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("empty SSH credential id was accepted")
	}
	target := sshTarget{}
	if err := loadSSHCredential(database, databasePath, "missing", &target, "override", "secret", true, true); err != nil {
		t.Fatalf("manual override without a credential table failed: %v", err)
	}
	if target.username != "override" || target.password != "secret" {
		t.Fatalf("manual SSH override = %#v", target)
	}
	if err := loadSSHCredential(database, databasePath, "missing", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("missing credential table returned no error")
	}

	_, err = database.Exec(`
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY, Username TEXT NULL, Kind INTEGER NULL,
    Protocol INTEGER NULL, SecretProvider INTEGER NULL
);
INSERT INTO CredentialProfiles (Id, Username, Kind, Protocol, SecretProvider) VALUES
    ('11111111-1111-4111-8111-111111111111', 'vault-user', 0, 0, 1),
    ('22222222-2222-4222-8222-222222222222', 'rdp-user', 0, 1, 0),
    ('33333333-3333-4333-8333-333333333333', 'key-user', 1, 0, 0),
    ('44444444-4444-4444-8444-444444444444', 'password-user', 0, 0, 0);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSSHCredential(database, databasePath, "missing", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("unknown SSH credential returned no error")
	}
	if err := loadSSHCredential(database, databasePath, "11111111-1111-4111-8111-111111111111", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("locked Bitwarden credential returned no error")
	}
	target = sshTarget{}
	if err := loadSSHCredential(
		database, databasePath, "11111111-1111-4111-8111-111111111111", &target,
		"manual-user", "manual-password", true, false,
	); err != nil {
		t.Fatal(err)
	}
	if target.username != "manual-user" || target.password != "manual-password" {
		t.Fatalf("Bitwarden override target = %#v", target)
	}
	if err := loadSSHCredential(database, databasePath, "22222222-2222-4222-8222-222222222222", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("RDP credential was accepted for SSH")
	}
	if err := loadSSHCredential(database, databasePath, "33333333-3333-4333-8333-333333333333", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("missing protected key returned no error")
	}
	if err := loadSSHCredential(database, databasePath, "44444444-4444-4444-8444-444444444444", &sshTarget{}, "", "", false, false); err == nil {
		t.Fatal("missing protected password returned no error")
	}
	if secret, err := readOptionalCredentialSecret(database, "missing"); err != nil || secret != nil {
		t.Fatalf("optional missing secret = %q, %v", secret, err)
	}

	_, err = database.Exec(`
CREATE TABLE CredentialSecrets (Id TEXT PRIMARY KEY, Secret TEXT NOT NULL, Encoding TEXT NOT NULL);
INSERT INTO CredentialSecrets (Id, Secret, Encoding)
VALUES ('44444444-4444-4444-8444-444444444444', 'opaque', 'unsupported');`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialSecret(database, "44444444-4444-4444-8444-444444444444"); err == nil {
		t.Fatal("unsupported required secret encoding returned no error")
	}
	if _, err := readOptionalCredentialSecret(database, "44444444-4444-4444-8444-444444444444"); err == nil {
		t.Fatal("unsupported optional secret encoding returned no error")
	}
}

func TestLoadSSHCredentialSnapshotsKeyAndPassphraseAgainstConcurrentReplacement(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	oldKeyPath := filepath.Join(t.TempDir(), "old.pem")
	oldKey := testSshPrivateKey(t, "old-passphrase")
	if err := os.WriteFile(oldKeyPath, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Runtime key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "old-passphrase", PrivateKeyPath: oldKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	keyRead := make(chan struct{})
	continueLoad := make(chan struct{})
	defer func() {
		select {
		case <-continueLoad:
		default:
			close(continueLoad)
		}
	}()
	previousUnprotect := credentialPrivateKeyUnprotect
	credentialPrivateKeyUnprotect = func(path string) ([]byte, error) {
		key, err := previousUnprotect(path)
		if err == nil {
			close(keyRead)
			<-continueLoad
		}
		return key, err
	}
	t.Cleanup(func() { credentialPrivateKeyUnprotect = previousUnprotect })

	previousStageProtect := credentialPrivateKeyStageProtect
	replacementStaged := make(chan struct{}, 1)
	credentialPrivateKeyStageProtect = func(finalPath, pendingPath string, plaintext []byte) error {
		if err := previousStageProtect(finalPath, pendingPath, plaintext); err != nil {
			return err
		}
		replacementStaged <- struct{}{}
		return nil
	}
	t.Cleanup(func() { credentialPrivateKeyStageProtect = previousStageProtect })

	target := sshTarget{}
	loadDone := make(chan error, 1)
	go func() {
		loadDone <- loadSSHCredential(database, databasePath, created.ID, &target, "", "", false, false)
	}()
	select {
	case <-keyRead:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime credential load did not reach the SSH private key")
	}

	replacementPath := filepath.Join(t.TempDir(), "replacement.pem")
	if err := os.WriteFile(replacementPath, testSshPrivateKey(t, "replacement-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateDone := make(chan error, 1)
	go func() {
		_, err := updateCredential(databasePath, credentialUpdateRequest{
			ID: created.ID,
			credentialCreateRequest: credentialCreateRequest{
				Name: "Runtime key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
				Passphrase: "replacement-passphrase", PrivateKeyPath: replacementPath,
			},
		})
		updateDone <- err
	}()

	select {
	case <-replacementStaged:
		close(continueLoad)
		t.Fatal("SSH key replacement reached staging during runtime credential loading")
	case err := <-updateDone:
		close(continueLoad)
		t.Fatalf("SSH key replacement did not wait for runtime credential loading: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(continueLoad)
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime credential load did not finish")
	}
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH key replacement did not resume after runtime credential loading")
	}
	defer clearBytes(target.privateKey)
	if target.keyPassphrase != "old-passphrase" || !bytes.Equal(target.privateKey, oldKey) {
		t.Fatalf("runtime SSH key snapshot = passphrase:%q key-bytes:%d", target.keyPassphrase, len(target.privateKey))
	}
}

func TestLoadSSHCredentialWaitsForReplacementBeforeReadingProfile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	oldKeyPath := filepath.Join(t.TempDir(), "old.pem")
	if err := os.WriteFile(oldKeyPath, testSshPrivateKey(t, "old-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Runtime key", Protocol: "ssh", Kind: "sshKey", Username: "old-user",
		Passphrase: "old-passphrase", PrivateKeyPath: oldKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	replacementPath := filepath.Join(t.TempDir(), "replacement.pem")
	replacementKey := testSshPrivateKey(t, "replacement-passphrase")
	if err := os.WriteFile(replacementPath, replacementKey, 0o600); err != nil {
		t.Fatal(err)
	}
	replacementStaged := make(chan struct{})
	continueUpdate := make(chan struct{})
	defer func() {
		select {
		case <-continueUpdate:
		default:
			close(continueUpdate)
		}
	}()
	previousStageProtect := credentialPrivateKeyStageProtect
	credentialPrivateKeyStageProtect = func(finalPath, pendingPath string, plaintext []byte) error {
		if err := previousStageProtect(finalPath, pendingPath, plaintext); err != nil {
			return err
		}
		close(replacementStaged)
		<-continueUpdate
		return nil
	}
	t.Cleanup(func() { credentialPrivateKeyStageProtect = previousStageProtect })

	updateDone := make(chan error, 1)
	go func() {
		_, err := updateCredential(databasePath, credentialUpdateRequest{
			ID: created.ID,
			credentialCreateRequest: credentialCreateRequest{
				Name: "Runtime key", Protocol: "ssh", Kind: "sshKey", Username: "new-user",
				Passphrase: "replacement-passphrase", PrivateKeyPath: replacementPath,
			},
		})
		updateDone <- err
	}()
	select {
	case <-replacementStaged:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH key replacement did not reach staging")
	}

	lockAttempted := make(chan struct{})
	previousRuntimeLock := sshCredentialPrivateKeyLock
	sshCredentialPrivateKeyLock = func(path string) (func(), error) {
		close(lockAttempted)
		return previousRuntimeLock(path)
	}
	t.Cleanup(func() { sshCredentialPrivateKeyLock = previousRuntimeLock })
	target := sshTarget{}
	loadDone := make(chan error, 1)
	go func() {
		loadDone <- loadSSHCredential(database, databasePath, created.ID, &target, "", "", false, false)
	}()
	select {
	case <-lockAttempted:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime credential load did not attempt to acquire the snapshot lock")
	}
	close(continueUpdate)

	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH key replacement did not finish")
	}
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime credential load did not resume")
	}
	defer clearBytes(target.privateKey)
	if target.username != "new-user" || target.keyPassphrase != "replacement-passphrase" ||
		!bytes.Equal(target.privateKey, replacementKey) {
		t.Fatalf(
			"runtime SSH credential snapshot = user:%q passphrase:%q key-bytes:%d",
			target.username,
			target.keyPassphrase,
			len(target.privateKey),
		)
	}
}

func TestDialNativeSSHUsesGoSSHClientForPasswordAndPTY(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if connection.User() != "operator" || string(password) != "secret" {
				return nil, errors.New("invalid test credentials")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	serverDone := make(chan error, 1)
	go func() {
		rawConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverConnection, channels, requests, handshakeErr := ssh.NewServerConn(rawConnection, serverConfig)
		if handshakeErr != nil {
			serverDone <- handshakeErr
			return
		}
		defer serverConnection.Close()
		go ssh.DiscardRequests(requests)
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "test only accepts sessions")
				continue
			}
			channel, channelRequests, channelErr := newChannel.Accept()
			if channelErr != nil {
				serverDone <- channelErr
				return
			}
			go func() {
				defer channel.Close()
				for request := range channelRequests {
					switch request.Type {
					case "pty-req":
						_ = request.Reply(true, nil)
					case "window-change":
						_ = request.Reply(true, nil)
					case "shell":
						_ = request.Reply(true, nil)
						_, _ = channel.Write([]byte("native ready\r\n"))
						go func() {
							buffer := make([]byte, 128)
							count, readErr := channel.Read(buffer)
							if readErr == nil && strings.Contains(string(buffer[:count]), "echo test") {
								_, _ = channel.Write([]byte("native response\r\n"))
							}
							_ = channel.Close()
						}()
					default:
						_ = request.Reply(false, nil)
					}
				}
			}()
		}
		serverDone <- nil
	}()

	target := sshTarget{
		host:     "127.0.0.1",
		port:     listener.Addr().(*net.TCPAddr).Port,
		username: "operator",
		password: "secret",
	}
	native, fingerprint, err := dialNativeSSH(context.Background(), target, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("unexpected host fingerprint: %q", fingerprint)
	}
	var output synchronizedBuffer
	server := &sshServer{
		output: &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: map[string]*sshNativeSession{
			"native": native,
		},
	}
	native.id = "native"
	native.server = server
	native.start()
	native.start()
	if err := native.resize(100, 30); err != nil {
		t.Fatalf("native resize failed: %v", err)
	}
	native.snapshot()
	if err := native.write([]byte("echo test\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-native.done:
	case <-time.After(5 * time.Second):
		t.Fatal("native SSH lifecycle did not finish")
	}
	native.waitForOutputDrain()
	native.close(true)
	if replay := string(native.mcpReplay.snapshotTail(4096)); !strings.Contains(replay, "native ready") || !strings.Contains(replay, "native response") {
		t.Fatalf("unexpected terminal replay: %q", replay)
	}
	events := decodeSSHEvents(t, output.Bytes())
	var screens, closed int
	for _, event := range events {
		switch event.Type {
		case "screen":
			screens++
		case "closed":
			closed++
		}
	}
	if screens == 0 || closed != 1 {
		t.Fatalf("native lifecycle events = %#v", events)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH test server did not stop")
	}
}
