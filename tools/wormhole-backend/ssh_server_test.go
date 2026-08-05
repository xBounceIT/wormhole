package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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

func TestLoadSSHTargetRejectsInheritedVPNRouteUntilElectronSupportsIt(t *testing.T) {
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
	if !strings.HasPrefix(value, "sudo -S -p '") || !strings.HasSuffix(value, "' su\r") {
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

	// The PTY echoes the command containing the nonce. That echo is not the prompt and must not
	// release the saved password.
	driver.observe([]byte(initial))
	if got := input.String(); got != initial {
		t.Fatalf("auto sudo answered on its command echo: %q", got)
	}

	driver.observe([]byte(driver.prompt))
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

	driver.observe([]byte(driver.prompt))
	if got := input.String(); got != initial+"secret\r"+"whoami\r" {
		t.Fatalf("expected password before buffered user input, got %q", got)
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

	driver.observe([]byte(driver.prompt))
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
	driver.observe([]byte(driver.prompt))
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
	driver.observe([]byte(driver.prompt))
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
	prompt := driver.prompt
	driver.observe([]byte(prompt[:len(prompt)-2]))
	requireAutoSudoCommand(t, input.String())
	driver.observe([]byte(prompt[len(prompt)-2:]))
	if got := input.String(); !strings.HasSuffix(got, "' su\rsecret\r") {
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
	if isSafeSftpName("report:2026.txt") {
		t.Fatal("remote filename containing a colon was accepted")
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
	var output bytes.Buffer
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
	var output bytes.Buffer
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
		var output bytes.Buffer
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
	var output bytes.Buffer
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
	var output bytes.Buffer
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
	var output bytes.Buffer
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
	var output bytes.Buffer
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

func TestSSHSnapshotIgnoresAClosedSession(t *testing.T) {
	var output bytes.Buffer
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
	var output bytes.Buffer
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
	var output bytes.Buffer
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
					case "shell":
						_ = request.Reply(true, nil)
						_, _ = channel.Write([]byte("native ready\r\n"))
						buffer := make([]byte, 128)
						count, readErr := channel.Read(buffer)
						if readErr == nil && strings.Contains(string(buffer[:count]), "echo test") {
							_, _ = channel.Write([]byte("native response\r\n"))
						}
						return
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
	defer native.close(false)
	if fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("unexpected host fingerprint: %q", fingerprint)
	}

	ready := readNativeSSHOutput(t, native.stdout)
	if !strings.Contains(string(ready), "native ready") {
		t.Fatalf("unexpected initial terminal output: %q", ready)
	}
	if err := native.write([]byte("echo test\r")); err != nil {
		t.Fatal(err)
	}
	response := readNativeSSHOutput(t, native.stdout)
	if !strings.Contains(string(response), "native response") {
		t.Fatalf("unexpected command output: %q", response)
	}
}

func readNativeSSHOutput(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	result := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 1024)
		count, _ := reader.Read(buffer)
		result <- buffer[:count]
	}()
	select {
	case output := <-result:
		return output
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSH terminal output")
		return nil
	}
}
