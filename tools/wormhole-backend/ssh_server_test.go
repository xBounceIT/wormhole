package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
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
