package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vnc "github.com/kward/go-vnc"
)

func TestBackendLongOperationCommandsAreNarrowlyValidated(t *testing.T) {
	valid := []backendCommand{
		{ID: "1", Action: "backup.export", SessionID: "operation-1", Path: "backup.json"},
		{ID: "2", Action: "backup.import", SessionID: "operation-2", Path: "backup.json"},
		{
			ID: "3", Action: "mremote.import.commit", SessionID: "operation-3", Path: "connections.xml",
			PlanNonce: "11111111-2222-4333-8444-555555555555", PlanToken: strings.Repeat("b", 64),
		},
		{ID: "4", Action: "operation.cancel", SessionID: "operation-1"},
	}
	for _, command := range valid {
		if err := validateBackendCommand(command); err != nil {
			t.Fatalf("valid %s command rejected: %v", command.Action, err)
		}
	}
	invalid := []backendCommand{
		{ID: "1", Action: "backup.export", SessionID: "operation-1"},
		{ID: "2", Action: "backup.import", SessionID: "operation-2", Path: "backup.json", Password: strings.Repeat("x", maxStoredCredentialBytes+1)},
		{ID: "3", Action: "mremote.import.commit", SessionID: "operation-3", Path: "connections.xml", PlanNonce: "bad", PlanToken: "bad"},
		{ID: "4", Action: "operation.cancel"},
	}
	for _, command := range invalid {
		if err := validateBackendCommand(command); err == nil {
			t.Fatalf("invalid %s command accepted", command.Action)
		}
	}
}

func TestBackendOperationCancellationDoesNotBlockCommandReader(t *testing.T) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readPipe.Close()
	defer writePipe.Close()
	manager := newVncManager(nil, newBackendLineWriter(writePipe))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	manager.operations["operation-1"] = &pendingBackendOperation{cancel: cancel, done: done}

	returned := make(chan struct{})
	go func() {
		manager.handle(backendCommand{ID: "cancel-1", Action: "operation.cancel", SessionID: "operation-1"})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("operation cancellation blocked the backend command reader")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("operation cancellation did not cancel its context")
	}
	close(done)
	manager.cleanup.Wait()
}

func TestVncDisconnectWaitsForConnectCleanupBoundary(t *testing.T) {
	session := newVncSession("session-1", nil, nil)
	session.done = make(chan struct{})
	finished := make(chan struct{})
	go func() {
		session.closeAndWait()
		close(finished)
	}()

	deadline := time.After(time.Second)
	for !session.isStopped() {
		select {
		case <-deadline:
			t.Fatal("VNC disconnect did not begin")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-finished:
		t.Fatal("VNC disconnect completed before the connect goroutine released its resources")
	default:
	}
	close(session.done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("VNC disconnect did not complete after connect cleanup")
	}
}

func TestSplitVncHostPortSupportsCommonForms(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		wantHost string
		wantPort int
	}{
		{name: "default", host: "vnc.example", wantHost: "vnc.example", wantPort: 5900},
		{name: "host port", host: "vnc.example:5901", wantHost: "vnc.example", wantPort: 5901},
		{name: "bracketed ipv6", host: "[::1]:5902", wantHost: "::1", wantPort: 5902},
		{name: "bare bracketed ipv6", host: "[::1]", wantHost: "::1", wantPort: 5900},
		{name: "explicit port wins", host: "vnc.example:5901", port: 5903, wantHost: "vnc.example", wantPort: 5903},
		{name: "explicit default port wins", host: "vnc.example:5901", port: 5900, wantHost: "vnc.example", wantPort: 5900},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := splitVncHostPort(test.host, test.port)
			if err != nil {
				t.Fatal(err)
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf("got %q:%d, want %q:%d", host, port, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestVncPersistedInputLimitsAreSharedWithCommands(t *testing.T) {
	if err := validateVncHost(strings.Repeat("h", maxVncHostLength)); err != nil {
		t.Fatal(err)
	}
	if err := validateVncHost(strings.Repeat("h", maxVncHostLength+1)); err == nil {
		t.Fatal("oversized VNC host was accepted")
	}
	if err := validateVncPassword(strings.Repeat("p", maxVncPasswordSize)); err != nil {
		t.Fatal(err)
	}
	if err := validateVncPassword(strings.Repeat("p", maxVncPasswordSize+1)); err == nil {
		t.Fatal("oversized VNC password was accepted")
	}
}

func TestVncExplicitEmptyPasswordDoesNotReloadSavedSecret(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port)
VALUES ('vnc-node', NULL, 'VNC node', 1, 6, 'vnc.example', 5900);`)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolveVncTarget(database, backendCommand{
		NodeID: "vnc-node", Password: "", PasswordProvided: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.password != "" {
		t.Fatalf("explicit empty password was replaced: %q", target.password)
	}
}

func TestBitwardenSessionClearCancelsPendingVncHandshakeOnly(t *testing.T) {
	manager := newVncManager(nil, nil)
	pending := newVncSession("pending", nil, manager)
	pendingContext, ok := pending.beginConnect()
	if !ok {
		t.Fatal("pending VNC connection did not start")
	}
	pendingClient, pendingPeer := net.Pipe()
	defer pendingPeer.Close()
	if !pending.setNetworkConnection(pendingClient) {
		t.Fatal("pending VNC network was rejected")
	}

	connected := newVncSession("connected", nil, manager)
	connectedContext, ok := connected.beginConnect()
	if !ok {
		t.Fatal("connected VNC connection did not start")
	}
	connectedClient, connectedPeer := net.Pipe()
	defer connectedClient.Close()
	defer connectedPeer.Close()
	connected.stateMu.Lock()
	connected.netConn = connectedClient
	connected.conn = &vnc.ClientConn{}
	connected.stateMu.Unlock()

	manager.sessions[pending.id] = pending
	manager.sessions[connected.id] = connected
	manager.cancelPendingVncConnections()

	select {
	case <-pendingContext.Done():
	default:
		t.Fatal("pending VNC handshake was not cancelled")
	}
	select {
	case <-connectedContext.Done():
		t.Fatal("established VNC session was cancelled")
	default:
	}

	pending.endConnect()
	connected.endConnect()
}

func TestVncCommandHostPortWinsOverPersistedPort(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port)
VALUES ('vnc-node', NULL, 'VNC node', 1, 6, 'vnc.example', 5900);
`)
	if err != nil {
		t.Fatal(err)
	}

	target, err := resolveVncTarget(database, backendCommand{NodeID: "vnc-node", Host: "vnc.example:5901"})
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "vnc.example" || target.port != 5901 {
		t.Fatalf("got target %q:%d", target.host, target.port)
	}
}

func TestResolveVncTargetPreservesQuickConnectTunnel(t *testing.T) {
	const tunnelID = "11111111-2222-3333-4444-555555555555"
	target, err := resolveVncTarget(nil, backendCommand{
		Host: "vnc.example", TunnelConfigID: tunnelID,
	})
	if err != nil {
		t.Fatalf("resolve VNC target with tunnel: %v", err)
	}
	if target.tunnelConfigID != tunnelID {
		t.Fatalf("quick-connect tunnel was not preserved: %#v", target)
	}
}

func TestResolveVncTargetPreservesSavedTunnelInheritance(t *testing.T) {
	const tunnelID = "11111111-2222-3333-4444-555555555555"
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL,
    TunnelEnabled INTEGER NULL,
    TunnelConfigId TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, TunnelConfigId)
VALUES ('vnc-node', NULL, 'Private VNC', 1, 6, 'vnc.example', 5900, 1, '` + tunnelID + `');
`)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolveVncTarget(database, backendCommand{NodeID: "vnc-node"})
	if err != nil {
		t.Fatal(err)
	}
	if target.tunnelConfigID != tunnelID || target.nodeID != "vnc-node" || target.displayName != "Private VNC" {
		t.Fatalf("saved VPN route was not preserved: %#v", target)
	}
}

func TestVncCommandRejectsSavedTunnelOverride(t *testing.T) {
	err := validateBackendCommand(backendCommand{
		ID: "command-1", Action: "vnc.connect", SessionID: "session-1",
		NodeID: "saved-vnc", TunnelConfigID: "11111111-2222-3333-4444-555555555555",
	})
	if err == nil {
		t.Fatal("VNC command allowed a saved connection tunnel override")
	}
}

func TestVncCommandRejectsSavedCredentialOverride(t *testing.T) {
	err := validateBackendCommand(backendCommand{
		ID: "command-1", Action: "vnc.connect", SessionID: "session-1",
		NodeID: "saved-vnc", CredentialID: "11111111-2222-3333-4444-555555555555",
	})
	if err == nil {
		t.Fatal("VNC command allowed a saved connection credential override")
	}
}

func TestFinishTunnelAcquireHandlesCancellationBeforeLeaseCreation(t *testing.T) {
	outputFile, err := os.CreateTemp(t.TempDir(), "backend-output-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	output := newBackendLineWriter(outputFile)
	manager := newVncManager(nil, output)
	manager.finishTunnelAcquire(
		backendCommand{ID: "command-1", SessionID: "lease-1"},
		nil,
		nil,
		errors.New("cancelled"),
	)
	if err := outputFile.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "VPN tunnel establishment was cancelled") {
		t.Fatalf("unexpected cancellation response: %s", data)
	}
}

func TestFinishTunnelAcquireCannotReplaceNewAttemptWithLateOldLease(t *testing.T) {
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(&bytes.Buffer{})})
	oldStart := &pendingTunnelStart{cancel: func() {}}
	newStart := &pendingTunnelStart{cancel: func() {}}
	manager.tunnelStarts["shared-session"] = newStart

	oldProcess := newTestTunnelProcess()
	oldPool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		return nil, errors.New("unexpected start")
	})
	oldEntry := &sharedTunnelEntry{key: "old", refs: 1, process: oldProcess}
	oldPool.entries[oldEntry.key] = oldEntry
	manager.finishTunnelAcquire(
		backendCommand{ID: "old-command", SessionID: "shared-session"},
		oldStart,
		&tunnelRuntime{entry: oldEntry, pool: oldPool},
		nil,
	)

	if manager.tunnelStarts["shared-session"] != newStart {
		t.Fatal("late old acquisition removed the replacement attempt")
	}
	if manager.tunnelLeases["shared-session"] != nil {
		t.Fatal("late old acquisition replaced the new attempt with its stale lease")
	}
	if oldProcess.alive() {
		t.Fatal("late old acquisition did not close its orphaned sidecar reference")
	}
}

func TestReleaseTunnelWaitsForPendingAcquireCleanup(t *testing.T) {
	var output bytes.Buffer
	writer := &backendLineWriter{writer: bufio.NewWriter(&output)}
	manager := newVncManager(nil, writer)
	cancelled := make(chan struct{})
	finished := make(chan struct{})
	manager.tunnelStarts["pending-session"] = &pendingTunnelStart{
		cancel: func() { close(cancelled) },
		done:   finished,
	}

	manager.releaseTunnel(backendCommand{
		ID: "release-pending", Action: "tunnel.release", SessionID: "pending-session",
	})
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("pending tunnel acquire was not cancelled")
	}
	time.Sleep(20 * time.Millisecond)
	writer.mu.Lock()
	earlyOutput := output.String()
	writer.mu.Unlock()
	if strings.Contains(earlyOutput, "release-pending") {
		t.Fatal("pending tunnel release was acknowledged before acquire cleanup completed")
	}

	close(finished)
	manager.cleanup.Wait()
	writer.mu.Lock()
	finalOutput := output.String()
	writer.mu.Unlock()
	if !strings.Contains(finalOutput, `"id":"release-pending"`) || !strings.Contains(finalOutput, `"ok":true`) {
		t.Fatalf("pending tunnel release response = %q", finalOutput)
	}
}

func TestVncInlinePasswordFlagDoesNotSuppressSavedCredentialInheritance(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    SecretProvider INTEGER NULL,
    Protocol INTEGER NULL,
    Kind INTEGER NULL
);
CREATE TABLE CredentialSecrets (
    Id TEXT PRIMARY KEY NOT NULL,
    Secret TEXT NOT NULL,
    Encoding TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, CredentialId, CredentialMode)
VALUES ('folder', NULL, 'VNC defaults', 0, 6, 'vnc-credential', 2);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Host, UseInlinePassword)
VALUES ('leaf', 'folder', 'VNC leaf', 1, 'vnc.example', 1);
INSERT INTO CredentialProfiles (Id, SecretProvider, Protocol, Kind)
VALUES ('vnc-credential', 0, 6, 0);
INSERT INTO CredentialSecrets (Id, Secret, Encoding)
VALUES ('vnc-credential', 'not-a-secret', 'unsupported-test-encoding');
`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolveVncTarget(database, backendCommand{NodeID: "leaf"})
	if err == nil || !strings.Contains(err.Error(), errUnsupportedSecretEncoding.Error()) {
		t.Fatalf("VNC inline-password flag suppressed its inherited saved credential: %v", err)
	}
}

func TestVncUnknownCredentialModeStopsSavedCredentialInheritance(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, CredentialId, CredentialMode) VALUES
    ('folder', NULL, 'VNC defaults', 0, 6, NULL, 'parent-credential', 2),
    ('leaf', 'folder', 'VNC leaf', 1, NULL, 'vnc.example', NULL, 99);
`)
	if err != nil {
		t.Fatal(err)
	}

	target, err := resolveVncTarget(database, backendCommand{NodeID: "leaf"})
	if err != nil {
		t.Fatalf("unknown credential mode inherited the parent credential: %v", err)
	}
	if target.password != "" {
		t.Fatal("unknown credential mode resolved an inherited password")
	}
}

func TestApplyVncFramebufferUpdateProducesPng(t *testing.T) {
	session := newVncSession("test", nil, nil)
	if err := session.resetFramebuffer(2, 1); err != nil {
		t.Fatal(err)
	}

	frame, width, height, err := session.applyFramebufferUpdate(&vnc.FramebufferUpdate{
		Rects: []vnc.Rectangle{
			{
				X:      0,
				Y:      0,
				Width:  2,
				Height: 1,
				Enc: &vnc.RawEncoding{Colors: []vnc.Color{
					{R: 255, G: 0, B: 0},
					{R: 0, G: 128, B: 255},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if width != 2 || height != 1 || len(frame) == 0 {
		t.Fatalf("unexpected frame metadata: %d x %d, %d bytes", width, height, len(frame))
	}

	decoded, err := png.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, a := decoded.At(0, 0).RGBA()
	if r != 0xffff || g != 0 || b != 0 || a != 0xffff {
		t.Fatalf("unexpected first pixel: %#x %#x %#x %#x", r, g, b, a)
	}
	r, g, b, a = decoded.At(1, 0).RGBA()
	if r != 0 || g != 0x8080 || b != 0xffff || a != 0xffff {
		t.Fatalf("unexpected second pixel: %#x %#x %#x %#x", r, g, b, a)
	}
}

func TestVncFramePayloadIsBoundedForElectronTransport(t *testing.T) {
	if err := validateVncFramePayload(maxVncFramePayload); err != nil {
		t.Fatal(err)
	}
	if err := validateVncFramePayload(maxVncFramePayload + 1); err == nil {
		t.Fatal("oversized VNC frame payload was accepted")
	}
}

func TestVncRawRectangleIsBoundedBeforePayloadAllocation(t *testing.T) {
	encoder := &boundedRawEncoding{connection: &vncReadGuard{}}
	_, err := encoder.Read(nil, &vnc.Rectangle{Width: 4096, Height: 4096})
	if !errors.Is(err, errVncRawReadLimit) {
		t.Fatalf("expected raw rectangle limit error, got %v", err)
	}
}

func TestVncSessionCloseCancelsConnectContext(t *testing.T) {
	session := newVncSession("test", nil, nil)
	connectContext, ok := session.beginConnect()
	if !ok {
		t.Fatal("expected a fresh VNC session to accept a connect context")
	}
	session.close()
	select {
	case <-connectContext.Done():
	case <-time.After(time.Second):
		t.Fatal("closing a VNC session did not cancel its connect context")
	}
}

func TestVncSessionCompletesRfbHandshakeAndStreamsInput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverInputs := make(chan string, 2)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveFakeVnc(listener, serverInputs)
	}()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readPipe.Close()
	defer writePipe.Close()

	output := newBackendLineWriter(writePipe)
	manager := newVncManager(nil, output)
	session := newVncSession("rfb-test", output, manager)
	defer session.close()

	connectDone := make(chan struct{})
	go func() {
		session.connect(backendCommand{
			Action:    "vnc.connect",
			SessionID: session.id,
			Host:      "127.0.0.1",
			Port:      listener.Addr().(*net.TCPAddr).Port,
		}, nil)
		close(connectDone)
	}()

	reader := bufio.NewReader(readPipe)
	readBackendEvent(t, reader, "connecting")
	frameEvent := readBackendEvent(t, reader, "connected")
	if frameEvent.Status != "connected" {
		t.Fatalf("expected connected status, got %#v", frameEvent)
	}
	frameEvent = readBackendEvent(t, reader, "frame")
	if frameEvent.Type != "vnc.frame" || frameEvent.Width != 1 || frameEvent.Height != 1 {
		t.Fatalf("unexpected framebuffer event: %#v", frameEvent)
	}
	encodedFrame := strings.TrimPrefix(frameEvent.Image, "data:image/png;base64,")
	frameBytes, err := base64.StdEncoding.DecodeString(encodedFrame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, a := decoded.At(0, 0).RGBA()
	if r != 0xffff || g != 0 || b != 0 || a != 0xffff {
		t.Fatalf("unexpected streamed framebuffer pixel: %#x %#x %#x %#x", r, g, b, a)
	}

	if err := session.pointer(0, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := session.key(true, 0xff0d); err != nil {
		t.Fatal(err)
	}
	seenInputs := map[string]bool{}
	for len(seenInputs) < 2 {
		select {
		case input := <-serverInputs:
			seenInputs[input] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("server did not receive both input events: %#v", seenInputs)
		}
	}

	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("VNC session did not finish after the fake server closed")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func readBackendEvent(t *testing.T, reader *bufio.Reader, want string) backendEvent {
	t.Helper()
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var event backendEvent
	if err := json.Unmarshal(line, &event); err != nil {
		t.Fatal(err)
	}
	if want == "frame" && event.Type != "vnc.frame" {
		t.Fatalf("expected framebuffer event, got %#v", event)
	}
	if want != "frame" && (event.Type != "vnc.status" || event.Status != want) {
		t.Fatalf("expected VNC status %q, got %#v", want, event)
	}
	return event
}

func serveFakeVnc(listener net.Listener, inputs chan<- string) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(connection, "RFB 003.008\n"); err != nil {
		return err
	}
	clientVersion := make([]byte, 12)
	if _, err := io.ReadFull(connection, clientVersion); err != nil {
		return err
	}
	if _, err := connection.Write([]byte{1, 1}); err != nil {
		return err
	}
	var selectedSecurity [1]byte
	if _, err := io.ReadFull(connection, selectedSecurity[:]); err != nil {
		return err
	}
	if selectedSecurity[0] != 1 {
		return fmt.Errorf("client selected unexpected security type %d", selectedSecurity[0])
	}
	var clientInit [1]byte
	if _, err := io.ReadFull(connection, clientInit[:]); err != nil {
		return err
	}
	if err := writeFakeServerInit(connection); err != nil {
		return err
	}

	frameSent := false
	inputsSeen := 0
	for {
		messageType, payload, err := readFakeClientMessage(connection)
		if err != nil {
			return err
		}
		switch messageType {
		case 3:
			if !frameSent && payload[0] == 0 {
				if err := writeFakeFramebuffer(connection); err != nil {
					return err
				}
				frameSent = true
			}
		case 4:
			inputs <- "key"
			inputsSeen++
		case 5:
			inputs <- "pointer"
			inputsSeen++
		}
		if inputsSeen == 2 {
			return nil
		}
	}
}

func writeFakeServerInit(connection net.Conn) error {
	if err := binary.Write(connection, binary.BigEndian, uint16(1)); err != nil {
		return err
	}
	if err := binary.Write(connection, binary.BigEndian, uint16(1)); err != nil {
		return err
	}
	// 32bpp, 24-bit depth, little-endian true color, RGB shifts 16/8/0.
	if _, err := connection.Write([]byte{
		32, 24, 0, 1,
		0, 255, 0, 255, 0, 255,
		16, 8, 0,
		0, 0, 0,
	}); err != nil {
		return err
	}
	return binary.Write(connection, binary.BigEndian, uint32(0))
}

func writeFakeFramebuffer(connection net.Conn) error {
	message := make([]byte, 4+12+4)
	message[0] = 0
	binary.BigEndian.PutUint16(message[2:4], 1)
	binary.BigEndian.PutUint16(message[8:10], 1)
	binary.BigEndian.PutUint16(message[10:12], 1)
	// Raw encoding, followed by one red pixel in the negotiated little-endian format.
	binary.BigEndian.PutUint32(message[12:16], 0)
	copy(message[16:], []byte{0, 0, 255, 0})
	_, err := connection.Write(message)
	return err
}

func readFakeClientMessage(connection net.Conn) (byte, []byte, error) {
	var messageType [1]byte
	if _, err := io.ReadFull(connection, messageType[:]); err != nil {
		return 0, nil, err
	}
	switch messageType[0] {
	case 0:
		payload := make([]byte, 19)
		_, err := io.ReadFull(connection, payload)
		return messageType[0], payload, err
	case 2:
		header := make([]byte, 3)
		if _, err := io.ReadFull(connection, header); err != nil {
			return 0, nil, err
		}
		payload := make([]byte, 3+int(binary.BigEndian.Uint16(header[1:3]))*4)
		copy(payload, header)
		_, err := io.ReadFull(connection, payload[3:])
		return messageType[0], payload, err
	case 3:
		payload := make([]byte, 9)
		_, err := io.ReadFull(connection, payload)
		return messageType[0], payload, err
	case 4:
		payload := make([]byte, 7)
		_, err := io.ReadFull(connection, payload)
		return messageType[0], payload, err
	case 5:
		payload := make([]byte, 5)
		_, err := io.ReadFull(connection, payload)
		return messageType[0], payload, err
	default:
		return 0, nil, fmt.Errorf("unexpected client message type %d", messageType[0])
	}
}

func TestVncTargetCanResolvePersistedHostAndPort(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Host, Port)
VALUES ('folder', NULL, 'Folder', 0, 'vnc.example', 5904),
       ('connection', 'folder', 'Connection', 1, NULL, NULL);
`)
	if err != nil {
		t.Fatal(err)
	}

	target, err := resolveVncTarget(database, backendCommand{
		Host:     "",
		NodeID:   "connection",
		Port:     0,
		Password: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "vnc.example" || target.port != 5904 {
		t.Fatalf("got target %q:%d", target.host, target.port)
	}
}

func TestVncTargetRejectsInheritedVpnRouting(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL,
    TunnelEnabled INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled)
VALUES ('vpn-folder', NULL, 'VPN folder', 0, 6, 'vnc.example', 5900, 1),
       ('vpn-connection', 'vpn-folder', 'VPN connection', 1, 6, NULL, NULL, NULL);
`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolveVncTarget(database, backendCommand{
		NodeID:   "vpn-connection",
		Host:     "direct.example",
		Port:     5900,
		Password: "typed-at-connect-time",
	})
	if err == nil {
		t.Fatal("VNC target with inherited VPN routing was allowed to fall back to direct TCP")
	}
}

func TestVncTargetRejectsNonVncProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port)
VALUES ('ssh-node', NULL, 'SSH node', 1, 0, 'ssh.example', 22);
`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolveVncTarget(database, backendCommand{NodeID: "ssh-node"})
	if err == nil || !strings.Contains(err.Error(), "VNC protocol") {
		t.Fatalf("expected non-VNC protocol error, got %v", err)
	}
}

func TestLoadTreeResolvesInheritedVncProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host)
VALUES ('vnc-folder', NULL, 'VNC folder', 0, 6, NULL),
       ('vnc-connection', 'vnc-folder', 'Inherited VNC', 1, NULL, 'vnc.example');
`)
	if err != nil {
		t.Fatal(err)
	}

	tree, err := loadTree(database)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 1 || len(tree[0].Children) != 1 {
		t.Fatalf("unexpected tree: %#v", tree)
	}
	if tree[0].Children[0].Protocol != "vnc" {
		t.Fatalf("expected inherited VNC protocol, got %q", tree[0].Children[0].Protocol)
	}
}

func TestVncTargetRejectsParentCycle(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    Host TEXT NULL,
    Port INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port)
VALUES ('cycle-a', 'cycle-b', 'Cycle A', 0, NULL, 'vnc.example', 5900),
       ('cycle-b', 'cycle-a', 'Cycle B', 1, 6, NULL, NULL);
`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolveVncTarget(database, backendCommand{NodeID: "cycle-b"})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected parent-cycle error, got %v", err)
	}
}

func TestStoredVncSecretSizeIsBounded(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`
CREATE TABLE CredentialSecrets (
    Id TEXT PRIMARY KEY NOT NULL,
    Secret TEXT NOT NULL,
    Encoding TEXT NOT NULL
);
INSERT INTO CredentialSecrets (Id, Secret, Encoding)
VALUES ('too-large', ?, 'windows-dpapi-v1');
`, strings.Repeat("A", maxVncEncodedSecret+1))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = readStoredSecret(database, "too-large")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected oversized-secret error, got %v", err)
	}
}

func TestLoadTreeRejectsInheritedProtocolCycle(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
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
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host)
VALUES ('cycle-a', 'cycle-b', 'Cycle A', 0, 0, NULL, NULL),
       ('cycle-b', 'cycle-a', 'Cycle B', 1, 1, NULL, 'vnc.example');
`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadTree(database)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected inherited-protocol cycle error, got %v", err)
	}
}

func TestPublicVncConnectErrorOffersManualFallbackForUnavailableBitwardenCredential(t *testing.T) {
	message, passwordRequired := publicVncConnectError(errors.New("the linked Bitwarden item was not found"))
	if !passwordRequired || !strings.Contains(message, "Enter the VNC password") {
		t.Fatalf("manual fallback was not offered: message=%q required=%v", message, passwordRequired)
	}
}

func TestPublicVncConnectErrorKeepsLockedVaultUnlockFlow(t *testing.T) {
	message, passwordRequired := publicVncConnectError(errors.New("Bitwarden vault is locked or the session is invalid"))
	if passwordRequired || !strings.Contains(message, "vault is locked") {
		t.Fatalf("locked vault was not preserved: message=%q required=%v", message, passwordRequired)
	}
}
