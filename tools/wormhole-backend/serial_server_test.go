package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativeSerial "go.bug.st/serial"
)

func TestNormalizeSerialTargetAppliesWinUIValues(t *testing.T) {
	target, err := normalizeSerialTarget(serialTarget{
		PortName:    " COM10 ",
		BaudRate:    0,
		DataBits:    4,
		StopBits:    0,
		Parity:      9,
		FlowControl: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.PortName != "COM10" || target.BaudRate != 9600 || target.DataBits != 8 ||
		target.StopBits != 1 || target.Parity != serialParityNone || target.FlowControl != serialFlowNone {
		t.Fatalf("unexpected normalized serial target: %#v", target)
	}

	if _, err := normalizeSerialTarget(serialTarget{PortName: "COM\x00"}); err == nil {
		t.Fatal("expected an invalid serial line name to be rejected")
	}
}

func TestResolveSerialTargetFromNodesInheritsFolderSettings(t *testing.T) {
	rootProtocol := serialProtocolValue
	rootBaud := int64(115200)
	rootDataBits := int64(7)
	rootStopBits := int64(2)
	rootParity := int64(serialParityEven)
	rootFlow := int64(serialFlowRtsCts)
	leafProtocol := serialProtocolValue
	leafBaud := int64(57600)
	nodes := map[string]*serialNode{
		"folder": {
			id:          "folder",
			kind:        0,
			protocol:    &rootProtocol,
			host:        "COM10",
			baudRate:    &rootBaud,
			dataBits:    &rootDataBits,
			stopBits:    &rootStopBits,
			parity:      &rootParity,
			flowControl: &rootFlow,
		},
		"leaf": {
			id:       "leaf",
			kind:     1,
			parentID: "folder",
			protocol: &leafProtocol,
			baudRate: &leafBaud,
		},
	}

	target, err := resolveSerialTargetFromNodes(nodes, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if target.PortName != "COM10" || target.BaudRate != 57600 || target.DataBits != 7 ||
		target.StopBits != 2 || target.Parity != serialParityEven || target.FlowControl != serialFlowRtsCts {
		t.Fatalf("unexpected inherited serial target: %#v", target)
	}
}

func TestLoadTreePublishesEffectiveSerialSettings(t *testing.T) {
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
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    SerialBaudRate INTEGER NULL,
    SerialDataBits INTEGER NULL,
    SerialStopBits INTEGER NULL,
    SerialParity INTEGER NULL,
    SerialFlowControl INTEGER NULL,
    TunnelEnabled INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host, SerialBaudRate, SerialDataBits, SerialStopBits, SerialParity, SerialFlowControl, TunnelEnabled, UpdatedAt) VALUES
    ('folder', NULL, 'Serial defaults', 0, 0, 5, 'COM10', 115200, 7, 2, 2, 2, 1, 'now'),
    ('leaf', 'folder', 'Serial console', 1, 0, NULL, NULL, 57600, NULL, NULL, NULL, NULL, NULL, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}

	tree, err := loadTree(database)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 1 || len(tree[0].Children) != 1 {
		t.Fatalf("unexpected tree shape: %#v", tree)
	}
	leaf := tree[0].Children[0]
	if leaf.Protocol != "serial" || leaf.Host != "COM10" || leaf.SerialBaudRate == nil ||
		*leaf.SerialBaudRate != 57600 || leaf.SerialDataBits == nil || *leaf.SerialDataBits != 7 ||
		leaf.SerialStopBits == nil || *leaf.SerialStopBits != 2 || leaf.SerialParity == nil ||
		*leaf.SerialParity != serialParityEven || leaf.SerialFlowControl == nil ||
		*leaf.SerialFlowControl != serialFlowRtsCts {
		t.Fatalf("unexpected effective serial tree node: %#v", leaf)
	}
}

func TestSerialXonXoffFiltersControlBytesAndPausesWrites(t *testing.T) {
	port := &testSerialPort{}
	native := newSerialNativeSession(port, serialTarget{FlowControl: serialFlowXonXoff}, 80, 24)
	defer native.close(false)

	filtered := native.consumeSoftwareFlowControl([]byte{'a', 0x13, 'b', 0x11, 'c'})
	if string(filtered) != "abc" {
		t.Fatalf("unexpected filtered serial data: %q", filtered)
	}

	native.setRemotePaused(true)
	writeDone := make(chan error, 1)
	go func() { writeDone <- native.writePortData([]byte("x")) }()
	select {
	case err := <-writeDone:
		t.Fatalf("serial write completed while remote was paused: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	native.setRemotePaused(false)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serial write did not resume after XON")
	}
	if got := string(port.lastWrite()); got != "x" {
		t.Fatalf("unexpected serial write: %q", got)
	}
}

func TestSerialWaitForTransmitHonorsModemStatus(t *testing.T) {
	port := &testSerialPort{}
	native := newSerialNativeSession(port, serialTarget{FlowControl: serialFlowRtsCts}, 80, 24)
	defer native.close(false)

	transmitReady := make(chan error, 1)
	go func() { transmitReady <- native.waitForTransmit() }()
	select {
	case err := <-transmitReady:
		t.Fatalf("serial write ignored CTS=false: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	port.setStatus(nativeSerial.ModemStatusBits{CTS: true})
	select {
	case err := <-transmitReady:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serial write did not resume after CTS=true")
	}

	port.setStatus(nativeSerial.ModemStatusBits{})
	dsrNative := newSerialNativeSession(port, serialTarget{FlowControl: serialFlowDsrDtr}, 80, 24)
	defer dsrNative.close(false)
	dsrReady := make(chan error, 1)
	go func() { dsrReady <- dsrNative.waitForTransmit() }()
	select {
	case err := <-dsrReady:
		t.Fatalf("serial write ignored DSR=false: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	port.setStatus(nativeSerial.ModemStatusBits{DSR: true})
	select {
	case err := <-dsrReady:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serial write did not resume after DSR=true")
	}
}

func TestSerialWaitForTransmitReturnsWhenClosed(t *testing.T) {
	port := &testSerialPort{}
	native := newSerialNativeSession(port, serialTarget{FlowControl: serialFlowRtsCts}, 80, 24)

	transmitReady := make(chan error, 1)
	go func() { transmitReady <- native.waitForTransmit() }()
	select {
	case err := <-transmitReady:
		t.Fatalf("serial write completed before close with CTS=false: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	native.close(false)
	select {
	case err := <-transmitReady:
		if !errors.Is(err, errSerialSessionClosed) {
			t.Fatalf("unexpected close wait error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serial write did not unblock after close")
	}
}

func TestSerialPauseResumeAppliesReceiveFlowControl(t *testing.T) {
	xonPort := &testSerialPort{}
	xonNative := newSerialNativeSession(xonPort, serialTarget{FlowControl: serialFlowXonXoff}, 80, 24)
	defer xonNative.close(false)

	xonNative.PauseReading()
	if got := xonPort.lastWrite(); len(got) != 1 || got[0] != 0x13 {
		t.Fatalf("serial XON/XOFF pause wrote %v, want XOFF", got)
	}
	xonNative.ResumeReading()
	if got := xonPort.lastWrite(); len(got) != 1 || got[0] != 0x11 {
		t.Fatalf("serial XON/XOFF resume wrote %v, want XON", got)
	}

	rtsPort := &testSerialPort{rts: true}
	rtsNative := newSerialNativeSession(rtsPort, serialTarget{FlowControl: serialFlowRtsCts}, 80, 24)
	defer rtsNative.close(false)
	rtsNative.PauseReading()
	if _, rts := rtsPort.lines(); rts {
		t.Fatal("serial RTS/CTS pause left RTS asserted")
	}
	rtsNative.ResumeReading()
	if _, rts := rtsPort.lines(); !rts {
		t.Fatal("serial RTS/CTS resume did not assert RTS")
	}

	dtrPort := &testSerialPort{dtr: true}
	dtrNative := newSerialNativeSession(dtrPort, serialTarget{FlowControl: serialFlowDsrDtr}, 80, 24)
	defer dtrNative.close(false)
	dtrNative.PauseReading()
	if dtr, _ := dtrPort.lines(); dtr {
		t.Fatal("serial DSR/DTR pause left DTR asserted")
	}
	dtrNative.ResumeReading()
	if dtr, _ := dtrPort.lines(); !dtr {
		t.Fatal("serial DSR/DTR resume did not assert DTR")
	}
}

func TestSerialModeMapsParityAndStopBits(t *testing.T) {
	mode := serialMode(serialTarget{
		BaudRate: 115200,
		DataBits: 7,
		Parity:   serialParityMark,
		StopBits: 3,
	})
	if mode.BaudRate != 115200 || mode.DataBits != 7 || mode.Parity != nativeSerial.MarkParity ||
		mode.StopBits != nativeSerial.OnePointFiveStopBits || mode.InitialStatusBits == nil ||
		!mode.InitialStatusBits.DTR || !mode.InitialStatusBits.RTS {
		t.Fatalf("unexpected native serial mode: %#v", mode)
	}
}

func TestServeSerialDispatchesInvalidAndDisconnectedCommands(t *testing.T) {
	longID := strings.Repeat("s", serialMaxSessionIDLength+1)
	commands := []string{
		`{`,
		`{"type":"input","session_id":""}`,
		`{"type":"unsupported","session_id":"session"}`,
		`{"type":"input","session_id":"session","data":"%%%"}`,
		`{"type":"input","session_id":"session","data":"YQ=="}`,
		`{"type":"resize","session_id":"session","columns":80,"rows":24}`,
		`{"type":"snapshot","session_id":"session"}`,
		`{"type":"close","session_id":"session"}`,
		`{"type":"open","session_id":"session"}`,
		fmt.Sprintf(`{"type":"open","session_id":"session","node_id":%q}`, longID),
	}
	var output synchronizedBuffer
	if err := serveSerial("", strings.NewReader(strings.Join(commands, "\n")), &output, "userdata"); err != nil {
		t.Fatalf("serveSerial returned %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	events := 0
	for decoder.More() {
		var event serialWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		events++
	}
	if events < 6 {
		t.Fatalf("serveSerial emitted only %d events: %s", events, output.String())
	}
}

func TestSerialServerManagesConnectedSession(t *testing.T) {
	var output synchronizedBuffer
	server := &serialServer{
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	port := &testSerialPort{}
	native := newSerialNativeSession(port, serialTarget{FlowControl: serialFlowNone}, 80, 24)
	native.id = "session"
	native.server = server
	server.sessions[native.id] = native

	server.handle(serialWireCommand{Type: "input", SessionID: "session", Data: base64.StdEncoding.EncodeToString([]byte("hello"))})
	if len(native.inputQueue) != 1 {
		t.Fatalf("input queue length = %d", len(native.inputQueue))
	}
	server.handle(serialWireCommand{Type: "resize", SessionID: "session", Columns: 100, Rows: 40})
	server.handle(serialWireCommand{Type: "snapshot", SessionID: "session"})
	if !server.isActive(native) {
		t.Fatal("connected session was not active")
	}
	if !server.publishConnected("session", native, serialWireEvent{Type: "connected", SessionID: "session"}) {
		t.Fatal("publishConnected rejected active session")
	}
	if server.publishConnected("missing", native, serialWireEvent{}) {
		t.Fatal("publishConnected accepted inactive session")
	}

	server.handle(serialWireCommand{Type: "close", SessionID: "session"})
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), `"type":"closed"`) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.isActive(native) || !native.isClosed() {
		t.Fatal("close did not remove and close session")
	}
}

func TestSerialServerOpenResolvesAndSupervisesNativeSession(t *testing.T) {
	previousResolve := resolveSerialTargetForOpen
	previousOpen := openNativeSerialForOpen
	t.Cleanup(func() {
		resolveSerialTargetForOpen = previousResolve
		openNativeSerialForOpen = previousOpen
	})
	resolveSerialTargetForOpen = func(ctx context.Context, databasePath, userDataPath string, command serialWireCommand) (serialTarget, error) {
		if err := ctx.Err(); err != nil {
			return serialTarget{}, err
		}
		if databasePath != "database" || userDataPath != "userdata" || command.PortName != "COM42" {
			t.Fatalf("unexpected serial resolve request: %#v", command)
		}
		return serialTarget{PortName: "COM42", BaudRate: 115200, DataBits: 8, StopBits: 1}, nil
	}
	port := newBlockingSerialPort()
	openNativeSerialForOpen = func(ctx context.Context, target serialTarget, columns, rows uint32) (*serialNativeSession, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if target.PortName != "COM42" || columns != 100 || rows != 40 {
			t.Fatalf("unexpected native open: %#v %dx%d", target, columns, rows)
		}
		return newSerialNativeSession(port, target, columns, rows), nil
	}
	var output synchronizedBuffer
	server := &serialServer{
		databasePath: "database", electronUserDataPath: "userdata",
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession), pending: make(map[string]context.CancelFunc),
	}
	command := serialWireCommand{Type: "open", SessionID: "session", PortName: "COM42", Columns: 100, Rows: 40}
	server.open(command)
	waitForSerialOutput(t, &output, `"type":"connected"`)
	server.open(command)
	waitForSerialOutput(t, &output, "already open")
	server.close(command.SessionID)
	waitForSerialOutput(t, &output, `"type":"closed"`)
	if !port.closedState() {
		t.Fatal("serial close did not close native port")
	}
}

func TestSerialServerOpenReportsResolutionAndNativeFailures(t *testing.T) {
	previousResolve := resolveSerialTargetForOpen
	previousOpen := openNativeSerialForOpen
	t.Cleanup(func() {
		resolveSerialTargetForOpen = previousResolve
		openNativeSerialForOpen = previousOpen
	})
	var output synchronizedBuffer
	server := &serialServer{
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession), pending: make(map[string]context.CancelFunc),
	}
	resolveSerialTargetForOpen = func(context.Context, string, string, serialWireCommand) (serialTarget, error) {
		return serialTarget{}, errors.New("resolve failed")
	}
	server.open(serialWireCommand{SessionID: "resolve", PortName: "COM1"})
	waitForSerialOutput(t, &output, "resolve failed")
	waitForSerialPendingClear(t, server, "resolve")

	resolveSerialTargetForOpen = func(context.Context, string, string, serialWireCommand) (serialTarget, error) {
		return serialTarget{PortName: "COM1"}, nil
	}
	openNativeSerialForOpen = func(context.Context, serialTarget, uint32, uint32) (*serialNativeSession, error) {
		return nil, errors.New("open failed")
	}
	server.open(serialWireCommand{SessionID: "open", PortName: "COM1"})
	waitForSerialOutput(t, &output, "open failed")
	waitForSerialPendingClear(t, server, "open")

	releaseOpen := make(chan struct{})
	openNativeSerialForOpen = func(context.Context, serialTarget, uint32, uint32) (*serialNativeSession, error) {
		<-releaseOpen
		return nil, errors.New("open failed")
	}
	server.open(serialWireCommand{SessionID: "pending", PortName: "COM1"})
	server.open(serialWireCommand{SessionID: "pending", PortName: "COM1"})
	close(releaseOpen)
	waitForSerialOutput(t, &output, "already connecting")
	waitForSerialPendingClear(t, server, "pending")
}

func TestResolveSerialTargetLoadsSavedAndQuickConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolveSerialTarget(ctx, "", "", serialWireCommand{PortName: "COM1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled target resolution = %v", err)
	}
	quick, err := resolveSerialTarget(context.Background(), "", "userdata", serialWireCommand{
		PortName: " COM7 ", BaudRate: 19200, DataBits: 7, StopBits: 2,
		Parity: serialParityEven, FlowControl: serialFlowRtsCts,
	})
	if err != nil || quick.PortName != "COM7" || quick.BaudRate != 19200 {
		t.Fatalf("quick serial target = %#v, %v", quick, err)
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY, ParentId TEXT NULL, Kind INTEGER NOT NULL, Protocol INTEGER NULL,
    Host TEXT NULL, SerialBaudRate INTEGER NULL, SerialDataBits INTEGER NULL,
    SerialStopBits INTEGER NULL, SerialParity INTEGER NULL, SerialFlowControl INTEGER NULL
);
INSERT INTO Nodes VALUES ('saved', NULL, 1, 5, 'COM9', 57600, 8, 1, 0, 0);`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	saved, err := resolveSerialTarget(context.Background(), databasePath, "", serialWireCommand{NodeID: "saved"})
	if err != nil || saved.NodeID != "saved" || saved.PortName != "COM9" || saved.BaudRate != 57600 {
		t.Fatalf("saved serial target = %#v, %v", saved, err)
	}
	if _, err := loadSerialTarget(databasePath, "missing"); err == nil {
		t.Fatal("missing saved serial target was accepted")
	}
	if _, err := loadSerialTarget(filepath.Join(t.TempDir(), "missing.db"), "saved"); err == nil {
		t.Fatal("missing serial database was accepted")
	}
}

func TestSerialModesAndPublicErrorsCoverAllMappings(t *testing.T) {
	parities := map[int]nativeSerial.Parity{
		serialParityNone:  nativeSerial.NoParity,
		serialParityOdd:   nativeSerial.OddParity,
		serialParityEven:  nativeSerial.EvenParity,
		serialParityMark:  nativeSerial.MarkParity,
		serialParitySpace: nativeSerial.SpaceParity,
	}
	for input, want := range parities {
		if mode := serialMode(serialTarget{Parity: input, StopBits: 2}); mode.Parity != want || mode.StopBits != nativeSerial.TwoStopBits {
			t.Fatalf("serial mode %d = %#v", input, mode)
		}
	}
	for _, test := range []struct {
		err      error
		contains string
	}{
		{err: nil, contains: "Serial connection failed."},
		{err: errors.New(""), contains: "Serial connection failed."},
		{err: errors.New("port unavailable"), contains: "port unavailable"},
		{err: errors.New(strings.Repeat("x", 532)), contains: strings.Repeat("x", 20)},
	} {
		if message := publicSerialError(test.err); !strings.Contains(message, test.contains) {
			t.Fatalf("public serial error = %q", message)
		}
	}
	if nullableSerialValue(nil) != 0 {
		t.Fatal("nil serial value was accepted")
	}
}

func waitForSerialOutput(t *testing.T, output interface{ String() string }, expected string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(output.String(), expected) {
		if time.Now().After(deadline) {
			t.Fatalf("serial output did not contain %q: %s", expected, output.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForSerialPendingClear(t *testing.T, server *serialServer, sessionID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		_, pending := server.pending[sessionID]
		server.mu.Unlock()
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("serial session %q remained pending", sessionID)
		}
		time.Sleep(time.Millisecond)
	}
}

type blockingSerialPort struct {
	testSerialPort
	release chan struct{}
	once    sync.Once
}

func newBlockingSerialPort() *blockingSerialPort {
	return &blockingSerialPort{release: make(chan struct{})}
}

func (port *blockingSerialPort) Read([]byte) (int, error) {
	<-port.release
	return 0, io.EOF
}

func (port *blockingSerialPort) Close() error {
	port.once.Do(func() { close(port.release) })
	return port.testSerialPort.Close()
}

func (port *blockingSerialPort) closedState() bool {
	port.mu.Lock()
	defer port.mu.Unlock()
	return port.closed
}

func TestSerialServerPendingPromotionAndShutdown(t *testing.T) {
	var output synchronizedBuffer
	server := &serialServer{
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	cancelled := false
	server.pending["pending"] = func() { cancelled = true }
	port := &testSerialPort{}
	native := newSerialNativeSession(port, serialTarget{}, 80, 24)
	native.id = "pending"
	native.server = server
	if !server.promote("pending", native) || server.promote("missing", native) {
		t.Fatal("serial promotion state was incorrect")
	}
	server.remove(native)
	if server.isActive(native) {
		t.Fatal("remove left session active")
	}
	server.pending["pending"] = func() { cancelled = true }
	if !server.finishPending("pending") || server.finishPending("missing") {
		t.Fatal("finishPending result was incorrect")
	}

	server.pending["shutdown"] = func() { cancelled = true }
	shutdownNative := newSerialNativeSession(&testSerialPort{}, serialTarget{}, 80, 24)
	shutdownNative.id = "shutdown"
	shutdownNative.server = server
	server.sessions["shutdown"] = shutdownNative
	server.shutdown()
	if !cancelled || !shutdownNative.isClosed() || len(server.pending) != 0 || len(server.sessions) != 0 {
		t.Fatalf("shutdown state: cancelled=%v pending=%d sessions=%d closed=%v", cancelled, len(server.pending), len(server.sessions), shutdownNative.isClosed())
	}
}

func TestSerialNativeSessionLifecyclePublishesFrames(t *testing.T) {
	var output synchronizedBuffer
	server := &serialServer{
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	native := newSerialNativeSession(&testSerialPort{}, serialTarget{}, 80, 24)
	native.id = "session"
	native.server = server
	server.sessions[native.id] = native
	native.publishTerminalData([]byte("hello\r\n"))
	native.publishTerminalFrame(native.terminal.snapshot())
	native.start()
	deadline := time.Now().Add(time.Second)
	for !native.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !native.isClosed() {
		t.Fatal("native session did not close after EOF")
	}
	if !strings.Contains(output.String(), `"type":"screen"`) {
		t.Fatalf("screen frames were not published: %s", output.String())
	}
}

func TestSerialNativeSessionRecoversTerminalEmulatorPanicWithoutClosingConnection(t *testing.T) {
	var output synchronizedBuffer
	server := &serialServer{
		output:   &serialEventWriter{encoder: json.NewEncoder(&output)},
		sessions: make(map[string]*serialNativeSession),
		pending:  make(map[string]context.CancelFunc),
	}
	native := newSerialNativeSession(&testSerialPort{}, serialTarget{}, 8, 2)
	brokenTerminal := &sshTerminalEmulator{columns: 8, rows: 2}
	native.id = "session"
	native.server = server
	native.terminal = brokenTerminal
	server.sessions[native.id] = native

	native.publishTerminalData([]byte("serial ready"))
	native.publishTerminalData([]byte("next frame"))

	if native.isClosed() {
		t.Fatal("terminal emulator panic closed the serial connection")
	}
	if server.sessions[native.id] != native {
		t.Fatal("terminal emulator panic removed the active serial session")
	}
	if native.terminal == brokenTerminal || native.terminal.vt == nil {
		t.Fatal("terminal emulator panic did not install a healthy replacement")
	}
	if !native.terminalRecoveryLogged {
		t.Fatal("terminal emulator recovery was not recorded")
	}
	decoder := json.NewDecoder(&output)
	for index := 0; index < 2; index++ {
		var event serialWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "screen" || event.Frame == nil {
			t.Fatalf("terminal recovery event %d = %#v", index, event)
		}
	}
	var extra serialWireEvent
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected event after terminal recovery: event=%#v err=%v", extra, err)
	}
}

type testSerialPort struct {
	mu     sync.Mutex
	writes [][]byte
	dtr    bool
	rts    bool
	status nativeSerial.ModemStatusBits
	closed bool
}

func (port *testSerialPort) Read([]byte) (int, error) { return 0, io.EOF }

func (port *testSerialPort) Write(data []byte) (int, error) {
	port.mu.Lock()
	defer port.mu.Unlock()
	if port.closed {
		return 0, errors.New("port closed")
	}
	port.writes = append(port.writes, append([]byte(nil), data...))
	return len(data), nil
}

func (port *testSerialPort) Drain() error { return nil }

func (port *testSerialPort) SetDTR(enabled bool) error {
	port.mu.Lock()
	defer port.mu.Unlock()
	port.dtr = enabled
	return nil
}

func (port *testSerialPort) SetRTS(enabled bool) error {
	port.mu.Lock()
	defer port.mu.Unlock()
	port.rts = enabled
	return nil
}

func (port *testSerialPort) GetModemStatusBits() (*nativeSerial.ModemStatusBits, error) {
	port.mu.Lock()
	defer port.mu.Unlock()
	status := port.status
	return &status, nil
}

func (port *testSerialPort) setStatus(status nativeSerial.ModemStatusBits) {
	port.mu.Lock()
	defer port.mu.Unlock()
	port.status = status
}

func (port *testSerialPort) Close() error {
	port.mu.Lock()
	defer port.mu.Unlock()
	port.closed = true
	return nil
}

func (port *testSerialPort) lastWrite() []byte {
	port.mu.Lock()
	defer port.mu.Unlock()
	if len(port.writes) == 0 {
		return nil
	}
	return append([]byte(nil), port.writes[len(port.writes)-1]...)
}

func (port *testSerialPort) lines() (bool, bool) {
	port.mu.Lock()
	defer port.mu.Unlock()
	return port.dtr, port.rts
}
