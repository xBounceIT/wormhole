package main

import (
	"errors"
	"io"
	"path/filepath"
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
