package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	nativeSerial "go.bug.st/serial"
)

const (
	serialProtocolValue         = int64(5)
	serialDefaultBaud           = 9600
	serialDefaultBits           = 8
	serialDefaultStop           = 1
	serialDefaultParity         = 0
	serialDefaultFlow           = 0
	serialInputMaxBytes         = 1024 * 1024
	serialInputQueueCapacity    = 16
	serialReadChunk             = 16 * 1024
	serialModemPollInterval     = 10 * time.Millisecond
	serialCloseReadDrainTimeout = 250 * time.Millisecond
	serialMaxSessionIDLength    = 128
)

const (
	serialParityNone  = 0
	serialParityOdd   = 1
	serialParityEven  = 2
	serialParityMark  = 3
	serialParitySpace = 4
)

const (
	serialFlowNone    = 0
	serialFlowXonXoff = 1
	serialFlowRtsCts  = 2
	serialFlowDsrDtr  = 3
)

// serialWireCommand is deliberately separate from sshWireCommand. Serial sessions never
// accept credentials, tunnel identifiers, or network targets at the process boundary.
type serialWireCommand struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	NodeID      string `json:"node_id"`
	PortName    string `json:"port_name"`
	BaudRate    int    `json:"baud_rate"`
	DataBits    int    `json:"data_bits"`
	StopBits    int    `json:"stop_bits"`
	Parity      int    `json:"parity"`
	FlowControl int    `json:"flow_control"`
	Data        string `json:"data"`
	Columns     uint32 `json:"columns"`
	Rows        uint32 `json:"rows"`
}

type serialWireEvent struct {
	Type        string            `json:"type"`
	SessionID   string            `json:"session_id"`
	Frame       *sshTerminalFrame `json:"frame,omitempty"`
	PortName    string            `json:"port_name,omitempty"`
	BaudRate    int               `json:"baud_rate,omitempty"`
	DataBits    int               `json:"data_bits,omitempty"`
	StopBits    int               `json:"stop_bits,omitempty"`
	Parity      int               `json:"parity,omitempty"`
	FlowControl int               `json:"flow_control,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type serialTarget struct {
	NodeID      string
	PortName    string
	BaudRate    int
	DataBits    int
	StopBits    int
	Parity      int
	FlowControl int
}

type serialNodeRow struct {
	ID          string
	ParentID    sql.NullString
	Kind        int64
	Protocol    sql.NullInt64
	Host        sql.NullString
	BaudRate    sql.NullInt64
	DataBits    sql.NullInt64
	StopBits    sql.NullInt64
	Parity      sql.NullInt64
	FlowControl sql.NullInt64
}

type serialNode struct {
	id          string
	parentID    string
	kind        int64
	protocol    *int64
	host        string
	baudRate    *int64
	dataBits    *int64
	stopBits    *int64
	parity      *int64
	flowControl *int64
}

type serialEventWriter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func (writer *serialEventWriter) write(event serialWireEvent) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	_ = writer.encoder.Encode(event)
}

type serialServer struct {
	databasePath         string
	electronUserDataPath string
	output               *serialEventWriter

	mu       sync.Mutex
	sessions map[string]*serialNativeSession
	pending  map[string]context.CancelFunc
}

var (
	resolveSerialTargetForOpen = resolveSerialTarget
	openNativeSerialForOpen    = openNativeSerial
)

func serveSerial(databasePath string, input io.Reader, output io.Writer, electronUserDataPath ...string) error {
	userDataPath := ""
	if len(electronUserDataPath) > 0 {
		userDataPath = electronUserDataPath[0]
	}
	server := &serialServer{
		databasePath:         databasePath,
		electronUserDataPath: userDataPath,
		output:               &serialEventWriter{encoder: json.NewEncoder(output)},
		sessions:             make(map[string]*serialNativeSession),
		pending:              make(map[string]context.CancelFunc),
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	for scanner.Scan() {
		var command serialWireCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			server.writeError("", "invalid serial command")
			continue
		}
		server.handle(command)
	}
	server.shutdown()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("serial command channel failed: %w", err)
	}
	return nil
}

func (server *serialServer) handle(command serialWireCommand) {
	command.Type = strings.ToLower(strings.TrimSpace(command.Type))
	command.SessionID = strings.TrimSpace(command.SessionID)
	if command.SessionID == "" || len(command.SessionID) > serialMaxSessionIDLength {
		server.writeError(command.SessionID, "serial session id is invalid")
		return
	}

	switch command.Type {
	case "open":
		server.open(command)
	case "input":
		server.input(command)
	case "resize":
		server.resize(command)
	case "snapshot":
		server.snapshot(command)
	case "close":
		server.close(command.SessionID)
	default:
		server.writeError(command.SessionID, "unsupported serial command")
	}
}

func (server *serialServer) open(command serialWireCommand) {
	nodeID := strings.TrimSpace(command.NodeID)
	portName := strings.TrimSpace(command.PortName)
	if len(nodeID) > serialMaxSessionIDLength || len(portName) > 256 {
		server.writeError(command.SessionID, "serial connection identity is invalid")
		return
	}
	if nodeID == "" && portName == "" {
		server.writeError(command.SessionID, "serial line name is required")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	server.mu.Lock()
	if _, exists := server.sessions[command.SessionID]; exists {
		server.mu.Unlock()
		cancel()
		server.writeError(command.SessionID, "serial session is already open")
		return
	}
	if _, exists := server.pending[command.SessionID]; exists {
		server.mu.Unlock()
		cancel()
		server.writeError(command.SessionID, "serial session is already connecting")
		return
	}
	server.pending[command.SessionID] = cancel
	server.mu.Unlock()

	go func() {
		target, err := resolveSerialTargetForOpen(
			ctx,
			server.databasePath,
			server.electronUserDataPath,
			command,
		)
		if err == nil {
			var native *serialNativeSession
			native, err = openNativeSerialForOpen(ctx, target, command.Columns, command.Rows)
			if err == nil {
				native.id = command.SessionID
				native.server = server
				if !server.promote(command.SessionID, native) {
					native.close(false)
					return
				}
				if !server.publishConnected(command.SessionID, native, serialWireEvent{
					Type:        "connected",
					SessionID:   command.SessionID,
					PortName:    target.PortName,
					BaudRate:    target.BaudRate,
					DataBits:    target.DataBits,
					StopBits:    target.StopBits,
					Parity:      target.Parity,
					FlowControl: target.FlowControl,
				}) {
					native.close(false)
					return
				}
				logInfo("serial session connected: %s @ %d baud", target.PortName, target.BaudRate)
				native.publishTerminalFrame(native.terminal.initialFrame())
				native.start()
				return
			}
		}

		pending := server.finishPending(command.SessionID)
		if pending && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			logError("serial session failed to connect: %v", publicSerialError(err))
			server.output.write(serialWireEvent{
				Type:      "error",
				SessionID: command.SessionID,
				Error:     publicSerialError(err),
			})
		}
	}()
}

func (server *serialServer) input(command serialWireCommand) {
	data, err := base64.StdEncoding.DecodeString(command.Data)
	if err != nil || len(data) > serialInputMaxBytes {
		server.writeError(command.SessionID, "serial input is invalid")
		return
	}
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native == nil {
		server.writeError(command.SessionID, "serial session is not connected")
		return
	}
	if err := native.write(data); err != nil && server.isActive(native) {
		message := "serial input failed"
		if errors.Is(err, errSerialInputFull) {
			message = "serial input queue is full"
		}
		server.writeError(command.SessionID, message)
	}
}

func (server *serialServer) resize(command serialWireCommand) {
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native == nil {
		server.writeError(command.SessionID, "serial session is not connected")
		return
	}
	if err := native.resize(command.Columns, command.Rows); err != nil && server.isActive(native) {
		server.writeError(command.SessionID, "serial terminal resize failed")
	}
}

func (server *serialServer) snapshot(command serialWireCommand) {
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native != nil {
		native.snapshot()
	}
}

func (server *serialServer) close(sessionID string) {
	server.mu.Lock()
	cancel := server.pending[sessionID]
	delete(server.pending, sessionID)
	native := server.sessions[sessionID]
	delete(server.sessions, sessionID)
	server.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if native != nil {
		if native.portName != "" {
			logInfo("serial session closed: %s", native.portName)
		}
		native.close(true)
	}
}

func (server *serialServer) finishPending(sessionID string) bool {
	server.mu.Lock()
	_, pending := server.pending[sessionID]
	delete(server.pending, sessionID)
	server.mu.Unlock()
	return pending
}

func (server *serialServer) promote(sessionID string, native *serialNativeSession) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.pending[sessionID]; !exists {
		return false
	}
	delete(server.pending, sessionID)
	server.sessions[sessionID] = native
	return true
}

func (server *serialServer) publishConnected(
	sessionID string,
	native *serialNativeSession,
	event serialWireEvent,
) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.sessions[sessionID] != native {
		return false
	}
	server.output.write(event)
	return true
}

func (server *serialServer) remove(native *serialNativeSession) {
	server.mu.Lock()
	if current := server.sessions[native.id]; current == native {
		delete(server.sessions, native.id)
	}
	server.mu.Unlock()
}

func (server *serialServer) isActive(native *serialNativeSession) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.sessions[native.id] == native
}

func (server *serialServer) shutdown() {
	server.mu.Lock()
	pending := make([]context.CancelFunc, 0, len(server.pending))
	for sessionID, cancel := range server.pending {
		pending = append(pending, cancel)
		delete(server.pending, sessionID)
	}
	sessions := make([]*serialNativeSession, 0, len(server.sessions))
	for sessionID, native := range server.sessions {
		sessions = append(sessions, native)
		delete(server.sessions, sessionID)
	}
	server.mu.Unlock()

	for _, cancel := range pending {
		cancel()
	}
	for _, native := range sessions {
		native.close(false)
	}
}

func (server *serialServer) writeError(sessionID, message string) {
	server.output.write(serialWireEvent{Type: "error", SessionID: sessionID, Error: message})
}

func resolveSerialTarget(
	ctx context.Context,
	databasePath string,
	electronUserDataPath string,
	command serialWireCommand,
) (serialTarget, error) {
	if err := ctx.Err(); err != nil {
		return serialTarget{}, err
	}
	if nodeID := strings.TrimSpace(command.NodeID); nodeID != "" {
		return loadSerialTarget(databasePath, nodeID)
	}
	_ = electronUserDataPath // Serial is local and never reads credentials or tunnel state.
	target := serialTarget{
		PortName:    strings.TrimSpace(command.PortName),
		BaudRate:    command.BaudRate,
		DataBits:    command.DataBits,
		StopBits:    command.StopBits,
		Parity:      command.Parity,
		FlowControl: command.FlowControl,
	}
	return normalizeSerialTarget(target)
}

func loadSerialTarget(databasePath, nodeID string) (serialTarget, error) {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return serialTarget{}, err
	}
	if database == nil {
		return serialTarget{}, errors.New("serial connection was not found")
	}
	defer database.Close()

	nodes, err := loadSerialNodes(database)
	if err != nil {
		return serialTarget{}, err
	}
	return resolveSerialTargetFromNodes(nodes, nodeID)
}

func resolveSerialTargetFromNodes(nodes map[string]*serialNode, nodeID string) (serialTarget, error) {
	root := nodes[normalizeID(nodeID)]
	if root == nil || root.kind == 0 {
		return serialTarget{}, errors.New("serial connection was not found")
	}

	var (
		protocol    int64
		protocolSet bool
		portName    string
		baudRate    *int64
		dataBits    *int64
		stopBits    *int64
		parity      *int64
		flowControl *int64
	)
	current := root
	seen := make(map[string]struct{})
	for current != nil {
		if _, duplicate := seen[current.id]; duplicate {
			return serialTarget{}, errors.New("serial connection tree contains a cycle")
		}
		seen[current.id] = struct{}{}
		if !protocolSet && current.protocol != nil {
			protocol = *current.protocol
			protocolSet = true
		}
		if portName == "" && strings.TrimSpace(current.host) != "" {
			portName = strings.TrimSpace(current.host)
		}
		if baudRate == nil {
			baudRate = current.baudRate
		}
		if dataBits == nil {
			dataBits = current.dataBits
		}
		if stopBits == nil {
			stopBits = current.stopBits
		}
		if parity == nil {
			parity = current.parity
		}
		if flowControl == nil {
			flowControl = current.flowControl
		}
		if current.parentID == "" {
			break
		}
		current = nodes[current.parentID]
	}

	if !protocolSet || protocol != serialProtocolValue {
		return serialTarget{}, errors.New("the selected connection is not a serial connection")
	}
	return normalizeSerialTarget(serialTarget{
		NodeID:      normalizeID(nodeID),
		PortName:    portName,
		BaudRate:    nullableSerialValue(baudRate),
		DataBits:    nullableSerialValue(dataBits),
		StopBits:    nullableSerialValue(stopBits),
		Parity:      nullableSerialValue(parity),
		FlowControl: nullableSerialValue(flowControl),
	})
}

func serialIntPointer(value int) *int {
	return &value
}

func loadSerialNodes(database *sql.DB) (map[string]*serialNode, error) {
	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("Wormhole database has no connections")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return nil, err
	}
	expression := func(name string) string {
		if _, ok := columns[name]; ok {
			return "n." + name
		}
		return "NULL"
	}
	query := `SELECT ` + expression("Id") + ", " +
		expression("ParentId") + ", " +
		expression("Kind") + ", " +
		expression("Protocol") + ", " +
		expression("Host") + ", " +
		expression("SerialBaudRate") + ", " +
		expression("SerialDataBits") + ", " +
		expression("SerialStopBits") + ", " +
		expression("SerialParity") + ", " +
		expression("SerialFlowControl") + " FROM Nodes n;"
	rows, err := database.Query(query)
	if err != nil {
		return nil, fmt.Errorf("cannot read serial connections: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*serialNode)
	for rows.Next() {
		var row serialNodeRow
		if err := rows.Scan(
			&row.ID,
			&row.ParentID,
			&row.Kind,
			&row.Protocol,
			&row.Host,
			&row.BaudRate,
			&row.DataBits,
			&row.StopBits,
			&row.Parity,
			&row.FlowControl,
		); err != nil {
			return nil, fmt.Errorf("cannot read a serial connection: %w", err)
		}
		node := &serialNode{
			id:          normalizeID(row.ID),
			kind:        row.Kind,
			host:        nullableString(row.Host),
			baudRate:    nullableSerialPointer(row.BaudRate),
			dataBits:    nullableSerialPointer(row.DataBits),
			stopBits:    nullableSerialPointer(row.StopBits),
			parity:      nullableSerialPointer(row.Parity),
			flowControl: nullableSerialPointer(row.FlowControl),
		}
		if row.ParentID.Valid {
			node.parentID = normalizeID(row.ParentID.String)
		}
		if row.Protocol.Valid {
			value := row.Protocol.Int64
			node.protocol = &value
		}
		result[node.id] = node
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate serial connections: %w", err)
	}
	return result, nil
}

func nullableSerialPointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	copy := value.Int64
	return &copy
}

func nullableSerialValue(value *int64) int {
	if value == nil {
		return 0
	}
	if *value > int64(maxIntValue()) || *value < int64(minIntValue()) {
		return 0
	}
	return int(*value)
}

func maxIntValue() int {
	return int(^uint(0) >> 1)
}

func minIntValue() int {
	return -maxIntValue() - 1
}

func normalizeSerialTarget(target serialTarget) (serialTarget, error) {
	target.PortName = strings.TrimSpace(target.PortName)
	if target.PortName == "" {
		return serialTarget{}, errors.New("serial connection has no line name")
	}
	if len(target.PortName) > 256 || strings.ContainsAny(target.PortName, "\x00\r\n") {
		return serialTarget{}, errors.New("serial line name is invalid")
	}
	if target.BaudRate <= 0 {
		target.BaudRate = serialDefaultBaud
	}
	if target.DataBits < 5 || target.DataBits > 8 {
		target.DataBits = serialDefaultBits
	}
	if target.StopBits != 1 && target.StopBits != 2 && target.StopBits != 3 {
		target.StopBits = serialDefaultStop
	}
	if target.Parity < serialParityNone || target.Parity > serialParitySpace {
		target.Parity = serialDefaultParity
	}
	if target.FlowControl < serialFlowNone || target.FlowControl > serialFlowDsrDtr {
		target.FlowControl = serialDefaultFlow
	}
	return target, nil
}

func serialMode(target serialTarget) *nativeSerial.Mode {
	parity := nativeSerial.NoParity
	switch target.Parity {
	case serialParityOdd:
		parity = nativeSerial.OddParity
	case serialParityEven:
		parity = nativeSerial.EvenParity
	case serialParityMark:
		parity = nativeSerial.MarkParity
	case serialParitySpace:
		parity = nativeSerial.SpaceParity
	}
	stopBits := nativeSerial.OneStopBit
	switch target.StopBits {
	case 2:
		stopBits = nativeSerial.TwoStopBits
	case 3:
		stopBits = nativeSerial.OnePointFiveStopBits
	}
	return &nativeSerial.Mode{
		BaudRate:          target.BaudRate,
		DataBits:          target.DataBits,
		Parity:            parity,
		StopBits:          stopBits,
		InitialStatusBits: &nativeSerial.ModemOutputBits{DTR: true, RTS: true},
	}
}

func openNativeSerial(
	ctx context.Context,
	target serialTarget,
	columns, rows uint32,
) (*serialNativeSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	port, err := nativeSerial.Open(target.PortName, serialMode(target))
	if err != nil {
		return nil, fmt.Errorf("could not open serial port: %w", err)
	}
	closePort := true
	defer func() {
		if closePort {
			_ = port.Close()
		}
	}()
	if err := port.SetReadTimeout(nativeSerial.NoTimeout); err != nil {
		return nil, fmt.Errorf("could not configure serial port reads: %w", err)
	}
	if err := port.SetDTR(true); err != nil {
		return nil, fmt.Errorf("could not enable serial DTR: %w", err)
	}
	if err := port.SetRTS(true); err != nil {
		return nil, fmt.Errorf("could not enable serial RTS: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	closePort = false
	return newSerialNativeSession(port, target, columns, rows), nil
}

func publicSerialError(err error) string {
	if err == nil {
		return "Serial connection failed."
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "Serial connection failed."
	}
	return "Serial connection failed: " + truncateBackendMessage(message)
}

// serialNativePort is the small part of the serial library used by the lifecycle/session layer.
// Keeping it as an interface makes flow-control races testable without a physical COM adapter.
type serialNativePort interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Drain() error
	SetDTR(bool) error
	SetRTS(bool) error
	GetModemStatusBits() (*nativeSerial.ModemStatusBits, error)
	Close() error
}

var errSerialSessionClosed = errors.New("serial session is closed")
var errSerialInputFull = errors.New("serial input queue is full")

type serialNativeSession struct {
	id       string
	port     serialNativePort
	server   *serialServer
	terminal *sshTerminalEmulator
	flow     int
	portName string

	inputQueue chan []byte
	done       chan struct{}
	closeOnce  sync.Once
	outputWG   sync.WaitGroup

	lifecycleMu sync.Mutex
	closed      bool
	started     bool
	readDone    chan struct{}

	terminalOutputMu sync.Mutex
	writeMu          sync.Mutex
	readGateMu       sync.Mutex
	readGate         chan struct{}
	readingPaused    bool

	flowMu       sync.Mutex
	remotePaused bool
	flowChanged  chan struct{}
}

func newSerialNativeSession(
	port serialNativePort,
	target serialTarget,
	columns, rows uint32,
) *serialNativeSession {
	columns, rows = normalizeTerminalSize(columns, rows)
	terminal, err := newSSHTerminalEmulator(columns, rows)
	if err != nil {
		// vt10x construction only fails for an invalid geometry, and target geometry is normalized
		// at the wire boundary. Keep the error out of the hot path while preserving a useful panic
		// for an impossible programming error.
		panic(err)
	}
	readGate := make(chan struct{})
	close(readGate)
	return &serialNativeSession{
		port:        port,
		portName:    target.PortName,
		terminal:    terminal,
		flow:        target.FlowControl,
		inputQueue:  make(chan []byte, serialInputQueueCapacity),
		done:        make(chan struct{}),
		readGate:    readGate,
		flowChanged: make(chan struct{}),
		readDone:    make(chan struct{}),
	}
}

func (native *serialNativeSession) start() {
	native.lifecycleMu.Lock()
	if native.closed {
		native.lifecycleMu.Unlock()
		return
	}
	native.started = true
	native.outputWG.Add(2)
	go func() {
		defer native.outputWG.Done()
		defer close(native.readDone)
		native.readOutput()
	}()
	go func() {
		defer native.outputWG.Done()
		native.writeInput()
	}()
	native.lifecycleMu.Unlock()
}

func (native *serialNativeSession) readOutput() {
	buffer := make([]byte, serialReadChunk)
	for {
		if !native.waitForReadGate() {
			return
		}
		count, err := native.port.Read(buffer)
		if count > 0 {
			data := buffer[:count]
			if native.flow == serialFlowXonXoff {
				data = native.consumeSoftwareFlowControl(data)
			}
			if len(data) > 0 {
				native.publishTerminalData(data)
			}
		}
		if err != nil {
			if !native.isClosed() {
				native.close(true)
			}
			return
		}
		if count == 0 && native.isClosed() {
			return
		}
	}
}

func (native *serialNativeSession) consumeSoftwareFlowControl(data []byte) []byte {
	filtered := data[:0]
	for _, value := range data {
		switch value {
		case 0x11: // XON
			native.setRemotePaused(false)
		case 0x13: // XOFF
			native.setRemotePaused(true)
		default:
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (native *serialNativeSession) setRemotePaused(paused bool) {
	native.flowMu.Lock()
	if native.remotePaused == paused {
		native.flowMu.Unlock()
		return
	}
	native.remotePaused = paused
	close(native.flowChanged)
	native.flowChanged = make(chan struct{})
	native.flowMu.Unlock()
}

func (native *serialNativeSession) waitForReadGate() bool {
	native.readGateMu.Lock()
	gate := native.readGate
	native.readGateMu.Unlock()
	select {
	case <-gate:
		return !native.isClosed()
	case <-native.done:
		return false
	}
}

func (native *serialNativeSession) write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if native.isClosed() {
		return errSerialSessionClosed
	}
	copyOfData := append([]byte(nil), data...)
	select {
	case native.inputQueue <- copyOfData:
		return nil
	case <-native.done:
		return errSerialSessionClosed
	default:
		return errSerialInputFull
	}
}

func (native *serialNativeSession) writeInput() {
	for {
		select {
		case data := <-native.inputQueue:
			if err := native.writePortData(data); err != nil {
				if !native.isClosed() {
					native.close(true)
				}
				return
			}
		case <-native.done:
			return
		}
	}
}

func (native *serialNativeSession) writePortData(data []byte) error {
	for offset := 0; offset < len(data); {
		if err := native.waitForTransmit(); err != nil {
			return err
		}
		native.writeMu.Lock()
		count, err := native.port.Write(data[offset:])
		native.writeMu.Unlock()
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data)-offset {
			return errors.New("serial port returned an invalid write count")
		}
		offset += count
	}
	native.writeMu.Lock()
	err := native.port.Drain()
	native.writeMu.Unlock()
	return err
}

func (native *serialNativeSession) waitForTransmit() error {
	for {
		if native.isClosed() {
			return errSerialSessionClosed
		}
		switch native.flow {
		case serialFlowXonXoff:
			native.flowMu.Lock()
			paused := native.remotePaused
			changed := native.flowChanged
			native.flowMu.Unlock()
			if !paused {
				return nil
			}
			select {
			case <-changed:
			case <-native.done:
				return errSerialSessionClosed
			}
		case serialFlowRtsCts, serialFlowDsrDtr:
			status, err := native.port.GetModemStatusBits()
			if err != nil {
				return err
			}
			if (native.flow == serialFlowRtsCts && status.CTS) ||
				(native.flow == serialFlowDsrDtr && status.DSR) {
				return nil
			}
			timer := time.NewTimer(serialModemPollInterval)
			select {
			case <-timer.C:
			case <-native.done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return errSerialSessionClosed
			}
		default:
			return nil
		}
	}
}

func (native *serialNativeSession) resize(columns, rows uint32) error {
	columns, rows = normalizeTerminalSize(columns, rows)
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return errSerialSessionClosed
	}
	native.publishTerminalFrameLocked(native.terminal.resize(columns, rows))
	return nil
}

func (native *serialNativeSession) snapshot() {
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	native.publishTerminalFrameLocked(native.terminal.snapshot())
}

func (native *serialNativeSession) publishTerminalData(data []byte) {
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	frame, changed, err := native.terminal.write(data)
	if err != nil {
		if native.server != nil {
			native.server.writeError(native.id, "serial terminal emulation failed")
		}
		return
	}
	if changed {
		native.publishTerminalFrameLocked(frame)
	}
}

func (native *serialNativeSession) publishTerminalFrame(frame *sshTerminalFrame) {
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	native.publishTerminalFrameLocked(frame)
}

func (native *serialNativeSession) publishTerminalFrameLocked(frame *sshTerminalFrame) {
	if native.server == nil || frame == nil {
		return
	}
	native.server.output.write(serialWireEvent{
		Type:      "screen",
		SessionID: native.id,
		Frame:     frame,
	})
}

func (native *serialNativeSession) PauseReading() {
	if native.flow == serialFlowNone || native.isClosed() {
		return
	}
	native.readGateMu.Lock()
	if native.readingPaused || native.isClosed() {
		native.readGateMu.Unlock()
		return
	}
	native.readingPaused = true
	native.readGate = make(chan struct{})
	err := native.setReceiveFlow(false)
	if err != nil {
		native.readingPaused = false
		close(native.readGate)
	}
	native.readGateMu.Unlock()
	if err != nil {
		native.close(true)
	}
}

func (native *serialNativeSession) ResumeReading() {
	native.readGateMu.Lock()
	if !native.readingPaused {
		native.readGateMu.Unlock()
		return
	}
	err := native.setReceiveFlow(true)
	native.readingPaused = false
	close(native.readGate)
	native.readGateMu.Unlock()
	if err != nil {
		native.close(true)
		return
	}
}

func (native *serialNativeSession) setReceiveFlow(enabled bool) error {
	switch native.flow {
	case serialFlowXonXoff:
		if enabled {
			return native.writeControlByte(0x11)
		}
		return native.writeControlByte(0x13)
	case serialFlowRtsCts:
		return native.port.SetRTS(enabled)
	case serialFlowDsrDtr:
		return native.port.SetDTR(enabled)
	default:
		return nil
	}
}

func (native *serialNativeSession) writeControlByte(value byte) error {
	native.writeMu.Lock()
	defer native.writeMu.Unlock()
	if native.isClosed() {
		return errSerialSessionClosed
	}
	count, err := native.port.Write([]byte{value})
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("serial port returned an invalid control write count")
	}
	return native.port.Drain()
}

func (native *serialNativeSession) close(notify bool) {
	shouldNotify := false
	native.closeOnce.Do(func() {
		native.lifecycleMu.Lock()
		native.closed = true
		if !native.started {
			close(native.readDone)
		}
		native.lifecycleMu.Unlock()
		close(native.done)
		native.flowMu.Lock()
		close(native.flowChanged)
		native.flowChanged = make(chan struct{})
		native.flowMu.Unlock()
		native.readGateMu.Lock()
		if native.readingPaused {
			native.readingPaused = false
			close(native.readGate)
		}
		native.readGateMu.Unlock()
		_ = native.port.Close()
		if native.server != nil {
			native.server.remove(native)
			shouldNotify = notify
		}
	})
	if shouldNotify {
		go native.publishClosedAfterReadDrain()
	}
}

func (native *serialNativeSession) publishClosedAfterReadDrain() {
	timer := time.NewTimer(serialCloseReadDrainTimeout)
	defer timer.Stop()
	select {
	case <-native.readDone:
	case <-timer.C:
	}
	if native.server != nil {
		native.server.output.write(serialWireEvent{Type: "closed", SessionID: native.id})
	}
}

func (native *serialNativeSession) isClosed() bool {
	native.lifecycleMu.Lock()
	defer native.lifecycleMu.Unlock()
	return native.closed
}
