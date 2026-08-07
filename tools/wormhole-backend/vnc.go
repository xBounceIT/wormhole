package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	vnc "github.com/kward/go-vnc"
	"github.com/kward/go-vnc/buttons"
	"github.com/kward/go-vnc/encodings"
	"github.com/kward/go-vnc/keys"
)

const (
	vncConnectTimeout   = 20 * time.Second
	vncWriteTimeout     = 5 * time.Second
	backendLineLimit    = 32 * 1024 * 1024
	maxVncFrameWidth    = 16384
	maxVncFrameHeight   = 16384
	maxVncFramePixels   = 64 * 1024 * 1024
	maxVncFramePayload  = 20 * 1024 * 1024 // Keeps base64 JSON frames below the Electron 32 MiB line budget.
	maxVncRawRectPixels = 4 * 1024 * 1024
	maxVncHostLength    = 1024
	maxVncPasswordSize  = 16 * 1024
	maxVncEncodedSecret = 64 * 1024
	vncProtocolValue    = 6
)

type backendCommand struct {
	ID                string `json:"id"`
	Action            string `json:"action"`
	SessionID         string `json:"sessionId"`
	NodeID            string `json:"nodeId,omitempty"`
	ProgressSessionID string `json:"progressSessionId,omitempty"`
	CredentialID      string `json:"credentialId,omitempty"`
	Host              string `json:"host,omitempty"`
	Port              int    `json:"port,omitempty"`
	Password          string `json:"password,omitempty"`
	TunnelConfigID    string `json:"tunnelConfigId,omitempty"`
	Dedicated         bool   `json:"dedicated,omitempty"`
	PromptID          string `json:"promptId,omitempty"`
	Value             string `json:"value,omitempty"`
	Cancelled         bool   `json:"cancelled,omitempty"`
	X                 int    `json:"x,omitempty"`
	Y                 int    `json:"y,omitempty"`
	Buttons           uint8  `json:"buttons,omitempty"`
	Down              bool   `json:"down,omitempty"`
	KeySym            uint32 `json:"keysym,omitempty"`
}

type backendResponse struct {
	ID            string `json:"id"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	SocksEndpoint string `json:"socksEndpoint,omitempty"`
	LeaseID       string `json:"leaseId,omitempty"`
}

type backendEvent struct {
	Type                    string   `json:"type"`
	SessionID               string   `json:"sessionId"`
	LeaseID                 string   `json:"leaseId,omitempty"`
	Phase                   string   `json:"phase,omitempty"`
	Detail                  string   `json:"detail,omitempty"`
	ConnectionName          string   `json:"connectionName,omitempty"`
	TunnelName              string   `json:"tunnelName,omitempty"`
	Status                  string   `json:"status,omitempty"`
	Message                 string   `json:"message,omitempty"`
	PasswordRequired        bool     `json:"passwordRequired,omitempty"`
	Width                   int      `json:"width,omitempty"`
	Height                  int      `json:"height,omitempty"`
	Image                   string   `json:"image,omitempty"`
	PromptID                string   `json:"promptId,omitempty"`
	Title                   string   `json:"title,omitempty"`
	Secret                  bool     `json:"secret,omitempty"`
	URLs                    []string `json:"urls,omitempty"`
	IgnoreCertificateErrors bool     `json:"ignoreCertificateErrors,omitempty"`
	Completion              string   `json:"completion,omitempty"`
	RedirectPrefix          string   `json:"redirectPrefix,omitempty"`
	ExpectedState           string   `json:"expectedState,omitempty"`
	CookieName              string   `json:"cookieName,omitempty"`
	RequireHTTPOnly         bool     `json:"requireHttpOnly,omitempty"`
	Confirmation            bool     `json:"confirmation,omitempty"`
	AcceptLabel             string   `json:"acceptLabel,omitempty"`
}

type backendLineWriter struct {
	mu     sync.Mutex
	writer *bufio.Writer
}

func newBackendLineWriter(output *os.File) *backendLineWriter {
	return &backendLineWriter{writer: bufio.NewWriterSize(output, 64*1024)}
}

func (w *backendLineWriter) write(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.writer.Write(encoded); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}
	return w.writer.Flush()
}

func serveBackend(databasePath string, electronUserDataPath ...string) error {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return err
	}
	if database != nil {
		defer database.Close()
	}

	output := newBackendLineWriter(os.Stdout)
	manager := newVncManager(database, output, electronUserDataPath...)
	manager.databasePath = databasePath
	defer manager.close()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), backendLineLimit)
	for scanner.Scan() {
		var command backendCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			_ = output.write(backendResponse{OK: false, Error: "invalid backend command"})
			continue
		}
		manager.handle(command)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("backend command stream failed: %w", err)
	}
	return nil
}

type vncManager struct {
	database             *sql.DB
	electronUserDataPath string
	output               *backendLineWriter
	databasePath         string

	mu             sync.Mutex
	sessions       map[string]*vncSession
	tunnelLeases   map[string]*tunnelRuntime
	tunnelStarts   map[string]context.CancelFunc
	tunnelPrompts  map[string]*pendingTunnelPrompt
	promptSequence uint64
	routePrompts   map[string]*pendingTunnelPrompt
	routeSequence  uint64
	cleanup        sync.WaitGroup
}

type pendingTunnelPrompt struct {
	leaseID string
	result  chan tunnelPromptResult
}

type tunnelPromptResult struct {
	value     string
	cancelled bool
}

func newVncManager(
	database *sql.DB,
	output *backendLineWriter,
	electronUserDataPath ...string,
) *vncManager {
	userDataPath := ""
	if len(electronUserDataPath) > 0 {
		userDataPath = electronUserDataPath[0]
	}
	return &vncManager{
		database:             database,
		electronUserDataPath: userDataPath,
		output:               output,
		sessions:             make(map[string]*vncSession),
		tunnelLeases:         make(map[string]*tunnelRuntime),
		tunnelStarts:         make(map[string]context.CancelFunc),
		tunnelPrompts:        make(map[string]*pendingTunnelPrompt),
		routePrompts:         make(map[string]*pendingTunnelPrompt),
	}
}

func (m *vncManager) handle(command backendCommand) {
	if err := validateBackendCommand(command); err != nil {
		m.respond(command.ID, err)
		return
	}

	switch command.Action {
	case "vnc.connect":
		m.connect(command)
	case "vnc.disconnect":
		m.disconnect(command)
	case "vnc.pointer":
		m.input(command, func(session *vncSession) error {
			return session.pointer(command.X, command.Y, command.Buttons)
		})
	case "vnc.key":
		m.input(command, func(session *vncSession) error {
			return session.key(command.Down, command.KeySym)
		})
	case "tunnel.acquire":
		m.acquireTunnel(command)
	case "tunnel.release":
		m.releaseTunnel(command)
	case "tunnel.prompt-response":
		m.respondTunnelPrompt(command)
	case "tunnel.route-response":
		m.respondTunnelRoute(command)
	default:
		m.respond(command.ID, fmt.Errorf("unsupported backend action %q", command.Action))
	}
}

func (m *vncManager) connect(command backendCommand) {
	if command.SessionID == "" {
		m.respond(command.ID, errors.New("VNC session ID is required"))
		return
	}

	// A reconnect replaces the previous native session. Closing the old socket before starting
	// the new goroutine also guarantees that one tab cannot leave two RFB clients connected.
	m.mu.Lock()
	previous := m.sessions[command.SessionID]
	session := newVncSession(command.SessionID, m.output, m)
	m.sessions[command.SessionID] = session
	m.mu.Unlock()
	if previous != nil {
		previous.close()
	}

	m.respond(command.ID, nil)
	go session.connect(command, m.database, m.electronUserDataPath)
}

func (m *vncManager) disconnect(command backendCommand) {
	m.mu.Lock()
	session := m.sessions[command.SessionID]
	delete(m.sessions, command.SessionID)
	m.mu.Unlock()
	if session != nil {
		session.close()
	}
	m.respond(command.ID, nil)
}

func (m *vncManager) input(command backendCommand, send func(*vncSession) error) {
	m.mu.Lock()
	session := m.sessions[command.SessionID]
	m.mu.Unlock()
	if session == nil {
		m.respond(command.ID, errors.New("VNC session is not connected"))
		return
	}
	m.respond(command.ID, send(session))
}

func (m *vncManager) remove(session *vncSession) {
	m.mu.Lock()
	if current := m.sessions[session.id]; current == session {
		delete(m.sessions, session.id)
	}
	m.mu.Unlock()
}

func (m *vncManager) close() {
	m.mu.Lock()
	sessions := make([]*vncSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[string]*vncSession)
	leases := make([]*tunnelRuntime, 0, len(m.tunnelLeases))
	for _, lease := range m.tunnelLeases {
		leases = append(leases, lease)
	}
	for _, cancel := range m.tunnelStarts {
		cancel()
	}
	m.tunnelLeases = make(map[string]*tunnelRuntime)
	m.tunnelStarts = make(map[string]context.CancelFunc)
	m.tunnelPrompts = make(map[string]*pendingTunnelPrompt)
	m.routePrompts = make(map[string]*pendingTunnelPrompt)
	m.mu.Unlock()

	for _, session := range sessions {
		m.cleanupNative(session.close)
	}
	for _, lease := range leases {
		m.cleanupNative(lease.close)
	}
	m.cleanup.Wait()
}

func (m *vncManager) cleanupNative(close func()) {
	m.cleanup.Add(1)
	go func() {
		defer m.cleanup.Done()
		close()
	}()
}

func (m *vncManager) acquireTunnel(command backendCommand) {
	m.mu.Lock()
	if m.tunnelLeases[command.SessionID] != nil || m.tunnelStarts[command.SessionID] != nil {
		m.mu.Unlock()
		m.respond(command.ID, errors.New("VPN tunnel lease ID is already in use"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tunnelStartTimeout)
	m.tunnelStarts[command.SessionID] = cancel
	m.cleanup.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.cleanup.Done()
		defer cancel()
		configID := normalizeTunnelID(command.TunnelConfigID)
		if command.NodeID != "" {
			resolvedID, enabled, err := resolveNodeTunnel(m.databasePath, command.NodeID)
			if err != nil {
				m.finishTunnelAcquire(command, nil, err)
				return
			}
			if !enabled {
				m.finishTunnelAcquire(command, nil, nil)
				return
			}
			configID = resolvedID
		}
		if configID == "" {
			m.finishTunnelAcquire(command, nil, errors.New("VPN tunnel is enabled but no configuration is selected"))
			return
		}
		progressSessionID := command.ProgressSessionID
		if progressSessionID == "" {
			progressSessionID = command.SessionID
		}
		if command.NodeID != "" {
			useTunnel, err := readPromptBeforeTunnelConnect(m.databasePath)
			if err != nil {
				m.finishTunnelAcquire(command, nil, err)
				return
			}
			if useTunnel {
				route, err := m.routeTunnel(
					command.SessionID,
					progressSessionID,
					resolveNodeDisplayName(m.databasePath, command.NodeID),
					tunnelConfigName(m.databasePath, configID),
				)(ctx)
				if err != nil {
					m.finishTunnelAcquire(command, nil, err)
					return
				}
				if route == "direct" {
					m.finishTunnelAcquire(command, nil, nil)
					return
				}
			}
		}
		ctx = withTunnelProgressHandler(ctx, m.progressTunnel(progressSessionID))
		promptContext := withTunnelPromptHandler(ctx, m.promptTunnel(command.SessionID))
		var lease *tunnelRuntime
		var err error
		if command.Dedicated {
			lease, err = startTunnelRuntimeScoped(promptContext, m.databasePath, configID, command.SessionID)
		} else {
			lease, err = startTunnelRuntime(promptContext, m.databasePath, configID)
		}
		m.finishTunnelAcquire(command, lease, err)
	}()
}

func (m *vncManager) promptTunnel(leaseID string) tunnelPromptHandler {
	return func(ctx context.Context, prompt tunnelPrompt) (string, error) {
		m.mu.Lock()
		m.promptSequence++
		promptID := fmt.Sprintf("tunnel-prompt-%d", m.promptSequence)
		pending := &pendingTunnelPrompt{leaseID: leaseID, result: make(chan tunnelPromptResult, 1)}
		m.tunnelPrompts[promptID] = pending
		m.mu.Unlock()

		eventType := "tunnel.prompt"
		if prompt.Browser {
			eventType = "tunnel.browser"
		}
		m.emit(backendEvent{
			Type: eventType, SessionID: leaseID, PromptID: promptID,
			Title: prompt.Title, Message: prompt.Message, Secret: prompt.Secret,
			URLs: prompt.URLs, IgnoreCertificateErrors: prompt.IgnoreCertificateErrors,
			Completion: prompt.Completion, RedirectPrefix: prompt.RedirectPrefix,
			ExpectedState: prompt.ExpectedState,
			CookieName:    prompt.CookieName, RequireHTTPOnly: prompt.RequireHTTPOnly,
			Confirmation: prompt.Confirmation, AcceptLabel: prompt.AcceptLabel,
		})
		defer func() {
			m.mu.Lock()
			if m.tunnelPrompts[promptID] == pending {
				delete(m.tunnelPrompts, promptID)
			}
			m.mu.Unlock()
			m.emit(backendEvent{Type: "tunnel.prompt-closed", SessionID: leaseID, PromptID: promptID})
		}()
		select {
		case result := <-pending.result:
			if result.cancelled {
				return "", errors.New("VPN authentication was cancelled")
			}
			return result.value, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (m *vncManager) respondTunnelPrompt(command backendCommand) {
	m.mu.Lock()
	pending := m.tunnelPrompts[command.PromptID]
	if pending != nil && pending.leaseID == command.SessionID {
		delete(m.tunnelPrompts, command.PromptID)
	}
	m.mu.Unlock()
	if pending == nil || pending.leaseID != command.SessionID {
		m.respond(command.ID, errors.New("VPN authentication prompt is no longer active"))
		return
	}
	m.respond(command.ID, nil)
	pending.result <- tunnelPromptResult{value: command.Value, cancelled: command.Cancelled}
}

type tunnelRouteHandler func(context.Context) (string, error)

// routeTunnel asks the renderer whether a saved connection should use its configured VPN tunnel.
// It mirrors promptTunnel but emits tunnel.route events and accepts a three-way response
// (tunnel / direct / cancel) instead of free-form input.
func (m *vncManager) routeTunnel(leaseID, progressSessionID, connectionName, tunnelName string) tunnelRouteHandler {
	return func(ctx context.Context) (string, error) {
		m.mu.Lock()
		m.routeSequence++
		promptID := fmt.Sprintf("tunnel-route-%d", m.routeSequence)
		pending := &pendingTunnelPrompt{leaseID: leaseID, result: make(chan tunnelPromptResult, 1)}
		m.routePrompts[promptID] = pending
		m.mu.Unlock()

		m.emit(backendEvent{
			Type: "tunnel.route", SessionID: progressSessionID, LeaseID: leaseID, PromptID: promptID,
			ConnectionName: connectionName, TunnelName: tunnelName,
		})
		defer func() {
			m.mu.Lock()
			if m.routePrompts[promptID] == pending {
				delete(m.routePrompts, promptID)
			}
			m.mu.Unlock()
			m.emit(backendEvent{Type: "tunnel.route-closed", SessionID: progressSessionID, LeaseID: leaseID, PromptID: promptID})
		}()
		select {
		case result := <-pending.result:
			if result.cancelled {
				return "", errors.New("Connection cancelled.")
			}
			return result.value, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (m *vncManager) respondTunnelRoute(command backendCommand) {
	m.mu.Lock()
	pending := m.routePrompts[command.PromptID]
	if pending != nil && pending.leaseID == command.SessionID {
		delete(m.routePrompts, command.PromptID)
	}
	m.mu.Unlock()
	if pending == nil || pending.leaseID != command.SessionID {
		m.respond(command.ID, errors.New("VPN tunnel choice is no longer active"))
		return
	}
	m.respond(command.ID, nil)
	pending.result <- tunnelPromptResult{
		value:     command.Value,
		cancelled: command.Cancelled || command.Value == "cancel",
	}
}

func (m *vncManager) progressTunnel(progressSessionID string) tunnelProgressHandler {
	return func(_ context.Context, phase, detail string) error {
		m.emit(backendEvent{
			Type: "tunnel.progress", SessionID: progressSessionID, Phase: phase, Detail: detail,
		})
		return nil
	}
}

func (m *vncManager) finishTunnelAcquire(command backendCommand, lease *tunnelRuntime, err error) {
	m.mu.Lock()
	_, stillPending := m.tunnelStarts[command.SessionID]
	delete(m.tunnelStarts, command.SessionID)
	if err == nil && lease != nil && stillPending {
		m.tunnelLeases[command.SessionID] = lease
	}
	m.mu.Unlock()
	if !stillPending {
		if lease != nil {
			lease.close()
		}
		_ = m.output.write(backendResponse{
			ID: command.ID, OK: false, Error: "VPN tunnel establishment was cancelled",
		})
		return
	}
	response := backendResponse{ID: command.ID, OK: err == nil, LeaseID: command.SessionID}
	if err != nil {
		response.Error = publicBackendError(err)
	} else if lease != nil {
		response.SocksEndpoint = lease.socksEndpoint()
	}
	_ = m.output.write(response)
}

func (m *vncManager) releaseTunnel(command backendCommand) {
	m.mu.Lock()
	lease := m.tunnelLeases[command.SessionID]
	delete(m.tunnelLeases, command.SessionID)
	if cancel := m.tunnelStarts[command.SessionID]; cancel != nil {
		cancel()
		delete(m.tunnelStarts, command.SessionID)
	}
	m.mu.Unlock()
	m.respond(command.ID, nil)
	if lease != nil {
		m.cleanupNative(lease.close)
	}
}

func (m *vncManager) respond(id string, err error) {
	response := backendResponse{ID: id, OK: err == nil}
	if err != nil {
		response.Error = publicBackendError(err)
	}
	_ = m.output.write(response)
}

func (m *vncManager) emit(event backendEvent) {
	_ = m.output.write(event)
}

type vncSession struct {
	id      string
	output  *backendLineWriter
	manager *vncManager
	stop    chan struct{}

	stopOnce      sync.Once
	stateMu       sync.Mutex
	stopped       bool
	terminal      bool
	connectCancel context.CancelFunc
	conn          *vnc.ClientConn
	netConn       net.Conn
	tunnel        *tunnelRuntime
	writeMu       sync.Mutex
	eventMu       sync.Mutex

	frameMu     sync.Mutex
	frame       *image.RGBA
	frameWidth  int
	frameHeight int
}

func newVncSession(id string, output *backendLineWriter, manager *vncManager) *vncSession {
	return &vncSession{
		id:      id,
		output:  output,
		manager: manager,
		stop:    make(chan struct{}),
	}
}

func (s *vncSession) connect(command backendCommand, database *sql.DB, electronUserDataPath ...string) {
	target, err := resolveVncTarget(database, command, electronUserDataPath...)
	if err != nil {
		logError("VNC session failed to connect: %v", err)
		s.fail(err)
		return
	}
	connectContext, ok := s.beginConnect()
	if !ok {
		return
	}
	defer s.endConnect()
	s.emitStatus("connecting", "", false)

	var tunnel *tunnelRuntime
	if target.tunnelConfigID != "" {
		if target.nodeID != "" {
			useTunnel, promptErr := readPromptBeforeTunnelConnect(s.manager.databasePath)
			if promptErr != nil {
				s.fail(promptErr)
				return
			}
			if useTunnel {
				connectionName := target.displayName
				if connectionName == "" {
					connectionName = "the target"
				}
				route, routeErr := s.manager.routeTunnel(
					s.id,
					s.id,
					connectionName,
					tunnelConfigName(s.manager.databasePath, target.tunnelConfigID),
				)(connectContext)
				if routeErr != nil {
					s.fail(routeErr)
					return
				}
				if route == "direct" {
					target.tunnelConfigID = ""
				}
			}
		}
	}
	if target.tunnelConfigID != "" {
		progressContext := withTunnelProgressHandler(connectContext, s.manager.progressTunnel(s.id))
		promptContext := withTunnelPromptHandler(progressContext, s.manager.promptTunnel(s.id))
		tunnel, err = startTunnelRuntime(promptContext, s.manager.databasePath, target.tunnelConfigID)
		if err != nil {
			s.fail(err)
			return
		}
		if !s.setTunnel(tunnel) {
			tunnel.close()
			return
		}
	}
	address := net.JoinHostPort(target.host, strconv.Itoa(target.port))
	var network net.Conn
	if tunnel != nil {
		network, err = tunnel.dialContext(connectContext, "tcp", address)
	} else {
		dialer := net.Dialer{Timeout: vncConnectTimeout}
		network, err = dialer.DialContext(connectContext, "tcp", address)
	}
	if err != nil {
		s.fail(err)
		return
	}
	guardedNetwork := newVncReadGuard(network)
	if !s.setNetworkConnection(guardedNetwork) {
		_ = guardedNetwork.Close()
		return
	}

	// The package uses blocking reads during the RFB handshake, so enforce the connect timeout
	// at the socket too. It is cleared once ServerInit completes.
	_ = guardedNetwork.SetDeadline(time.Now().Add(vncConnectTimeout))
	messages := make(chan vnc.ServerMessage, 16)
	config := vnc.NewClientConfig(target.password)
	config.ServerMessageCh = messages
	// The renderer has no clipboard or color-map surface. Keeping those optional message types
	// out of the long-lived parser also avoids accepting unbounded server cut-text payloads.
	config.ServerMessages = []vnc.ServerMessage{
		&vnc.FramebufferUpdate{},
		&vnc.Bell{},
	}
	connection, err := vnc.Connect(connectContext, guardedNetwork, config)
	if err != nil {
		_ = guardedNetwork.Close()
		s.clearNetworkConnection(guardedNetwork)
		s.fail(err)
		return
	}
	_ = guardedNetwork.SetDeadline(time.Time{})
	if !s.setVncConnection(connection) {
		_ = connection.Close()
		return
	}

	s.writeMu.Lock()
	setupError := connection.SetPixelFormat(vnc.PixelFormat{
		BPP:        32,
		Depth:      32,
		BigEndian:  false,
		TrueColor:  true,
		RedMax:     255,
		GreenMax:   255,
		BlueMax:    255,
		RedShift:   16,
		GreenShift: 8,
		BlueShift:  0,
	})
	if setupError == nil {
		setupError = connection.SetEncodings(vnc.Encodings{
			&boundedRawEncoding{connection: guardedNetwork},
			&vnc.DesktopSizePseudoEncoding{},
		})
	}
	if setupError == nil {
		setupError = connection.FramebufferUpdateRequest(
			false,
			0,
			0,
			connection.FramebufferWidth(),
			connection.FramebufferHeight(),
		)
	}
	s.writeMu.Unlock()
	if setupError != nil {
		_ = connection.Close()
		s.clearVncConnection(connection)
		s.fail(setupError)
		return
	}

	if err := s.resetFramebuffer(int(connection.FramebufferWidth()), int(connection.FramebufferHeight())); err != nil {
		_ = connection.Close()
		s.clearVncConnection(connection)
		s.fail(err)
		return
	}
	s.emitStatus("connected", "", false)
	logInfo("VNC session connected: %s:%d", target.host, target.port)

	listenDone := make(chan error, 1)
	go func() {
		listenDone <- connection.ListenAndHandle()
	}()

	for {
		select {
		case <-s.stop:
			_ = connection.Close()
			// ListenAndHandle can be blocked delivering a parsed server message when the
			// renderer disconnects. Drain the channel until the reader observes the closed
			// socket, otherwise teardown can wait forever behind a full message buffer.
			for {
				select {
				case <-messages:
				case <-listenDone:
					s.manager.remove(s)
					return
				}
			}
		case err := <-listenDone:
			s.clearVncConnection(connection)
			if s.isStopped() {
				return
			}
			if err != nil {
				s.fail(err)
			} else {
				s.disconnected("VNC connection closed by the remote host.")
			}
			s.manager.remove(s)
			return
		case message := <-messages:
			s.handleServerMessage(connection, message)
		}
	}
}

func (s *vncSession) handleServerMessage(connection *vnc.ClientConn, message vnc.ServerMessage) {
	if s.isStopped() {
		return
	}
	update, ok := message.(*vnc.FramebufferUpdate)
	if !ok {
		return
	}

	frame, width, height, err := s.applyFramebufferUpdate(update)
	if err != nil {
		s.fail(err)
		_ = connection.Close()
		return
	}
	if frame != nil {
		if err := validateVncFramePayload(len(frame)); err != nil {
			s.fail(err)
			_ = connection.Close()
			return
		}
		s.emitFrame(frame, width, height)
	}

	requestWidth, requestHeight := s.frameDimensions()
	requestError := s.writeMessage(connection, func() error {
		return connection.FramebufferUpdateRequest(true, 0, 0, requestWidth, requestHeight)
	})
	if requestError != nil {
		s.fail(requestError)
		_ = connection.Close()
	}
}

func (s *vncSession) frameDimensions() (uint16, uint16) {
	s.frameMu.Lock()
	defer s.frameMu.Unlock()
	return uint16(s.frameWidth), uint16(s.frameHeight)
}

func (s *vncSession) applyFramebufferUpdate(update *vnc.FramebufferUpdate) ([]byte, int, int, error) {
	s.frameMu.Lock()
	defer s.frameMu.Unlock()

	changed := false
	for _, rectangle := range update.Rects {
		switch encoding := rectangle.Enc.(type) {
		case *vnc.DesktopSizePseudoEncoding:
			if err := validateVncDimensions(int(rectangle.Width), int(rectangle.Height)); err != nil {
				return nil, 0, 0, err
			}
			s.frame = image.NewRGBA(image.Rect(0, 0, int(rectangle.Width), int(rectangle.Height)))
			s.frameWidth = int(rectangle.Width)
			s.frameHeight = int(rectangle.Height)
		case *vnc.RawEncoding:
			if s.frame == nil {
				return nil, 0, 0, errors.New("VNC framebuffer was not initialized")
			}
			if int(rectangle.X)+int(rectangle.Width) > s.frameWidth || int(rectangle.Y)+int(rectangle.Height) > s.frameHeight {
				return nil, 0, 0, errors.New("VNC framebuffer update was outside the desktop")
			}
			if len(encoding.Colors) < int(rectangle.Width)*int(rectangle.Height) {
				return nil, 0, 0, errors.New("VNC framebuffer update was truncated")
			}
			for y := 0; y < int(rectangle.Height); y++ {
				for x := 0; x < int(rectangle.Width); x++ {
					color := encoding.Colors[y*int(rectangle.Width)+x]
					index := (int(rectangle.Y)+y)*s.frame.Stride + (int(rectangle.X)+x)*4
					s.frame.Pix[index] = vncColorByte(color.R)
					s.frame.Pix[index+1] = vncColorByte(color.G)
					s.frame.Pix[index+2] = vncColorByte(color.B)
					s.frame.Pix[index+3] = 255
				}
			}
			changed = true
		default:
			return nil, 0, 0, fmt.Errorf("unsupported VNC framebuffer encoding %T", rectangle.Enc)
		}
	}

	if !changed || s.frame == nil {
		return nil, s.frameWidth, s.frameHeight, nil
	}
	var encoded bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&encoded, s.frame); err != nil {
		return nil, 0, 0, fmt.Errorf("cannot encode VNC framebuffer: %w", err)
	}
	return encoded.Bytes(), s.frameWidth, s.frameHeight, nil
}

func (s *vncSession) resetFramebuffer(width, height int) error {
	if err := validateVncDimensions(width, height); err != nil {
		return err
	}
	s.frameMu.Lock()
	s.frame = image.NewRGBA(image.Rect(0, 0, width, height))
	s.frameWidth = width
	s.frameHeight = height
	s.frameMu.Unlock()
	return nil
}

func (s *vncSession) pointer(x, y int, mask uint8) error {
	if x < 0 || y < 0 || x > 65535 || y > 65535 {
		return errors.New("VNC pointer coordinates are out of range")
	}
	connection := s.currentConnection()
	if connection == nil {
		return errors.New("VNC session is not connected")
	}
	return s.writeMessage(connection, func() error {
		return connection.PointerEvent(buttons.Button(mask), uint16(x), uint16(y))
	})
}

func (s *vncSession) key(down bool, keySym uint32) error {
	if keySym == 0 {
		return errors.New("VNC key symbol is invalid")
	}
	connection := s.currentConnection()
	if connection == nil {
		return errors.New("VNC session is not connected")
	}
	return s.writeMessage(connection, func() error {
		return connection.KeyEvent(keys.Key(keySym), down)
	})
}

func (s *vncSession) writeMessage(connection *vnc.ClientConn, write func() error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	network := s.currentNetwork()
	if network != nil {
		_ = network.SetWriteDeadline(time.Now().Add(vncWriteTimeout))
		defer network.SetWriteDeadline(time.Time{})
	}
	return write()
}

func (s *vncSession) setNetworkConnection(connection net.Conn) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.stopped {
		return false
	}
	s.netConn = connection
	return true
}

func (s *vncSession) setTunnel(tunnel *tunnelRuntime) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.stopped {
		return false
	}
	s.tunnel = tunnel
	return true
}

func (s *vncSession) beginConnect() (context.Context, bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.stopped {
		return nil, false
	}
	connectContext, cancel := context.WithCancel(context.Background())
	s.connectCancel = cancel
	return connectContext, true
}

func (s *vncSession) endConnect() {
	s.stateMu.Lock()
	s.connectCancel = nil
	s.stateMu.Unlock()
}

func (s *vncSession) setVncConnection(connection *vnc.ClientConn) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.stopped {
		return false
	}
	s.conn = connection
	return true
}

func (s *vncSession) clearNetworkConnection(connection net.Conn) {
	s.stateMu.Lock()
	if s.netConn == connection {
		s.netConn = nil
	}
	s.stateMu.Unlock()
}

func (s *vncSession) clearVncConnection(connection *vnc.ClientConn) {
	s.stateMu.Lock()
	if s.conn == connection {
		s.conn = nil
		s.netConn = nil
	}
	s.stateMu.Unlock()
}

func (s *vncSession) currentConnection() *vnc.ClientConn {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.conn
}

func (s *vncSession) currentNetwork() net.Conn {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.netConn
}

func (s *vncSession) close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.stateMu.Lock()
		s.stopped = true
		cancel := s.connectCancel
		connection := s.conn
		network := s.netConn
		tunnel := s.tunnel
		s.stateMu.Unlock()
		if cancel != nil {
			cancel()
		}
		if connection != nil {
			_ = connection.Close()
		} else if network != nil {
			_ = network.Close()
		}
		if tunnel != nil {
			tunnel.close()
		}
		// Do not let an event that passed its stopped check race past teardown and overwrite a
		// replacement session with the same renderer session ID.
		s.eventMu.Lock()
		s.eventMu.Unlock()
	})
}

func (s *vncSession) isStopped() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.stopped
}

func (s *vncSession) emitStatus(status, message string, passwordRequired bool) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.isStopped() {
		return
	}
	s.manager.emit(backendEvent{
		Type:             "vnc.status",
		SessionID:        s.id,
		Status:           status,
		Message:          message,
		PasswordRequired: passwordRequired,
	})
}

func (s *vncSession) emitFrame(frame []byte, width, height int) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.isStopped() {
		return
	}
	s.output.write(backendEvent{
		Type:      "vnc.frame",
		SessionID: s.id,
		Width:     width,
		Height:    height,
		Image:     "data:image/png;base64," + base64.StdEncoding.EncodeToString(frame),
	})
}

func (s *vncSession) fail(err error) {
	message, passwordRequired := publicVncConnectError(err)
	if !s.claimTerminal() {
		return
	}
	logError("VNC session failed: %v", message)
	s.emitStatus("failed", message, passwordRequired)
	// Failures before the long-lived listen loop (DNS/SOCKS/RFB handshake, authentication,
	// framebuffer setup) do not pass through its normal teardown path. Close here so a failed
	// connection cannot retain its socket, VPN sidecar, or manager slot until the user retries.
	s.close()
	s.manager.remove(s)
}

func validateVncFramePayload(size int) error {
	if size > maxVncFramePayload {
		return errors.New("VNC framebuffer is too large to display")
	}
	return nil
}

var errVncRawReadLimit = errors.New("VNC raw framebuffer rectangle exceeded the native memory limit")

type vncReadGuard struct {
	net.Conn
	mu        sync.Mutex
	limited   bool
	remaining int64
}

func newVncReadGuard(connection net.Conn) *vncReadGuard {
	return &vncReadGuard{Conn: connection}
}

func (g *vncReadGuard) beginRawRead(size int64) error {
	if size <= 0 {
		return errors.New("VNC raw framebuffer rectangle is empty")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.limited {
		return errors.New("VNC raw framebuffer read state is invalid")
	}
	g.limited = true
	g.remaining = size
	return nil
}

func (g *vncReadGuard) endRawRead() {
	g.mu.Lock()
	g.limited = false
	g.remaining = 0
	g.mu.Unlock()
}

func (g *vncReadGuard) Read(buffer []byte) (int, error) {
	g.mu.Lock()
	if !g.limited {
		g.mu.Unlock()
		return g.Conn.Read(buffer)
	}
	if g.remaining == 0 {
		g.mu.Unlock()
		return 0, errVncRawReadLimit
	}
	readBuffer := buffer
	if int64(len(readBuffer)) > g.remaining {
		readBuffer = readBuffer[:int(g.remaining)]
	}
	g.mu.Unlock()

	read, err := g.Conn.Read(readBuffer)
	if read > 0 {
		g.mu.Lock()
		g.remaining -= int64(read)
		g.mu.Unlock()
	}
	return read, err
}

type boundedRawEncoding struct {
	connection *vncReadGuard
}

func (e *boundedRawEncoding) Marshal() ([]byte, error) {
	return (&vnc.RawEncoding{}).Marshal()
}

func (e *boundedRawEncoding) Read(connection *vnc.ClientConn, rectangle *vnc.Rectangle) (vnc.Encoding, error) {
	area := int64(rectangle.Width) * int64(rectangle.Height)
	if area <= 0 || area > maxVncRawRectPixels {
		return nil, errVncRawReadLimit
	}
	if e.connection == nil {
		return nil, errors.New("VNC raw framebuffer reader is unavailable")
	}
	if err := e.connection.beginRawRead(area * 4); err != nil {
		return nil, err
	}
	defer e.connection.endRawRead()
	return (&vnc.RawEncoding{}).Read(connection, rectangle)
}

func (e *boundedRawEncoding) String() string { return "BoundedRawEncoding" }

func (e *boundedRawEncoding) Type() encodings.Encoding { return encodings.Raw }

func (s *vncSession) disconnected(message string) {
	if !s.claimTerminal() {
		return
	}
	logInfo("VNC session disconnected: %s", message)
	s.emitStatus("disconnected", message, false)
	s.close()
	s.manager.remove(s)
}

func (s *vncSession) claimTerminal() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.stopped || s.terminal {
		return false
	}
	s.terminal = true
	return true
}

func validateBackendCommand(command backendCommand) error {
	if command.ID == "" || len(command.ID) > 128 {
		return errors.New("backend command ID is invalid")
	}
	if command.SessionID == "" || len(command.SessionID) > 128 {
		return errors.New("backend session ID is invalid")
	}
	switch command.Action {
	case "vnc.connect":
		if len(command.NodeID) > 128 || len(command.CredentialID) > 128 {
			return errors.New("VNC connection identity is invalid")
		}
		if command.NodeID != "" && command.TunnelConfigID != "" {
			return errors.New("VNC tunnel configuration cannot override a saved connection")
		}
		if command.TunnelConfigID != "" && normalizeTunnelID(command.TunnelConfigID) == "" {
			return errors.New("VNC tunnel configuration is invalid")
		}
		if err := validateVncHost(command.Host); err != nil {
			return err
		}
		if err := validateVncPassword(command.Password); err != nil {
			return err
		}
		if command.Port < 0 || command.Port > 65535 {
			return errors.New("VNC port is invalid")
		}
	case "vnc.disconnect":
	case "vnc.pointer":
		if command.X < 0 || command.Y < 0 || command.X > 65535 || command.Y > 65535 {
			return errors.New("VNC pointer coordinates are invalid")
		}
	case "vnc.key":
		if command.KeySym == 0 {
			return errors.New("VNC key symbol is invalid")
		}
	case "tunnel.acquire":
		if len(command.NodeID) > 128 {
			return errors.New("VPN connection identity is invalid")
		}
		if command.NodeID == "" && normalizeTunnelID(command.TunnelConfigID) == "" {
			return errors.New("VPN tunnel configuration is invalid")
		}
	case "tunnel.release":
	case "tunnel.prompt-response":
		if command.PromptID == "" || len(command.PromptID) > 128 || len(command.Value) > 16*1024 {
			return errors.New("VPN authentication response is invalid")
		}
	case "tunnel.route-response":
		if command.PromptID == "" || len(command.PromptID) > 128 {
			return errors.New("VPN tunnel choice is invalid")
		}
		switch command.Value {
		case "tunnel", "direct", "cancel":
		default:
			return errors.New("VPN tunnel choice is invalid")
		}
	default:
		return fmt.Errorf("unsupported backend action %q", command.Action)
	}
	return nil
}

func resolveVncTarget(
	database *sql.DB,
	command backendCommand,
	electronUserDataPath ...string,
) (vncTarget, error) {
	tunnelConfigID := normalizeTunnelID(command.TunnelConfigID)
	if command.TunnelConfigID != "" && tunnelConfigID == "" {
		return vncTarget{}, errors.New("VNC tunnel configuration is invalid")
	}
	target := vncTarget{
		host:           strings.TrimSpace(command.Host),
		port:           command.Port,
		password:       command.Password,
		tunnelConfigID: tunnelConfigID,
	}
	hostHasPort := target.host != "" && vncHostIncludesPort(target.host)
	if database != nil && (command.NodeID != "" || command.CredentialID != "") {
		databaseTarget, err := readVncTargetFromDatabase(
			database,
			command.NodeID,
			command.CredentialID,
			command.Password == "",
			electronUserDataPath...,
		)
		if err != nil {
			return vncTarget{}, err
		}
		if target.host == "" {
			target.host = databaseTarget.host
		}
		if target.port == 0 && !hostHasPort {
			target.port = databaseTarget.port
		}
		if target.password == "" {
			target.password = databaseTarget.password
		}
		target.nodeID = databaseTarget.nodeID
		target.displayName = databaseTarget.displayName
		if target.tunnelConfigID == "" {
			target.tunnelConfigID = databaseTarget.tunnelConfigID
		}
	}

	if target.host == "" {
		return vncTarget{}, errors.New("VNC host is required")
	}
	parsedHost, parsedPort, err := splitVncHostPort(target.host, target.port)
	if err != nil {
		return vncTarget{}, err
	}
	if parsedHost == "" {
		return vncTarget{}, errors.New("VNC host is invalid")
	}
	target.host, target.port = parsedHost, parsedPort
	return target, nil
}

type vncTarget struct {
	host           string
	port           int
	password       string
	tunnelConfigID string
	nodeID         string
	displayName    string
	tunnelName     string
}

func splitVncHostPort(host string, port int) (string, int, error) {
	if err := validateVncHost(host); err != nil {
		return "", 0, err
	}
	portProvided := port != 0
	if port == 0 {
		port = 5900
	}
	if port < 1 || port > 65535 {
		return "", 0, errors.New("VNC port is invalid")
	}

	if strings.HasPrefix(host, "[") {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
			if !portProvided {
				port = parsedPortNumber(parsedPort)
			}
			return parsedHost, port, validateVncPort(port)
		}
		if strings.HasSuffix(host, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), port, nil
		}
		return "", 0, errors.New("VNC host is invalid")
	}
	if strings.Count(host, ":") == 1 {
		parts := strings.SplitN(host, ":", 2)
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, errors.New("VNC port is invalid")
		}
		if !portProvided {
			port = parsed
		}
		return parts[0], port, validateVncPort(port)
	}
	if strings.ContainsAny(host, "\r\n\x00") {
		return "", 0, errors.New("VNC host is invalid")
	}
	return host, port, nil
}

func validateVncHost(host string) error {
	if len(host) > maxVncHostLength {
		return errors.New("VNC host is too long")
	}
	return nil
}

func validateVncPassword(password string) error {
	if len(password) > maxVncPasswordSize {
		return errors.New("VNC password is too long")
	}
	return nil
}

func vncHostIncludesPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		_, _, err := net.SplitHostPort(host)
		return err == nil
	}
	return strings.Count(host, ":") == 1
}

func parsedPortNumber(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func validateVncPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("VNC port is invalid")
	}
	return nil
}

func validateVncDimensions(width, height int) error {
	if width <= 0 || height <= 0 || width > maxVncFrameWidth || height > maxVncFrameHeight || width > maxVncFramePixels/height {
		return errors.New("VNC framebuffer dimensions are invalid")
	}
	return nil
}

func vncColorByte(value uint16) byte {
	if value > 255 {
		return byte(value >> 8)
	}
	return byte(value)
}

func publicVncConnectError(err error) (string, bool) {
	message := strings.TrimSpace(err.Error())
	lower := strings.ToLower(message)
	if strings.Contains(lower, "password") || strings.Contains(lower, "authentication") || strings.Contains(lower, "security handshake") {
		return "VNC authentication failed. Enter the VNC password and try again.", true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(lower, "i/o timeout") {
		return "VNC connection timed out.", false
	}
	return "VNC connection failed: " + truncateBackendMessage(message), false
}

func publicBackendError(err error) string {
	message := strings.TrimSpace(err.Error())
	switch {
	case errors.Is(err, io.EOF):
		message = "the VPN gateway closed the connection"
	case errors.Is(err, io.ErrUnexpectedEOF):
		message = "the VPN gateway closed the connection unexpectedly"
	case errors.Is(err, context.DeadlineExceeded):
		message = "the operation timed out"
	case errors.Is(err, context.Canceled):
		message = "the operation was cancelled"
	}
	return truncateBackendMessage(message)
}

func truncateBackendMessage(message string) string {
	if len(message) <= 512 {
		return message
	}
	return message[:512] + "…"
}

type vncNodeRow struct {
	id             string
	parentID       sql.NullString
	name           sql.NullString
	kind           int64
	protocol       sql.NullInt64
	host           sql.NullString
	port           sql.NullInt64
	credentialID   sql.NullString
	credentialMode sql.NullInt64
	inlinePassword sql.NullInt64
	tunnelEnabled  sql.NullInt64
	tunnelConfigID sql.NullString
}

func readVncTargetFromDatabase(
	database *sql.DB,
	nodeID, credentialID string,
	resolvePassword bool,
	electronUserDataPath ...string,
) (vncTarget, error) {
	target := vncTarget{}
	target.nodeID = normalizeID(nodeID)
	if resolvePassword && credentialID != "" {
		password, _, err := readVncCredentialSecret(database, credentialID, electronUserDataPath...)
		if err != nil {
			return vncTarget{}, err
		}
		target.password = password
	}
	if nodeID == "" {
		return target, nil
	}

	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return vncTarget{}, err
	}
	if len(columns) == 0 {
		return target, nil
	}
	visited := make(map[string]struct{})
	currentID := normalizeID(nodeID)
	inheritCredential := true
	leaf := true
	var resolvedProtocol int64
	var portContextProtocol int64
	protocolResolved := false
	portContextResolved := false
	tunnelResolved := false
	tunnelEnabled := false
	tunnelConfigID := ""
	displayName := ""
	for currentID != "" {
		if _, seen := visited[currentID]; seen {
			return vncTarget{}, errors.New("VNC connection tree contains a cycle")
		}
		visited[currentID] = struct{}{}
		row, err := readVncNode(database, columns, currentID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return vncTarget{}, err
		}
		if displayName == "" && row.name.Valid && strings.TrimSpace(row.name.String) != "" {
			displayName = strings.TrimSpace(row.name.String)
		}
		if !protocolResolved && row.protocol.Valid {
			resolvedProtocol = row.protocol.Int64
			protocolResolved = true
		}
		if !target.hostSet() && row.host.Valid && strings.TrimSpace(row.host.String) != "" {
			target.host = strings.TrimSpace(row.host.String)
		}
		if target.port == 0 && row.port.Valid && row.port.Int64 > 0 && row.port.Int64 <= 65535 {
			target.port = int(row.port.Int64)
		}
		if target.port != 0 && !portContextResolved && row.protocol.Valid {
			portContextProtocol = row.protocol.Int64
			portContextResolved = true
		}
		if !tunnelResolved && row.tunnelEnabled.Valid {
			tunnelResolved = true
			tunnelEnabled = row.tunnelEnabled.Int64 != 0
		}
		if tunnelConfigID == "" && row.tunnelConfigID.Valid {
			tunnelConfigID = normalizeTunnelID(row.tunnelConfigID.String)
		}

		if leaf && row.inlinePassword.Valid && row.inlinePassword.Int64 != 0 {
			// Inline passwords are an SSH/RDP-only setting in the legacy resolver. A VNC
			// node carrying the flag must stop saved-credential inheritance, but its
			// per-node secret is not a VNC credential; the UI will prompt instead.
			inheritCredential = false
		}
		if inheritCredential {
			if row.credentialMode.Valid {
				switch row.credentialMode.Int64 {
				case 1:
					inheritCredential = false
				case 2:
					inheritCredential = false
					if resolvePassword && row.credentialID.Valid && strings.TrimSpace(row.credentialID.String) != "" {
						password, found, err := readVncCredentialSecret(
							database,
							row.credentialID.String,
							electronUserDataPath...,
						)
						if err != nil {
							return vncTarget{}, err
						}
						if found {
							target.password = password
						}
					}
				}
			} else if row.credentialID.Valid && strings.TrimSpace(row.credentialID.String) != "" {
				if resolvePassword {
					password, found, err := readVncCredentialSecret(
						database,
						row.credentialID.String,
						electronUserDataPath...,
					)
					if err != nil {
						return vncTarget{}, err
					}
					if found {
						target.password = password
					}
				}
				inheritCredential = false
			}
		}
		if !row.parentID.Valid {
			break
		}
		currentID = normalizeID(row.parentID.String)
		leaf = false
	}
	if protocolResolved && portContextResolved && resolvedProtocol != portContextProtocol {
		target.port = 0
	}
	if protocolResolved && resolvedProtocol != vncProtocolValue {
		return vncTarget{}, errors.New("VNC node does not resolve to the VNC protocol")
	}
	if tunnelEnabled && tunnelConfigID == "" {
		return vncTarget{}, errors.New("VNC connection enables a VPN tunnel but no tunnel is configured")
	}
	if tunnelEnabled {
		target.tunnelConfigID = tunnelConfigID
	}
	target.displayName = displayName
	return target, nil
}

func (target vncTarget) hostSet() bool { return strings.TrimSpace(target.host) != "" }

func readVncNode(database *sql.DB, columns map[string]struct{}, id string) (vncNodeRow, error) {
	column := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	query := `SELECT Id, ` + column("ParentId") + `, ` + column("Name") + `, ` + column("Kind") + `, ` + column("Protocol") + `, ` + column("Host") + `, ` + column("Port") + `, ` + column("CredentialId") + `, ` + column("CredentialMode") + `, ` + column("UseInlinePassword") + `, ` + column("TunnelEnabled") + `, ` + column("TunnelConfigId") + ` FROM Nodes WHERE Id = ?;`
	var row vncNodeRow
	err := database.QueryRow(query, id).Scan(
		&row.id,
		&row.parentID,
		&row.name,
		&row.kind,
		&row.protocol,
		&row.host,
		&row.port,
		&row.credentialID,
		&row.credentialMode,
		&row.inlinePassword,
		&row.tunnelEnabled,
		&row.tunnelConfigID,
	)
	return row, err
}

func readVncCredentialSecret(
	database *sql.DB,
	credentialID string,
	electronUserDataPath ...string,
) (string, bool, error) {
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return "", false, err
	}
	if len(columns) == 0 {
		return "", false, nil
	}
	providerExpression := "0"
	if _, ok := columns["SecretProvider"]; ok {
		providerExpression = "COALESCE(SecretProvider, 0)"
	}
	protocolExpression := "NULL"
	if _, ok := columns["Protocol"]; ok {
		protocolExpression = "Protocol"
	}
	kindExpression := "NULL"
	if _, ok := columns["Kind"]; ok {
		kindExpression = "Kind"
	}
	var provider, protocol, kind sql.NullInt64
	if err := database.QueryRow(
		"SELECT "+providerExpression+", "+protocolExpression+", "+kindExpression+" FROM CredentialProfiles WHERE Id = ?;",
		normalizeID(credentialID),
	).Scan(&provider, &protocol, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	if provider.Valid && provider.Int64 != 0 {
		// Bitwarden values are intentionally not exposed to the renderer or copied into the
		// database. The UI can provide a connect-time password when the native cache has none.
		return "", false, nil
	}
	if protocol.Valid && protocol.Int64 != vncProtocolValue {
		return "", false, nil
	}
	if kind.Valid && kind.Int64 != 0 {
		return "", false, nil
	}
	return readStoredSecret(database, credentialID, electronUserDataPath...)
}

func readStoredSecret(database *sql.DB, id string, electronUserDataPath ...string) (string, bool, error) {
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil || !exists {
		return "", false, err
	}
	var encoded, encoding string
	err = database.QueryRow("SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;", normalizeID(id)).Scan(&encoded, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if len(encoded) > maxVncEncodedSecret {
		return "", false, errors.New("stored VNC secret is too large")
	}
	secretBytes, err := unprotectStoredSecret(id, encoded, encoding, electronUserDataPath...)
	if errors.Is(err, errUnsupportedSecretEncoding) {
		return "", false, errors.New("stored secret uses an unsupported encoding")
	}
	if err != nil {
		return "", false, err
	}
	secret := string(secretBytes)
	if err := validateVncPassword(secret); err != nil {
		return "", false, errors.New("stored VNC secret is too large")
	}
	return secret, true, nil
}
