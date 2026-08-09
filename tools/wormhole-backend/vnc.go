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
	backendLineLimit    = 64 * 1024 * 1024
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
	Username          string `json:"username,omitempty"`
	Domain            string `json:"domain,omitempty"`
	Password          string `json:"password,omitempty"`
	PasswordProvided  bool   `json:"passwordProvided,omitempty"`
	ManualCredentials bool   `json:"manualCredentials,omitempty"`
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
	Enabled           *bool  `json:"enabled,omitempty"`
	Path              string `json:"path,omitempty"`
	ServerRegion      int    `json:"serverRegion,omitempty"`
	Email             string `json:"email,omitempty"`
	MasterPassword    string `json:"masterPassword,omitempty"`
	AuthenticatorCode string `json:"authenticatorCode,omitempty"`
	Query             string `json:"query,omitempty"`
	ItemID            string `json:"itemId,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	LocalJSON         string `json:"localJson,omitempty"`
	SessionJSON       string `json:"sessionJson,omitempty"`
	SourceRevision    int64  `json:"sourceRevision,omitempty"`
	ProfilePath       string `json:"profilePath,omitempty"`
	StructureOnly     bool   `json:"structureOnly,omitempty"`
	PlanNonce         string `json:"planNonce,omitempty"`
	PlanToken         string `json:"planToken,omitempty"`
}

type backendResponse struct {
	ID            string `json:"id"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	SocksEndpoint string `json:"socksEndpoint,omitempty"`
	ForwardHost   string `json:"forwardHost,omitempty"`
	ForwardPort   int    `json:"forwardPort,omitempty"`
	TunnelActive  bool   `json:"tunnelActive,omitempty"`
	LeaseID       string `json:"leaseId,omitempty"`
	Result        any    `json:"result,omitempty"`
}

type backendEvent struct {
	Type                    string   `json:"type"`
	SessionID               string   `json:"sessionId"`
	LeaseID                 string   `json:"leaseId,omitempty"`
	Phase                   string   `json:"phase,omitempty"`
	Detail                  string   `json:"detail,omitempty"`
	Percent                 int      `json:"percent,omitempty"`
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

	mu                                 sync.Mutex
	sessions                           map[string]*vncSession
	tunnelLeases                       map[string]*tunnelRuntime
	tunnelForwarders                   map[string]*tunnelForwarder
	tunnelStarts                       map[string]*pendingTunnelStart
	tunnelPrompts                      map[string]*pendingTunnelPrompt
	promptSequence                     uint64
	routePrompts                       map[string]*pendingTunnelPrompt
	routeSequence                      uint64
	operations                         map[string]*pendingBackendOperation
	cleanup                            sync.WaitGroup
	bitwardenMu                        sync.RWMutex
	bitwardenOperationMu               sync.Mutex
	bitwardenBrowserMu                 sync.Mutex
	bitwardenSessionKey                string
	bitwardenSessionGeneration         uint64
	bitwardenBrowserLoaded             bool
	bitwardenBrowserPrimaryNeedsRepair bool
	bitwardenBrowserStorage            bitwardenBrowserStorageSnapshot
}

type pendingTunnelPrompt struct {
	leaseID string
	result  chan tunnelPromptResult
}

type pendingTunnelStart struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type pendingBackendOperation struct {
	cancel context.CancelFunc
	done   chan struct{}
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
		tunnelForwarders:     make(map[string]*tunnelForwarder),
		tunnelStarts:         make(map[string]*pendingTunnelStart),
		tunnelPrompts:        make(map[string]*pendingTunnelPrompt),
		routePrompts:         make(map[string]*pendingTunnelPrompt),
		operations:           make(map[string]*pendingBackendOperation),
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
	case "tunnel.forward":
		m.bindTunnelForwarder(command)
	case "tunnel.probe":
		m.probeTunnelTarget(command)
	case "tunnel.prompt-response":
		m.respondTunnelPrompt(command)
	case "tunnel.route-response":
		m.respondTunnelRoute(command)
	case "backup.export", "backup.import", "mremote.import.commit":
		m.startBackendOperation(command)
	case "operation.cancel":
		m.cleanup.Add(1)
		go func() {
			defer m.cleanup.Done()
			m.cancelBackendOperation(command)
		}()
	case "bitwarden.clear-session":
		// App lock must invalidate the in-memory vault session immediately. In particular, do not
		// queue this command behind a potentially long-running Bitwarden CLI operation.
		m.handleBitwarden(command, m.bitwardenGeneration())
	case "bitwarden.read", "bitwarden.set-enabled", "bitwarden.set-config",
		"bitwarden.install", "bitwarden.ensure-installed", "bitwarden.status", "bitwarden.login", "bitwarden.unlock",
		"bitwarden.logout", "bitwarden.sync", "bitwarden.sync-if-stale", "bitwarden.list", "bitwarden.search",
		"bitwarden.get", "bitwarden.resolve-credential", "bitwarden.resolve-node",
		"bitwarden.node-reference", "bitwarden.browser-storage-read",
		"bitwarden.browser-storage-capture", "bitwarden.browser-profile-seed",
		"bitwarden.browser-profile-register", "rdp.resolve-credential", "rdp.resolve-profile",
		"rdp.system-client-capability", "rdp.resolve-system-profile":
		generation := m.bitwardenGeneration()
		go m.handleBitwarden(command, generation)
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
		previous.closeAndWait()
	}

	m.respond(command.ID, nil)
	session.start(command, m.database, m.electronUserDataPath)
}

func (m *vncManager) disconnect(command backendCommand) {
	m.mu.Lock()
	session := m.sessions[command.SessionID]
	delete(m.sessions, command.SessionID)
	m.mu.Unlock()
	if session != nil {
		session.closeAndWait()
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
	m.clearBitwardenSession()
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
	for _, start := range m.tunnelStarts {
		start.cancel()
	}
	operations := make([]*pendingBackendOperation, 0, len(m.operations))
	for _, operation := range m.operations {
		operation.cancel()
		operations = append(operations, operation)
	}
	forwarders := make([]*tunnelForwarder, 0, len(m.tunnelForwarders))
	for _, forwarder := range m.tunnelForwarders {
		forwarders = append(forwarders, forwarder)
	}
	m.tunnelLeases = make(map[string]*tunnelRuntime)
	m.tunnelForwarders = make(map[string]*tunnelForwarder)
	m.tunnelStarts = make(map[string]*pendingTunnelStart)
	m.tunnelPrompts = make(map[string]*pendingTunnelPrompt)
	m.routePrompts = make(map[string]*pendingTunnelPrompt)
	m.operations = make(map[string]*pendingBackendOperation)
	m.mu.Unlock()

	for _, session := range sessions {
		m.cleanupNative(session.closeAndWait)
	}
	for _, forwarder := range forwarders {
		forwarder.close()
	}
	for _, lease := range leases {
		m.cleanupNative(lease.close)
	}
	for _, operation := range operations {
		<-operation.done
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
	start := &pendingTunnelStart{cancel: cancel, done: make(chan struct{})}
	m.tunnelStarts[command.SessionID] = start
	m.cleanup.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.cleanup.Done()
		defer close(start.done)
		defer cancel()
		configID := normalizeTunnelID(command.TunnelConfigID)
		if command.NodeID != "" {
			resolvedID, enabled, err := resolveNodeTunnel(m.databasePath, command.NodeID)
			if err != nil {
				m.finishTunnelAcquire(command, start, nil, err)
				return
			}
			if !enabled {
				m.finishTunnelAcquire(command, start, nil, nil)
				return
			}
			configID = resolvedID
		}
		if configID == "" {
			m.finishTunnelAcquire(command, start, nil, errors.New("VPN tunnel is enabled but no configuration is selected"))
			return
		}
		progressSessionID := command.ProgressSessionID
		if progressSessionID == "" {
			progressSessionID = command.SessionID
		}
		if command.NodeID != "" {
			useTunnel, err := readPromptBeforeTunnelConnect(m.databasePath)
			if err != nil {
				m.finishTunnelAcquire(command, start, nil, err)
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
					m.finishTunnelAcquire(command, start, nil, err)
					return
				}
				if route == "direct" {
					m.finishTunnelAcquire(command, start, nil, nil)
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
		m.finishTunnelAcquire(command, start, lease, err)
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

func (m *vncManager) finishTunnelAcquire(
	command backendCommand,
	start *pendingTunnelStart,
	lease *tunnelRuntime,
	err error,
) {
	m.mu.Lock()
	stillPending := m.tunnelStarts[command.SessionID] == start && start != nil
	if stillPending {
		delete(m.tunnelStarts, command.SessionID)
	}
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
		response.TunnelActive = true
		response.SocksEndpoint = lease.socksEndpoint()
	}
	_ = m.output.write(response)
}

func (m *vncManager) releaseTunnel(command backendCommand) {
	m.mu.Lock()
	lease := m.tunnelLeases[command.SessionID]
	delete(m.tunnelLeases, command.SessionID)
	forwarder := m.tunnelForwarders[command.SessionID]
	delete(m.tunnelForwarders, command.SessionID)
	start := m.tunnelStarts[command.SessionID]
	if start != nil {
		start.cancel()
		delete(m.tunnelStarts, command.SessionID)
	}
	m.mu.Unlock()
	forwarder.close()
	if lease == nil && start == nil {
		m.respond(command.ID, nil)
		return
	}
	m.cleanup.Add(1)
	go func() {
		defer m.cleanup.Done()
		if start != nil && start.done != nil {
			<-start.done
		}
		if lease != nil {
			lease.close()
		}
		// A successful release acknowledges that the sidecar reference is gone. In particular, the
		// final lease or cancelled pending acquire cannot race application shutdown or a subsequent
		// connection attempt.
		m.respond(command.ID, nil)
	}()
}

func (m *vncManager) bindTunnelForwarder(command backendCommand) {
	targetHost := strings.TrimSpace(command.Host)
	if strings.HasPrefix(targetHost, "[") && strings.HasSuffix(targetHost, "]") {
		targetHost = strings.TrimSuffix(strings.TrimPrefix(targetHost, "["), "]")
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(command.Port))

	m.mu.Lock()
	lease := m.tunnelLeases[command.SessionID]
	if lease == nil {
		m.mu.Unlock()
		m.respond(command.ID, errors.New("VPN tunnel lease is not active"))
		return
	}
	if m.tunnelForwarders[command.SessionID] != nil {
		m.mu.Unlock()
		m.respond(command.ID, errors.New("VPN tunnel forwarder is already active"))
		return
	}
	forwarder, err := startTunnelForwarder(lease, target)
	if err == nil {
		m.tunnelForwarders[command.SessionID] = forwarder
	}
	m.mu.Unlock()
	if err != nil {
		m.respond(command.ID, err)
		return
	}
	host, port := forwarder.address()
	_ = m.output.write(backendResponse{
		ID: command.ID, OK: true, LeaseID: command.SessionID, ForwardHost: host, ForwardPort: port,
	})
}

func (m *vncManager) probeTunnelTarget(command backendCommand) {
	m.mu.Lock()
	lease := m.tunnelLeases[command.SessionID]
	m.mu.Unlock()
	if lease == nil {
		m.respond(command.ID, errors.New("VPN tunnel lease is not active"))
		return
	}

	targetHost := strings.TrimSpace(command.Host)
	if strings.HasPrefix(targetHost, "[") && strings.HasSuffix(targetHost, "]") {
		targetHost = strings.TrimSuffix(strings.TrimPrefix(targetHost, "["), "]")
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(command.Port))
	m.cleanup.Add(1)
	go func() {
		defer m.cleanup.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		connection, err := lease.dialContext(ctx, "tcp", target)
		if connection != nil {
			_ = connection.Close()
		}
		m.respond(command.ID, err)
	}()
}

func (m *vncManager) respond(id string, err error) {
	response := backendResponse{ID: id, OK: err == nil}
	if err != nil {
		response.Error = publicBackendError(err)
	}
	_ = m.output.write(response)
}

func (m *vncManager) respondResult(id string, result any, err error) {
	response := backendResponse{ID: id, OK: err == nil, Result: result}
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
	done    chan struct{}

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

func (s *vncSession) start(command backendCommand, database *sql.DB, electronUserDataPath ...string) {
	s.done = make(chan struct{})
	go s.run(command, database, electronUserDataPath...)
}

func (s *vncSession) run(command backendCommand, database *sql.DB, electronUserDataPath ...string) {
	defer close(s.done)
	s.connect(command, database, electronUserDataPath...)
}

func (s *vncSession) connect(command backendCommand, database *sql.DB, electronUserDataPath ...string) {
	connectContext, ok := s.beginConnect()
	if !ok {
		return
	}
	defer s.endConnect()

	target, err := resolveVncTarget(database, command, electronUserDataPath...)
	if err != nil {
		logError("VNC session failed to connect: %v", err)
		s.fail(err)
		return
	}
	passwordProvided := command.PasswordProvided || command.Password != ""
	if target.password == "" && !passwordProvided && database != nil {
		credentialID := command.CredentialID
		if credentialID == "" && command.NodeID != "" {
			credentialID, err = resolveNodeCredentialID(database, command.NodeID, vncProtocolValue)
		}
		if err == nil && credentialID != "" {
			generation := s.manager.bitwardenGeneration()
			s.manager.bitwardenOperationMu.Lock()
			var resolved bitwardenResolvedCredential
			if s.manager.bitwardenGenerationIs(generation) {
				resolved, err = s.manager.resolveBitwardenCredential(credentialID, vncProtocolValue)
			} else {
				err = errBitwardenSessionInvalidated
			}
			s.manager.bitwardenOperationMu.Unlock()
			if err == nil && !s.manager.bitwardenGenerationIs(generation) {
				resolved = bitwardenResolvedCredential{}
				err = errBitwardenSessionInvalidated
			}
			if err == nil && resolved.Bitwarden {
				target.password = resolved.Password
			}
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
	if connectContext.Err() != nil {
		s.fail(errors.New("VNC connection was cancelled"))
		return
	}
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

func (s *vncSession) cancelPendingConnect() {
	s.stateMu.Lock()
	if s.conn != nil {
		s.stateMu.Unlock()
		return
	}
	cancel := s.connectCancel
	network := s.netConn
	s.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if network != nil {
		_ = network.Close()
	}
}

func (m *vncManager) cancelPendingVncConnections() {
	m.mu.Lock()
	sessions := make([]*vncSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		session.cancelPendingConnect()
	}
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

func (s *vncSession) closeAndWait() {
	s.close()
	if s.done != nil {
		<-s.done
	}
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
	bitwardenAction := strings.HasPrefix(command.Action, "bitwarden.")
	requiresSession := !bitwardenAction &&
		command.Action != "rdp.resolve-profile" &&
		command.Action != "rdp.resolve-credential" &&
		command.Action != "rdp.system-client-capability" &&
		command.Action != "rdp.resolve-system-profile"
	if requiresSession && (command.SessionID == "" || len(command.SessionID) > 128) {
		return errors.New("backend session ID is invalid")
	}
	switch command.Action {
	case "vnc.connect":
		if len(command.NodeID) > 128 || len(command.CredentialID) > 128 {
			return errors.New("VNC connection identity is invalid")
		}
		if command.NodeID != "" && command.CredentialID != "" {
			return errors.New("VNC credentials cannot override a saved connection")
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
	case "tunnel.forward":
		if strings.TrimSpace(command.Host) == "" || command.Port < 1 || command.Port > 65535 {
			return errors.New("VPN tunnel forward target is invalid")
		}
		if _, err := buildWebURL("http", command.Host, command.Port); err != nil {
			return errors.New("VPN tunnel forward target is invalid")
		}
	case "tunnel.probe":
		if strings.TrimSpace(command.Host) == "" || command.Port < 1 || command.Port > 65535 {
			return errors.New("VPN tunnel probe target is invalid")
		}
		if _, err := buildWebURL("http", command.Host, command.Port); err != nil {
			return errors.New("VPN tunnel probe target is invalid")
		}
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
	case "backup.export", "backup.import":
		if command.Path == "" || len([]rune(command.Path)) > 4096 || len(command.Password) > maxStoredCredentialBytes {
			return errors.New("backup operation request is invalid")
		}
	case "mremote.import.commit":
		if command.Path == "" || len([]rune(command.Path)) > 4096 || len(command.Password) > maxStoredCredentialBytes ||
			!validMRemotePlanNonce(command.PlanNonce) || !validSHA256(command.PlanToken) {
			return errors.New("mRemoteNG import request is invalid")
		}
	case "operation.cancel":
	case "bitwarden.read", "bitwarden.install", "bitwarden.ensure-installed", "bitwarden.status", "bitwarden.logout",
		"bitwarden.sync", "bitwarden.sync-if-stale",
		"bitwarden.clear-session":
	case "bitwarden.browser-storage-read":
		if !validBitwardenBrowserProfilePath(command.ProfilePath) {
			return errors.New("Bitwarden browser profile path is invalid")
		}
	case "bitwarden.browser-storage-capture":
		if !validBitwardenBrowserProfilePath(command.ProfilePath) || command.SourceRevision < 0 ||
			len(command.LocalJSON) > bitwardenBrowserStorageMaxJSON ||
			len(command.SessionJSON) > bitwardenBrowserStorageMaxJSON {
			return errors.New("Bitwarden browser storage capture is invalid")
		}
	case "bitwarden.browser-profile-seed":
		if !validBitwardenBrowserProfilePath(command.ProfilePath) ||
			len(command.Path) == 0 || len(command.Path) > 4096 ||
			!validBitwardenRouteKey(command.Query) {
			return errors.New("Bitwarden browser profile seed request is invalid")
		}
	case "bitwarden.browser-profile-register":
		if !validBitwardenBrowserProfilePath(command.ProfilePath) ||
			len(command.Path) == 0 || len(command.Path) > 4096 ||
			!validBitwardenExtensionID(command.Value) || !validBitwardenRouteKey(command.Query) {
			return errors.New("Bitwarden browser profile registration is invalid")
		}
	case "bitwarden.set-enabled":
		if command.Enabled == nil {
			return errors.New("Bitwarden enabled setting is invalid")
		}
	case "bitwarden.set-config":
		if len([]rune(command.Path)) > 4096 || command.ServerRegion < 0 || command.ServerRegion > 2 {
			return errors.New("Bitwarden CLI configuration is invalid")
		}
	case "bitwarden.login":
		if len([]rune(command.Email)) > 320 || len([]rune(command.MasterPassword)) > 4096 ||
			len([]rune(command.AuthenticatorCode)) > 64 {
			return errors.New("Bitwarden login request is invalid")
		}
	case "bitwarden.unlock":
		if command.MasterPassword == "" || len([]rune(command.MasterPassword)) > 4096 {
			return errors.New("Bitwarden unlock request is invalid")
		}
	case "bitwarden.list", "bitwarden.search":
		if len([]rune(command.Query)) > 2048 {
			return errors.New("Bitwarden search query is invalid")
		}
	case "bitwarden.get":
		if strings.TrimSpace(command.ItemID) == "" || len([]rune(command.ItemID)) > maxBitwardenItemIDLength {
			return errors.New("Bitwarden item id is invalid")
		}
	case "bitwarden.resolve-credential":
		if len(command.CredentialID) > 128 || bitwardenProtocolValue(command.Protocol) < 0 {
			return errors.New("Bitwarden credential request is invalid")
		}
	case "rdp.resolve-credential":
		if !validCredentialID(normalizeID(command.CredentialID)) {
			return errors.New("RDP credential request is invalid")
		}
	case "bitwarden.resolve-node", "bitwarden.node-reference":
		if len(command.NodeID) == 0 || len(command.NodeID) > 128 || bitwardenProtocolValue(command.Protocol) < 0 {
			return errors.New("Bitwarden connection request is invalid")
		}
	case "rdp.resolve-profile":
		if !validCredentialID(normalizeID(command.NodeID)) ||
			(command.CredentialID != "" && !validCredentialID(normalizeID(command.CredentialID))) ||
			(command.ManualCredentials && command.CredentialID != "") ||
			(command.ManualCredentials && (!validRdpText(command.Username, 513) ||
				!validRdpText(command.Domain, 512) || !validRdpText(command.Password, 4096))) {
			return errors.New("RDP connection request is invalid")
		}
	case "rdp.system-client-capability", "rdp.resolve-system-profile":
		if !validCredentialID(normalizeID(command.NodeID)) || command.CredentialID != "" ||
			command.ManualCredentials || command.Username != "" || command.Domain != "" || command.Password != "" {
			return errors.New("RDP system client request is invalid")
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
	passwordProvided := command.PasswordProvided || command.Password != ""
	hostHasPort := target.host != "" && vncHostIncludesPort(target.host)
	if database != nil && (command.NodeID != "" || command.CredentialID != "") {
		databaseTarget, err := readVncTargetFromDatabase(
			database,
			command.NodeID,
			command.CredentialID,
			!passwordProvided,
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
		if target.password == "" && !passwordProvided {
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
	bitwardenFailure := strings.Contains(lower, "bitwarden") || strings.Contains(lower, "vault")
	if bitwardenFailure &&
		(strings.Contains(lower, "locked") || strings.Contains(lower, "unlock") || strings.Contains(lower, "session")) {
		return "The Bitwarden vault is locked. Unlock it to continue.", false
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "authentication") || strings.Contains(lower, "security handshake") {
		return "VNC authentication failed. Enter the VNC password and try again.", true
	}
	if bitwardenFailure {
		return "The saved Bitwarden credential is unavailable. Enter the VNC password and try again.", true
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

		if inheritCredential {
			if row.credentialMode.Valid {
				if row.credentialMode.Int64 != 0 {
					inheritCredential = false
					if row.credentialMode.Int64 == 2 && resolvePassword && row.credentialID.Valid && strings.TrimSpace(row.credentialID.String) != "" {
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
	query := `SELECT Id, ` + column("ParentId") + `, ` + column("Name") + `, ` + column("Kind") + `, ` + column("Protocol") + `, ` + column("Host") + `, ` + column("Port") + `, ` + column("CredentialId") + `, ` + column("CredentialMode") + `, ` + column("TunnelEnabled") + `, ` + column("TunnelConfigId") + ` FROM Nodes WHERE Id = ?;`
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
