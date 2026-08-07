package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpStatusResponse struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint"`
}

type mcpSettings struct {
	Enabled bool
	Port    int
}

type mcpApprovalWaiter struct {
	requestID string
	sessionID string
	done      chan struct{}
	approved  bool
	err       error
	waiters   int
}

type mcpController struct {
	server *sshServer

	lifecycleMu sync.Mutex
	httpServer  *http.Server
	listener    net.Listener
	port        int

	tokenMu sync.Mutex
	token   string

	approvalMu      sync.Mutex
	locked          bool
	decisions       map[string]bool
	pending         map[string]*mcpApprovalWaiter
	pendingByTarget map[string]*mcpApprovalWaiter
}

func newMcpController(server *sshServer) *mcpController {
	return &mcpController{
		server:          server,
		locked:          true,
		decisions:       make(map[string]bool),
		pending:         make(map[string]*mcpApprovalWaiter),
		pendingByTarget: make(map[string]*mcpApprovalWaiter),
	}
}

func (controller *mcpController) status() (mcpStatusResponse, error) {
	settings, err := loadMcpSettings(controller.server.databasePath)
	if err != nil {
		return mcpStatusResponse{}, err
	}

	controller.lifecycleMu.Lock()
	running := controller.httpServer != nil
	port := controller.port
	controller.lifecycleMu.Unlock()
	if port <= 0 {
		port = settings.Port
	}
	return mcpStatusResponse{
		Enabled:  settings.Enabled,
		Running:  running,
		Port:     port,
		Endpoint: mcpEndpointURL(port),
	}, nil
}

func (controller *mcpController) start(port int, persist bool) error {
	if err := validateMcpPort(port); err != nil {
		return err
	}

	controller.lifecycleMu.Lock()
	if controller.httpServer != nil {
		runningPort := controller.port
		controller.lifecycleMu.Unlock()
		if runningPort != port {
			return errors.New("MCP server is already running on another port")
		}
		if persist {
			return saveMcpSettings(controller.server.databasePath, mcpSettings{Enabled: true, Port: port})
		}
		return nil
	}

	if _, err := controller.getOrCreateToken(); err != nil {
		controller.lifecycleMu.Unlock()
		return err
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		controller.lifecycleMu.Unlock()
		return fmt.Errorf("could not bind MCP server: %w", err)
	}

	server := newMcpServer(controller)
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	mux := http.NewServeMux()
	authorizedHandler := mcpBearerMiddleware(controller, handler)
	// Keep /mcp as the Electron-facing endpoint while accepting the legacy WinUI root endpoint
	// during the migration. Both paths remain loopback-bound and bearer-protected.
	mux.Handle("/mcp", authorizedHandler)
	mux.Handle("/", authorizedHandler)
	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	controller.listener = listener
	controller.httpServer = httpServer
	controller.port = port
	controller.lifecycleMu.Unlock()

	if persist {
		if err := saveMcpSettings(controller.server.databasePath, mcpSettings{Enabled: true, Port: port}); err != nil {
			_ = controller.stop(false)
			return err
		}
	}

	go controller.serve(httpServer, listener)
	return nil
}

func (controller *mcpController) serve(httpServer *http.Server, listener net.Listener) {
	err := httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return
	}

	controller.lifecycleMu.Lock()
	if controller.httpServer == httpServer {
		controller.httpServer = nil
		controller.listener = nil
		controller.port = 0
	}
	controller.lifecycleMu.Unlock()
	controller.cancelPending("MCP server stopped unexpectedly")
}

func (controller *mcpController) stop(persist bool) error {
	if persist {
		settings, err := loadMcpSettings(controller.server.databasePath)
		if err != nil {
			return err
		}
		settings.Enabled = false
		if err := saveMcpSettings(controller.server.databasePath, settings); err != nil {
			return err
		}
	}

	controller.lifecycleMu.Lock()
	httpServer := controller.httpServer
	controller.httpServer = nil
	controller.listener = nil
	controller.port = 0
	controller.lifecycleMu.Unlock()

	controller.cancelPending("MCP server stopped")
	if httpServer == nil {
		return nil
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownContext)
}

func (controller *mcpController) setPort(port int) (mcpStatusResponse, error) {
	if err := validateMcpPort(port); err != nil {
		return mcpStatusResponse{}, err
	}
	controller.lifecycleMu.Lock()
	running := controller.httpServer != nil
	controller.lifecycleMu.Unlock()
	if running {
		return mcpStatusResponse{}, errors.New("stop the MCP server before changing its port")
	}
	settings, err := loadMcpSettings(controller.server.databasePath)
	if err != nil {
		return mcpStatusResponse{}, err
	}
	settings.Port = port
	if err := saveMcpSettings(controller.server.databasePath, settings); err != nil {
		return mcpStatusResponse{}, err
	}
	return controller.status()
}

func (controller *mcpController) getOrCreateToken() (string, error) {
	controller.tokenMu.Lock()
	defer controller.tokenMu.Unlock()
	if controller.token != "" {
		return controller.token, nil
	}

	database, err := openDatabase(controller.server.databasePath, false)
	if err != nil {
		return "", err
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		return "", err
	}
	var encoded, encoding string
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&encoded, &encoding)
	if err == nil {
		secret, decodeErr := unprotectStoredSecret(mcpTokenCredentialID, encoded, encoding, controller.server.electronUserDataPath)
		if decodeErr != nil {
			return "", fmt.Errorf("stored MCP token could not be decrypted: %w", decodeErr)
		}
		defer clearBytes(secret)
		if len(secret) > 0 && len(secret) <= 4096 {
			controller.token = string(secret)
			return controller.token, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("cannot read the stored MCP token: %w", err)
	}

	token, err := generateMcpToken()
	if err != nil {
		return "", err
	}
	if err := storeMcpToken(database, token); err != nil {
		return "", err
	}
	controller.token = token
	return token, nil
}

func (controller *mcpController) regenerateToken() (string, error) {
	controller.tokenMu.Lock()
	defer controller.tokenMu.Unlock()
	token, err := generateMcpToken()
	if err != nil {
		return "", err
	}
	database, err := openDatabase(controller.server.databasePath, false)
	if err != nil {
		return "", err
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		return "", err
	}
	if err := storeMcpToken(database, token); err != nil {
		return "", err
	}
	controller.token = token
	return token, nil
}

func (controller *mcpController) currentToken() string {
	controller.tokenMu.Lock()
	defer controller.tokenMu.Unlock()
	return controller.token
}

func (controller *mcpController) setLocked(locked bool) {
	controller.approvalMu.Lock()
	controller.locked = locked
	controller.approvalMu.Unlock()
	if locked {
		controller.cancelPending("Wormhole is locked. Unlock the app before using MCP tools.")
	}
}

func (controller *mcpController) ensureUnlocked() error {
	controller.approvalMu.Lock()
	locked := controller.locked
	controller.approvalMu.Unlock()
	if locked {
		return errors.New("Wormhole is locked. Unlock the app before using MCP tools.")
	}
	return nil
}

func (controller *mcpController) listSessions() ([]mcpSessionInfo, error) {
	if err := controller.ensureUnlocked(); err != nil {
		return nil, err
	}
	controller.server.mu.Lock()
	defer controller.server.mu.Unlock()
	result := make([]mcpSessionInfo, 0, len(controller.server.sessions))
	for _, native := range controller.server.sessions {
		if native == nil || native.isClosed() {
			continue
		}
		result = append(result, native.mcpSession)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

func (controller *mcpController) resolveSession(sessionID string) (*sshNativeSession, error) {
	if err := controller.ensureUnlocked(); err != nil {
		return nil, err
	}
	if sessionID == "" || len(sessionID) > 128 || strings.TrimSpace(sessionID) != sessionID {
		return nil, errors.New("SSH session id is invalid")
	}
	controller.server.mu.Lock()
	native := controller.server.sessions[sessionID]
	controller.server.mu.Unlock()
	if native == nil || native.isClosed() {
		return nil, fmt.Errorf("no live SSH session with id '%s'", sessionID)
	}
	return native, nil
}

func (controller *mcpController) ensureApproval(
	ctx context.Context,
	native *sshNativeSession,
	tool string,
) error {
	if err := controller.ensureUnlocked(); err != nil {
		return err
	}
	sessionID := native.id

	controller.approvalMu.Lock()
	if approved, exists := controller.decisions[sessionID]; exists {
		controller.approvalMu.Unlock()
		if approved {
			return controller.ensureUnlocked()
		}
		return errors.New("the user denied AI-agent control of that session")
	}
	if pending := controller.pendingByTarget[sessionID]; pending != nil {
		pending.waiters++
		done := pending.done
		controller.approvalMu.Unlock()
		select {
		case <-done:
			controller.approvalMu.Lock()
			approved := pending.approved
			waitErr := pending.err
			controller.approvalMu.Unlock()
			if waitErr != nil {
				return waitErr
			}
			if approved {
				return controller.ensureUnlocked()
			}
			return errors.New("the user denied AI-agent control of that session")
		case <-ctx.Done():
			controller.releasePending(pending)
			return ctx.Err()
		}
	}

	requestID, err := newMcpRequestID()
	if err != nil {
		controller.approvalMu.Unlock()
		return err
	}
	waiter := &mcpApprovalWaiter{
		requestID: requestID,
		sessionID: sessionID,
		done:      make(chan struct{}),
		waiters:   1,
	}
	controller.pending[requestID] = waiter
	controller.pendingByTarget[sessionID] = waiter
	controller.approvalMu.Unlock()

	controller.server.output.write(sshWireEvent{
		Type:      "mcp.approval",
		RequestID: requestID,
		SessionID: native.id,
		Host:      native.mcpSession.Host,
		Port:      native.mcpSession.Port,
		Username:  native.mcpSession.Username,
		Title:     native.mcpSession.Title,
		Tool:      tool,
	})

	select {
	case <-waiter.done:
		controller.approvalMu.Lock()
		approved := waiter.approved
		waitErr := waiter.err
		controller.approvalMu.Unlock()
		if waitErr != nil {
			return waitErr
		}
		if approved {
			return controller.ensureUnlocked()
		}
		return errors.New("the user denied AI-agent control of that session")
	case <-ctx.Done():
		controller.releasePending(waiter)
		return ctx.Err()
	case <-native.done:
		controller.releasePending(waiter)
		return errSSHSessionClosed
	}
}

func (controller *mcpController) resolveApproval(requestID string, approved bool) error {
	controller.approvalMu.Lock()
	waiter := controller.pending[requestID]
	if waiter != nil {
		delete(controller.pending, requestID)
		delete(controller.pendingByTarget, waiter.sessionID)
		if !controller.locked {
			controller.decisions[waiter.sessionID] = approved
		}
		waiter.approved = approved
		close(waiter.done)
	}
	controller.approvalMu.Unlock()
	if waiter == nil {
		return errors.New("MCP approval request is no longer pending")
	}
	return nil
}

func (controller *mcpController) releasePending(waiter *mcpApprovalWaiter) {
	controller.approvalMu.Lock()
	if current := controller.pending[waiter.requestID]; current == waiter {
		waiter.waiters--
		if waiter.waiters <= 0 {
			delete(controller.pending, waiter.requestID)
			delete(controller.pendingByTarget, waiter.sessionID)
			waiter.approved = false
			close(waiter.done)
		}
	}
	controller.approvalMu.Unlock()
}

func (controller *mcpController) cancelPending(reason string) {
	controller.approvalMu.Lock()
	for requestID, waiter := range controller.pending {
		delete(controller.pending, requestID)
		delete(controller.pendingByTarget, waiter.sessionID)
		waiter.approved = false
		waiter.err = errors.New(reason)
		close(waiter.done)
	}
	controller.approvalMu.Unlock()
}

func (controller *mcpController) forgetSession(sessionID string) {
	controller.approvalMu.Lock()
	delete(controller.decisions, sessionID)
	waiter := controller.pendingByTarget[sessionID]
	if waiter != nil {
		delete(controller.pending, waiter.requestID)
		delete(controller.pendingByTarget, sessionID)
		waiter.approved = false
		waiter.err = errSSHSessionClosed
		close(waiter.done)
	}
	controller.approvalMu.Unlock()
}

func newMcpServer(controller *mcpController) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "wormhole", Version: "0.9.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_sessions",
		Description: "List the SSH sessions currently open and connected in Wormhole. Returns each session's id, host, port, username, tab title, and status.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, []mcpSessionInfo, error) {
		sessions, err := controller.listSessions()
		return nil, sessions, err
	})

	type runCommandInput struct {
		SessionID      string `json:"sessionId"`
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_command",
		Description: "Run a single shell command on a connected SSH session and return its captured output and exit code. This drives the user's live terminal, so it assumes a normal POSIX shell prompt is in the foreground. The first action on a session asks the user to approve AI-agent control.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input runCommandInput) (*mcp.CallToolResult, mcpCommandResult, error) {
		native, err := controller.resolveSession(input.SessionID)
		if err != nil {
			return nil, mcpCommandResult{}, err
		}
		if err := controller.ensureApproval(ctx, native, "run_command"); err != nil {
			return nil, mcpCommandResult{}, err
		}
		timeout, err := mcpCommandTimeout(input.TimeoutSeconds)
		if err != nil {
			return nil, mcpCommandResult{}, err
		}
		result, err := native.runMcpCommand(ctx, input.Command, timeout)
		return nil, result, err
	})

	type sendTextInput struct {
		SessionID string `json:"sessionId"`
		Text      string `json:"text"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "send_text",
		Description: "Type raw text into a connected SSH session exactly as if the user typed it; no output is captured. Append a carriage return to submit a line. The first action on a session asks the user to approve AI-agent control.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input sendTextInput) (*mcp.CallToolResult, string, error) {
		if len(input.Text) > mcpMaxSendTextBytes {
			return nil, "", errors.New("text is too large")
		}
		native, err := controller.resolveSession(input.SessionID)
		if err != nil {
			return nil, "", err
		}
		if err := controller.ensureApproval(ctx, native, "send_text"); err != nil {
			return nil, "", err
		}
		if err := native.write([]byte(input.Text)); err != nil {
			return nil, "", err
		}
		return nil, "ok", nil
	})

	type readTerminalInput struct {
		SessionID string `json:"sessionId"`
		MaxBytes  int    `json:"maxBytes,omitempty"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_terminal",
		Description: "Return recent terminal output from a connected SSH session as plain text with ANSI codes stripped. The first action on a session asks the user to approve AI-agent control.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input readTerminalInput) (*mcp.CallToolResult, string, error) {
		native, err := controller.resolveSession(input.SessionID)
		if err != nil {
			return nil, "", err
		}
		if err := controller.ensureApproval(ctx, native, "read_terminal"); err != nil {
			return nil, "", err
		}
		maxBytes := input.MaxBytes
		if maxBytes <= 0 {
			maxBytes = mcpDefaultReadBytes
		}
		if maxBytes > mcpMaxReadBytes {
			return nil, "", errors.New("maxBytes is out of range")
		}
		return nil, string(stripMcpAnsi(native.mcpReplay.snapshotTail(maxBytes))), nil
	})
	return server
}

func mcpBearerMiddleware(controller *mcpController, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		expected := controller.currentToken()
		if expected == "" || !isMcpAuthorized(request.Header.Get("Authorization"), expected) {
			response.Header().Set("WWW-Authenticate", `Bearer realm="Wormhole MCP"`)
			http.Error(response, "Unauthorized: missing or invalid bearer token.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func isMcpAuthorized(header, expected string) bool {
	const prefix = "Bearer "
	if header == "" || !strings.HasPrefix(strings.ToLower(header), strings.ToLower(prefix)) {
		return false
	}
	presented := strings.TrimSpace(header[len(prefix):])
	if presented == "" || len(presented) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

func generateMcpToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("could not generate MCP bearer token")
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func storeMcpToken(database *sql.DB, token string) error {
	protected, err := protectSecret(token)
	if err != nil {
		return errors.New("could not protect MCP bearer token")
	}
	defer clearBytes([]byte(protected))
	_, err = database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?)
ON CONFLICT(Id) DO UPDATE SET
    Secret = excluded.Secret,
    Encoding = excluded.Encoding,
    UpdatedAt = excluded.UpdatedAt;`,
		normalizeID(mcpTokenCredentialID),
		protected,
		protectedSecretEncoding,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("could not store MCP bearer token: %w", err)
	}
	return nil
}

func mcpEndpointURL(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/mcp"
}

func validateMcpPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("MCP port must be between 1 and 65535")
	}
	return nil
}

func mcpCommandTimeout(timeoutSeconds int) (time.Duration, error) {
	if timeoutSeconds <= 0 {
		return mcpDefaultCommandTimeout, nil
	}
	if timeoutSeconds > int(mcpMaxCommandTimeout/time.Second) {
		return 0, errors.New("timeoutSeconds is out of range")
	}
	return time.Duration(timeoutSeconds) * time.Second, nil
}

func loadMcpSettings(databasePath string) (mcpSettings, error) {
	settings := mcpSettings{Port: McpDefaultPort}
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil || document == nil {
		return settings, nil
	}
	if value, ok := document["EnableMcpServer"]; ok {
		_ = json.Unmarshal(value, &settings.Enabled)
	}
	if value, ok := document["McpServerPort"]; ok {
		var port int
		if json.Unmarshal(value, &port) == nil && validateMcpPort(port) == nil {
			settings.Port = port
		}
	}
	return settings, nil
}

func saveMcpSettings(databasePath string, settings mcpSettings) error {
	if err := validateMcpPort(settings.Port); err != nil {
		return err
	}
	_, settingsPath := authPaths(databasePath)
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		enabled, _ := json.Marshal(settings.Enabled)
		port, _ := json.Marshal(settings.Port)
		document["EnableMcpServer"] = enabled
		document["McpServerPort"] = port
		return nil
	})
}

func newMcpRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("could not create MCP request id")
	}
	return "mcp-" + hex.EncodeToString(value[:]), nil
}

const McpDefaultPort = 8765

func (server *sshServer) handleMcp(command sshWireCommand) {
	requestID := strings.TrimSpace(command.RequestID)
	respond := func(status *mcpStatusResponse, token string, err error) {
		event := sshWireEvent{Type: "mcp.response", RequestID: requestID, McpStatus: status, Token: token}
		if err != nil {
			event.Error = err.Error()
		}
		server.output.write(event)
	}
	if requestID == "" || len(requestID) > 128 {
		respond(nil, "", errors.New("MCP request id is invalid"))
		return
	}
	if server.mcp == nil {
		respond(nil, "", errors.New("MCP controller is unavailable"))
		return
	}

	switch command.Type {
	case "mcp.status":
		status, err := server.mcp.status()
		respond(&status, "", err)
	case "mcp.start":
		port := command.Port
		if port == 0 {
			settings, err := loadMcpSettings(server.databasePath)
			if err != nil {
				respond(nil, "", err)
				return
			}
			port = settings.Port
		}
		err := server.mcp.start(port, true)
		if err != nil {
			respond(nil, "", err)
			return
		}
		status, err := server.mcp.status()
		respond(&status, "", err)
	case "mcp.stop":
		err := server.mcp.stop(true)
		if err != nil {
			respond(nil, "", err)
			return
		}
		status, err := server.mcp.status()
		respond(&status, "", err)
	case "mcp.set-port":
		status, err := server.mcp.setPort(command.Port)
		respond(&status, "", err)
	case "mcp.get-token":
		token, err := server.mcp.getOrCreateToken()
		respond(nil, token, err)
	case "mcp.regenerate-token":
		token, err := server.mcp.regenerateToken()
		respond(nil, token, err)
	case "mcp.lock":
		server.mcp.setLocked(true)
		respond(nil, "", nil)
	case "mcp.unlock":
		server.mcp.setLocked(false)
		respond(nil, "", nil)
	case "mcp.approve":
		if err := server.mcp.resolveApproval(strings.TrimSpace(command.ApprovalID), command.Approved); err != nil {
			respond(nil, "", err)
			return
		}
		respond(nil, "", nil)
	default:
		respond(nil, "", fmt.Errorf("unsupported MCP command %q", command.Type))
	}
}
