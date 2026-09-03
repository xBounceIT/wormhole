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
	"unicode/utf8"

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
	requestID        string
	sessionID        string
	done             chan struct{}
	approved         bool
	err              error
	waiters          int
	rememberDecision bool
	processed        chan struct{}
	processingErr    error
}

type mcpConnectionInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
	Folder   string `json:"folder,omitempty"`
}

type mcpOpenConnectionResult struct {
	Connection mcpConnectionInfo `json:"connection"`
	Status     string            `json:"status"`
}

type mcpConnectionList struct {
	Connections []mcpConnectionInfo `json:"connections"`
	Total       int                 `json:"total"`
	NextOffset  int                 `json:"nextOffset,omitempty"`
}

const (
	mcpDefaultConnectionListLimit = 100
	mcpMaxConnectionListLimit     = 500
	mcpMaxConnectionFolderBytes   = 4096
)

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

// This indirection keeps legacy-token read tests independent of the host operating system.
var mcpUnprotectStoredSecret = unprotectStoredSecret

func newMcpController(server *sshServer) *mcpController {
	return &mcpController{
		server:          server,
		locked:          true,
		decisions:       make(map[string]bool),
		pending:         make(map[string]*mcpApprovalWaiter),
		pendingByTarget: make(map[string]*mcpApprovalWaiter),
	}
}

func loadPersistedMcpStatus(databasePath string) (mcpStatusResponse, error) {
	settings, err := loadMcpSettings(databasePath)
	if err != nil {
		return mcpStatusResponse{}, err
	}
	return mcpStatusResponse{
		Enabled:  settings.Enabled,
		Port:     settings.Port,
		Endpoint: mcpEndpointURL(settings.Port),
	}, nil
}

func (controller *mcpController) status() (mcpStatusResponse, error) {
	status, err := loadPersistedMcpStatus(controller.server.databasePath)
	if err != nil {
		return mcpStatusResponse{}, err
	}

	controller.lifecycleMu.Lock()
	running := controller.httpServer != nil
	port := controller.port
	controller.lifecycleMu.Unlock()
	if port <= 0 {
		port = status.Port
	}
	status.Running = running
	status.Port = port
	status.Endpoint = mcpEndpointURL(port)
	return status, nil
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
		legacySafeStorage := strings.TrimSpace(encoding) == electronSafeStorageSecretEncoding
		secret, decodeErr := mcpUnprotectStoredSecret(mcpTokenCredentialID, encoded, encoding, controller.server.electronUserDataPath)
		if decodeErr != nil {
			if !legacySafeStorage {
				return "", fmt.Errorf("stored MCP token could not be decrypted: %w", decodeErr)
			}
		} else {
			defer clearBytes(secret)
			if len(secret) > 0 && len(secret) <= 4096 {
				token := string(secret)
				if legacySafeStorage {
					// The legacy value is still protected and usable. A failed best-effort rewrite
					// must not disable MCP; a later process can retry the migration.
					_ = storeMcpToken(database, token)
				}
				controller.token = token
				return controller.token, nil
			}
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

func (controller *mcpController) loadConnectionTree() ([]*treeNode, error) {
	if err := controller.ensureUnlocked(); err != nil {
		return nil, err
	}
	database, err := openDatabase(controller.server.databasePath, true)
	if err != nil {
		return nil, err
	}
	if database == nil {
		return []*treeNode{}, nil
	}
	defer database.Close()
	tree, err := loadTree(database)
	if err != nil {
		return nil, err
	}
	if err := controller.ensureUnlocked(); err != nil {
		return nil, err
	}
	return tree, nil
}

func validateMcpConnectionPage(offset int, limit int) (int, error) {
	if offset < 0 {
		return 0, errors.New("offset is out of range")
	}
	if limit == 0 {
		limit = mcpDefaultConnectionListLimit
	}
	if limit < 1 || limit > mcpMaxConnectionListLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", mcpMaxConnectionListLimit)
	}
	return limit, nil
}

func (controller *mcpController) listConnectionPage(offset int, limit int) (mcpConnectionList, error) {
	limit, err := validateMcpConnectionPage(offset, limit)
	if err != nil {
		return mcpConnectionList{}, err
	}
	tree, err := controller.loadConnectionTree()
	if err != nil {
		return mcpConnectionList{}, err
	}
	connections := make([]mcpConnectionInfo, 0, limit)
	total := 0
	walkMcpConnections(tree, func(connection mcpConnectionInfo) bool {
		if total >= offset && len(connections) < limit {
			connections = append(connections, connection)
		}
		total++
		return true
	})
	result := mcpConnectionList{Connections: connections, Total: total}
	if offset < total && len(connections) < total-offset {
		result.NextOffset = offset + len(connections)
	}
	return result, nil
}

func walkMcpConnections(nodes []*treeNode, visit func(mcpConnectionInfo) bool) {
	type frame struct {
		nodes  []*treeNode
		index  int
		folder string
	}
	stack := []frame{{nodes: nodes}}
	for len(stack) > 0 {
		current := &stack[len(stack)-1]
		if current.index >= len(current.nodes) {
			stack = stack[:len(stack)-1]
			continue
		}
		node := current.nodes[current.index]
		current.index++
		if node == nil {
			continue
		}
		if node.Kind == "folder" {
			stack = append(stack, frame{
				nodes:  node.Children,
				folder: appendBoundedMcpConnectionFolder(current.folder, node.Name),
			})
			continue
		}
		if node.Kind != "connection" || node.ID == "" || node.Protocol == "" {
			continue
		}
		if !visit(mcpConnectionInfo{
			ID:       node.ID,
			Name:     node.Name,
			Protocol: node.Protocol,
			Host:     node.Host,
			Port:     node.Port,
			Path:     node.HTTPPath,
			Folder:   current.folder,
		}) {
			return
		}
	}
}

func appendBoundedMcpConnectionFolder(parent string, name string) string {
	if parent == "" {
		return boundedMcpConnectionFolderValue(name)
	}
	return boundedMcpConnectionFolderValue(parent + " / " + name)
}

func boundedMcpConnectionFolderValue(value string) string {
	if len(value) <= mcpMaxConnectionFolderBytes {
		return value
	}
	const prefix = "…"
	start := len(value) - (mcpMaxConnectionFolderBytes - len(prefix))
	for start < len(value) && !utf8.RuneStart(value[start]) {
		start++
	}
	return prefix + value[start:]
}

func loadMcpConnection(database *sql.DB, connectionID string) (mcpConnectionInfo, error) {
	currentID := normalizeID(connectionID)
	seen := make(map[string]struct{})
	folders := make([]string, 0, 4)
	connection := mcpConnectionInfo{}
	var resolvedProtocol sql.NullInt64
	for currentID != "" {
		if _, duplicate := seen[currentID]; duplicate {
			return mcpConnectionInfo{}, errors.New("connection tree contains a cycle")
		}
		seen[currentID] = struct{}{}
		var (
			id       string
			parentID sql.NullString
			name     string
			kind     int64
			protocol sql.NullInt64
		)
		err := database.QueryRow(`
SELECT Id, ParentId, Name, Kind, Protocol
FROM Nodes
WHERE lower(Id) = ?
LIMIT 1;`, currentID).Scan(&id, &parentID, &name, &kind, &protocol)
		if errors.Is(err, sql.ErrNoRows) {
			if connection.ID == "" {
				return mcpConnectionInfo{}, fmt.Errorf("no saved connection with id '%s'", connectionID)
			}
			break
		}
		if err != nil {
			return mcpConnectionInfo{}, fmt.Errorf("cannot read connection metadata: %w", err)
		}
		if connection.ID == "" {
			if kind != workspaceNodeConnection {
				return mcpConnectionInfo{}, fmt.Errorf("no saved connection with id '%s'", connectionID)
			}
			connection.ID = strings.TrimSpace(id)
			connection.Name = name
		} else if kind == workspaceNodeFolder {
			folders = append(folders, name)
		}
		if !resolvedProtocol.Valid && protocol.Valid {
			resolvedProtocol = protocol
		}
		if !parentID.Valid || strings.TrimSpace(parentID.String) == "" {
			break
		}
		currentID = normalizeID(parentID.String)
	}
	if !resolvedProtocol.Valid {
		return mcpConnectionInfo{}, errors.New("connection has no protocol")
	}
	connection.Protocol = protocolName(resolvedProtocol)
	if protocolValue, ok := workspaceProtocolValue(connection.Protocol); !ok || protocolValue != resolvedProtocol.Int64 {
		return mcpConnectionInfo{}, errors.New("connection protocol is not supported")
	}
	for index := len(folders) - 1; index >= 0; index-- {
		connection.Folder = appendBoundedMcpConnectionFolder(connection.Folder, folders[index])
	}
	return connection, nil
}

func resolveMcpSSHConnection(database *sql.DB, connection mcpConnectionInfo) (mcpConnectionInfo, error) {
	nodes, err := loadSSHNodes(database)
	if err != nil {
		return mcpConnectionInfo{}, err
	}
	endpoint, err := resolveSSHNodeEndpoint(nodes, connection.ID)
	if err != nil {
		return mcpConnectionInfo{}, err
	}
	connection.Host = endpoint.host
	connection.Port = endpoint.port
	return connection, nil
}

func resolveMcpConnectionTarget(database *sql.DB, connection mcpConnectionInfo) (mcpConnectionInfo, error) {
	switch connection.Protocol {
	case "ssh":
		return resolveMcpSSHConnection(database, connection)
	case "rdp":
		chain, err := loadRdpNodeChain(database, connection.ID)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		host, port, err := resolveRdpTargetFromChain(chain)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		connection.Host, connection.Port = host, port
		return connection, nil
	case "vnc":
		target, err := readVncTargetFromDatabase(database, connection.ID, "", false)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		host, port, err := splitVncHostPort(target.host, target.port)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		if host == "" {
			return mcpConnectionInfo{}, errors.New("VNC host is invalid")
		}
		connection.Host, connection.Port = host, port
		return connection, nil
	case "http", "https":
		nodes, err := loadWebNodes(database)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		leaf := nodes[normalizeID(connection.ID)]
		if leaf == nil || leaf.Kind != workspaceNodeConnection {
			return mcpConnectionInfo{}, errors.New("web connection was not found")
		}
		target, err := resolveWebTargetFromNodes(leaf, nodes)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		connection.Protocol = target.Protocol
		connection.Host, connection.Port, connection.Path = target.Host, target.Port, target.path
		return connection, nil
	case "serial":
		nodes, err := loadSerialNodes(database)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		target, err := resolveSerialTargetFromNodes(nodes, connection.ID)
		if err != nil {
			return mcpConnectionInfo{}, err
		}
		connection.Host, connection.Port, connection.Path = target.PortName, 0, ""
		return connection, nil
	default:
		return mcpConnectionInfo{}, errors.New("connection protocol is not supported")
	}
}

func (controller *mcpController) resolveConnectionTarget(connectionID string) (mcpConnectionInfo, error) {
	if connectionID == "" || len(connectionID) > 128 || strings.TrimSpace(connectionID) != connectionID {
		return mcpConnectionInfo{}, errors.New("connection id is invalid")
	}
	if err := controller.ensureUnlocked(); err != nil {
		return mcpConnectionInfo{}, err
	}
	database, err := openDatabase(controller.server.databasePath, true)
	if err != nil {
		return mcpConnectionInfo{}, err
	}
	if database == nil {
		return mcpConnectionInfo{}, errors.New("Wormhole database has no connections")
	}
	defer database.Close()
	connection, err := loadMcpConnection(database, connectionID)
	if err != nil {
		return mcpConnectionInfo{}, err
	}
	connection, err = resolveMcpConnectionTarget(database, connection)
	if err != nil {
		return mcpConnectionInfo{}, err
	}
	if len([]byte(connection.Name)) > 2048 || len([]byte(connection.Host)) > 4096 ||
		len([]byte(connection.Path)) > 4096 || len([]byte(connection.Folder)) > mcpMaxConnectionFolderBytes {
		return mcpConnectionInfo{}, errors.New("connection metadata is too large for an approval request")
	}
	if err := controller.ensureUnlocked(); err != nil {
		return mcpConnectionInfo{}, err
	}
	return connection, nil
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
		requestID:        requestID,
		sessionID:        sessionID,
		done:             make(chan struct{}),
		waiters:          1,
		rememberDecision: true,
	}
	controller.pending[requestID] = waiter
	controller.pendingByTarget[sessionID] = waiter
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
	controller.approvalMu.Unlock()

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

func (controller *mcpController) requestOpenConnection(
	ctx context.Context,
	connectionID string,
) (mcpOpenConnectionResult, error) {
	connection, err := controller.resolveConnectionTarget(connectionID)
	if err != nil {
		return mcpOpenConnectionResult{}, err
	}
	if err := controller.ensureConnectionOpenApproval(ctx, connection); err != nil {
		return mcpOpenConnectionResult{}, err
	}
	return mcpOpenConnectionResult{Connection: connection, Status: "opening"}, nil
}

func (controller *mcpController) ensureConnectionOpenApproval(
	ctx context.Context,
	connection mcpConnectionInfo,
) (resultErr error) {
	if err := controller.ensureUnlocked(); err != nil {
		return err
	}
	requestID, err := newMcpRequestID()
	if err != nil {
		return err
	}
	waiter := &mcpApprovalWaiter{
		requestID: requestID,
		sessionID: connection.ID,
		done:      make(chan struct{}),
		waiters:   1,
		processed: make(chan struct{}),
	}
	defer func() {
		controller.approvalMu.Lock()
		if waiter.approved {
			waiter.processingErr = resultErr
		}
		controller.approvalMu.Unlock()
		close(waiter.processed)
	}()

	controller.approvalMu.Lock()
	if controller.locked {
		controller.approvalMu.Unlock()
		return errors.New("Wormhole is locked. Unlock the app before using MCP tools.")
	}
	controller.pending[requestID] = waiter
	controller.server.output.write(sshWireEvent{
		Type:             "mcp.approval",
		RequestID:        requestID,
		SessionID:        connection.ID,
		Host:             connection.Host,
		Port:             connection.Port,
		Title:            connection.Name,
		Tool:             "open_connection",
		ApprovalKind:     "open_connection",
		ConnectionID:     connection.ID,
		Protocol:         connection.Protocol,
		Path:             connection.Path,
		ConnectionFolder: connection.Folder,
	})
	controller.approvalMu.Unlock()

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
			if err := ctx.Err(); err != nil {
				return err
			}
			current, err := controller.resolveConnectionTarget(connection.ID)
			if err != nil {
				return err
			}
			if current != connection {
				return errors.New("the saved connection changed while approval was pending")
			}
			return ctx.Err()
		}
		return errors.New("the user denied opening that connection")
	case <-ctx.Done():
		controller.releasePending(waiter)
		return ctx.Err()
	}
}

func (controller *mcpController) resolveApproval(requestID string, approved bool) error {
	controller.approvalMu.Lock()
	waiter := controller.pending[requestID]
	var processed chan struct{}
	if waiter != nil {
		delete(controller.pending, requestID)
		if controller.pendingByTarget[waiter.sessionID] == waiter {
			delete(controller.pendingByTarget, waiter.sessionID)
		}
		if !controller.locked && waiter.rememberDecision {
			controller.decisions[waiter.sessionID] = approved
		}
		waiter.approved = approved
		close(waiter.done)
		processed = waiter.processed
	}
	controller.approvalMu.Unlock()
	if waiter == nil {
		return errors.New("MCP approval request is no longer pending")
	}
	if processed != nil {
		<-processed
		controller.approvalMu.Lock()
		processingErr := waiter.processingErr
		controller.approvalMu.Unlock()
		if processingErr != nil {
			controller.emitApprovalCancelled(waiter)
			return processingErr
		}
	}
	return nil
}

func (controller *mcpController) releasePending(waiter *mcpApprovalWaiter) {
	cancelled := false
	controller.approvalMu.Lock()
	if current := controller.pending[waiter.requestID]; current == waiter {
		waiter.waiters--
		if waiter.waiters <= 0 {
			delete(controller.pending, waiter.requestID)
			if controller.pendingByTarget[waiter.sessionID] == waiter {
				delete(controller.pendingByTarget, waiter.sessionID)
			}
			waiter.approved = false
			cancelled = true
		}
	}
	controller.approvalMu.Unlock()
	if cancelled {
		controller.emitApprovalCancelled(waiter)
		close(waiter.done)
	}
}

func (controller *mcpController) cancelPending(reason string) {
	var cancelledWaiters []*mcpApprovalWaiter
	controller.approvalMu.Lock()
	for requestID, waiter := range controller.pending {
		delete(controller.pending, requestID)
		if controller.pendingByTarget[waiter.sessionID] == waiter {
			delete(controller.pendingByTarget, waiter.sessionID)
		}
		waiter.approved = false
		waiter.err = errors.New(reason)
		cancelledWaiters = append(cancelledWaiters, waiter)
	}
	controller.approvalMu.Unlock()
	for _, waiter := range cancelledWaiters {
		controller.emitApprovalCancelled(waiter)
		close(waiter.done)
	}
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
	}
	controller.approvalMu.Unlock()
	if waiter != nil {
		controller.emitApprovalCancelled(waiter)
		close(waiter.done)
	}
}

func (controller *mcpController) emitApprovalCancelled(waiter *mcpApprovalWaiter) {
	if waiter == nil || controller.server == nil || controller.server.output == nil {
		return
	}
	controller.server.output.write(sshWireEvent{
		Type:      "mcp.approval-cancelled",
		RequestID: waiter.requestID,
		SessionID: waiter.sessionID,
	})
}

func newMcpServer(controller *mcpController) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "wormhole", Version: "0.9.0"}, nil)
	type listConnectionsInput struct {
		Offset int `json:"offset,omitempty"`
		Limit  int `json:"limit,omitempty"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_connections",
		Description: "List saved Wormhole connections without exposing credentials. Returns a bounded page with each connection's id, name, protocol, host, port, and folder path. Pass nextOffset as offset to continue, then use an id with open_connection.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, input listConnectionsInput) (*mcp.CallToolResult, mcpConnectionList, error) {
		page, err := controller.listConnectionPage(input.Offset, input.Limit)
		return nil, page, err
	})

	type openConnectionInput struct {
		ConnectionID string `json:"connectionId"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "open_connection",
		Description: "Open a saved Wormhole connection in the desktop app. Wormhole asks the user for explicit approval every time this tool is called; approval is never remembered for a later open request.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input openConnectionInput) (*mcp.CallToolResult, mcpOpenConnectionResult, error) {
		result, err := controller.requestOpenConnection(ctx, input.ConnectionID)
		return nil, result, err
	})

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
		Description: "Run a single shell command on a connected SSH session and return its captured output and exit code. This drives the user's live terminal, so it assumes a normal POSIX shell prompt is in the foreground. A timed-out command can remain active and blocks another run_command call until it finishes; use send_text to interrupt it when needed. The first action on a session asks the user to approve AI-agent control.",
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
	var previousEncoded, previousEncoding sql.NullString
	err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&previousEncoded, &previousEncoding)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("could not read the previous MCP bearer token: %w", err)
	}

	encoded, encoding, err := credentialSecretStore(mcpTokenCredentialID, "", token)
	if err != nil {
		return errors.New("could not protect MCP bearer token")
	}

	transaction, err := database.Begin()
	if err != nil {
		_ = credentialSecretDelete(mcpTokenCredentialID, encoded, encoding)
		return fmt.Errorf("could not start the MCP bearer token save: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
			_ = credentialSecretDelete(mcpTokenCredentialID, encoded, encoding)
		}
	}()
	if err := upsertCredentialSecret(
		transaction,
		normalizeID(mcpTokenCredentialID),
		encoded,
		encoding,
	); err != nil {
		return fmt.Errorf("could not store MCP bearer token: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("could not store MCP bearer token: %w", err)
	}
	committed = true

	if previousEncoded.Valid && previousEncoding.Valid &&
		(previousEncoded.String != encoded || previousEncoding.String != encoding) {
		_ = credentialSecretDelete(
			mcpTokenCredentialID,
			previousEncoded.String,
			previousEncoding.String,
		)
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
