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
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshConnectTimeout      = 15 * time.Second
	sshKeepAliveInterval   = 30 * time.Second
	sshOutputDrainTimeout  = 2 * time.Second
	sshInputMaxBytes       = 1024 * 1024
	sshInputQueueCapacity  = 16
	sshOutputChunk         = 16 * 1024
	sshMaxColumns          = 500
	sshMaxRows             = 500
)

var (
	errSSHSessionClosed           = errors.New("SSH session is closed")
	errSSHInputFull               = errors.New("SSH input queue is full")
	errSSHHostFingerprintChanged  = errors.New("SSH host fingerprint changed while connecting")
)

type sshWireCommand struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	NodeID    string `json:"node_id"`
	Data      string `json:"data"`
	Columns   uint32 `json:"columns"`
	Rows      uint32 `json:"rows"`
}

type sshWireEvent struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	Data        string `json:"data,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Username    string `json:"username,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

type sshNodeRow struct {
	ID                   string
	ParentID             sql.NullString
	Name                 string
	Kind                 int64
	Protocol             sql.NullInt64
	Host                 sql.NullString
	Port                 sql.NullInt64
	Username             sql.NullString
	CredentialID         sql.NullString
	CredentialMode       sql.NullInt64
	UseInlinePassword    sql.NullInt64
	KnownHostFingerprint sql.NullString
	TunnelEnabled        sql.NullInt64
}

type sshNode struct {
	id                   string
	parentID             string
	name                 string
	kind                 int64
	protocol             *int64
	host                 string
	port                 *int64
	username             string
	credentialID         string
	credentialMode       *int64
	useInlinePassword    bool
	knownHostFingerprint string
	tunnelEnabled        *bool
}

type sshTarget struct {
	nodeID               string
	host                 string
	port                 int
	username             string
	password             string
	privateKey           []byte
	keyPassphrase        string
	knownHostFingerprint string
}

type sshCredentialRow struct {
	Username       sql.NullString
	Kind           sql.NullInt64
	Protocol       sql.NullInt64
	SecretProvider sql.NullInt64
}

type sshNativeSession struct {
	id      string
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
	server  *sshServer

	inputQueue chan []byte
	done       chan struct{}
	outputWG   sync.WaitGroup
	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	closeOnce  sync.Once
}

type sshServer struct {
	databasePath string
	output       *sshEventWriter

	mu       sync.Mutex
	sessions map[string]*sshNativeSession
	pending  map[string]context.CancelFunc
}

type sshEventWriter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func (writer *sshEventWriter) write(event sshWireEvent) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	_ = writer.encoder.Encode(event)
}

func serveSSH(databasePath string, input io.Reader, output io.Writer) error {
	server := &sshServer{
		databasePath: databasePath,
		output:       &sshEventWriter{encoder: json.NewEncoder(output)},
		sessions:     make(map[string]*sshNativeSession),
		pending:      make(map[string]context.CancelFunc),
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	for scanner.Scan() {
		var command sshWireCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			server.writeError("", "invalid SSH command")
			continue
		}
		server.handle(command)
	}
	server.shutdown()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("SSH command channel failed: %w", err)
	}
	return nil
}

func (server *sshServer) handle(command sshWireCommand) {
	command.Type = strings.ToLower(strings.TrimSpace(command.Type))
	command.SessionID = strings.TrimSpace(command.SessionID)
	if command.SessionID == "" || len(command.SessionID) > 128 {
		server.writeError(command.SessionID, "SSH session id is invalid")
		return
	}

	switch command.Type {
	case "open":
		server.open(command)
	case "input":
		server.input(command)
	case "resize":
		server.resize(command)
	case "close":
		server.close(command.SessionID)
	default:
		server.writeError(command.SessionID, "unsupported SSH command")
	}
}

func (server *sshServer) open(command sshWireCommand) {
	nodeID := strings.TrimSpace(command.NodeID)
	if nodeID == "" || len(nodeID) > 128 {
		server.writeError(command.SessionID, "SSH connection id is invalid")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	server.mu.Lock()
	if _, exists := server.sessions[command.SessionID]; exists {
		server.mu.Unlock()
		cancel()
		server.writeError(command.SessionID, "SSH session is already open")
		return
	}
	if _, exists := server.pending[command.SessionID]; exists {
		server.mu.Unlock()
		cancel()
		server.writeError(command.SessionID, "SSH session is already connecting")
		return
	}
	server.pending[command.SessionID] = cancel
	server.mu.Unlock()

	go func() {
		native, target, err := openNativeSSH(ctx, server.databasePath, nodeID, command.Columns, command.Rows)
		if err != nil {
			pending := server.finishPending(command.SessionID)
			if pending && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				server.writeError(command.SessionID, safeSSHError(err))
			}
			return
		}

		native.id = command.SessionID
		native.server = server
		if !server.promote(command.SessionID, native) {
			native.close(false)
			return
		}
		if !server.publishConnected(command.SessionID, native, sshWireEvent{
			Type:        "connected",
			SessionID:   command.SessionID,
			Host:        target.host,
			Port:        target.port,
			Username:    target.username,
			Fingerprint: target.knownHostFingerprint,
		}) {
			native.close(false)
			return
		}
		native.start()
	}()
}

func (server *sshServer) input(command sshWireCommand) {
	data, err := base64.StdEncoding.DecodeString(command.Data)
	if err != nil || len(data) > sshInputMaxBytes {
		server.writeError(command.SessionID, "SSH input is invalid")
		return
	}

	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native == nil {
		server.writeError(command.SessionID, "SSH session is not connected")
		return
	}
	if err := native.write(data); err != nil {
		if server.isActive(native) {
			message := "SSH input failed"
			if errors.Is(err, errSSHInputFull) {
				message = "SSH input queue is full"
			}
			server.writeError(command.SessionID, message)
		}
	}
}

func (server *sshServer) resize(command sshWireCommand) {
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native == nil {
		server.writeError(command.SessionID, "SSH session is not connected")
		return
	}
	if err := native.resize(command.Columns, command.Rows); err != nil {
		if server.isActive(native) {
			server.writeError(command.SessionID, "SSH terminal resize failed")
		}
	}
}

func (server *sshServer) close(sessionID string) {
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
		native.close(true)
	}
}

func (server *sshServer) finishPending(sessionID string) bool {
	server.mu.Lock()
	_, pending := server.pending[sessionID]
	delete(server.pending, sessionID)
	server.mu.Unlock()
	return pending
}

func (server *sshServer) promote(sessionID string, native *sshNativeSession) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.pending[sessionID]; !exists {
		return false
	}
	delete(server.pending, sessionID)
	server.sessions[sessionID] = native
	return true
}

func (server *sshServer) publishConnected(
	sessionID string,
	native *sshNativeSession,
	event sshWireEvent,
) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.sessions[sessionID] != native {
		return false
	}
	server.output.write(event)
	return true
}

func (server *sshServer) remove(native *sshNativeSession) {
	server.mu.Lock()
	if current := server.sessions[native.id]; current == native {
		delete(server.sessions, native.id)
	}
	server.mu.Unlock()
}

func (server *sshServer) isActive(native *sshNativeSession) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.sessions[native.id] == native
}

func (server *sshServer) shutdown() {
	server.mu.Lock()
	pending := make([]context.CancelFunc, 0, len(server.pending))
	for sessionID, cancel := range server.pending {
		pending = append(pending, cancel)
		delete(server.pending, sessionID)
	}
	sessions := make([]*sshNativeSession, 0, len(server.sessions))
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

func (server *sshServer) writeError(sessionID, message string) {
	server.output.write(sshWireEvent{Type: "error", SessionID: sessionID, Error: message})
}

func (native *sshNativeSession) start() {
	native.lifecycleMu.Lock()
	if native.closed || native.started {
		native.lifecycleMu.Unlock()
		return
	}
	native.started = true
	native.outputWG.Add(2)
	go func() {
		defer native.outputWG.Done()
		native.readOutput(native.stdout)
	}()
	go func() {
		defer native.outputWG.Done()
		native.readOutput(native.stderr)
	}()
	go native.keepAlive()
	go func() {
		_ = native.session.Wait()
		native.waitForOutputDrain()
		native.close(true)
	}()
	native.lifecycleMu.Unlock()
}

func (native *sshNativeSession) keepAlive() {
	if native.client == nil || native.done == nil {
		return
	}
	ticker := time.NewTicker(sshKeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, _, err := native.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				native.close(true)
				return
			}
		case <-native.done:
			return
		}
	}
}

func (native *sshNativeSession) waitForOutputDrain() {
	drained := make(chan struct{})
	go func() {
		native.outputWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(sshOutputDrainTimeout):
	}
}

func (native *sshNativeSession) readOutput(reader io.Reader) {
	buffer := make([]byte, sshOutputChunk)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			native.server.output.write(sshWireEvent{
				Type:      "data",
				SessionID: native.id,
				Data:      base64.StdEncoding.EncodeToString(buffer[:count]),
			})
		}
		if err != nil {
			return
		}
	}
}

func (native *sshNativeSession) write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if native.inputQueue == nil || native.done == nil {
		_, err := native.stdin.Write(data)
		return err
	}
	copyOfData := append([]byte(nil), data...)
	select {
	case <-native.done:
		return errSSHSessionClosed
	default:
	}
	select {
	case native.inputQueue <- copyOfData:
		return nil
	case <-native.done:
		return errSSHSessionClosed
	default:
		return errSSHInputFull
	}
}

func (native *sshNativeSession) resize(columns, rows uint32) error {
	columns, rows = normalizeTerminalSize(columns, rows)
	return native.session.WindowChange(int(rows), int(columns))
}

func (native *sshNativeSession) close(notify bool) {
	native.closeOnce.Do(func() {
		native.lifecycleMu.Lock()
		native.closed = true
		native.lifecycleMu.Unlock()
		if native.done != nil {
			close(native.done)
		}
		if native.stdin != nil {
			_ = native.stdin.Close()
		}
		if native.session != nil {
			_ = native.session.Close()
		}
		if native.client != nil {
			_ = native.client.Close()
		}
		if native.server != nil {
			native.server.remove(native)
			if notify {
				native.server.output.write(sshWireEvent{Type: "closed", SessionID: native.id})
			}
		}
	})
}

func (native *sshNativeSession) startInputPump() {
	if native.inputQueue == nil || native.done == nil || native.stdin == nil {
		return
	}
	go func() {
		for {
			select {
			case data := <-native.inputQueue:
				if _, err := native.stdin.Write(data); err != nil {
					native.close(native.server != nil)
					return
				}
			case <-native.done:
				return
			}
		}
	}()
}

func openNativeSSH(
	ctx context.Context,
	databasePath string,
	nodeID string,
	columns uint32,
	rows uint32,
) (*sshNativeSession, sshTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, sshTarget{}, err
	}
	target, err := loadSSHTarget(databasePath, nodeID)
	if err != nil {
		return nil, sshTarget{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, sshTarget{}, err
	}
	native, fingerprint, err := dialNativeSSH(ctx, target, columns, rows)
	if err != nil {
		return nil, sshTarget{}, err
	}
	if target.knownHostFingerprint == "" {
		if err := persistSSHFingerprint(databasePath, target.nodeID, fingerprint); err != nil {
			if errors.Is(err, errSSHHostFingerprintChanged) {
				native.close(false)
				return nil, sshTarget{}, err
			}
			// A host-key pin is defense in depth, not a reason to throw away a healthy shell if an
			// old/partial database schema cannot store it. The active session still returns the
			// observed fingerprint so the renderer can display it.
		}
	}
	target.knownHostFingerprint = fingerprint
	return native, target, nil
}

func dialNativeSSH(
	ctx context.Context,
	target sshTarget,
	columns uint32,
	rows uint32,
) (*sshNativeSession, string, error) {
	var fingerprint string
	config := &ssh.ClientConfig{
		User:    target.username,
		Timeout: sshConnectTimeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			if target.knownHostFingerprint != "" && target.knownHostFingerprint != fingerprint {
				return fmt.Errorf(
					"SSH host key mismatch (expected %s, received %s)",
					target.knownHostFingerprint,
					fingerprint,
				)
			}
			return nil
		},
	}
	if len(target.privateKey) > 0 {
		signer, parseErr := ssh.ParsePrivateKey(target.privateKey)
		if parseErr != nil && target.keyPassphrase != "" {
			signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(
				target.privateKey,
				[]byte(target.keyPassphrase),
			)
		}
		if parseErr != nil {
			return nil, "", fmt.Errorf("could not read the SSH private key: %w", parseErr)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}
	if target.password != "" {
		config.Auth = append(config.Auth, ssh.Password(target.password))
	}
	if len(config.Auth) == 0 {
		return nil, "", errors.New("the connection has no usable SSH credential")
	}

	address := net.JoinHostPort(normalizeSSHHost(target.host), fmt.Sprintf("%d", target.port))
	dialer := net.Dialer{Timeout: sshConnectTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, "", fmt.Errorf("could not reach SSH server: %w", err)
	}
	stopConnectionOnCancel := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopConnectionOnCancel()
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		_ = connection.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, "", err
	}
	if err := ctx.Err(); err != nil {
		_ = clientConnection.Close()
		return nil, "", err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, "", fmt.Errorf("could not create the SSH terminal: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("could not create the SSH input stream: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("could not create the SSH output stream: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("could not create the SSH error stream: %w", err)
	}
	columns, rows = normalizeTerminalSize(columns, rows)
	if err := session.RequestPty(
		"xterm-256color",
		int(rows),
		int(columns),
		ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		},
	); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("SSH server rejected the terminal: %w", err)
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("SSH server rejected the shell: %w", err)
	}
	native := &sshNativeSession{
		id:      "",
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		inputQueue: make(chan []byte, sshInputQueueCapacity),
		done:       make(chan struct{}),
	}
	native.startInputPump()
	return native, fingerprint, nil
}

func normalizeSSHHost(host string) string {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

func normalizeTerminalSize(columns, rows uint32) (uint32, uint32) {
	if columns == 0 {
		columns = 80
	}
	if rows == 0 {
		rows = 24
	}
	if columns > sshMaxColumns {
		columns = sshMaxColumns
	}
	if rows > sshMaxRows {
		rows = sshMaxRows
	}
	return columns, rows
}

func loadSSHTarget(databasePath, nodeID string) (sshTarget, error) {
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return sshTarget{}, err
	}
	defer database.Close()

	nodes, err := loadSSHNodes(database)
	if err != nil {
		return sshTarget{}, err
	}
	root := nodes[normalizeID(nodeID)]
	if root == nil || root.kind == 0 {
		return sshTarget{}, errors.New("SSH connection was not found")
	}

	protocol := int64(0)
	protocolSet := false
	host := ""
	port := int64(0)
	portSet := false
	var portContextProtocol *int64
	username := ""
	credentialID := ""
	credentialResolved := root.useInlinePassword
	identityBoundary := false
	credentialContextPending := false
	var credentialContextProtocol *int64
	knownFingerprint := ""
	tunnelEnabled := false
	tunnelSet := false
	current := root
	seen := make(map[string]struct{})
	for current != nil {
		if _, duplicate := seen[current.id]; duplicate {
			return sshTarget{}, errors.New("SSH connection tree contains a cycle")
		}
		seen[current.id] = struct{}{}
		if !protocolSet && current.protocol != nil {
			protocol = *current.protocol
			protocolSet = true
		}
		if host == "" && strings.TrimSpace(current.host) != "" {
			host = strings.TrimSpace(current.host)
		}
		if !portSet && current.port != nil {
			port = *current.port
			portSet = true
			if current.protocol != nil {
				value := *current.protocol
				portContextProtocol = &value
			}
		} else if portSet && portContextProtocol == nil && current.protocol != nil {
			value := *current.protocol
			portContextProtocol = &value
		}
		if !identityBoundary && username == "" && strings.TrimSpace(current.username) != "" {
			username = strings.TrimSpace(current.username)
		}
		if knownFingerprint == "" && strings.TrimSpace(current.knownHostFingerprint) != "" {
			knownFingerprint = strings.TrimSpace(current.knownHostFingerprint)
		}
		if !tunnelSet && current.tunnelEnabled != nil {
			tunnelEnabled = *current.tunnelEnabled
			tunnelSet = true
		}
		if !credentialResolved {
			if current.credentialMode != nil {
				switch *current.credentialMode {
				case 1: // explicit none
					credentialResolved = true
				case 2: // saved
					credentialResolved = true
					credentialID = current.credentialID
					if credentialID != "" {
						identityBoundary = true
						credentialContextPending = true
					}
				}
			} else if current.credentialID != "" {
				credentialResolved = true
				credentialID = current.credentialID
				identityBoundary = true
				credentialContextPending = true
			}
		}
		if credentialContextPending && credentialContextProtocol == nil && current.protocol != nil {
			value := *current.protocol
			credentialContextProtocol = &value
		}
		if current.parentID == "" {
			break
		}
		current = nodes[current.parentID]
	}

	if protocol != 0 {
		return sshTarget{}, errors.New("the selected connection is not an SSH connection")
	}
	if tunnelSet && tunnelEnabled {
		return sshTarget{}, errors.New("SSH connections configured with a VPN tunnel are not available in the Electron shell yet")
	}
	if host == "" {
		return sshTarget{}, errors.New("SSH connection has no host")
	}
	if portContextProtocol != nil && *portContextProtocol != protocol {
		portSet = false
		port = 0
	}
	if credentialContextProtocol != nil && *credentialContextProtocol != protocol {
		credentialID = ""
	}
	if port <= 0 || port > 65535 {
		port = 22
	}

	target := sshTarget{
		nodeID:               root.id,
		host:                 host,
		port:                 int(port),
		username:             username,
		knownHostFingerprint: knownFingerprint,
	}
	if root.useInlinePassword {
		secret, err := readCredentialSecret(database, root.id)
		if err != nil {
			return sshTarget{}, fmt.Errorf("could not read the SSH password: %w", err)
		}
		target.password = string(secret)
	} else if credentialID != "" {
		if err := loadSSHCredential(database, databasePath, credentialID, &target); err != nil {
			return sshTarget{}, err
		}
	}
	if target.username == "" {
		return sshTarget{}, errors.New("SSH connection has no username")
	}
	return target, nil
}

func loadSSHNodes(database *sql.DB) (map[string]*sshNode, error) {
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
	query := `SELECT n.Id, n.ParentId, n.Name, n.Kind, ` +
		expression("Protocol") + ", " +
		expression("Host") + ", " +
		expression("Port") + ", " +
		expression("Username") + ", " +
		expression("CredentialId") + ", " +
		expression("CredentialMode") + ", " +
		expression("UseInlinePassword") + ", " +
		expression("SshKnownHostFingerprint") + ", " +
		expression("TunnelEnabled") + " FROM Nodes n;"
	rows, err := database.Query(query)
	if err != nil {
		return nil, fmt.Errorf("cannot read SSH connections: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*sshNode)
	for rows.Next() {
		var row sshNodeRow
		if err := rows.Scan(
			&row.ID,
			&row.ParentID,
			&row.Name,
			&row.Kind,
			&row.Protocol,
			&row.Host,
			&row.Port,
			&row.Username,
			&row.CredentialID,
			&row.CredentialMode,
			&row.UseInlinePassword,
			&row.KnownHostFingerprint,
			&row.TunnelEnabled,
		); err != nil {
			return nil, fmt.Errorf("cannot read an SSH connection: %w", err)
		}
		node := &sshNode{
			id:                   normalizeID(row.ID),
			name:                 row.Name,
			kind:                 row.Kind,
			host:                 nullableString(row.Host),
			username:             nullableString(row.Username),
			credentialID:         normalizeID(nullableString(row.CredentialID)),
			useInlinePassword:    row.UseInlinePassword.Valid && row.UseInlinePassword.Int64 != 0,
			knownHostFingerprint: nullableString(row.KnownHostFingerprint),
		}
		if row.TunnelEnabled.Valid {
			value := row.TunnelEnabled.Int64 != 0
			node.tunnelEnabled = &value
		}
		if row.ParentID.Valid {
			node.parentID = normalizeID(row.ParentID.String)
		}
		if row.Protocol.Valid {
			value := row.Protocol.Int64
			node.protocol = &value
		}
		if row.Port.Valid {
			value := row.Port.Int64
			node.port = &value
		}
		if row.CredentialMode.Valid {
			value := row.CredentialMode.Int64
			node.credentialMode = &value
		}
		result[node.id] = node
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate SSH connections: %w", err)
	}
	return result, nil
}

func loadSSHCredential(database *sql.DB, databasePath, credentialID string, target *sshTarget) error {
	if strings.TrimSpace(credentialID) == "" {
		return errors.New("SSH credential id is empty")
	}
	exists, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("Wormhole database has no SSH credentials")
	}
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return err
	}
	expression := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	var row sshCredentialRow
	err = database.QueryRow(
		"SELECT "+expression("Username")+", "+expression("Kind")+", "+expression("Protocol")+", "+expression("SecretProvider")+
			" FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(credentialID),
	).Scan(&row.Username, &row.Kind, &row.Protocol, &row.SecretProvider)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("SSH credential was not found")
	}
	if err != nil {
		return fmt.Errorf("cannot read SSH credential: %w", err)
	}
	if row.SecretProvider.Valid && row.SecretProvider.Int64 != 0 {
		return errors.New("Bitwarden SSH credentials are not available in the Electron shell yet")
	}
	if row.Protocol.Valid && row.Protocol.Int64 != 0 {
		return errors.New("the selected credential is not an SSH credential")
	}
	if target.username == "" {
		target.username = strings.TrimSpace(nullableString(row.Username))
	}

	if row.Kind.Valid && row.Kind.Int64 == 1 {
		stem, err := protectedCredentialFileStem(credentialID)
		if err != nil {
			return err
		}
		keyPath := filepath.Join(filepath.Dir(databasePath), "keys", stem+".dpapi")
		key, err := unprotectFile(keyPath)
		if err != nil {
			return errors.New("could not read the SSH private key")
		}
		target.privateKey = key
		passphrase, err := readOptionalCredentialSecret(database, credentialID)
		if err != nil {
			return fmt.Errorf("could not read the SSH key passphrase: %w", err)
		}
		target.keyPassphrase = string(passphrase)
		return nil
	}
	secret, err := readCredentialSecret(database, credentialID)
	if err != nil {
		return fmt.Errorf("could not read the SSH password: %w", err)
	}
	target.password = string(secret)
	return nil
}

func protectedCredentialFileStem(id string) (string, error) {
	normalized := normalizeID(id)
	if len(normalized) != 32 && len(normalized) != 36 {
		return "", errors.New("SSH credential id is invalid")
	}
	for index, character := range normalized {
		if len(normalized) == 36 && (index == 8 || index == 13 || index == 18 || index == 23) {
			if character != '-' {
				return "", errors.New("SSH credential id is invalid")
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return "", errors.New("SSH credential id is invalid")
		}
	}
	return strings.ReplaceAll(normalized, "-", ""), nil
}

func readCredentialSecret(database *sql.DB, credentialID string) ([]byte, error) {
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("stored SSH secret is missing")
	}
	var encoded, encoding string
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(credentialID),
	).Scan(&encoded, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("stored SSH secret is missing")
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read stored SSH secret: %w", err)
	}
	if encoding != protectedSecretEncoding {
		return nil, errors.New("stored SSH secret uses an unsupported encoding")
	}
	secret, err := unprotectSecret(encoded)
	if err != nil {
		return nil, errors.New("stored SSH secret could not be decrypted")
	}
	return secret, nil
}

func readOptionalCredentialSecret(database *sql.DB, credentialID string) ([]byte, error) {
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	var encoded, encoding string
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(credentialID),
	).Scan(&encoded, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read stored SSH secret: %w", err)
	}
	if encoding != protectedSecretEncoding {
		return nil, errors.New("stored SSH secret uses an unsupported encoding")
	}
	secret, err := unprotectSecret(encoded)
	if err != nil {
		return nil, errors.New("stored SSH secret could not be decrypted")
	}
	return secret, nil
}

func persistSSHFingerprint(databasePath, nodeID, fingerprint string) error {
	if strings.TrimSpace(fingerprint) == "" {
		return errors.New("SSH fingerprint is empty")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	exists, err := tableExists(database, "Nodes")
	if err != nil || !exists {
		return err
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	if _, ok := columns["SshKnownHostFingerprint"]; !ok {
		return errors.New("SSH fingerprint column is missing")
	}
	result, err := database.Exec(
		"UPDATE Nodes SET SshKnownHostFingerprint = ?, UpdatedAt = ? WHERE lower(Id) = ? AND COALESCE(TRIM(SshKnownHostFingerprint), '') = '';",
		fingerprint,
		time.Now().UTC().Format(time.RFC3339Nano),
		normalizeID(nodeID),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected > 0 {
		return err
	}

	var existing sql.NullString
	err = database.QueryRow(
		"SELECT SshKnownHostFingerprint FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(nodeID),
	).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(nullableString(existing)) != "" && strings.TrimSpace(existing.String) != fingerprint {
		return fmt.Errorf("%w: expected %s, received %s", errSSHHostFingerprintChanged, existing.String, fingerprint)
	}
	return nil
}

func safeSSHError(err error) string {
	if err == nil {
		return "SSH connection failed"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "SSH connection failed"
	}
	return message
}
