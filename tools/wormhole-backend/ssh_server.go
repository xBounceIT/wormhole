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
	"io"
	"io/fs"
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sshConnectTimeout                  = 15 * time.Second
	sshKeepAliveInterval               = 30 * time.Second
	sshOutputDrainTimeout              = 2 * time.Second
	sshInputMaxBytes                   = 1024 * 1024
	sshInputQueueCapacity              = 16
	sshOutputChunk                     = 16 * 1024
	sshMaxColumns                      = 500
	sshMaxRows                         = 500
	sshMaxHostLength                   = 4096
	sshMaxUsernameLength               = 512
	sshMaxPasswordBytes                = 4096
	sshAutoSudoTimeout                 = 10 * time.Second
	sshAutoSudoTailBytes               = 512
	sshAutoReconnectMaxAttempts        = 3
	sshAutoReconnectDelay              = 10 * time.Second
	sshAutoReconnectStableWindow       = 30 * time.Second
	sshSftpMaxPathBytes                = 16 * 1024
	sshSftpMaxNameBytes                = 4 * 1024
	sshSftpMaxEntryCount               = 4096
	sshSftpListTimeout                 = 30 * time.Second
	sshSftpMaxSafeSize           int64 = 1<<53 - 1
	sshSftpMaxTransferItems            = 256
	sshSftpMaxTransferPlanCount        = 4096
	sshSftpTransferBuffer              = 128 * 1024
)

var (
	errSSHSessionClosed          = errors.New("SSH session is closed")
	errSSHInputFull              = errors.New("SSH input queue is full")
	errSSHHostFingerprintChanged = errors.New("SSH host fingerprint changed while connecting")
	errSSHSftpClosed             = errors.New("SFTP browser is closed")
	errSSHSftpOpening            = errors.New("SFTP browser is opening")
)

type sshHostKeyMismatchError struct {
	expected string
	received string
}

func (err *sshHostKeyMismatchError) Error() string {
	return fmt.Sprintf(
		"SSH host key mismatch (expected %s, received %s)",
		err.expected,
		err.received,
	)
}

type sshWireCommand struct {
	Type                          string                `json:"type"`
	SessionID                     string                `json:"session_id"`
	NodeID                        string                `json:"node_id"`
	CredentialID                  string                `json:"credential_id"`
	AutoSudo                      bool                  `json:"auto_sudo"`
	Host                          string                `json:"host"`
	Username                      string                `json:"username"`
	Password                      string                `json:"password"`
	TunnelConfigID                string                `json:"tunnel_config_id"`
	SocksEndpoint                 string                `json:"socks_endpoint"`
	UsernameOverride              string                `json:"username_override,omitempty"`
	UsernameOverrideAuthoritative bool                  `json:"username_override_authoritative,omitempty"`
	PasswordOverride              string                `json:"password_override,omitempty"`
	CredentialOverride            bool                  `json:"credential_override,omitempty"`
	KeyPassphraseOverride         string                `json:"key_passphrase_override,omitempty"`
	TunnelEnabled                 *bool                 `json:"tunnel_enabled,omitempty"`
	Data                          string                `json:"data"`
	Path                          string                `json:"path"`
	DestinationPath               string                `json:"destination_path"`
	RequestID                     string                `json:"request_id"`
	ApprovalID                    string                `json:"approval_id"`
	Pane                          string                `json:"pane"`
	Operation                     string                `json:"operation"`
	TransferID                    string                `json:"transfer_id"`
	ItemID                        string                `json:"item_id"`
	Direction                     string                `json:"direction"`
	Decision                      string                `json:"decision"`
	ApplyToAll                    bool                  `json:"apply_to_all"`
	Items                         []sshSftpTransferItem `json:"items"`
	Columns                       uint32                `json:"columns"`
	Rows                          uint32                `json:"rows"`
	Port                          int                   `json:"port"`
	Approved                      bool                  `json:"approved"`
}

type sshWireEvent struct {
	Type                string             `json:"type"`
	RequestID           string             `json:"request_id,omitempty"`
	SessionID           string             `json:"session_id"`
	Phase               string             `json:"phase,omitempty"`
	Detail              string             `json:"detail,omitempty"`
	Frame               *sshTerminalFrame  `json:"frame,omitempty"`
	Host                string             `json:"host,omitempty"`
	Port                int                `json:"port,omitempty"`
	Username            string             `json:"username,omitempty"`
	Title               string             `json:"title,omitempty"`
	Tool                string             `json:"tool,omitempty"`
	Fingerprint         string             `json:"fingerprint,omitempty"`
	Error               string             `json:"error,omitempty"`
	McpStatus           *mcpStatusResponse `json:"mcp_status,omitempty"`
	Token               string             `json:"token,omitempty"`
	HostKeyExpected     string             `json:"host_key_expected,omitempty"`
	HostKeyReceived     string             `json:"host_key_received,omitempty"`
	Path                string             `json:"path,omitempty"`
	Entries             []sshSftpEntry     `json:"entries"`
	QuickPaths          []sshSftpQuickPath `json:"quick_paths,omitempty"`
	Truncated           bool               `json:"truncated"`
	Pane                string             `json:"pane,omitempty"`
	Operation           string             `json:"operation,omitempty"`
	TransferID          string             `json:"transfer_id,omitempty"`
	ItemID              string             `json:"item_id,omitempty"`
	TransferState       string             `json:"transfer_state,omitempty"`
	Direction           string             `json:"direction,omitempty"`
	DisplayName         string             `json:"display_name,omitempty"`
	ExpectedBytes       int64              `json:"expected_bytes,omitempty"`
	BytesTransferred    int64              `json:"bytes_transferred,omitempty"`
	IncomingSize        int64              `json:"incoming_size,omitempty"`
	ExistingSize        int64              `json:"existing_size,omitempty"`
	ExistingIsDirectory bool               `json:"existing_is_directory,omitempty"`
	Attempt             int                `json:"attempt,omitempty"`
	MaxAttempts         int                `json:"max_attempts,omitempty"`
	DelaySeconds        int                `json:"delay_seconds,omitempty"`
}

type sshSftpEntry struct {
	Name            string `json:"name"`
	FullPath        string `json:"full_path"`
	IsDirectory     bool   `json:"is_directory"`
	IsSymbolicLink  bool   `json:"is_symbolic_link"`
	Size            int64  `json:"size"`
	LastModifiedUTC string `json:"last_modified_utc,omitempty"`
}

type sshSftpTransferItem struct {
	SourcePath  string `json:"source_path"`
	Name        string `json:"name"`
	IsDirectory bool   `json:"is_directory"`
	Size        int64  `json:"size"`
}

type sshHostKeyTrustRequest struct {
	NodeID   string `json:"nodeId"`
	Expected string `json:"expected"`
	Received string `json:"received"`
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
	TunnelConfigID       sql.NullString
	SshAutoSudo          sql.NullInt64
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
	tunnelConfigID       string
	autoSudo             *bool
}

type sshTarget struct {
	nodeID               string
	title                string
	host                 string
	port                 int
	username             string
	password             string
	privateKey           []byte
	keyPassphrase        string
	knownHostFingerprint string
	autoSudo             bool
	tunnelConfigID       string
	socksEndpoint        string
}

type sshCredentialRow struct {
	Username       sql.NullString
	Kind           sql.NullInt64
	Protocol       sql.NullInt64
	SecretProvider sql.NullInt64
}

type sshNativeSession struct {
	id               string
	client           *ssh.Client
	session          *ssh.Session
	stdin            io.WriteCloser
	stdout           io.Reader
	stderr           io.Reader
	server           *sshServer
	terminal         *sshTerminalEmulator
	autoSudo         *sshAutoSudoDriver
	mcpSession       mcpSessionInfo
	mcpReplay        *mcpReplayBuffer
	mcpCommandReplay *mcpReplayBuffer
	mcpCommandGateMu sync.Mutex
	mcpCommandGate   chan struct{}
	tunnel           *tunnelRuntime

	sftpMu         sync.Mutex
	sftpListMu     sync.Mutex
	sftpClient     *sftp.Client
	sftpOpening    bool
	sftpClosed     bool
	sftpGeneration uint64
	sftpListSeq    uint64

	inputQueue              chan []byte
	done                    chan struct{}
	outputWG                sync.WaitGroup
	lifecycleMu             sync.Mutex
	terminalOutputMu        sync.Mutex
	mcpPresentation         *mcpCommandPresentationFilter
	mcpRetiredPresentations []*mcpCommandPresentationFilter
	started                 bool
	closed                  bool
	closeOnce               sync.Once
}

type sshServer struct {
	databasePath         string
	electronUserDataPath string
	output               *sshEventWriter
	mcp                  *mcpController

	mu                     sync.Mutex
	sessions               map[string]*sshNativeSession
	pending                map[string]context.CancelFunc
	lifecycles             map[string]*sshReconnectState
	openSSH                func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error)
	reconnectDelayOverride *time.Duration

	transferMu sync.Mutex
	transfers  map[string]*sshSftpTransfer
	transferWG sync.WaitGroup

	localQuickPaths localQuickPathCache
}

type sshReconnectState struct {
	commandMu         sync.Mutex
	command           sshWireCommand
	attempts          int
	connectedAt       time.Time
	reconnectDisabled bool
}

func (state *sshReconnectState) commandSnapshot() sshWireCommand {
	state.commandMu.Lock()
	defer state.commandMu.Unlock()
	return state.command
}

func (state *sshReconnectState) clearSecrets() {
	state.commandMu.Lock()
	defer state.commandMu.Unlock()
	state.command.Password = ""
	state.command.PasswordOverride = ""
	state.command.KeyPassphraseOverride = ""
}

type sshSftpTransfer struct {
	id        string
	sessionID string
	cancel    context.CancelFunc
	decisions chan sshSftpTransferDecision

	itemMu         sync.Mutex
	itemCancels    map[string]context.CancelFunc
	cancelledItems map[string]struct{}
}

type sshSftpTransferDecision struct {
	itemID   string
	decision string
	applyAll bool
}

func awaitSftpTransferDecision(
	ctx context.Context,
	decisions <-chan sshSftpTransferDecision,
	itemID string,
) (sshSftpTransferDecision, error) {
	for {
		select {
		case decision := <-decisions:
			if decision.itemID == itemID {
				return decision, nil
			}
		case <-ctx.Done():
			return sshSftpTransferDecision{}, ctx.Err()
		}
	}
}

func (transfer *sshSftpTransfer) startItem(parent context.Context, itemID string) context.Context {
	itemContext, cancel := context.WithCancel(parent)
	transfer.itemMu.Lock()
	if _, cancelled := transfer.cancelledItems[itemID]; cancelled {
		cancel()
	} else {
		transfer.itemCancels[itemID] = cancel
	}
	transfer.itemMu.Unlock()
	return itemContext
}

func (transfer *sshSftpTransfer) finishItem(itemID string) {
	transfer.itemMu.Lock()
	delete(transfer.itemCancels, itemID)
	transfer.itemMu.Unlock()
}

func (transfer *sshSftpTransfer) cancelItem(itemID string) {
	transfer.itemMu.Lock()
	transfer.cancelledItems[itemID] = struct{}{}
	cancel := transfer.itemCancels[itemID]
	transfer.itemMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

type sshSftpTransferPlan struct {
	sourcePath      string
	destinationPath string
	displayName     string
	incomingSize    int64
	isDirectory     bool
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

func serveSSH(databasePath string, input io.Reader, output io.Writer, electronUserDataPath ...string) error {
	userDataPath := ""
	if len(electronUserDataPath) > 0 {
		userDataPath = electronUserDataPath[0]
	}
	server := &sshServer{
		databasePath:         databasePath,
		electronUserDataPath: userDataPath,
		output:               &sshEventWriter{encoder: json.NewEncoder(output)},
		sessions:             make(map[string]*sshNativeSession),
		pending:              make(map[string]context.CancelFunc),
		lifecycles:           make(map[string]*sshReconnectState),
		transfers:            make(map[string]*sshSftpTransfer),
	}
	server.mcp = newMcpController(server)

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
	if strings.HasPrefix(command.Type, "mcp.") {
		server.handleMcp(command)
		return
	}
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
	case "snapshot":
		server.snapshot(command)
	case "sftp-open":
		server.sftpOpen(command)
	case "sftp-list":
		server.sftpList(command)
	case "sftp-local-list":
		server.sftpLocalList(command)
	case "sftp-operation":
		server.sftpOperation(command)
	case "sftp-transfer":
		server.sftpTransfer(command)
	case "sftp-transfer-decision":
		server.sftpTransferDecision(command)
	case "sftp-transfer-cancel":
		server.sftpTransferCancel(command)
	case "sftp-close":
		server.sftpClose(command)
	case "auto-sudo-cancel":
		server.cancelAutoSudo(command)
	case "app-lock":
		server.prepareSessionForLock(command.SessionID)
	case "close":
		server.close(command.SessionID)
	default:
		server.writeError(command.SessionID, "unsupported SSH command")
	}
}

func (server *sshServer) cancelAutoSudo(command sshWireCommand) {
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native != nil {
		native.cancelAutoSudo()
	}
}

func (server *sshServer) prepareSessionForLock(sessionID string) {
	server.mu.Lock()
	state := server.lifecycles[sessionID]
	native := server.sessions[sessionID]
	cancel := server.pending[sessionID]
	delete(server.pending, sessionID)
	emitClosed := false
	if state != nil {
		state.reconnectDisabled = true
		state.clearSecrets()
		if native == nil {
			delete(server.lifecycles, sessionID)
			emitClosed = true
		}
	}
	server.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if native != nil {
		native.cancelAutoSudo()
	}
	if emitClosed {
		server.output.write(sshWireEvent{Type: "closed", SessionID: sessionID})
	}
}

func (server *sshServer) open(command sshWireCommand) {
	nodeID := strings.TrimSpace(command.NodeID)
	if nodeID != "" {
		if len(nodeID) > 128 ||
			command.Host != "" ||
			command.Port != 0 ||
			command.Username != "" ||
			command.Password != "" ||
			command.TunnelConfigID != "" {
			server.writeError(command.SessionID, "SSH connection target is invalid")
			return
		}
		if command.CredentialID != "" && !validCredentialID(normalizeID(command.CredentialID)) {
			server.writeError(command.SessionID, "SSH credential is invalid")
			return
		}
	} else {
		if _, err := resolveDirectSSHTarget(command); err != nil {
			server.writeError(command.SessionID, err.Error())
			return
		}
		if command.CredentialID != "" && !validCredentialID(normalizeID(command.CredentialID)) {
			server.writeError(command.SessionID, "SSH credential is invalid")
			return
		}
	}
	if command.SocksEndpoint != "" && !isLoopbackSocksEndpoint(command.SocksEndpoint) {
		server.writeError(command.SessionID, "SSH VPN proxy endpoint is invalid")
		return
	}
	if len([]rune(command.UsernameOverride)) > maxCredentialUsernameLength ||
		len([]rune(command.PasswordOverride)) > maxStoredCredentialPassword ||
		len([]rune(command.KeyPassphraseOverride)) > maxStoredCredentialPassword {
		server.writeError(command.SessionID, "SSH credential override is invalid")
		return
	}
	if command.CredentialOverride && command.CredentialID != "" {
		server.writeError(command.SessionID, "SSH credential override is ambiguous")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	state := &sshReconnectState{command: command}
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
	if _, exists := server.lifecycles[command.SessionID]; exists {
		server.mu.Unlock()
		cancel()
		server.writeError(command.SessionID, "SSH session is already open")
		return
	}
	server.pending[command.SessionID] = cancel
	server.lifecycles[command.SessionID] = state
	server.mu.Unlock()

	go server.connectSSH(ctx, state, true)
}

func (server *sshServer) connectSSH(ctx context.Context, state *sshReconnectState, initial bool) {
	command := state.commandSnapshot()
	openContext := withTunnelProgressHandler(ctx, func(_ context.Context, phase, detail string) error {
		server.output.write(sshWireEvent{
			Type: "tunnel.progress", SessionID: command.SessionID, Phase: phase, Detail: detail,
		})
		return nil
	})
	native, target, err := server.openNativeSSH(openContext, state)
	if err != nil {
		if initial {
			pending := server.finishPendingState(state, true)
			if pending && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				logError("SSH session failed to connect: %v", safeSSHError(err))
				event := sshWireEvent{
					Type: "error", SessionID: command.SessionID, Error: safeSSHError(err),
				}
				var mismatch *sshHostKeyMismatchError
				if errors.As(err, &mismatch) {
					event.HostKeyExpected = mismatch.expected
					event.HostKeyReceived = mismatch.received
				}
				server.output.write(event)
			}
		} else {
			server.reconnectAttemptFailed(state, err)
		}
		return
	}

	native.id = command.SessionID
	native.server = server
	native.mcpSession = mcpSessionInfo{
		ID: command.SessionID, Host: target.host, Port: target.port, Username: target.username,
		Title: target.title, Status: "connected",
	}
	if !server.promote(command.SessionID, native, state) {
		native.close(false)
		return
	}
	if !server.publishConnected(command.SessionID, native, sshWireEvent{
		Type: "connected", SessionID: command.SessionID, Host: target.host, Port: target.port,
		Username: target.username, Fingerprint: target.knownHostFingerprint,
	}) {
		native.close(false)
		return
	}
	logInfo("SSH session connected: %s@%s:%d", target.username, target.host, target.port)
	native.publishTerminalFrame(native.terminal.initialFrame())
	native.start()
}

func (server *sshServer) openNativeSSH(
	ctx context.Context,
	state *sshReconnectState,
) (*sshNativeSession, sshTarget, error) {
	if server.openSSH != nil {
		return server.openSSH(ctx, state)
	}
	command := state.commandSnapshot()
	nodeID := strings.TrimSpace(command.NodeID)
	var directTarget *sshTarget
	if nodeID == "" {
		target, err := resolveDirectSSHTarget(command)
		if err != nil {
			return nil, sshTarget{}, err
		}
		directTarget = &target
	}
	return openNativeSSH(
		ctx, server.databasePath, server.electronUserDataPath, nodeID,
		directTarget, command.CredentialID, command.SocksEndpoint, command.TunnelEnabled,
		command.UsernameOverride, command.PasswordOverride, command.CredentialOverride,
		command.UsernameOverrideAuthoritative, command.KeyPassphraseOverride,
		command.Columns, command.Rows,
	)
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

func (server *sshServer) snapshot(command sshWireCommand) {
	server.mu.Lock()
	native := server.sessions[command.SessionID]
	server.mu.Unlock()
	if native == nil {
		return
	}
	native.snapshot()
}

func (server *sshServer) sftpOpen(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeSftpRequestError(command.SessionID, command.RequestID, errSSHSessionClosed.Error())
		return
	}
	native.startSftpOpen(command.RequestID)
}

func (server *sshServer) sftpList(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeSftpRequestError(command.SessionID, command.RequestID, errSSHSessionClosed.Error())
		return
	}
	native.startSftpList(command.Path, 0, command.RequestID)
}

func (server *sshServer) sftpLocalList(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeSftpLocalError(command.SessionID, command.RequestID, command.Path, errSSHSessionClosed)
		return
	}
	native.startLocalList(command.Path, command.RequestID)
}

func (server *sshServer) sftpOperation(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeSftpOperationError(command, errSSHSessionClosed)
		return
	}
	native.startSftpOperation(command)
}

func (server *sshServer) sftpTransfer(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeTransferBatchError(command, errSSHSftpClosed)
		return
	}
	if err := validateSftpTransferCommand(command); err != nil {
		server.writeTransferBatchError(command, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	transfer := &sshSftpTransfer{
		id:             command.TransferID,
		sessionID:      command.SessionID,
		cancel:         cancel,
		decisions:      make(chan sshSftpTransferDecision, 1),
		itemCancels:    make(map[string]context.CancelFunc),
		cancelledItems: make(map[string]struct{}),
	}
	server.transferMu.Lock()
	if _, exists := server.transfers[transfer.id]; exists {
		server.transferMu.Unlock()
		cancel()
		server.writeTransferBatchError(command, errors.New("SFTP transfer is already running"))
		return
	}
	server.transfers[transfer.id] = transfer
	server.transferMu.Unlock()

	server.transferWG.Add(1)
	go func() {
		defer server.transferWG.Done()
		defer func() {
			server.transferMu.Lock()
			delete(server.transfers, transfer.id)
			server.transferMu.Unlock()
		}()
		server.runSftpTransfer(native, command, transfer, ctx)
	}()
}

func (server *sshServer) sftpTransferDecision(command sshWireCommand) {
	if (command.Decision != "overwrite" && command.Decision != "skip") || command.ItemID == "" {
		return
	}
	server.transferMu.Lock()
	transfer := server.transfers[command.TransferID]
	server.transferMu.Unlock()
	if transfer == nil || transfer.sessionID != command.SessionID {
		return
	}
	select {
	case transfer.decisions <- sshSftpTransferDecision{
		itemID:   command.ItemID,
		decision: command.Decision,
		applyAll: command.ApplyToAll,
	}:
	default:
		// A decision that arrives after cancellation or after the conflict was already
		// resolved is stale and must not affect a later conflict.
	}
}

func (server *sshServer) sftpTransferCancel(command sshWireCommand) {
	server.transferMu.Lock()
	transfer := server.transfers[command.TransferID]
	server.transferMu.Unlock()
	if transfer != nil && transfer.sessionID == command.SessionID {
		if command.ItemID == "" {
			transfer.cancel()
		} else {
			transfer.cancelItem(command.ItemID)
		}
	}
}

func (server *sshServer) cancelTransfersForSession(sessionID string) {
	server.transferMu.Lock()
	transfers := make([]*sshSftpTransfer, 0)
	for _, transfer := range server.transfers {
		if transfer.sessionID == sessionID {
			transfers = append(transfers, transfer)
		}
	}
	server.transferMu.Unlock()
	for _, transfer := range transfers {
		transfer.cancel()
	}
}

func (server *sshServer) sftpClose(command sshWireCommand) {
	native := server.session(command.SessionID)
	if native == nil {
		server.writeSftpError(command.SessionID, errSSHSessionClosed.Error())
		return
	}
	server.cancelTransfersForSession(command.SessionID)
	native.closeSftp(true)
}

func (server *sshServer) session(sessionID string) *sshNativeSession {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.sessions[sessionID]
}

func (server *sshServer) close(sessionID string) {
	server.mu.Lock()
	cancel := server.pending[sessionID]
	delete(server.pending, sessionID)
	native := server.sessions[sessionID]
	delete(server.sessions, sessionID)
	state, hadLifecycle := server.lifecycles[sessionID]
	delete(server.lifecycles, sessionID)
	server.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if state != nil {
		state.clearSecrets()
	}
	server.cancelTransfersForSession(sessionID)
	if native != nil {
		logInfo("SSH session closed: %s@%s:%d", native.mcpSession.Username, native.mcpSession.Host, native.mcpSession.Port)
		native.close(false)
	}
	if hadLifecycle {
		server.output.write(sshWireEvent{Type: "closed", SessionID: sessionID})
	}
}

func (server *sshServer) finishPendingState(state *sshReconnectState, abandon bool) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	sessionID := state.commandSnapshot().SessionID
	_, pending := server.pending[sessionID]
	if server.lifecycles[sessionID] != state {
		return false
	}
	delete(server.pending, sessionID)
	if abandon {
		delete(server.lifecycles, sessionID)
		state.clearSecrets()
	}
	return pending
}

func (server *sshServer) promote(
	sessionID string,
	native *sshNativeSession,
	state *sshReconnectState,
) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.pending[sessionID]; !exists || server.lifecycles[sessionID] != state {
		return false
	}
	delete(server.pending, sessionID)
	server.sessions[sessionID] = native
	state.connectedAt = time.Now()
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

func (server *sshServer) nativeClosed(native *sshNativeSession) {
	server.mu.Lock()
	if server.sessions[native.id] != native {
		server.mu.Unlock()
		return
	}
	delete(server.sessions, native.id)
	state := server.lifecycles[native.id]
	reconnectDisabled := state != nil && state.reconnectDisabled
	if reconnectDisabled {
		delete(server.lifecycles, native.id)
	}
	if state != nil && !state.connectedAt.IsZero() && time.Since(state.connectedAt) >= sshAutoReconnectStableWindow {
		state.attempts = 0
	}
	server.mu.Unlock()
	server.cancelTransfersForSession(native.id)
	if state == nil || reconnectDisabled {
		server.output.write(sshWireEvent{Type: "closed", SessionID: native.id})
		return
	}
	server.scheduleReconnect(state, "SSH connection closed unexpectedly")
}

func (server *sshServer) scheduleReconnect(state *sshReconnectState, lastError string) {
	reconnectDelay := sshAutoReconnectDelay
	if server.reconnectDelayOverride != nil {
		reconnectDelay = *server.reconnectDelayOverride
	}
	delaySeconds := int((reconnectDelay + time.Second - 1) / time.Second)
	server.mu.Lock()
	sessionID := state.commandSnapshot().SessionID
	if server.lifecycles[sessionID] != state || server.sessions[sessionID] != nil || server.pending[sessionID] != nil {
		server.mu.Unlock()
		return
	}
	if state.attempts >= sshAutoReconnectMaxAttempts {
		delete(server.lifecycles, sessionID)
		state.clearSecrets()
		server.output.write(sshWireEvent{
			Type: "reconnect-failed", SessionID: sessionID, Error: lastError,
			Attempt: state.attempts, MaxAttempts: sshAutoReconnectMaxAttempts,
		})
		server.mu.Unlock()
		logError("SSH automatic reconnect exhausted for session %s", sessionID)
		return
	}
	state.attempts++
	attempt := state.attempts
	ctx, cancel := context.WithCancel(context.Background())
	server.pending[sessionID] = cancel
	server.output.write(sshWireEvent{
		Type: "reconnecting", SessionID: sessionID, Error: lastError,
		Attempt: attempt, MaxAttempts: sshAutoReconnectMaxAttempts, DelaySeconds: delaySeconds,
	})
	server.mu.Unlock()
	go func() {
		timer := time.NewTimer(reconnectDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			server.connectSSH(ctx, state, false)
		}
	}()
}

func (server *sshServer) reconnectAttemptFailed(state *sshReconnectState, err error) {
	if !server.finishPendingState(state, false) || errors.Is(err, context.Canceled) {
		return
	}
	message := safeSSHError(err)
	logError("SSH automatic reconnect attempt failed: %v", message)
	server.scheduleReconnect(state, message)
}

func (server *sshServer) isActive(native *sshNativeSession) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.sessions[native.id] == native
}

func (server *sshServer) shutdown() {
	if server.mcp != nil {
		_ = server.mcp.stop(false)
	}
	server.mu.Lock()
	lifecycles := make([]*sshReconnectState, 0, len(server.lifecycles))
	pending := make([]context.CancelFunc, 0, len(server.pending))
	for sessionID, cancel := range server.pending {
		pending = append(pending, cancel)
		delete(server.pending, sessionID)
	}
	for sessionID, state := range server.lifecycles {
		lifecycles = append(lifecycles, state)
		delete(server.lifecycles, sessionID)
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
	for _, state := range lifecycles {
		state.clearSecrets()
	}
	server.cancelAllTransfers()
	for _, native := range sessions {
		native.close(false)
	}
	server.transferWG.Wait()
}

func (server *sshServer) cancelAllTransfers() {
	server.transferMu.Lock()
	transfers := make([]*sshSftpTransfer, 0, len(server.transfers))
	for _, transfer := range server.transfers {
		transfers = append(transfers, transfer)
	}
	server.transferMu.Unlock()
	for _, transfer := range transfers {
		transfer.cancel()
	}
}

func (server *sshServer) writeError(sessionID, message string) {
	server.output.write(sshWireEvent{Type: "error", SessionID: sessionID, Error: message})
}

func (server *sshServer) writeSftpError(sessionID, message string, path ...string) {
	event := sshWireEvent{Type: "sftp.error", SessionID: sessionID, Error: message}
	if len(path) > 0 {
		event.Path = path[0]
	}
	server.output.write(event)
}

func (server *sshServer) writeSftpRequestError(sessionID, requestID, message string, path ...string) {
	event := sshWireEvent{
		Type:      "sftp.error",
		SessionID: sessionID,
		RequestID: requestID,
		Error:     message,
	}
	if len(path) > 0 {
		event.Path = path[0]
	}
	server.output.write(event)
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
	if native.autoSudo != nil {
		native.autoSudo.start()
	}
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
			native.publishTerminalData(buffer[:count])
		}
		if err != nil {
			return
		}
	}
}

func (native *sshNativeSession) publishTerminalData(data []byte) {
	if native.server == nil || native.terminal == nil {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	if native.autoSudo != nil {
		native.autoSudo.observe(data)
	}
	native.mcpCommandReplay.append(data)
	visible := native.filterMcpPresentationLocked(data)
	if len(visible) == 0 {
		return
	}
	native.publishVisibleTerminalDataLocked(visible)
}

func (native *sshNativeSession) publishVisibleTerminalDataLocked(data []byte) {
	native.mcpReplay.append(data)
	frame, changed, err := native.terminal.write(data)
	if err != nil {
		native.server.writeError(native.id, fmt.Sprintf("SSH terminal emulation failed: %v", err))
		return
	}
	if changed {
		native.publishTerminalFrameLocked(frame)
	}
}

func (native *sshNativeSession) beginMcpCommandPresentation(
	command string,
	payload []byte,
	startMarker []byte,
	endMarkerPrefix []byte,
) error {
	if native == nil {
		return errSSHSessionClosed
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return errSSHSessionClosed
	}
	if native.mcpPresentation != nil {
		return errMcpCommandInProgress
	}
	native.mcpPresentation = newMcpCommandPresentationFilter(command, payload, startMarker, endMarkerPrefix)
	return nil
}

func (native *sshNativeSession) clearMcpCommandPresentation() {
	if native == nil {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	native.clearMcpCommandPresentationLocked()
}

func (native *sshNativeSession) abandonMcpCommandPresentation() {
	if native == nil {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.mcpPresentation != nil {
		native.mcpPresentation.abandoned = true
	}
}

func (native *sshNativeSession) retireAbandonedMcpCommandPresentationOnInterrupt(data []byte) {
	if native == nil || bytes.IndexByte(data, '\x03') < 0 {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.mcpPresentation != nil && native.mcpPresentation.abandoned {
		if len(native.mcpRetiredPresentations) >= mcpMaxRetiredPresentations {
			// A retired filter buffers only suffixes that may belong to its internal wrapper.
			// Drop the oldest filter and those private bytes rather than leaking them or
			// permanently blocking recovery after repeated interrupted commands.
			copy(native.mcpRetiredPresentations, native.mcpRetiredPresentations[1:])
			native.mcpRetiredPresentations[len(native.mcpRetiredPresentations)-1] = nil
			native.mcpRetiredPresentations = native.mcpRetiredPresentations[:len(native.mcpRetiredPresentations)-1]
		}
		native.mcpPresentation.retired = true
		native.mcpRetiredPresentations = append(
			native.mcpRetiredPresentations,
			native.mcpPresentation,
		)
		native.mcpPresentation = nil
	}
}

func (native *sshNativeSession) filterMcpPresentationLocked(data []byte) []byte {
	visible := data
	if len(native.mcpRetiredPresentations) > 0 {
		remaining := native.mcpRetiredPresentations[:0]
		for _, presentation := range native.mcpRetiredPresentations {
			visible = presentation.filter(visible)
			if !presentation.complete {
				remaining = append(remaining, presentation)
			}
		}
		for index := len(remaining); index < len(native.mcpRetiredPresentations); index++ {
			native.mcpRetiredPresentations[index] = nil
		}
		native.mcpRetiredPresentations = remaining
	}
	if native.mcpPresentation == nil {
		return visible
	}
	visible = native.mcpPresentation.filter(visible)
	if native.mcpPresentation.complete {
		native.mcpPresentation = nil
	}
	return visible
}

func (native *sshNativeSession) clearMcpCommandPresentationLocked() {
	native.mcpPresentation = nil
}

func (native *sshNativeSession) clearAllMcpCommandPresentationsLocked() {
	native.clearMcpCommandPresentationLocked()
	clear(native.mcpRetiredPresentations)
	native.mcpRetiredPresentations = nil
}

func (native *sshNativeSession) publishTerminalFrame(frame *sshTerminalFrame) {
	if native.server == nil || frame == nil {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	native.publishTerminalFrameLocked(frame)
}

func (native *sshNativeSession) publishTerminalFrameLocked(frame *sshTerminalFrame) {
	native.server.output.write(sshWireEvent{
		Type:      "screen",
		SessionID: native.id,
		Frame:     frame,
	})
}

func (native *sshNativeSession) snapshot() {
	if native.server == nil || native.terminal == nil {
		return
	}
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return
	}
	native.publishTerminalFrameLocked(native.terminal.snapshot())
}

func (native *sshNativeSession) write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if native.isClosed() {
		return errSSHSessionClosed
	}
	if native.autoSudo != nil {
		handled, err := native.autoSudo.queueUserInput(data)
		if handled {
			return err
		}
	}
	return native.writeRaw(data)
}

func (native *sshNativeSession) writeRaw(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if native.isClosed() {
		return errSSHSessionClosed
	}
	if native.inputQueue == nil || native.done == nil {
		return native.writeRemoteInput(data)
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

func (native *sshNativeSession) writeRemoteInput(data []byte) error {
	written, err := native.stdin.Write(data)
	if written > len(data) {
		written = len(data)
	}
	if written > 0 {
		native.retireAbandonedMcpCommandPresentationOnInterrupt(data[:written])
	}
	return err
}

func (native *sshNativeSession) resize(columns, rows uint32) error {
	columns, rows = normalizeTerminalSize(columns, rows)
	native.terminalOutputMu.Lock()
	defer native.terminalOutputMu.Unlock()
	if native.isClosed() {
		return errSSHSessionClosed
	}
	if err := native.session.WindowChange(int(rows), int(columns)); err != nil {
		return err
	}
	if native.terminal != nil {
		frame := native.terminal.resize(columns, rows)
		if native.server != nil {
			native.publishTerminalFrameLocked(frame)
		}
	}
	return nil
}

func (native *sshNativeSession) close(notify bool) {
	native.closeOnce.Do(func() {
		native.terminalOutputMu.Lock()
		native.clearAllMcpCommandPresentationsLocked()
		native.lifecycleMu.Lock()
		native.closed = true
		native.lifecycleMu.Unlock()
		native.terminalOutputMu.Unlock()
		if native.done != nil {
			close(native.done)
		}
		native.closeSftp(false)
		native.terminalOutputMu.Lock()
		defer native.terminalOutputMu.Unlock()
		// publishTerminalData holds terminalOutputMu before it touches the Auto Sudo driver.
		// Keep shutdown in that same order so disconnect cannot deadlock with prompt detection.
		if native.autoSudo != nil {
			native.autoSudo.dispose()
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
		if native.tunnel != nil {
			native.tunnel.close()
		}
		if native.server != nil {
			if native.server.mcp != nil {
				native.server.mcp.forgetSession(native.id)
			}
			if notify {
				native.server.nativeClosed(native)
			} else {
				native.server.remove(native)
			}
		}
	})
}

func (native *sshNativeSession) cancelAutoSudo() {
	if native.autoSudo != nil {
		native.autoSudo.dispose()
	}
}

func (native *sshNativeSession) isClosed() bool {
	native.lifecycleMu.Lock()
	defer native.lifecycleMu.Unlock()
	return native.closed
}

func (native *sshNativeSession) startInputPump() {
	if native.inputQueue == nil || native.done == nil || native.stdin == nil {
		return
	}
	go func() {
		for {
			select {
			case data := <-native.inputQueue:
				if native.isClosed() {
					return
				}
				if err := native.writeRemoteInput(data); err != nil {
					native.close(native.server != nil)
					return
				}
			case <-native.done:
				return
			}
		}
	}()
}

type sshAutoSudoState uint8

const (
	sshAutoSudoWaitingForShell sshAutoSudoState = iota
	sshAutoSudoWaitingForPassword
	sshAutoSudoDone
)

// sshAutoSudoDriver intentionally lives in the Go backend. The renderer must never receive the
// saved login password. Password credentials first write `sudo su` and queue the password only
// after sudo emits its standard `[sudo] ...:` prompt. Requiring sudo's prefix avoids treating a
// login banner or unrelated password text as permission to send the secret. Key credentials have
// no login password, so they use `sudo -n su` and can elevate only when sudo permits NOPASSWD.
type sshAutoSudoDriver struct {
	session  *sshNativeSession
	password string

	mu           sync.Mutex
	state        sshAutoSudoState
	tail         []byte
	pendingInput []byte
	timeout      *time.Timer
}

func newSSHAutoSudoDriver(session *sshNativeSession, password string) *sshAutoSudoDriver {
	// A line-oriented sudo prompt cannot safely carry a password containing a newline. Refuse to
	// automate such a credential rather than risk turning the suffix into a shell command.
	if strings.ContainsAny(password, "\r\n") {
		return nil
	}
	return &sshAutoSudoDriver{
		session:  session,
		password: password,
		state:    sshAutoSudoWaitingForShell,
		tail:     make([]byte, 0, sshAutoSudoTailBytes),
	}
}

func (driver *sshAutoSudoDriver) start() {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.startLocked()
}

func (driver *sshAutoSudoDriver) startLocked() {
	if driver.state != sshAutoSudoWaitingForShell {
		return
	}
	if driver.password == "" {
		_ = driver.session.writeRaw([]byte("sudo -n su\r"))
		driver.finishLocked(nil)
		return
	}
	driver.state = sshAutoSudoWaitingForPassword
	driver.timeout = time.AfterFunc(sshAutoSudoTimeout, driver.onTimeout)
	if err := driver.session.writeRaw([]byte("sudo su\r")); err != nil {
		driver.finishLocked(nil)
	}
}

func (driver *sshAutoSudoDriver) queueUserInput(data []byte) (bool, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.state == sshAutoSudoDone {
		return false, nil
	}
	if len(driver.pendingInput)+len(data) > sshInputMaxBytes {
		return true, errSSHInputFull
	}
	driver.pendingInput = append(driver.pendingInput, data...)
	return true, nil
}

func (driver *sshAutoSudoDriver) observe(data []byte) {
	if len(data) == 0 {
		return
	}

	driver.mu.Lock()
	defer driver.mu.Unlock()
	switch driver.state {
	case sshAutoSudoWaitingForShell:
		driver.startLocked()
	case sshAutoSudoWaitingForPassword:
		driver.tail = append(driver.tail, data...)
		if len(driver.tail) > sshAutoSudoTailBytes {
			driver.tail = driver.tail[len(driver.tail)-sshAutoSudoTailBytes:]
		}
		if hasSSHSudoPasswordPrompt(driver.tail) {
			passwordInput := append([]byte(driver.password), '\r')
			driver.finishLocked(passwordInput)
			clear(passwordInput)
		}
	}
}

func hasSSHSudoPasswordPrompt(tail []byte) bool {
	trimmed := strings.TrimRight(string(tail), " \t\r\n")
	lineStart := strings.LastIndexAny(trimmed, "\r\n")
	line := strings.TrimSpace(trimmed[lineStart+1:])
	return strings.HasPrefix(line, "[sudo]") && strings.HasSuffix(line, ":")
}

func (driver *sshAutoSudoDriver) onTimeout() {
	driver.mu.Lock()
	if driver.state == sshAutoSudoWaitingForPassword {
		driver.finishLocked(nil)
	}
	driver.mu.Unlock()
}

func (driver *sshAutoSudoDriver) finishLocked(priorityInput []byte) {
	driver.state = sshAutoSudoDone
	if driver.timeout != nil {
		driver.timeout.Stop()
		driver.timeout = nil
	}
	pendingInput := driver.pendingInput
	driver.pendingInput = nil
	driver.password = ""
	driver.tail = driver.tail[:0]
	if len(priorityInput) > 0 {
		_ = driver.session.writeRaw(priorityInput)
	}
	if len(pendingInput) > 0 {
		_ = driver.session.writeRaw(pendingInput)
	}
	clear(pendingInput)
}

func (driver *sshAutoSudoDriver) dispose() {
	driver.mu.Lock()
	driver.finishLocked(nil)
	driver.mu.Unlock()
}

func (native *sshNativeSession) startSftpOpen(requestID string) {
	if native.server == nil {
		return
	}

	native.sftpMu.Lock()
	if native.isClosed() {
		native.sftpMu.Unlock()
		native.server.writeSftpRequestError(native.id, requestID, errSSHSessionClosed.Error())
		return
	}
	if native.sftpOpening {
		native.sftpMu.Unlock()
		native.server.writeSftpRequestError(native.id, requestID, errSSHSftpOpening.Error())
		return
	}

	native.sftpClosed = false
	native.sftpGeneration++
	generation := native.sftpGeneration
	clientReady := native.sftpClient != nil
	if !clientReady {
		native.sftpOpening = true
	}
	native.sftpMu.Unlock()

	// Reserve the generation before launching network work. A close command can therefore
	// invalidate this open even if the goroutine has not started yet.
	native.server.output.write(sshWireEvent{
		Type:      "sftp.opening",
		SessionID: native.id,
		RequestID: requestID,
	})
	if clientReady {
		// Opening is idempotent after an initial directory-list failure. The client may be healthy
		// even when the first ReadDir failed, so retry the listing instead of another SSH channel.
		native.startSftpListWithGeneration("", generation, requestID)
		return
	}
	go native.openSftp(generation, requestID)
}

func (native *sshNativeSession) openSftp(generation uint64, requestID string) {
	client, err := sftp.NewClient(native.client)
	if err != nil {
		native.sftpMu.Lock()
		current := native.sftpGeneration == generation
		if current {
			native.sftpOpening = false
		}
		native.sftpMu.Unlock()
		if !current || native.isClosed() {
			return
		}
		native.server.writeSftpRequestError(
			native.id,
			requestID,
			fmt.Sprintf("could not open SFTP: %v", err),
		)
		return
	}

	native.sftpMu.Lock()
	current := native.sftpGeneration == generation
	closed := native.sftpClosed || native.isClosed()
	if current && !closed {
		native.sftpClient = client
	}
	if current {
		native.sftpOpening = false
	}
	native.sftpMu.Unlock()
	if !current || closed {
		_ = client.Close()
		return
	}

	native.startSftpListWithGeneration("", generation, requestID)
}

func (native *sshNativeSession) startSftpList(requestedPath string, generation uint64, requestID string) {
	path, err := normalizeSftpPath(requestedPath)
	if err != nil {
		native.server.writeSftpRequestError(native.id, requestID, err.Error(), requestedPath)
		return
	}
	native.startSftpListWithGeneration(path, generation, requestID)
}

func (native *sshNativeSession) startSftpListWithGeneration(requestedPath string, generation uint64, requestID string) {
	native.sftpMu.Lock()
	client := native.sftpClient
	currentGeneration := native.sftpGeneration
	if generation == 0 {
		generation = currentGeneration
	}
	if generation != currentGeneration || client == nil || native.sftpClosed || native.isClosed() {
		native.sftpMu.Unlock()
		native.server.writeSftpRequestError(native.id, requestID, errSSHSftpClosed.Error(), requestedPath)
		return
	}
	native.sftpListSeq++
	sequence := native.sftpListSeq
	native.sftpMu.Unlock()

	go native.listSftp(requestedPath, generation, sequence, requestID)
}

func (native *sshNativeSession) listSftp(requestedPath string, generation, sequence uint64, requestID string) {
	// pkg/sftp supports concurrent clients, but serializing directory reads keeps this browser's
	// request order deterministic while allowing closeSftp to interrupt an in-flight read.
	native.sftpListMu.Lock()
	defer native.sftpListMu.Unlock()

	native.sftpMu.Lock()
	client := native.sftpClient
	current := generation == native.sftpGeneration && sequence == native.sftpListSeq && !native.sftpClosed
	native.sftpMu.Unlock()
	if !current || client == nil || native.isClosed() {
		return
	}

	resolvedPath, entries, truncated, err := readSftpDirectory(client, requestedPath)
	if err != nil {
		native.sftpMu.Lock()
		current = generation == native.sftpGeneration && sequence == native.sftpListSeq && !native.sftpClosed
		native.sftpMu.Unlock()
		if !current || native.isClosed() {
			return
		}
		native.server.writeSftpRequestError(
			native.id,
			requestID,
			fmt.Sprintf("could not list SFTP directory: %v", err),
			requestedPath,
		)
		return
	}

	native.sftpMu.Lock()
	current = generation == native.sftpGeneration && sequence == native.sftpListSeq && !native.sftpClosed
	native.sftpMu.Unlock()
	if !current || native.isClosed() {
		return
	}
	native.server.output.write(sshWireEvent{
		Type:      "sftp.ready",
		SessionID: native.id,
		Path:      resolvedPath,
		Entries:   entries,
		Truncated: truncated,
		RequestID: requestID,
	})
}

func (native *sshNativeSession) closeSftp(notify bool) {
	native.sftpMu.Lock()
	native.sftpGeneration++
	native.sftpListSeq++
	native.sftpClosed = true
	native.sftpOpening = false
	client := native.sftpClient
	native.sftpClient = nil
	native.sftpMu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if notify && native.server != nil && !native.isClosed() {
		native.server.output.write(sshWireEvent{Type: "sftp.closed", SessionID: native.id})
	}
}

func (native *sshNativeSession) startLocalList(requestedPath, requestID string) {
	path, err := normalizeLocalPath(requestedPath)
	if err != nil {
		native.writeLocalSftpError(requestID, requestedPath, err)
		return
	}
	server := native.server
	if server == nil {
		return
	}
	go func() {
		quickPaths := server.localQuickPaths.get()
		entries, truncated, err := readLocalDirectory(path)
		if err != nil {
			native.writeLocalSftpError(requestID, path, err)
			return
		}
		if native.isClosed() {
			return
		}
		server.output.write(sshWireEvent{
			Type:       "sftp.local.ready",
			SessionID:  native.id,
			RequestID:  requestID,
			Pane:       "local",
			Path:       path,
			QuickPaths: quickPaths,
			Entries:    entries,
			Truncated:  truncated,
		})
	}()
}

func (server *sshServer) writeSftpLocalError(sessionID, requestID, path string, err error) {
	server.output.write(sshWireEvent{
		Type:      "sftp.local.error",
		SessionID: sessionID,
		RequestID: requestID,
		Pane:      "local",
		Path:      path,
		Error:     safeSftpError(err),
	})
}

func (server *sshServer) writeSftpOperationError(command sshWireCommand, err error) {
	server.output.write(sshWireEvent{
		Type:      "sftp.operation",
		SessionID: command.SessionID,
		RequestID: command.RequestID,
		Pane:      command.Pane,
		Operation: command.Operation,
		Path:      command.Path,
		Error:     safeSftpError(err),
	})
}

func (native *sshNativeSession) writeLocalSftpError(requestID, path string, err error) {
	if native.server == nil || native.isClosed() {
		return
	}
	native.server.output.write(sshWireEvent{
		Type:      "sftp.local.error",
		SessionID: native.id,
		RequestID: requestID,
		Pane:      "local",
		Path:      path,
		Error:     safeSftpError(err),
	})
}

func (native *sshNativeSession) startSftpOperation(command sshWireCommand) {
	go func() {
		err := native.runSftpOperation(command)
		if native.server == nil || native.isClosed() {
			return
		}
		event := sshWireEvent{
			Type:      "sftp.operation",
			SessionID: native.id,
			RequestID: command.RequestID,
			Pane:      command.Pane,
			Operation: command.Operation,
			Path:      command.Path,
		}
		if err != nil {
			event.Error = safeSftpError(err)
		}
		native.server.output.write(event)
	}()
}

func (native *sshNativeSession) runSftpOperation(command sshWireCommand) error {
	if command.Pane != "local" && command.Pane != "remote" {
		return errors.New("SFTP pane is invalid")
	}
	if command.Operation != "mkdir" && command.Operation != "file" &&
		command.Operation != "delete" && command.Operation != "rename" && command.Operation != "open" {
		return errors.New("SFTP operation is invalid")
	}
	if command.Pane == "remote" && command.Operation == "open" {
		return errors.New("remote files cannot be opened locally")
	}
	if command.Pane == "local" {
		path, err := normalizeLocalPath(command.Path)
		if err != nil {
			return err
		}
		if isLocalPathRoot(path) && (command.Operation == "delete" || command.Operation == "rename") {
			return errors.New("cannot modify the local filesystem root")
		}
		if command.Operation == "rename" {
			destination, err := normalizeLocalPath(command.DestinationPath)
			if err != nil {
				return err
			}
			if isLocalPathRoot(destination) {
				return errors.New("cannot rename to the local filesystem root")
			}
			return os.Rename(path, destination)
		}
		switch command.Operation {
		case "mkdir":
			return os.MkdirAll(path, 0o755)
		case "file":
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			return file.Close()
		case "delete":
			return os.RemoveAll(path)
		case "open":
			return openLocalPath(path)
		default:
			return errors.New("SFTP operation is invalid")
		}
	}

	path, err := normalizeSftpPath(command.Path)
	if err != nil || path == "" {
		if err != nil {
			return err
		}
		return errors.New("SFTP path is required")
	}
	if path == "/" && (command.Operation == "delete" || command.Operation == "rename") {
		return errors.New("cannot modify the remote filesystem root")
	}
	return native.withSftpClient(func(client *sftp.Client) error {
		switch command.Operation {
		case "mkdir":
			return client.MkdirAll(path)
		case "file":
			file, err := client.Create(path)
			if err != nil {
				return err
			}
			return file.Close()
		case "delete":
			return removeRemotePath(client, path)
		case "rename":
			destination, err := normalizeSftpPath(command.DestinationPath)
			if err != nil || destination == "" {
				if err != nil {
					return err
				}
				return errors.New("SFTP destination path is required")
			}
			if destination == "/" {
				return errors.New("cannot rename to the remote filesystem root")
			}
			return client.Rename(path, destination)
		default:
			return errors.New("SFTP operation is invalid")
		}
	})
}

func isLocalPathRoot(path string) bool {
	clean := filepath.Clean(path)
	return filepath.Dir(clean) == clean
}

func (native *sshNativeSession) withSftpClient(action func(*sftp.Client) error) error {
	native.sftpListMu.Lock()
	defer native.sftpListMu.Unlock()
	native.sftpMu.Lock()
	client := native.sftpClient
	closed := native.sftpClosed || native.isClosed()
	native.sftpMu.Unlock()
	if client == nil || closed {
		return errSSHSftpClosed
	}
	return action(client)
}

func normalizeLocalPath(value string) (string, error) {
	if len([]byte(value)) > sshSftpMaxPathBytes {
		return "", errors.New("local path is too long")
	}
	if strings.ContainsRune(value, '\x00') {
		return "", errors.New("local path is invalid")
	}
	if value == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("could not determine the local home directory")
		}
		value = home
	}
	if !filepath.IsAbs(value) {
		return "", errors.New("local path must be absolute")
	}
	return filepath.Clean(value), nil
}

func readLocalDirectory(path string) ([]sshSftpEntry, bool, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()

	// Read one entry past the renderer limit so very large directories are not
	// fully enumerated and sorted by os.ReadDir before we discard the excess.
	// File.ReadDir uses the platform's native directory iterator on every OS.
	entries, err := directory.ReadDir(sshSftpMaxEntryCount + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	truncated := len(entries) > sshSftpMaxEntryCount
	if truncated {
		entries = entries[:sshSftpMaxEntryCount]
	}
	result := make([]sshSftpEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !isSafeLocalSftpName(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fullPath := filepath.Join(path, name)
		if len([]byte(fullPath)) > sshSftpMaxPathBytes {
			truncated = true
			continue
		}
		size := int64(0)
		if !info.IsDir() {
			size = info.Size()
			if size < 0 {
				size = 0
			} else if size > sshSftpMaxSafeSize {
				size = sshSftpMaxSafeSize
			}
		}
		lastModified := ""
		if !info.ModTime().IsZero() {
			lastModified = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		result = append(result, sshSftpEntry{
			Name:            name,
			FullPath:        fullPath,
			IsDirectory:     info.IsDir(),
			IsSymbolicLink:  entry.Type()&os.ModeSymlink != 0,
			Size:            size,
			LastModifiedUTC: lastModified,
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].IsDirectory != result[j].IsDirectory {
			return result[i].IsDirectory
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, truncated, nil
}

func openLocalPath(path string) error {
	return openLocalPathWithShell(path)
}

func removeRemotePath(client *sftp.Client, path string) error {
	info, err := client.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return client.Remove(path)
	}
	entries, err := client.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !isSafeSftpName(name) {
			continue
		}
		if err := removeRemotePath(client, pathpkg.Join(path, name)); err != nil {
			return err
		}
	}
	return client.RemoveDirectory(path)
}

func validateSftpTransferCommand(command sshWireCommand) error {
	if command.TransferID == "" || len(command.TransferID) > 128 {
		return errors.New("SFTP transfer id is invalid")
	}
	if command.Direction != "local-to-remote" && command.Direction != "remote-to-local" && command.Direction != "local-to-local" {
		return errors.New("SFTP transfer direction is invalid")
	}
	if len(command.Items) == 0 || len(command.Items) > sshSftpMaxTransferItems {
		return errors.New("SFTP transfer item count is invalid")
	}
	if command.DestinationPath == "" {
		return errors.New("SFTP transfer destination is required")
	}
	if command.Direction == "local-to-remote" {
		if _, err := normalizeSftpPath(command.DestinationPath); err != nil {
			return err
		}
	} else if _, err := normalizeLocalPath(command.DestinationPath); err != nil {
		return err
	}
	for _, item := range command.Items {
		if !isSafeTransferName(command.Direction, item.Name) {
			return errors.New("SFTP transfer item name is invalid")
		}
		if item.SourcePath == "" {
			return errors.New("SFTP transfer source is required")
		}
		if item.Size < 0 {
			return errors.New("SFTP transfer size is invalid")
		}
		if command.Direction == "remote-to-local" {
			if _, err := normalizeSftpPath(item.SourcePath); err != nil {
				return err
			}
		} else if _, err := normalizeLocalPath(item.SourcePath); err != nil {
			return err
		}
	}
	return nil
}

func isSafeTransferName(direction, name string) bool {
	if direction == "local-to-remote" {
		return isSafeSftpName(name)
	}
	return isSafeLocalSftpName(name)
}

func (server *sshServer) writeTransferBatchError(command sshWireCommand, err error) {
	server.output.write(sshWireEvent{
		Type:          "sftp.transfer",
		SessionID:     command.SessionID,
		TransferID:    command.TransferID,
		TransferState: "batch-failed",
		Direction:     command.Direction,
		Error:         safeSftpError(err),
	})
}

func (server *sshServer) writeTransferBatchTerminal(command sshWireCommand, state string) {
	server.output.write(sshWireEvent{
		Type:          "sftp.transfer",
		SessionID:     command.SessionID,
		TransferID:    command.TransferID,
		TransferState: state,
		Direction:     command.Direction,
	})
}

func (server *sshServer) writeTransferEvent(command sshWireCommand, itemID, state, displayName string, expected, transferred int64, err error) {
	event := sshWireEvent{
		Type:             "sftp.transfer",
		SessionID:        command.SessionID,
		TransferID:       command.TransferID,
		ItemID:           itemID,
		TransferState:    state,
		Direction:        command.Direction,
		DisplayName:      displayName,
		ExpectedBytes:    expected,
		BytesTransferred: transferred,
	}
	if err != nil {
		event.Error = safeSftpError(err)
	}
	server.output.write(event)
}

func (server *sshServer) runSftpTransfer(native *sshNativeSession, command sshWireCommand, transfer *sshSftpTransfer, ctx context.Context) {
	var client *sftp.Client
	remote := command.Direction != "local-to-local"
	if remote {
		native.sftpListMu.Lock()
		defer native.sftpListMu.Unlock()
		native.sftpMu.Lock()
		client = native.sftpClient
		closed := native.sftpClosed || native.isClosed()
		native.sftpMu.Unlock()
		if client == nil || closed {
			server.writeTransferBatchError(command, errSSHSftpClosed)
			return
		}
	}

	plans, err := buildSftpTransferPlans(client, command, ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			server.writeTransferBatchTerminal(command, "batch-cancelled")
		} else {
			server.writeTransferBatchError(command, err)
		}
		return
	}

	var sticky *sshSftpTransferDecision
	for index, plan := range plans {
		if err := ctx.Err(); err != nil {
			server.writeTransferBatchTerminal(command, "batch-cancelled")
			return
		}
		itemID := sftpTransferItemID(index)
		itemContext := transfer.startItem(ctx, itemID)
		err := func() error {
			defer transfer.finishItem(itemID)
			if err := itemContext.Err(); err != nil {
				return err
			}
			if command.Direction != "local-to-remote" {
				if err := validateLocalTransferDestinationParents(plan.destinationPath); err != nil {
					return err
				}
			}
			if plan.isDirectory {
				if err := removeTransferDestinationSymlink(client, command.Direction, plan.destinationPath); err != nil {
					return err
				}
				return ensureTransferDirectory(client, command.Direction, plan.destinationPath)
			}

			exists, isDirectory, existingSize, err := transferDestinationInfo(client, command.Direction, plan.destinationPath)
			if err != nil {
				return err
			}
			decision := "overwrite"
			if exists {
				if sticky != nil {
					decision = sticky.decision
				} else {
					server.output.write(sshWireEvent{
						Type:       "sftp.conflict",
						SessionID:  command.SessionID,
						TransferID: command.TransferID,
						// Item IDs are scoped by TransferID in the renderer. Keeping the index
						// independent of the caller-supplied transfer ID keeps the wire value
						// bounded even when a valid transfer ID is near its length limit.
						ItemID:              itemID,
						Direction:           command.Direction,
						DisplayName:         plan.displayName,
						Path:                plan.destinationPath,
						IncomingSize:        plan.incomingSize,
						ExistingSize:        existingSize,
						ExistingIsDirectory: isDirectory,
					})
					chosen, err := awaitSftpTransferDecision(
						itemContext,
						transfer.decisions,
						itemID,
					)
					if err != nil {
						return err
					}
					decision = chosen.decision
					if chosen.applyAll {
						copy := chosen
						sticky = &copy
					}
				}
			}
			if decision == "skip" || itemContext.Err() != nil {
				return itemContext.Err()
			}

			if err := ensureTransferParent(client, command.Direction, plan.destinationPath); err != nil {
				return err
			}
			if err := removeTransferDestinationSymlink(client, command.Direction, plan.destinationPath); err != nil {
				return err
			}
			if err := itemContext.Err(); err != nil {
				return err
			}
			server.writeTransferEvent(command, itemID, "running", plan.displayName, plan.incomingSize, 0, nil)
			var lastTransferred int64
			err = copyTransferFile(itemContext, client, command.Direction, plan, func(transferred int64) {
				lastTransferred = transferred
				server.writeTransferEvent(command, itemID, "progress", plan.displayName, plan.incomingSize, transferred, nil)
			})
			if errors.Is(err, context.Canceled) {
				server.writeTransferEvent(command, itemID, "cancelled", plan.displayName, plan.incomingSize, lastTransferred, nil)
				return err
			}
			if err != nil {
				server.writeTransferEvent(command, itemID, "failed", plan.displayName, plan.incomingSize, lastTransferred, err)
				return nil
			}
			server.writeTransferEvent(command, itemID, "completed", plan.displayName, plan.incomingSize, plan.incomingSize, nil)
			return nil
		}()
		if errors.Is(err, context.Canceled) {
			if ctx.Err() != nil {
				server.writeTransferBatchTerminal(command, "batch-cancelled")
				return
			}
			// A row-level cancellation only skips this plan; later rows in the same
			// batch remain available, matching the WinUI transfer queue.
			continue
		}
		if err != nil {
			server.writeTransferBatchError(command, err)
			return
		}
	}
	server.writeTransferBatchTerminal(command, "batch-completed")
}

func sftpTransferItemID(index int) string {
	return fmt.Sprintf("item-%d", index)
}

func buildSftpTransferPlans(client *sftp.Client, command sshWireCommand, ctx context.Context) ([]sshSftpTransferPlan, error) {
	plans := make([]sshSftpTransferPlan, 0)
	for _, item := range command.Items {
		if command.Direction == "remote-to-local" {
			if err := appendRemoteTransferPlans(client, command.DestinationPath, item, &plans, ctx); err != nil {
				return nil, err
			}
		} else {
			if err := appendLocalTransferPlans(command.Direction, command.DestinationPath, item, &plans, ctx); err != nil {
				return nil, err
			}
		}
		if len(plans) > sshSftpMaxTransferPlanCount {
			return nil, errors.New("SFTP transfer contains too many files")
		}
	}
	return plans, nil
}

func appendLocalTransferPlans(direction, destination string, item sshSftpTransferItem, plans *[]sshSftpTransferPlan, ctx context.Context) error {
	source, err := normalizeLocalPath(item.SourcePath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	isDirectory := isSftpTransferDirectory(info)
	if direction == "local-to-local" {
		target := joinTransferDestination(direction, destination, item.Name)
		if err := validateLocalTransferDestination(source, destination, target, isDirectory); err != nil {
			return err
		}
	}
	if !isDirectory {
		*plans = append(*plans, sshSftpTransferPlan{
			sourcePath:      source,
			destinationPath: joinTransferDestination(direction, destination, item.Name),
			displayName:     item.Name,
			incomingSize:    safeTransferSize(info.Size()),
		})
		return nil
	}

	rootDestination := joinTransferDestination(direction, destination, item.Name)
	*plans = append(*plans, sshSftpTransferPlan{
		sourcePath:      source,
		destinationPath: rootDestination,
		displayName:     item.Name,
		isDirectory:     true,
	})
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == source {
			return nil
		}
		if len(*plans) >= sshSftpMaxTransferPlanCount {
			return errors.New("SFTP transfer contains too many files")
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !isSafeTransferRelativePath(direction, relative) {
			return fmt.Errorf("local transfer path is unsafe: %s", relative)
		}
		displayName := item.Name + "/" + relative
		*plans = append(*plans, sshSftpTransferPlan{
			sourcePath:      path,
			destinationPath: joinTransferDestination(direction, destination, displayName),
			displayName:     displayName,
			incomingSize:    localEntrySize(entry),
			isDirectory:     entry.IsDir(),
		})
		return nil
	})
}

func validateLocalTransferDestination(source, destination, target string, sourceIsDirectory bool) error {
	source = filepath.Clean(source)
	destination = filepath.Clean(destination)
	target = filepath.Clean(target)
	if sameLocalPath(source, target) {
		return errors.New("SFTP source and destination are the same path")
	}
	if sourceIsDirectory && (localPathContains(source, destination) || localPathContains(source, target)) {
		return errors.New("SFTP cannot copy a folder into itself")
	}
	return nil
}

func sameLocalPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

func localPathContains(parent, candidate string) bool {
	parent = filepath.Clean(parent)
	candidate = filepath.Clean(candidate)
	if sameLocalPath(parent, candidate) {
		return true
	}
	relative, err := filepath.Rel(parent, candidate)
	if err == nil && !filepath.IsAbs(relative) &&
		relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}

	parentInfo, err := os.Stat(parent)
	if err != nil {
		return false
	}
	for current := candidate; ; current = filepath.Dir(current) {
		if currentInfo, statErr := os.Stat(current); statErr == nil && os.SameFile(parentInfo, currentInfo) {
			return true
		}
		if filepath.Dir(current) == current {
			return false
		}
	}
}

func validateLocalTransferDestinationParents(path string) error {
	current := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("SFTP destination contains a symbolic link: %s", current)
			}
		} else if !os.IsNotExist(err) {
			return err
		}

		parent := filepath.Dir(current)
		if sameLocalPath(parent, current) {
			return nil
		}
		current = parent
	}
}

func appendRemoteTransferPlans(client *sftp.Client, destination string, item sshSftpTransferItem, plans *[]sshSftpTransferPlan, ctx context.Context) error {
	source, err := normalizeSftpPath(item.SourcePath)
	if err != nil || source == "" {
		if err != nil {
			return err
		}
		return errors.New("remote transfer source is required")
	}
	info, err := client.Lstat(source)
	if err != nil {
		return err
	}
	if !isSftpTransferDirectory(info) {
		*plans = append(*plans, sshSftpTransferPlan{
			sourcePath:      source,
			destinationPath: joinTransferDestination("remote-to-local", destination, item.Name),
			displayName:     item.Name,
			incomingSize:    safeTransferSize(info.Size()),
		})
		return nil
	}

	*plans = append(*plans, sshSftpTransferPlan{
		sourcePath:      source,
		destinationPath: joinTransferDestination("remote-to-local", destination, item.Name),
		displayName:     item.Name,
		isDirectory:     true,
	})
	return walkRemoteTransferPlans(client, source, destination, item.Name, plans, ctx)
}

func isSftpTransferDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func walkRemoteTransferPlans(client *sftp.Client, source, destination, relativeRoot string, plans *[]sshSftpTransferPlan, ctx context.Context) error {
	entries, err := client.ReadDirContext(ctx, source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !isSafeSftpName(entry.Name()) || !isSafeTransferName("remote-to-local", entry.Name()) {
			continue
		}
		if len(*plans) >= sshSftpMaxTransferPlanCount {
			return errors.New("SFTP transfer contains too many files")
		}
		relative := relativeRoot + "/" + entry.Name()
		fullPath := pathpkg.Join(source, entry.Name())
		*plans = append(*plans, sshSftpTransferPlan{
			sourcePath:      fullPath,
			destinationPath: joinTransferDestination("remote-to-local", destination, relative),
			displayName:     relative,
			incomingSize:    safeTransferSize(entry.Size()),
			isDirectory:     entry.IsDir() && entry.Mode()&os.ModeSymlink == 0,
		})
		if entry.IsDir() && entry.Mode()&os.ModeSymlink == 0 {
			if err := walkRemoteTransferPlans(client, fullPath, destination, relative, plans, ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSafeTransferRelativePath(direction, value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !isSafeTransferName(direction, segment) {
			return false
		}
	}
	return true
}

func joinTransferDestination(direction, root, relative string) string {
	if direction == "local-to-remote" {
		return pathpkg.Join(root, strings.ReplaceAll(relative, "\\", "/"))
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

func localEntrySize(entry fs.DirEntry) int64 {
	if entry.IsDir() {
		return 0
	}
	info, err := entry.Info()
	if err != nil {
		return 0
	}
	return safeTransferSize(info.Size())
}

func safeTransferSize(size int64) int64 {
	if size < 0 {
		return 0
	}
	if size > sshSftpMaxSafeSize {
		return sshSftpMaxSafeSize
	}
	return size
}

func ensureTransferDirectory(client *sftp.Client, direction, path string) error {
	if direction == "local-to-remote" {
		return client.MkdirAll(path)
	}
	return os.MkdirAll(path, 0o755)
}

func ensureTransferParent(client *sftp.Client, direction, path string) error {
	parent := filepath.Dir(path)
	if direction == "local-to-remote" {
		parent = pathpkg.Dir(path)
		return client.MkdirAll(parent)
	}
	return os.MkdirAll(parent, 0o755)
}

func transferDestinationInfo(client *sftp.Client, direction, path string) (bool, bool, int64, error) {
	var info os.FileInfo
	var err error
	if direction == "local-to-remote" {
		info, err = client.Lstat(path)
	} else {
		info, err = os.Lstat(path)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, 0, nil
		}
		return false, false, 0, err
	}
	size := int64(0)
	if !info.IsDir() {
		size = safeTransferSize(info.Size())
	}
	return true, info.IsDir(), size, nil
}

func removeTransferDestinationSymlink(client *sftp.Client, direction, path string) error {
	if direction == "local-to-remote" {
		info, err := client.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return client.Remove(path)
		}
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(path)
	}
	return nil
}

func copyTransferFile(ctx context.Context, client *sftp.Client, direction string, plan sshSftpTransferPlan, report func(int64)) error {
	if direction == "local-to-local" && sameLocalPath(plan.sourcePath, plan.destinationPath) {
		return errors.New("SFTP source and destination are the same file")
	}
	var source io.ReadCloser
	var destination io.WriteCloser
	var err error
	switch direction {
	case "local-to-remote":
		source, err = os.Open(plan.sourcePath)
		if err != nil {
			return err
		}
		destination, err = client.OpenFile(plan.destinationPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	case "remote-to-local":
		source, err = client.Open(plan.sourcePath)
		if err != nil {
			return err
		}
		destination, err = os.OpenFile(plan.destinationPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	case "local-to-local":
		source, err = os.Open(plan.sourcePath)
		if err != nil {
			return err
		}
		destination, err = os.OpenFile(plan.destinationPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	default:
		return errors.New("SFTP transfer direction is invalid")
	}
	if err != nil {
		if source != nil {
			_ = source.Close()
		}
		return err
	}
	defer source.Close()
	defer destination.Close()

	buffer := make([]byte, sshSftpTransferBuffer)
	var transferred int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if err := writeTransferBytes(destination, buffer[:read]); err != nil {
				return err
			}
			transferred += int64(read)
			report(transferred)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func writeTransferBytes(destination io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := destination.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func normalizeSftpPath(value string) (string, error) {
	if len([]byte(value)) > sshSftpMaxPathBytes {
		return "", errors.New("SFTP path is too long")
	}
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\\\x00") {
		return "", errors.New("SFTP path is invalid")
	}
	if !strings.HasPrefix(value, "/") {
		return "", errors.New("SFTP path must be absolute")
	}
	return pathpkg.Clean(value), nil
}

func readSftpDirectory(client *sftp.Client, requestedPath string) (string, []sshSftpEntry, bool, error) {
	path := requestedPath
	if path == "" {
		workingDirectory, err := client.Getwd()
		if err != nil {
			return "", nil, false, err
		}
		path = workingDirectory
	}
	path, err := normalizeSftpPath(path)
	if err != nil {
		return "", nil, false, err
	}
	if path == "" {
		path = "/"
	}

	listContext, cancel := context.WithTimeout(context.Background(), sshSftpListTimeout)
	defer cancel()
	files, err := client.ReadDirContext(listContext, path)
	if err != nil {
		return "", nil, false, err
	}
	truncated := len(files) > sshSftpMaxEntryCount
	if truncated {
		files = files[:sshSftpMaxEntryCount]
	}
	entries := make([]sshSftpEntry, 0, len(files))
	for _, file := range files {
		name := file.Name()
		if !isSafeSftpName(name) {
			continue
		}
		fullPath := path
		if fullPath == "/" {
			fullPath += name
		} else {
			fullPath += "/" + name
		}
		if len([]byte(fullPath)) > sshSftpMaxPathBytes {
			truncated = true
			continue
		}
		lastModified := ""
		if !file.ModTime().IsZero() {
			lastModified = file.ModTime().UTC().Format(time.RFC3339Nano)
		}
		size := int64(0)
		if !file.IsDir() {
			size = file.Size()
			if size < 0 {
				size = 0
			} else if size > sshSftpMaxSafeSize {
				size = sshSftpMaxSafeSize
			}
		}
		entries = append(entries, sshSftpEntry{
			Name:            name,
			FullPath:        fullPath,
			IsDirectory:     file.IsDir(),
			IsSymbolicLink:  file.Mode()&os.ModeSymlink != 0,
			Size:            size,
			LastModifiedUTC: lastModified,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDirectory != entries[j].IsDirectory {
			return entries[i].IsDirectory
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return path, entries, truncated, nil
}

func isSafeSftpName(name string) bool {
	if !hasSafeSftpNameShape(name) {
		return false
	}
	return !strings.ContainsAny(name, "/\\\x00")
}

func isSafeLocalSftpName(name string) bool {
	if !hasSafeSftpNameShape(name) || strings.ContainsAny(name, "/\x00") {
		return false
	}
	return runtime.GOOS != "windows" || !strings.ContainsAny(name, "\\:")
}

func hasSafeSftpNameShape(name string) bool {
	return name != "" && name != "." && name != ".." && len([]byte(name)) <= sshSftpMaxNameBytes
}

func resolveDirectSSHTarget(command sshWireCommand) (sshTarget, error) {
	host := strings.TrimSpace(command.Host)
	if host == "" {
		return sshTarget{}, errors.New("SSH host is required")
	}
	if len([]byte(host)) > sshMaxHostLength || strings.ContainsAny(host, "\r\n\x00") {
		return sshTarget{}, errors.New("SSH host is invalid")
	}
	username := strings.TrimSpace(command.Username)
	if username == "" && command.CredentialID == "" {
		return sshTarget{}, errors.New("SSH username is required")
	}
	if len([]byte(username)) > sshMaxUsernameLength || strings.ContainsAny(username, "\r\n\x00") {
		return sshTarget{}, errors.New("SSH username is invalid")
	}
	if len([]byte(command.Password)) > sshMaxPasswordBytes {
		return sshTarget{}, errors.New("SSH password is too long")
	}
	port := command.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return sshTarget{}, errors.New("SSH port is invalid")
	}
	tunnelConfigID := normalizeTunnelID(command.TunnelConfigID)
	if command.TunnelConfigID != "" && tunnelConfigID == "" {
		return sshTarget{}, errors.New("SSH VPN tunnel is invalid")
	}
	return sshTarget{
		title:          host,
		host:           host,
		port:           port,
		username:       username,
		password:       command.Password,
		autoSudo:       command.AutoSudo,
		tunnelConfigID: tunnelConfigID,
	}, nil
}

func openNativeSSH(
	ctx context.Context,
	databasePath string,
	electronUserDataPath string,
	nodeID string,
	directTarget *sshTarget,
	directCredentialID string,
	socksEndpoint string,
	tunnelEnabled *bool,
	usernameOverride string,
	passwordOverride string,
	credentialOverride bool,
	usernameOverrideAuthoritative bool,
	keyPassphraseOverride string,
	columns uint32,
	rows uint32,
) (*sshNativeSession, sshTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, sshTarget{}, err
	}
	var target sshTarget
	var err error
	if directTarget != nil {
		target = *directTarget
		if directCredentialID != "" {
			database, openErr := openDatabase(databasePath, false)
			if openErr != nil {
				return nil, sshTarget{}, errors.New("Wormhole database is unavailable")
			}
			credentialErr := loadSSHCredential(
				database,
				databasePath,
				normalizeID(directCredentialID),
				&target,
				"",
				"",
				false,
				false,
				electronUserDataPath,
			)
			closeErr := database.Close()
			if credentialErr != nil {
				return nil, sshTarget{}, credentialErr
			}
			if closeErr != nil {
				return nil, sshTarget{}, errors.New("Wormhole database could not be closed")
			}
		}
		if target.username == "" {
			return nil, sshTarget{}, errors.New("SSH username is required")
		}
	} else if nodeID != "" {
		target, err = loadSSHTargetWithCredentialOverrides(
			databasePath,
			nodeID,
			usernameOverride,
			passwordOverride,
			credentialOverride,
			usernameOverrideAuthoritative,
			directCredentialID,
			electronUserDataPath,
		)
	} else {
		err = errors.New("SSH connection target is missing")
	}
	if err != nil {
		return nil, sshTarget{}, err
	}
	defer clearBytes(target.privateKey)
	if keyPassphraseOverride != "" {
		target.keyPassphrase = keyPassphraseOverride
	}
	if err := ctx.Err(); err != nil {
		return nil, sshTarget{}, err
	}
	target.socksEndpoint = socksEndpoint
	if tunnelEnabled != nil && !*tunnelEnabled {
		target.tunnelConfigID = ""
	}
	var tunnel *tunnelRuntime
	if target.tunnelConfigID != "" && target.socksEndpoint == "" {
		tunnel, err = startTunnelRuntime(ctx, databasePath, target.tunnelConfigID)
		if err != nil {
			return nil, sshTarget{}, err
		}
	}
	native, fingerprint, err := dialNativeSSH(ctx, target, columns, rows, tunnel)
	if err != nil {
		tunnel.close()
		return nil, sshTarget{}, err
	}
	native.tunnel = tunnel
	if target.knownHostFingerprint == "" && target.nodeID != "" {
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
	target.privateKey = nil
	target.keyPassphrase = ""
	return native, target, nil
}

func dialNativeSSH(
	ctx context.Context,
	target sshTarget,
	columns uint32,
	rows uint32,
	tunnels ...*tunnelRuntime,
) (*sshNativeSession, string, error) {
	var tunnel *tunnelRuntime
	if len(tunnels) > 0 {
		tunnel = tunnels[0]
	}
	var fingerprint string
	config := &ssh.ClientConfig{
		User:    target.username,
		Timeout: sshConnectTimeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			if target.knownHostFingerprint != "" && target.knownHostFingerprint != fingerprint {
				return &sshHostKeyMismatchError{
					expected: target.knownHostFingerprint,
					received: fingerprint,
				}
			}
			return nil
		},
	}
	if len(target.privateKey) > 0 {
		signer, parseErr := ssh.ParsePrivateKey(target.privateKey)
		if parseErr != nil && target.keyPassphrase != "" {
			passphrase := []byte(target.keyPassphrase)
			signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(
				target.privateKey,
				passphrase,
			)
			clearBytes(passphrase)
		}
		if parseErr != nil {
			var missing *ssh.PassphraseMissingError
			if errors.As(parseErr, &missing) {
				return nil, "", errors.New("SSH private key passphrase is required")
			}
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
	var connection net.Conn
	var err error
	if target.socksEndpoint != "" {
		connection, err = dialSocks5(ctx, target.socksEndpoint, "tcp", address)
	} else if tunnel != nil {
		connection, err = tunnel.dialContext(ctx, "tcp", address)
	} else {
		dialer := net.Dialer{Timeout: sshConnectTimeout}
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
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
		if target.knownHostFingerprint != "" && fingerprint != "" && target.knownHostFingerprint != fingerprint {
			return nil, "", &sshHostKeyMismatchError{
				expected: target.knownHostFingerprint,
				received: fingerprint,
			}
		}
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
	terminal, err := newSSHTerminalEmulator(columns, rows)
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, "", fmt.Errorf("could not create the SSH terminal emulator: %w", err)
	}
	native := &sshNativeSession{
		id:               "",
		client:           client,
		session:          session,
		stdin:            stdin,
		stdout:           stdout,
		stderr:           stderr,
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		inputQueue:       make(chan []byte, sshInputQueueCapacity),
		done:             make(chan struct{}),
	}
	if target.autoSudo {
		native.autoSudo = newSSHAutoSudoDriver(native, target.password)
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

func loadSSHTarget(databasePath, nodeID string, electronUserDataPath ...string) (sshTarget, error) {
	return loadSSHTargetWithOverrides(databasePath, nodeID, "", "", false, false, electronUserDataPath...)
}

func loadSSHTargetWithOverrides(
	databasePath, nodeID, usernameOverride, passwordOverride string,
	credentialOverride bool,
	usernameOverrideAuthoritative bool,
	electronUserDataPath ...string,
) (sshTarget, error) {
	return loadSSHTargetWithCredentialOverrides(
		databasePath, nodeID, usernameOverride, passwordOverride, credentialOverride,
		usernameOverrideAuthoritative, "", electronUserDataPath...,
	)
}

func loadSSHTargetWithCredentialOverrides(
	databasePath, nodeID, usernameOverride, passwordOverride string,
	credentialOverride bool,
	usernameOverrideAuthoritative bool,
	credentialIDOverride string,
	electronUserDataPath ...string,
) (sshTarget, error) {
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
	autoSudo := false
	autoSudoSet := false
	tunnelEnabled := false
	tunnelSet := false
	tunnelConfigID := ""
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
		if !autoSudoSet && current.autoSudo != nil {
			autoSudo = *current.autoSudo
			autoSudoSet = true
		}
		if !tunnelSet && current.tunnelEnabled != nil {
			tunnelEnabled = *current.tunnelEnabled
			tunnelSet = true
		}
		if tunnelConfigID == "" && current.tunnelConfigID != "" {
			tunnelConfigID = current.tunnelConfigID
		}
		if !credentialResolved {
			if current.credentialMode != nil {
				if *current.credentialMode != 0 {
					credentialResolved = true
					if *current.credentialMode == 2 { // saved
						credentialID = current.credentialID
						if credentialID != "" {
							identityBoundary = true
							credentialContextPending = true
						}
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

	if !protocolSet {
		return sshTarget{}, errors.New("SSH connection has no protocol")
	}
	if protocol != 0 {
		return sshTarget{}, errors.New("the selected connection is not an SSH connection")
	}
	if tunnelSet && tunnelEnabled && tunnelConfigID == "" {
		return sshTarget{}, errors.New("SSH connection enables a VPN tunnel but no tunnel is configured")
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
		title:                root.name,
		host:                 host,
		port:                 int(port),
		username:             username,
		knownHostFingerprint: knownFingerprint,
		autoSudo:             autoSudo,
	}
	if tunnelSet && tunnelEnabled {
		target.tunnelConfigID = tunnelConfigID
	}
	if credentialOverride {
		applySSHCredentialOverride(
			&target,
			usernameOverride,
			passwordOverride,
			true,
			usernameOverrideAuthoritative,
		)
	} else if credentialIDOverride != "" {
		// An explicitly selected credential owns both halves of the identity for this attempt.
		// Retaining the connection username here could pair one account with another account's
		// password or private key.
		target.username = ""
		if err := loadSSHCredential(
			database,
			databasePath,
			normalizeID(credentialIDOverride),
			&target,
			"",
			"",
			false,
			false,
			electronUserDataPath...,
		); err != nil {
			return sshTarget{}, err
		}
	} else if root.useInlinePassword {
		secret, err := readCredentialSecret(database, root.id, electronUserDataPath...)
		if err != nil {
			return sshTarget{}, fmt.Errorf("could not read the SSH password: %w", err)
		}
		target.password = string(secret)
	} else if credentialID != "" {
		if err := loadSSHCredential(
			database,
			databasePath,
			credentialID,
			&target,
			usernameOverride,
			passwordOverride,
			credentialOverride,
			usernameOverrideAuthoritative,
			electronUserDataPath...,
		); err != nil {
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
		expression("TunnelEnabled") + ", " +
		expression("TunnelConfigId") + ", " +
		expression("SshAutoSudo") + " FROM Nodes n;"
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
			&row.TunnelConfigID,
			&row.SshAutoSudo,
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
			tunnelConfigID:       normalizeTunnelID(nullableString(row.TunnelConfigID)),
		}
		if row.TunnelEnabled.Valid {
			value := row.TunnelEnabled.Int64 != 0
			node.tunnelEnabled = &value
		}
		if row.SshAutoSudo.Valid {
			value := row.SshAutoSudo.Int64 != 0
			node.autoSudo = &value
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

func loadSSHCredential(
	database *sql.DB,
	databasePath, credentialID string,
	target *sshTarget,
	usernameOverride, passwordOverride string,
	credentialOverride bool,
	usernameOverrideAuthoritative bool,
	electronUserDataPath ...string,
) error {
	if strings.TrimSpace(credentialID) == "" {
		return errors.New("SSH credential id is empty")
	}
	exists, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return err
	}
	if !exists {
		if applySSHCredentialOverride(
			target,
			usernameOverride,
			passwordOverride,
			credentialOverride,
			usernameOverrideAuthoritative,
		) {
			return nil
		}
		return errors.New("Wormhole database has no SSH credentials")
	}
	release, err := sshCredentialPrivateKeyLock(databasePath)
	if err != nil {
		return err
	}
	defer release()
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
		// Virtual Bitwarden credentials intentionally exist only in the cache. The long-lived Go
		// vault backend resolves them and Electron forwards the values directly to this separate
		// Go SSH process for this one connection; they are never persisted here.
		if applySSHCredentialOverride(
			target,
			usernameOverride,
			passwordOverride,
			credentialOverride,
			usernameOverrideAuthoritative,
		) {
			return nil
		}
		return errors.New("SSH credential was not found")
	}
	if err != nil {
		return fmt.Errorf("cannot read SSH credential: %w", err)
	}
	if row.SecretProvider.Valid && row.SecretProvider.Int64 != 0 {
		if !applySSHCredentialOverride(
			target,
			usernameOverride,
			passwordOverride,
			credentialOverride,
			usernameOverrideAuthoritative,
		) {
			return errors.New("Bitwarden vault is locked or the linked credential is unavailable")
		}
		if target.username == "" {
			target.username = strings.TrimSpace(nullableString(row.Username))
		}
		return nil
	}
	if row.Protocol.Valid && row.Protocol.Int64 != 0 {
		return errors.New("the selected credential is not an SSH credential")
	}
	if target.username == "" {
		target.username = strings.TrimSpace(nullableString(row.Username))
	}

	if row.Kind.Valid && row.Kind.Int64 == 1 {
		if err := recoverCredentialPrivateKeyOperationsUnlocked(databasePath); err != nil {
			return err
		}
		stem, err := protectedCredentialFileStem(credentialID)
		if err != nil {
			return err
		}
		keyPath := filepath.Join(filepath.Dir(databasePath), "keys", stem+".dpapi")
		key, err := credentialPrivateKeyUnprotect(keyPath)
		if err != nil {
			return errors.New("could not read the SSH private key")
		}
		passphrase, err := readOptionalCredentialSecret(database, credentialID, electronUserDataPath...)
		if err != nil {
			clearBytes(key)
			return fmt.Errorf("could not read the SSH key passphrase: %w", err)
		}
		defer clearBytes(passphrase)
		target.privateKey = key
		target.keyPassphrase = string(passphrase)
		return nil
	}
	secret, err := readCredentialSecret(database, credentialID, electronUserDataPath...)
	if err != nil {
		return fmt.Errorf("could not read the SSH password: %w", err)
	}
	target.password = string(secret)
	return nil
}

// This indirection lets concurrency tests observe lock acquisition without changing the
// production locking behavior.
var sshCredentialPrivateKeyLock = acquireCredentialPrivateKeyLock

func applySSHCredentialOverride(
	target *sshTarget,
	usernameOverride, passwordOverride string,
	credentialOverride bool,
	usernameOverrideAuthoritative bool,
) bool {
	if !credentialOverride {
		return false
	}
	if username := strings.TrimSpace(usernameOverride); username != "" &&
		(usernameOverrideAuthoritative || target.username == "") {
		target.username = username
	}
	target.password = passwordOverride
	return true
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

func readCredentialSecret(database *sql.DB, credentialID string, electronUserDataPath ...string) ([]byte, error) {
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
	secret, err := unprotectStoredSecret(credentialID, encoded, encoding, electronUserDataPath...)
	if errors.Is(err, errUnsupportedSecretEncoding) {
		return nil, errors.New("stored SSH secret uses an unsupported encoding")
	}
	if err != nil {
		return nil, errors.New("stored SSH secret could not be decrypted")
	}
	return secret, nil
}

func readOptionalCredentialSecret(database *sql.DB, credentialID string, electronUserDataPath ...string) ([]byte, error) {
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
	secret, err := unprotectStoredSecret(credentialID, encoded, encoding, electronUserDataPath...)
	if errors.Is(err, errUnsupportedSecretEncoding) {
		return nil, errors.New("stored SSH secret uses an unsupported encoding")
	}
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

func trustSSHFingerprint(databasePath string, request sshHostKeyTrustRequest) error {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" || len(nodeID) > 128 {
		return errors.New("SSH connection id is invalid")
	}
	expected, err := normalizeSSHFingerprint(request.Expected)
	if err != nil {
		return fmt.Errorf("expected SSH fingerprint is invalid: %w", err)
	}
	received, err := normalizeSSHFingerprint(request.Received)
	if err != nil {
		return fmt.Errorf("received SSH fingerprint is invalid: %w", err)
	}
	if expected == received {
		return errors.New("the new SSH fingerprint must differ from the saved fingerprint")
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	if _, ok := columns["SshKnownHostFingerprint"]; !ok {
		return errors.New("SSH fingerprint column is missing")
	}
	effectiveFingerprint, err := loadEffectiveSSHFingerprint(database, nodeID, columns)
	if err != nil {
		return err
	}
	if effectiveFingerprint != expected {
		return errors.New("SSH host fingerprint changed; reload the connection before trusting it")
	}
	result, err := database.Exec(
		"UPDATE Nodes SET SshKnownHostFingerprint = ?, UpdatedAt = ? WHERE lower(Id) = ? AND (COALESCE(TRIM(SshKnownHostFingerprint), '') = '' OR TRIM(SshKnownHostFingerprint) = ?);",
		received,
		time.Now().UTC().Format(time.RFC3339Nano),
		normalizeID(nodeID),
		expected,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		return nil
	}

	var current sql.NullString
	err = database.QueryRow(
		"SELECT SshKnownHostFingerprint FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(nodeID),
	).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("SSH connection was not found")
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(nullableString(current)) != expected {
		return errors.New("SSH host fingerprint changed; reload the connection before trusting it")
	}
	return errors.New("SSH host fingerprint could not be updated")
}

func loadEffectiveSSHFingerprint(
	database *sql.DB,
	nodeID string,
	columns map[string]struct{},
) (string, error) {
	parentExpression := "NULL"
	if _, ok := columns["ParentId"]; ok {
		parentExpression = "ParentId"
	}
	currentID := normalizeID(nodeID)
	seen := make(map[string]struct{})
	for currentID != "" {
		if _, duplicate := seen[currentID]; duplicate {
			return "", errors.New("SSH connection tree contains a cycle")
		}
		seen[currentID] = struct{}{}

		var parentID, fingerprint sql.NullString
		err := database.QueryRow(
			"SELECT "+parentExpression+", SshKnownHostFingerprint FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
			currentID,
		).Scan(&parentID, &fingerprint)
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("SSH connection was not found")
		}
		if err != nil {
			return "", err
		}
		if value := strings.TrimSpace(nullableString(fingerprint)); value != "" {
			return value, nil
		}
		currentID = normalizeID(nullableString(parentID))
	}
	return "", nil
}

func normalizeSSHFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("fingerprint must use the SHA256 format")
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(digest) != 32 {
		return "", errors.New("fingerprint is not a valid SHA256 fingerprint")
	}
	return value, nil
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

func safeSftpError(err error) string {
	if err == nil {
		return "SFTP operation failed"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "SFTP operation failed"
	}
	if len(message) > 4096 {
		return message[:4096]
	}
	return message
}
