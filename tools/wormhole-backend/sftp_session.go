package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Each tab owns its subsystem. Only the authenticated transport and its route
// are shared, so closing the shell cannot interrupt a file transfer.
type sshSharedTransport struct {
	mu      sync.Mutex
	client  *ssh.Client
	tunnel  *tunnelRuntime
	refs    int
	opening int
}

func (transport *sshSharedTransport) retain() bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.refs == 0 {
		return false
	}
	transport.refs++
	return true
}

func (transport *sshSharedTransport) release() {
	transport.mu.Lock()
	if transport.refs == 0 {
		transport.mu.Unlock()
		return
	}
	transport.refs--
	last := transport.refs == 0
	transport.mu.Unlock()
	if last {
		if transport.client != nil {
			_ = transport.client.Close()
		}
		if transport.tunnel != nil {
			transport.tunnel.close()
		}
	}
}

func (server *sshServer) openSharedSftp(command sshWireCommand) {
	if command.Mode != "sftp" || command.SourceSessionID == command.SessionID {
		server.writeError(command.SessionID, "invalid shared SFTP session")
		return
	}
	server.mu.Lock()
	source := server.sessions[command.SourceSessionID]
	state := server.lifecycles[command.SourceSessionID]
	if source == nil || state == nil || source.transport == nil || source.isClosed() ||
		server.lifecycles[command.SessionID] != nil || !source.transport.retain() {
		server.mu.Unlock()
		server.writeError(command.SessionID, "source SSH connection is unavailable")
		return
	}
	// Credential material remains exclusively in the Go reconnect state.
	saved := state.commandSnapshot()
	saved.SessionID, saved.Mode, saved.SourceSessionID = command.SessionID, "sftp", ""
	saved.TerminalStream = false
	ctx, cancel := context.WithCancel(context.Background())
	next := &sshReconnectState{command: saved}
	server.lifecycles[command.SessionID] = next
	server.pending[command.SessionID] = cancel
	server.mu.Unlock()
	go func() {
		client, err := newSharedSftpClient(ctx, source)
		if err != nil {
			source.transport.release()
			server.finishInitialFailure(next, nil, &sshWireEvent{Type: "error", SessionID: command.SessionID, Error: safeSSHError(err)})
			return
		}
		native := &sshNativeSession{id: command.SessionID, server: server, client: source.client,
			fingerprint: source.fingerprint, sftpEditRoute: source.editRoute(), transport: source.transport, sftpOnly: true, sftpClient: client, done: make(chan struct{}), mcpSession: source.mcpSession}
		native.mcpSession.ID = command.SessionID
		if !server.promote(command.SessionID, native, next) {
			native.close(false)
			return
		}
		info := source.mcpSession
		if !server.publishConnected(command.SessionID, native, sshWireEvent{Type: "connected", SessionID: command.SessionID, Host: info.Host, Port: info.Port, Username: info.Username, Fingerprint: source.fingerprint}) {
			native.close(false)
			return
		}
		native.start()
	}()
}

var errSftpTreeBusy = errors.New("too many directory tree requests; retry shortly")

func (server *sshServer) sftpTreeList(command sshWireCommand) {
	native := server.session(command.SessionID)
	writeFailure := func(err error) {
		if command.Pane == "local" {
			server.writeSftpLocalError(command.SessionID, command.RequestID, command.Path, err)
		} else {
			server.writeSftpRequestError(command.SessionID, command.RequestID, safeSftpError(err), command.Path)
		}
	}
	if native == nil {
		writeFailure(errSSHSessionClosed)
		return
	}
	if command.Pane != "local" && command.Pane != "remote" {
		writeFailure(errors.New("invalid tree pane"))
		return
	}
	native.sftpMu.Lock()
	if native.treeRequests >= 4 {
		native.sftpMu.Unlock()
		writeFailure(errSftpTreeBusy)
		return
	}
	client, generation := native.sftpClient, native.sftpGeneration
	native.treeRequests++
	native.sftpMu.Unlock()
	go func() {
		defer func() { native.sftpMu.Lock(); native.treeRequests--; native.sftpMu.Unlock() }()
		var entries []sshSftpEntry
		var truncated bool
		var path string
		var err error
		if command.Pane == "local" {
			path, err = normalizeLocalPath(command.Path)
			if err == nil {
				entries, truncated, err = readLocalDirectory(path)
			}
		} else {
			path, err = normalizeSftpPath(command.Path)
			if err == nil && client == nil {
				err = errSSHSftpClosed
			}
			if err == nil {
				path, entries, truncated, err = readSftpDirectory(client, path)
			}
		}
		if err != nil {
			writeFailure(err)
			return
		}
		native.sftpMu.Lock()
		current := generation == native.sftpGeneration && !native.sftpClosed
		native.sftpMu.Unlock()
		if !current || native.isClosed() {
			writeFailure(errSSHSftpClosed)
			return
		}
		directories := make([]sshSftpEntry, 0)
		for _, entry := range entries {
			if entry.IsDirectory {
				directories = append(directories, entry)
			}
		}
		kind := "sftp.ready"
		if command.Pane == "local" {
			kind = "sftp.local.ready"
		}
		server.output.write(sshWireEvent{Type: kind, SessionID: native.id, RequestID: command.RequestID, Pane: command.Pane, Path: path, Entries: directories, Truncated: truncated})
	}()
}

func newSharedSftpClient(ctx context.Context, source *sshNativeSession) (*sftp.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	transport := source.transport
	transport.mu.Lock()
	if transport.opening >= 4 {
		transport.mu.Unlock()
		return nil, errors.New("too many pending SFTP subsystems")
	}
	transport.opening++
	transport.mu.Unlock()
	type result struct {
		client *sftp.Client
		err    error
	}
	ready := make(chan result)
	go func() {
		// SSH channel-open itself has no cancellation API. Keep that work bounded;
		// once a channel exists, cancellation closes only this SSH session, including
		// a stalled subsystem request or SFTP version handshake.
		defer func() { transport.mu.Lock(); transport.opening--; transport.mu.Unlock() }()
		session, err := source.client.NewSession()
		var client *sftp.Client
		if err == nil {
			stop := context.AfterFunc(ctx, func() { _ = session.Close() })
			if err = ctx.Err(); err == nil {
				err = session.RequestSubsystem("sftp")
			}
			if err == nil {
				var input io.Reader
				var output io.WriteCloser
				input, err = session.StdoutPipe()
				if err == nil {
					output, err = session.StdinPipe()
				}
				if err == nil {
					client, err = sftp.NewClientPipe(input, &sftpSessionWriter{WriteCloser: output, session: session})
				}
			}
			stop()
			if err != nil {
				_ = session.Close()
			}
		}
		select {
		case ready <- result{client, err}:
		case <-ctx.Done():
			if client != nil {
				_ = client.Close()
			}
		}
	}()
	select {
	case value := <-ready:
		if err := ctx.Err(); err != nil {
			if value.client != nil {
				_ = value.client.Close()
			}
			return nil, err
		}
		return value.client, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type sftpSessionWriter struct {
	io.WriteCloser
	session *ssh.Session
}

func (writer *sftpSessionWriter) Close() error {
	err := writer.WriteCloser.Close()
	_ = writer.session.Close()
	return err
}
