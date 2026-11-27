package main

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const sealedSSHSessionLimit = 32
const sealedSSHIdentityLimit = 1024

type sealedSSHMember struct {
	native          *sshNativeSession
	cancel          context.CancelFunc
	sftpOnly        bool
	closing, closed bool
}

// One credential handoff owns a transport, while each tab owns its subsystem.
// Retired identities remain reserved so late work can never target a reused tab.
type sealedSSHMembers struct {
	mu        sync.Mutex
	workers   sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	server    *sshServer
	entries   map[string]*sealedSSHMember
	active    int
	connected sshWireEvent
	primaryID string
}

func newSealedSSHMembers(ctx context.Context, cancel context.CancelFunc, server *sshServer, id string, sftpOnly bool) *sealedSSHMembers {
	m := &sealedSSHMembers{ctx: ctx, cancel: cancel, server: server, entries: map[string]*sealedSSHMember{id: {sftpOnly: sftpOnly}}, active: 1, primaryID: id}
	server.sealedClosed = m.nativeClosed
	return m
}

func (m *sealedSSHMembers) promote(id string, native *sshNativeSession, connected sshWireEvent) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	member := m.entries[id]
	if member == nil || member.closing || member.closed || m.ctx.Err() != nil {
		return false
	}
	native.id, native.server = id, m.server
	native.mcpSession = mcpSessionInfo{ID: id, Host: connected.Host, Port: connected.Port, Username: connected.Username, Status: "connected"}
	member.native = native
	if id == m.primaryID {
		m.connected = connected
	}
	m.server.mu.Lock()
	m.server.sessions[id] = native
	m.server.mu.Unlock()
	connected.Type, connected.SessionID = "connected", id
	m.server.output.write(connected)
	return true
}

func (m *sealedSSHMembers) nativeClosed(native *sshNativeSession) {
	m.mu.Lock()
	member := m.entries[native.id]
	if member == nil || member.native != native || member.closed {
		m.mu.Unlock()
		return
	}
	m.finishLocked(native.id, member)
	m.mu.Unlock()
}

func (m *sealedSSHMembers) finishLocked(id string, member *sealedSSHMember) {
	member.closed = true
	member.native = nil
	if member.cancel != nil {
		member.cancel()
		member.cancel = nil
	}
	m.active--
	m.server.output.write(sshWireEvent{Type: "closed", SessionID: id})
	if m.active == 0 {
		m.cancel()
	}
}

func (m *sealedSSHMembers) close(id string) bool {
	m.mu.Lock()
	member := m.entries[id]
	if !member.closed && !member.closing {
		member.closing = true
		if member.cancel != nil {
			member.cancel()
		}
		if member.native == nil {
			m.finishLocked(id, member)
		}
	}
	native := member.native
	m.mu.Unlock()
	if native != nil {
		native.close(true)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active == 0
}

func (m *sealedSSHMembers) command(raw []byte) (sshWireCommand, bool, error) {
	var header struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return sshWireCommand{}, false, vaultwire.ErrProtocol
	}
	m.mu.Lock()
	member := m.entries[header.SessionID]
	known, closed, sftpOnly := member != nil, false, false
	if known {
		closed, sftpOnly = member.closed || member.closing, member.sftpOnly
	}
	m.mu.Unlock()
	if !known {
		return sshWireCommand{}, false, vaultwire.ErrProtocol
	}
	if header.Type == "sftp-share" {
		var c sshWireCommand
		if decodeVaultObject(raw, map[string]any{"type": &c.Type, "sessionId": &c.SourceSessionID, "newSessionId": &c.SessionID}, "type", "sessionId", "newSessionId") != nil || !vaultCredentialID(c.SessionID) || c.SessionID == c.SourceSessionID {
			return sshWireCommand{}, false, vaultwire.ErrProtocol
		}
		return c, false, nil
	}
	c, err := decodeSealedSSHCommand(raw, header.SessionID)
	if err != nil {
		return c, false, err
	}
	if sftpOnly && c.Type != "close" && c.Type != "app-lock" && !isSealedSFTPCommand(c.Type) {
		return sshWireCommand{}, false, vaultwire.ErrProtocol
	}
	return c, closed, nil
}

func isSealedSFTPCommand(kind string) bool {
	switch kind {
	case "sftp-edit", "sftp-open", "sftp-close", "sftp-list", "sftp-local-list", "sftp-tree-list", "sftp-operation", "sftp-transfer", "sftp-transfer-decision", "sftp-transfer-cancel":
		return true
	default:
		return false
	}
}

func (m *sealedSSHMembers) share(c sshWireCommand) error {
	m.mu.Lock()
	source := m.entries[c.SourceSessionID]
	if m.entries[c.SessionID] != nil || len(m.entries) >= sealedSSHIdentityLimit || m.ctx.Err() != nil {
		m.mu.Unlock()
		return vaultwire.ErrProtocol
	}
	if source == nil || source.closed || source.closing || source.native == nil || source.native.transport == nil || source.native.isClosed() ||
		m.active >= sealedSSHSessionLimit || !source.native.transport.retain() {
		m.entries[c.SessionID] = &sealedSSHMember{closed: true, sftpOnly: true}
		m.server.writeError(c.SessionID, "source sealed SSH session is unavailable")
		m.server.output.write(sshWireEvent{Type: "closed", SessionID: c.SessionID})
		m.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	member := &sealedSSHMember{cancel: cancel, sftpOnly: true}
	m.entries[c.SessionID] = member
	m.active++
	nativeSource, connected := source.native, m.connected
	m.workers.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.workers.Done()
		defer cancel()
		client, err := newSharedSftpClient(ctx, nativeSource)
		if err != nil {
			nativeSource.transport.release()
			m.mu.Lock()
			if !member.closed {
				m.server.writeError(c.SessionID, "sealed SFTP subsystem could not open")
				m.finishLocked(c.SessionID, member)
			}
			m.mu.Unlock()
			return
		}
		native := &sshNativeSession{client: nativeSource.client, transport: nativeSource.transport, fingerprint: nativeSource.fingerprint, sftpEditRoute: nativeSource.sftpEditRoute, sftpOnly: true, sftpClient: client, done: make(chan struct{})}
		if !m.promote(c.SessionID, native, connected) {
			native.close(false)
			return
		}
		native.start()
	}()
	return nil
}

func (m *sealedSSHMembers) shutdown() {
	m.cancel()
	m.workers.Wait()
	m.mu.Lock()
	natives := make([]*sshNativeSession, 0, len(m.entries))
	for _, member := range m.entries {
		if member.native != nil {
			natives = append(natives, member.native)
		}
	}
	m.mu.Unlock()
	for _, native := range natives {
		native.close(false)
	}
}
