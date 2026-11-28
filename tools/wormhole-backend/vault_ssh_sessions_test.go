package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func waitSealedMemberEvent(t *testing.T, child sealedSSHTestChild, kind, id string) sshWireEvent {
	t.Helper()
	for {
		var event sshWireEvent
		if json.Unmarshal(child.line(t), &event) != nil {
			t.Fatal("invalid event")
		}
		if event.Type == kind && event.SessionID == id {
			return event
		}
		if event.Error != "" {
			t.Fatal("unexpected error", event)
		}
	}
}

func TestSealedSSHSharedSFTPTransportLifetime(t *testing.T) {
	child, source, id := sealedSFTPFixture(t)
	defer child.input.Close()
	first, second := uuid.NewString(), uuid.NewString()
	share := func(from, to string) {
		sendSealedSFTP(t, child, from, map[string]any{"type": "sftp-share", "newSessionId": to})
		event := waitSealedMemberEvent(t, child, "connected", to)
		if event.Username != "alice" || event.Fingerprint != source.fingerprint {
			t.Fatal("shared identity changed", event)
		}
	}
	share(id, first)
	sendSealedSFTP(t, child, id, map[string]any{"type": "close"})
	waitSealedMemberEvent(t, child, "closed", id)
	if !source.isClosed() {
		t.Fatal("shell remained open")
	}
	share(first, second)
	sendSealedSFTP(t, child, first, map[string]any{"type": "close"})
	waitSealedMemberEvent(t, child, "closed", first)
	// A retired source cannot open another tab, but cannot destroy a healthy sibling either.
	rejected := uuid.NewString()
	sendSealedSFTP(t, child, id, map[string]any{"type": "sftp-share", "newSessionId": rejected})
	waitSealedMemberEvent(t, child, "error", rejected)
	waitSealedMemberEvent(t, child, "closed", rejected)
	sendSealedSFTP(t, child, second, map[string]any{"type": "sftp-open", "request_id": "list"})
	if event := waitSealedMemberEvent(t, child, "sftp.ready", second); event.Path != "/" {
		t.Fatal(event)
	}
	source.transport.mu.Lock()
	refs := source.transport.refs
	source.transport.mu.Unlock()
	if refs != 1 {
		t.Fatalf("transport refs = %d", refs)
	}
	// Late valid commands to retired IDs are inert; identity reuse is prohibited.
	sendSealedSFTP(t, child, first, map[string]any{"type": "sftp-close"})
	sendSealedSFTP(t, child, second, map[string]any{"type": "close"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
	source.transport.mu.Lock()
	refs = source.transport.refs
	source.transport.mu.Unlock()
	if refs != 0 {
		t.Fatal("last tab retained transport")
	}
}

func TestSealedSSHSharedOpeningCancellation(t *testing.T) {
	for _, stop := range []string{"close", "app-lock", "eof"} {
		t.Run(stop, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			child, source, id := sealedSFTPFixture(t, func() { close(entered); <-release })
			defer child.input.Close()
			shared := uuid.NewString()
			sendSealedSFTP(t, child, id, map[string]any{"type": "sftp-share", "newSessionId": shared})
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("subsystem did not start")
			}
			if stop == "eof" {
				child.input.Close()
			} else {
				sendSealedSFTP(t, child, shared, map[string]any{"type": stop})
			}
			if stop == "close" {
				waitSealedMemberEvent(t, child, "closed", shared)
				if source.isClosed() {
					t.Fatal("cancelled opener closed source")
				}
				sendSealedSFTP(t, child, id, map[string]any{"type": "close"})
			}
			if err := child.wait(t); err != nil {
				t.Fatal(err)
			}
			unblock()
			for raw := range child.lines {
				var event sshWireEvent
				_ = json.Unmarshal(raw, &event)
				if event.Type == "connected" && event.SessionID == shared {
					t.Fatal("late opener revived cancelled tab")
				}
			}
		})
	}
}

func TestSealedSSHSharedSubsystemFailureIsLocal(t *testing.T) {
	child, source, id := sealedSFTPFixture(t)
	defer child.input.Close()
	// A closed SSH client returns an actual channel-open error, with no credential reload.
	_ = source.client.Close()
	shared := uuid.NewString()
	sendSealedSFTP(t, child, id, map[string]any{"type": "sftp-share", "newSessionId": shared})
	event := waitSealedMemberEvent(t, child, "error", shared)
	if event.Error != "sealed SFTP subsystem could not open" {
		t.Fatal("unredacted failure", event)
	}
	waitSealedMemberEvent(t, child, "closed", shared)
	sendSealedSFTP(t, child, id, map[string]any{"type": "close"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
}

func TestSealedSSHMemberStrictCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, files := uuid.NewString(), uuid.NewString()
	m := newSealedSSHMembers(ctx, cancel, newSSHTestServer(&synchronizedBuffer{}), id, false)
	m.entries[files] = &sealedSSHMember{sftpOnly: true}
	for _, kind := range []string{"sftp-open", "sftp-close", "close", "app-lock"} {
		if _, _, err := m.command(vaultInput(t, map[string]any{"type": kind, "sessionId": files})); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"input", "resize", "snapshot", "terminal-ack", "auto-sudo-cancel", "open", "sftp-edit"} {
		if _, _, err := m.command(vaultInput(t, map[string]any{"type": kind, "sessionId": files})); err == nil {
			t.Fatalf("file tab accepted %s", kind)
		}
	}
	for _, raw := range []string{
		`null`, `[]`, `{`, `{"type":"close","sessionId":"foreign"}`,
		fmt.Sprintf(`{"type":"sftp-share","sessionId":%q,"newSessionId":%q,"password":"injected"}`, id, uuid.NewString()),
		fmt.Sprintf(`{"type":"sftp-share","sessionId":%q,"newSessionId":%q}`, id, id),
		fmt.Sprintf(`{"type":"sftp-share","sessionId":%q,"newSessionId":"invalid"}`, id),
		fmt.Sprintf(`{"type":"sftp-share","sessionId":%q,"newSessionId":null}`, id),
		fmt.Sprintf(`{"type":"sftp-share","sessionId":%q,"newSessionId":%q,"newSessionId":%q}`, id, files, files),
	} {
		if _, _, err := m.command([]byte(raw)); err == nil {
			t.Fatal("unsafe member command", raw)
		}
	}
	c, retired, err := m.command(vaultInput(t, map[string]any{"type": "sftp-share", "sessionId": id, "newSessionId": uuid.NewString()}))
	if err != nil || retired || c.SourceSessionID != id || c.SessionID == id {
		t.Fatal("share contract", err)
	}
	m.entries[files].closed = true
	if _, retired, err := m.command(vaultInput(t, map[string]any{"type": "sftp-open", "sessionId": files})); err != nil || !retired {
		t.Fatal("retired command was not inert")
	}
}

func TestSealedSSHMemberAdmissionAndIdentityBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &synchronizedBuffer{}
	id := uuid.NewString()
	m := newSealedSSHMembers(ctx, cancel, newSSHTestServer(output), id, false)
	for _, source := range []string{id, "missing"} {
		command := sshWireCommand{SourceSessionID: source, SessionID: uuid.NewString()}
		if err := m.share(command); err != nil {
			t.Fatal(err)
		}
		if !m.entries[command.SessionID].closed || m.active != 1 {
			t.Fatal("rejected admission leaked a member")
		}
	}
	native := &sshNativeSession{done: make(chan struct{}), transport: &sshSharedTransport{refs: 1}}
	if !m.promote(id, native, sshWireEvent{Host: "host"}) {
		t.Fatal("root promotion")
	}
	if m.promote("missing", &sshNativeSession{}, sshWireEvent{}) {
		t.Fatal("unreserved native accepted")
	}
	m.nativeClosed(&sshNativeSession{id: id}) // stale callback cannot retire the current member
	if m.active != 1 {
		t.Fatal("foreign close retired owner")
	}
	m.active = sealedSSHSessionLimit
	if err := m.share(sshWireCommand{SourceSessionID: id, SessionID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if m.active != sealedSSHSessionLimit {
		t.Fatal("over-limit native launched")
	}
	m.active = 1
	if err := m.share(sshWireCommand{SourceSessionID: id, SessionID: id}); err == nil {
		t.Fatal("duplicate identity admitted")
	}
	for len(m.entries) < sealedSSHIdentityLimit {
		m.entries[uuid.NewString()] = &sealedSSHMember{closed: true}
	}
	if err := m.share(sshWireCommand{SourceSessionID: id, SessionID: uuid.NewString()}); err == nil {
		t.Fatal("identity history unbounded")
	}
	if !m.close(id) || !m.close(id) || !native.isClosed() {
		t.Fatal("last close failed")
	}
	if m.entries[id].native != nil || m.entries[id].cancel != nil {
		t.Fatal("retired identity retained native state")
	}
	m.nativeClosed(native)
	if m.active != 0 {
		t.Fatal("duplicate close decremented count")
	}
	if m.promote(id, &sshNativeSession{}, sshWireEvent{}) {
		t.Fatal("closed identity revived")
	}
	if err := m.share(sshWireCommand{SourceSessionID: id, SessionID: uuid.NewString()}); err == nil {
		t.Fatal("cancelled transport accepted member")
	}
	if strings.Contains(output.String(), "password") {
		t.Fatal("private material in events")
	}
	m.shutdown()
}
func TestSealedSFTPPrimaryAdmissionAndIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := uuid.NewString()
	m := newSealedSSHMembers(ctx, cancel, newSSHTestServer(&synchronizedBuffer{}), id, true)
	for _, kind := range []string{"input", "resize", "snapshot", "terminal-ack", "auto-sudo-cancel"} {
		if _, _, err := m.command(vaultInput(t, map[string]any{"type": kind, "sessionId": id})); err == nil {
			t.Fatal("SFTP accepted terminal command", kind)
		}
	}
	if _, _, err := m.command(vaultInput(t, map[string]any{"type": "sftp-open", "sessionId": id})); err != nil {
		t.Fatal(err)
	}
	identity := sshWireEvent{Host: "files.example", Port: 22, Username: "file-user", Fingerprint: "pin"}
	if !m.promote(id, &sshNativeSession{}, identity) || m.connected.Username != identity.Username || m.connected.Host != identity.Host {
		t.Fatal("SFTP source identity lost")
	}
}
