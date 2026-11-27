package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sealedEditServer(t *testing.T, options sealedSFTPEditOptions, workspace, node string) *sshServer {
	t.Helper()
	server := newSSHTestServer(io.Discard)
	server.sealedEdits = &sealedSFTPEdits{options: options, workspaceID: workspace, nodeID: node, stop: make(chan struct{})}
	t.Cleanup(server.closeSealedEdits)
	return server
}

func sealedEditOptions(t *testing.T) sealedSFTPEditOptions {
	t.Helper()
	return sealedSFTPEditOptions{UserDataPath: t.TempDir(), SettingsPath: filepath.Join(t.TempDir(), "settings.json")}
}

func TestSealedSFTPEditScopeAndLease(t *testing.T) {
	options, workspace, node := sealedEditOptions(t), uuid.NewString(), uuid.NewString()
	first := sealedEditServer(t, options, workspace, node)
	if err := first.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(options.UserDataPath, "vault-sftp-edit", workspace, node)
	if first.electronUserDataPath != expected {
		t.Fatal("working copies escaped the authenticated workspace/node scope")
	}
	if err := first.ensureSftpEdits(); err != nil {
		t.Fatal("owner could not reuse its lease", err)
	}
	second := sealedEditServer(t, options, workspace, node)
	if err := second.ensureSftpEdits(); !errors.Is(err, errSealedSFTPEditsUnavailable) {
		t.Fatal("concurrent editor owner admitted", err)
	}
	for _, pair := range [][2]string{{uuid.NewString(), node}, {workspace, uuid.NewString()}} {
		other := sealedEditServer(t, options, pair[0], pair[1])
		if err := other.ensureSftpEdits(); err != nil || other.electronUserDataPath == expected {
			t.Fatal("independent scope blocked or shared", err)
		}
	}
	first.closeSealedEdits()
	first.closeSealedEdits()
	if err := first.ensureSftpEdits(); err == nil {
		t.Fatal("closed editor owner revived")
	}
	if err := second.ensureSftpEdits(); err != nil {
		t.Fatal("busy scope could not be retried after retirement", err)
	}
}

func TestSealedSFTPEditInvalidScope(t *testing.T) {
	for _, mutate := range []func(*sealedSFTPEdits){
		func(e *sealedSFTPEdits) { e.options.UserDataPath = "relative" },
		func(e *sealedSFTPEdits) { e.options.SettingsPath = "" },
		func(e *sealedSFTPEdits) { e.workspaceID = "../workspace" },
		func(e *sealedSFTPEdits) { e.nodeID = "../node" },
		func(e *sealedSFTPEdits) {
			e.options.UserDataPath = filepath.Join(e.options.UserDataPath, "missing", "directory")
		},
	} {
		s := sealedEditServer(t, sealedEditOptions(t), uuid.NewString(), uuid.NewString())
		mutate(s.sealedEdits)
		if err := s.ensureSftpEdits(); !errors.Is(err, errSealedSFTPEditsUnavailable) {
			t.Fatal("unsafe scope accepted", err)
		}
	}
	for _, component := range []string{"vault-sftp-edit", ".owner.lock"} {
		t.Run(component, func(t *testing.T) {
			options, workspace, node := sealedEditOptions(t), uuid.NewString(), uuid.NewString()
			root := filepath.Join(options.UserDataPath, "vault-sftp-edit")
			if component == ".owner.lock" {
				root = filepath.Join(root, workspace, node, component)
				if err := os.MkdirAll(root, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(root, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			s := sealedEditServer(t, options, workspace, node)
			if err := s.ensureSftpEdits(); !errors.Is(err, errSealedSFTPEditsUnavailable) {
				t.Fatal("non-directory scope or non-file lock accepted", err)
			}
		})
	}
}

func TestSealedSFTPEditSettingsUseTrustedPath(t *testing.T) {
	options := sealedEditOptions(t)
	s := sealedEditServer(t, options, uuid.NewString(), uuid.NewString())
	settings := defaultSftpEditorSettings()
	settings.MaxFileSize = 12345
	settings.DefaultEditor = "system"
	if err := os.WriteFile(options.SettingsPath, vaultInput(t, map[string]any{"fileTransfer": settings}), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.readEditSettings()
	if err != nil || got.MaxFileSize != 12345 || got.DefaultEditor != "system" {
		t.Fatal("sealed owner used legacy database/cwd settings", err)
	}
	if err := os.Remove(options.SettingsPath); err != nil {
		t.Fatal(err)
	}
	got, err = s.readEditSettings()
	if err != nil || got.MaxFileSize != defaultSftpEditorSettings().MaxFileSize {
		t.Fatal(err)
	}
	if err := os.Mkdir(options.SettingsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureSftpEdits(); err == nil {
		t.Fatal("unreadable settings accepted")
	}
}

func TestSealedSFTPEditRetirementAndRecovery(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	options, workspace, node := sealedEditOptions(t), uuid.NewString(), uuid.NewString()
	server.sealedEdits = &sealedSFTPEdits{options: options, workspaceID: workspace, nodeID: node, stop: make(chan struct{})}
	server.editOnce = sync.Once{}
	t.Cleanup(server.closeSealedEdits)
	if err := server.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	native.sftpEditRoute = sealedSFTPEditRoute(nil)
	record := editFixtureRecord(t, server, native, remote)
	if record.View.NodeID != node {
		t.Fatal("authenticated node identity lost")
	}
	record.mu.Lock()
	if err := os.WriteFile(record.localPath(), []byte("pending changes"), 0o600); err != nil {
		t.Fatal(err)
	}
	record.mu.Unlock()
	// A lock retires network resources before joining file watchers.
	native.close(false)
	stopped := make(chan struct{})
	go func() { server.sealedEdits.watchers.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnected session kept retrying uploads")
	}
	server.closeSealedEdits()
	record.mu.Lock()
	if record.watching || !record.View.Recovered {
		t.Fatal("retirement left a live watcher")
	}
	record.mu.Unlock()
	server.startEditWatcher(record) // admission stays closed
	server.sealedEdits.watchers.Wait()
	reopened := sealedEditServer(t, options, workspace, node)
	if err := reopened.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	views := reopened.sftpEditSnapshot("new-session")
	if len(views) != 1 || !views[0].Recovered || views[0].NodeID != node {
		t.Fatal(views)
	}
	copy := reopened.edits[record.View.ID]
	contents, err := os.ReadFile(copy.localPath())
	if err != nil || string(contents) != "pending changes" {
		t.Fatal("retirement discarded unsent edits", err)
	}
	if err := reopened.runSftpEdit(sshWireCommand{SessionID: "missing", EditID: copy.View.ID, Operation: "recover"}); err == nil {
		t.Fatal("recovery started without an authenticated session")
	}
}

func TestSealedSFTPEditRouteAndSharedIdentity(t *testing.T) {
	route := routedSSHTestBinding()
	expected := sealedSFTPEditRoute(&route)
	if expected == "direct" || sealedSFTPEditRoute(nil) != "direct" {
		t.Fatal("route collapsed to direct")
	}
	changed := route
	changed.SessionID, changed.RequestID = uuid.NewString(), uuid.NewString()
	changed.Epoch++
	changed.RowVersion++
	if sealedSFTPEditRoute(&changed) != expected {
		t.Fatal("reconnect changed logical route")
	}
	for _, mutate := range []func(){
		func() { changed.FileID = uuid.NewString() },
		func() { changed.TunnelConfigID = uuid.NewString() },
		func() { changed.Kind++ },
		func() { changed.ConfigurationVersion++ },
	} {
		changed = route
		mutate()
		if sealedSFTPEditRoute(&changed) == expected {
			t.Fatal("different route/configuration accepted")
		}
	}
	child, source, id := sealedSFTPFixture(t)
	defer child.input.Close()
	if source.mcpSession.Host != sealedSSHFixtureBinding().Host || source.mcpSession.Username != "alice" || source.mcpSession.ID != id || source.editRoute() != "direct" {
		t.Fatal("primary lost authenticated file-edit identity")
	}
	// Publish immutable route state before another subsystem is requested.
	source.sftpEditRoute = expected
	first, second := uuid.NewString(), uuid.NewString()
	for _, pair := range [][2]string{{id, first}, {first, second}} {
		sendSealedSFTP(t, child, pair[0], map[string]any{"type": "sftp-share", "newSessionId": pair[1]})
		waitSealedMemberEvent(t, child, "connected", pair[1])
		shared := source.server.session(pair[1])
		if shared.mcpSession.ID != pair[1] || shared.mcpSession.Host != source.mcpSession.Host || shared.mcpSession.Port != source.mcpSession.Port || shared.mcpSession.Username != source.mcpSession.Username || shared.editRoute() != expected {
			t.Fatal("shared tab lost identity or configuration binding")
		}
		record := &sftpEditRecord{Host: shared.mcpSession.Host, Port: shared.mcpSession.Port, Username: shared.mcpSession.Username, Fingerprint: shared.fingerprint, Route: expected}
		if !record.matches(shared) {
			t.Fatal("matching shared session rejected")
		}
		record.Route = "direct"
		if record.matches(shared) {
			t.Fatal("VPN recovery allowed over direct route")
		}
	}
	sendSealedSFTP(t, child, id, map[string]any{"type": "app-lock"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
}

func TestSealedSFTPEditContextIsBoundToHandoff(t *testing.T) {
	options := sealedEditOptions(t)
	var native *sshNativeSession
	b := sealedSSHFixtureBinding()
	child := startSealedSSHTestChild(t, func(context.Context, sshTarget, uint16, uint16) (*sshNativeSession, string, error) {
		native = &sshNativeSession{sftpOnly: true, done: make(chan struct{})}
		return native, sealedSSHFixturePayload().Fingerprint, nil
	}, options)
	child.send(t, sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload()))
	waitSealedSFTPEvent(t, child, "connected", "")
	context := native.server.sealedEdits
	if context.workspaceID != b.WorkspaceID || context.nodeID != b.NodeID || context.options != options {
		t.Fatal("unbound editor context")
	}
	sendSealedSFTP(t, child, b.SessionID, map[string]any{"type": "app-lock"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
	select {
	case <-context.stop:
	case <-time.After(time.Second):
		t.Fatal("editor lifecycle survived vault lock")
	}
}
