package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func sealedSFTPFixture(t *testing.T, hooks ...func()) (sealedSSHTestChild, *sshNativeSession, string) {
	t.Helper()
	handlers := sftp.InMemHandler()
	client := newSftpSSHTestClient(t, &handlers, hooks...)
	native := &sshNativeSession{client: client, sftpOnly: true, done: make(chan struct{}), transport: &sshSharedTransport{client: client, refs: 1}}
	b := sealedSSHFixtureBinding()
	child := startSealedSSHTestChild(t, func(_ context.Context, target sshTarget, _, _ uint16) (*sshNativeSession, string, error) {
		if target.password != "sealed-password" || target.host != b.Host {
			t.Error("lost sealed target")
		}
		return native, sealedSSHFixturePayload().Fingerprint, nil
	})
	child.send(t, sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload()))
	waitSealedSFTPEvent(t, child, "connected", "")
	return child, native, b.SessionID
}

func waitSealedSFTPEvent(t *testing.T, child sealedSSHTestChild, kind, requestID string) sshWireEvent {
	t.Helper()
	for {
		var event sshWireEvent
		if json.Unmarshal(child.line(t), &event) != nil {
			t.Fatal("invalid event")
		}
		if event.Type == kind && (requestID == "" || event.RequestID == requestID) {
			return event
		}
		if event.Error != "" {
			t.Fatalf("unexpected SFTP error: %s", event.Error)
		}
	}
}

func sendSealedSFTP(t *testing.T, child sealedSSHTestChild, id string, command map[string]any) {
	t.Helper()
	command["sessionId"] = id
	child.send(t, vaultInput(t, command))
}

func TestSealedSFTPFilesAndTransfers(t *testing.T) {
	child, native, id := sealedSFTPFixture(t)
	defer child.input.Close()
	send := func(command map[string]any) { sendSealedSFTP(t, child, id, command) }
	send(map[string]any{"type": "sftp-open", "request_id": "open"})
	if event := waitSealedSFTPEvent(t, child, "sftp.ready", "open"); event.Error != "" || event.Path != "/" {
		t.Fatal(event)
	}
	directory := t.TempDir()
	content := []byte("file-transfer-payload")
	if err := os.WriteFile(filepath.Join(directory, "source"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	send(map[string]any{"type": "sftp-local-list", "path": directory, "request_id": "local"})
	if event := waitSealedSFTPEvent(t, child, "sftp.local.ready", "local"); len(event.Entries) != 1 {
		t.Fatal(event)
	}
	send(map[string]any{"type": "sftp-operation", "pane": "remote", "path": "/folder", "operation": "mkdir", "request_id": "mkdir"})
	if event := waitSealedSFTPEvent(t, child, "sftp.operation", "mkdir"); event.Error != "" {
		t.Fatal(event)
	}
	send(map[string]any{"type": "sftp-tree-list", "pane": "remote", "path": "/", "request_id": "tree"})
	if event := waitSealedSFTPEvent(t, child, "sftp.ready", "tree"); len(event.Entries) != 1 || event.Entries[0].Name != "folder" {
		t.Fatal(event)
	}
	transfer := func(direction, source, destination, name, transferID string) {
		send(map[string]any{"type": "sftp-transfer", "transfer_id": transferID, "direction": direction, "destination_path": destination, "items": []any{map[string]any{"source_path": source, "name": name, "is_directory": false, "size": len(content)}}})
		for {
			event := waitSealedSFTPEvent(t, child, "sftp.transfer", "")
			if event.Error != "" || event.TransferState == "batch-failed" {
				t.Fatal(event)
			}
			if event.TransferState == "batch-completed" {
				break
			}
		}
	}
	transfer("local-to-remote", filepath.Join(directory, "source"), "/folder", "uploaded", "upload")
	send(map[string]any{"type": "sftp-list", "path": "/folder", "request_id": "list"})
	if event := waitSealedSFTPEvent(t, child, "sftp.ready", "list"); len(event.Entries) != 1 || event.Entries[0].Name != "uploaded" {
		t.Fatal(event)
	}
	transfer("remote-to-local", "/folder/uploaded", directory, "downloaded", "download")
	got, err := os.ReadFile(filepath.Join(directory, "downloaded"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("download did not preserve bytes", err)
	}
	send(map[string]any{"type": "sftp-operation", "pane": "remote", "path": "/folder/uploaded", "destination_path": "/folder/renamed", "operation": "rename", "request_id": "rename"})
	if event := waitSealedSFTPEvent(t, child, "sftp.operation", "rename"); event.Error != "" {
		t.Fatal(event)
	}
	send(map[string]any{"type": "sftp-close"})
	waitSealedSFTPEvent(t, child, "sftp.closed", "")
	send(map[string]any{"type": "sftp-open", "request_id": "reopen"})
	waitSealedSFTPEvent(t, child, "sftp.ready", "reopen")
	send(map[string]any{"type": "app-lock"})
	if err := child.wait(t); err != nil || !native.isClosed() {
		t.Fatal("lock did not retire child", err)
	}
}

func TestSealedSFTPCancellationJoinsTransfers(t *testing.T) {
	for _, stop := range []string{"app-lock", "eof", "foreign-session", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			child, native, id := sealedSFTPFixture(t)
			defer child.input.Close()
			send := func(command map[string]any) { sendSealedSFTP(t, child, id, command) }
			send(map[string]any{"type": "sftp-open", "request_id": "open"})
			waitSealedSFTPEvent(t, child, "sftp.ready", "open")
			directory := t.TempDir()
			for _, name := range []string{"source", "destination"} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			send(map[string]any{"type": "sftp-transfer", "transfer_id": "blocked", "direction": "local-to-local", "destination_path": directory, "items": []any{map[string]any{"source_path": filepath.Join(directory, "source"), "name": "destination", "is_directory": false, "size": 6}}})
			waitSealedSFTPEvent(t, child, "sftp.conflict", "")
			switch stop {
			case "eof":
				child.input.Close()
			case "foreign-session":
				child.send(t, vaultInput(t, map[string]any{"type": "sftp-close", "sessionId": "another"}))
			case "cancel":
				send(map[string]any{"type": "sftp-transfer-cancel", "transfer_id": "blocked"})
				for {
					if waitSealedSFTPEvent(t, child, "sftp.transfer", "").TransferState == "batch-cancelled" {
						break
					}
				}
				send(map[string]any{"type": "close"})
			default:
				send(map[string]any{"type": stop})
			}
			err := child.wait(t)
			if (err != nil) != (stop == "foreign-session") {
				t.Fatal("unexpected shutdown", err)
			}
			native.server.transferMu.Lock()
			count := len(native.server.transfers)
			native.server.transferMu.Unlock()
			if count != 0 || !native.isClosed() {
				t.Fatal("work survived child exit")
			}
			got, err := os.ReadFile(filepath.Join(directory, "destination"))
			if err != nil || string(got) != "destination" {
				t.Fatal("cancelled transfer replaced destination", err)
			}
		})
	}
}

func TestSealedSFTPWorkBoundsAndStop(t *testing.T) {
	server := newSSHTestServer(&synchronizedBuffer{})
	server.sftpWork = &sftpWorkGroup{}
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	for i := 0; i < sealedSFTPWorkLimit; i++ {
		if !server.startSftpWork(func() { <-release }) {
			t.Fatal("early limit")
		}
	}
	if server.startSftpWork(func() { t.Error("overflow ran") }) {
		t.Fatal("unbounded workers")
	}
	server.sftpWork.stop()
	unblock()
	server.sftpWork.wg.Wait()
	if server.sftpWork.active != 0 || server.startSftpWork(func() { t.Error("closed work ran") }) {
		t.Fatal("work group reopened")
	}
	// Legacy callers keep their established behavior.
	server.sftpWork = nil
	done := make(chan struct{})
	if !server.startSftpWork(func() { close(done) }) {
		t.Fatal("legacy work rejected")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("legacy work not scheduled")
	}
}

func TestSealedSFTPOverflowReportsErrors(t *testing.T) {
	output := &synchronizedBuffer{}
	server := newSSHTestServer(output)
	server.sftpWork = &sftpWorkGroup{active: sealedSFTPWorkLimit}
	handlers := sftp.InMemHandler()
	client := newSftpReviewRequestClient(t, handlers)
	native := &sshNativeSession{id: "session", server: server, sftpClient: client, done: make(chan struct{})}
	server.sessions[native.id] = native
	defer native.close(false)
	for _, command := range []sshWireCommand{
		{Type: "sftp-list", Path: "/", RequestID: "list"},
		{Type: "sftp-local-list", Path: t.TempDir(), RequestID: "local"},
		{Type: "sftp-operation", Path: "/file", Pane: "remote", Operation: "file", RequestID: "operation"},
		{Type: "sftp-tree-list", Path: "/", Pane: "remote", RequestID: "tree"},
	} {
		command.SessionID = native.id
		server.handle(command)
		if event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == command.RequestID }); event.Error == "" {
			t.Fatal("overflow not reported", event)
		}
	}
	if native.treeRequests != 0 {
		t.Fatal("rejected tree request leaked capacity")
	}
	native.sftpClient = nil
	native.startSftpOpen("open")
	waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "open" && event.Error != "" })
	if native.sftpOpening {
		t.Fatal("rejected opening stayed busy")
	}
	native.sftpClient = client
	for i := 0; i < sealedSFTPTransferLimit; i++ {
		server.transfers[fmt.Sprint(i)] = &sshSftpTransfer{}
	}
	command := sshWireCommand{SessionID: native.id, TransferID: "overflow", Direction: "local-to-local", DestinationPath: t.TempDir(), Items: []sshSftpTransferItem{{SourcePath: filepath.Join(t.TempDir(), "source"), Name: "file"}}}
	server.sftpTransfer(command)
	if event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.TransferID == "overflow" }); event.TransferState != "batch-failed" || event.Error == "" {
		t.Fatal(event)
	}
	if len(server.transfers) != sealedSFTPTransferLimit {
		t.Fatal("overflow admitted")
	}
}

func TestSealedSFTPLocalListingErrorsAndLateCompletion(t *testing.T) {
	directory := t.TempDir()
	(&sshNativeSession{}).startLocalList(directory, "no-server")
	output := &synchronizedBuffer{}
	server := newSSHTestServer(output)
	server.sftpWork = &sftpWorkGroup{}
	server.localQuickPaths.build = func() []sshSftpQuickPath { return nil }
	native := &sshNativeSession{id: "local", server: server, done: make(chan struct{})}
	server.sessions[native.id] = native
	defer native.close(false)
	for _, path := range []string{"relative", filepath.Join(directory, "missing")} {
		native.startLocalList(path, path)
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == path })
		if event.Type != "sftp.local.error" || event.Error == "" {
			t.Fatal("local error not returned", event)
		}
	}
	server.sftpWork.wg.Wait()
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	server.localQuickPaths = localQuickPathCache{build: func() []sshSftpQuickPath { close(entered); <-release; return nil }}
	native.startLocalList(directory, "late")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("listing did not start")
	}
	server.sftpWork.stop()
	native.close(false)
	before := output.Len()
	unblock()
	server.sftpWork.wg.Wait()
	if output.Len() != before {
		t.Fatal("late listing was published after close")
	}
}
