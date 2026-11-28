package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSealedSFTPEditCommandContract(t *testing.T) {
	id, edit := uuid.NewString(), uuid.NewString()
	cases := []map[string]any{
		{"operation": "list"}, {"operation": "prepare-close"}, {"operation": "finish-close", "decision": "keep"},
		{"operation": "start", "pane": "remote", "path": "/file"},
		{"operation": "start", "pane": "local", "path": filepath.Join(t.TempDir(), "file"), "editor_id": "auto", "allow_binary": false},
		{"operation": "start", "pane": "remote", "path": "/file", "editor_id": "system", "allow_binary": true},
		{"operation": "recover", "edit_id": edit}, {"operation": "reveal", "edit_id": edit},
		{"operation": "discard", "edit_id": edit, "decision": "discard"},
		{"operation": "reload", "edit_id": edit, "decision": "discard"},
		{"operation": "upload", "edit_id": edit}, {"operation": "stop", "edit_id": edit},
		{"operation": "upload", "edit_id": edit, "decision": "overwrite", "destination_path": "/other"},
		{"operation": "stop", "edit_id": edit, "decision": "overwrite", "destination_path": ""},
	}
	for _, packet := range cases {
		packet["type"], packet["sessionId"], packet["request_id"] = "sftp-edit", id, "request"
		raw := vaultInput(t, packet)
		if c, err := decodeSealedSSHCommand(raw, id); err != nil || c.Operation != packet["operation"] || c.SessionID != id {
			t.Fatal("valid editor command rejected", packet, err)
		}
		if _, err := decodeSealedSSHCommand(raw, uuid.NewString()); err == nil {
			t.Fatal("foreign session accepted")
		}
		for field := range packet {
			changed := cloneSFTPPacket(packet)
			changed[field] = nil
			if _, err := decodeSealedSSHCommand(vaultInput(t, changed), id); err == nil {
				t.Fatal("null field accepted", field)
			}
			duplicate := bytes.Replace(raw, []byte(`"`+field+`":`), []byte(`"`+field+`":null,"`+field+`":`), 1)
			if _, err := decodeSealedSSHCommand(duplicate, id); err == nil {
				t.Fatal("duplicate field accepted", field)
			}
		}
		for _, field := range []string{"workspaceId", "nodeId", "password", "settingsPath", "executable", "arguments", "electronUserDataPath", "route", "publicKey"} {
			changed := cloneSFTPPacket(packet)
			changed[field] = "injected"
			if _, err := decodeSealedSSHCommand(vaultInput(t, changed), id); err == nil {
				t.Fatal("injected authority accepted", field)
			}
		}
	}
	for _, partial := range []map[string]any{
		{"operation": "unknown"}, {"operation": "start"}, {"operation": "finish-close"},
		{"operation": "list", "edit_id": edit}, {"operation": "reveal", "edit_id": edit, "destination_path": "/other"},
		{"operation": "recover", "edit_id": "../outside"}, {"operation": "reload", "edit_id": edit, "decision": "overwrite"},
		{"operation": "finish-close", "decision": "discard"}, {"operation": "discard", "edit_id": edit, "decision": "keep"},
		{"operation": "start", "pane": "remote", "path": "relative"}, {"operation": "start", "pane": "invalid", "path": "/file"},
		{"operation": "start", "pane": "remote", "path": "/file", "editor_id": "bad\n"},
		{"operation": "start", "pane": "remote", "path": "/file", "editor_id": strings.Repeat("e", 129)},
		{"operation": "start", "pane": "remote", "path": "/file", "allow_binary": "true"},
		{"operation": "upload", "edit_id": edit, "decision": "discard"},
		{"operation": "upload", "edit_id": edit, "destination_path": "relative"},
		{"operation": "list", "request_id": ""},
	} {
		partial["type"], partial["sessionId"] = "sftp-edit", id
		if _, ok := partial["request_id"]; !ok {
			partial["request_id"] = "request"
		}
		if _, err := decodeSealedSSHCommand(vaultInput(t, partial), id); err == nil {
			t.Fatal("invalid command accepted", partial)
		}
	}
	if _, err := decodeSealedSFTPEdit([]byte("["), id); err == nil {
		t.Fatal("malformed command accepted")
	}
}

func TestSealedSFTPEditListingCannotHidePendingFiles(t *testing.T) {
	entry := sftpEditView{ID: uuid.NewString(), RemotePath: "/" + strings.Repeat("a", sshSftpMaxPathBytes-1), Pending: true}
	event := sshWireEvent{Type: "sftp.edit", Edits: []sftpEditView{entry}}
	if got := boundSealedSFTPEntries(event); len(got.Edits) != 1 || got.Error != "" {
		t.Fatal("small editor response rejected")
	}
	for i := 0; i < 256; i++ {
		event.Edits = append(event.Edits, entry)
	}
	got := boundSealedSFTPEntries(event)
	raw, err := json.Marshal(got)
	if err != nil || len(raw) >= vaultwire.MaxFrameBytes || len(got.Edits) != 0 || got.Error == "" {
		t.Fatal("oversized response did not fail closed")
	}
	if len(event.Edits) != 257 {
		t.Fatal("caller snapshot mutated")
	}
}

func TestSealedSFTPEditAuthenticatedProcess(t *testing.T) {
	_, native, remote := newSftpEditFixture(t)
	native.sftpOnly = true
	options := sealedEditOptions(t)
	b := sealedSSHFixtureBinding()
	child := startSealedSSHTestChild(t, func(context.Context, sshTarget, uint16, uint16) (*sshNativeSession, string, error) {
		return native, sealedSSHFixturePayload().Fingerprint, nil
	}, options)
	child.send(t, sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload()))
	waitSealedSFTPEvent(t, child, "connected", "")
	defer child.input.Close()
	send := func(request string, fields map[string]any) sshWireEvent {
		fields["type"], fields["request_id"] = "sftp-edit", request
		sendSealedSFTP(t, child, b.SessionID, fields)
		return waitSealedSFTPEvent(t, child, "sftp.edit", request)
	}
	opened := send("start", map[string]any{"operation": "start", "pane": "remote", "path": remote})
	if opened.Error != "" || len(opened.Edits) != 1 || opened.Edits[0].NodeID != b.NodeID {
		t.Fatal(opened)
	}
	native.server.editMu.Lock()
	record := native.server.edits[opened.Edits[0].ID]
	native.server.editMu.Unlock()
	record.mu.Lock()
	err := os.WriteFile(record.localPath(), []byte("sealed editor saved bytes"), 0o600)
	record.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the actual watcher/debounce/retry path, not just explicit upload.
	for {
		event := waitSealedSFTPEvent(t, child, "sftp.edit", "")
		if event.Error != "" {
			t.Fatal(event)
		}
		if len(event.Edits) == 1 && event.Edits[0].State == "Uploaded" {
			break
		}
	}
	if event := send("upload", map[string]any{"operation": "upload", "edit_id": record.View.ID}); event.Error != "" {
		t.Fatal(event)
	}
	contents, err := readSftpTestFile(native.sftpClient, remote)
	if err != nil || string(contents) != "sealed editor saved bytes" {
		t.Fatal("authenticated file upload failed", err)
	}
	if event := send("prepare", map[string]any{"operation": "prepare-close"}); event.Error != "" || len(event.Edits) != 1 || event.Edits[0].Pending {
		t.Fatal(event)
	}
	sendSealedSFTP(t, child, b.SessionID, map[string]any{"type": "app-lock"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.watching || !record.View.Recovered {
		t.Fatal("process returned before edit teardown")
	}
}

func TestSealedSFTPEditWithoutOwnerConfigurationFailsClosed(t *testing.T) {
	child, native, id := sealedSFTPFixture(t)
	sendSealedSFTP(t, child, id, map[string]any{"type": "sftp-edit", "operation": "list", "request_id": "list"})
	event := waitSealedSFTPEvent(t, child, "sftp.edit", "list")
	if event.Error == "" || len(event.Edits) != 0 || native.server.electronUserDataPath != "" {
		t.Fatal("missing editor configuration fell back to legacy storage")
	}
	sendSealedSFTP(t, child, id, map[string]any{"type": "app-lock"})
	if err := child.wait(t); err != nil {
		t.Fatal(err)
	}
}

func TestSealedSFTPEditWorkerAdmission(t *testing.T) {
	server := sealedEditServer(t, sealedEditOptions(t), uuid.NewString(), uuid.NewString())
	var output bytes.Buffer
	server.output = &sshEventWriter{encoder: json.NewEncoder(&output), sealed: true}
	server.sftpWork = &sftpWorkGroup{}
	if err := server.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	command := sshWireCommand{Type: "sftp-edit", SessionID: uuid.NewString(), RequestID: "list", Operation: "list"}
	for i := 0; i < cap(server.editWorkers); i++ {
		server.editWorkers <- struct{}{}
	}
	server.handleSftpEdit(command)
	var event sshWireEvent
	if json.Unmarshal(output.Bytes(), &event) != nil || event.Error == "" {
		t.Fatal("editor worker limit ignored")
	}
	for i := 0; i < cap(server.editWorkers); i++ {
		<-server.editWorkers
	}
	output.Reset()
	server.handleSftpEdit(command)
	server.sftpWork.wg.Wait()
	if json.Unmarshal(output.Bytes(), &event) != nil || event.RequestID != "list" || len(server.editWorkers) != 0 {
		t.Fatal("admitted work was not joined")
	}
	output.Reset()
	server.sftpWork.stop()
	server.handleSftpEdit(command)
	if json.Unmarshal(output.Bytes(), &event) != nil || event.Error == "" || len(server.editWorkers) != 0 {
		t.Fatal("closed work group accepted edit or leaked capacity")
	}
}

func TestSealedSFTPEditCloseWithoutCopiesDoesNotAcquireScope(t *testing.T) {
	options, workspace, node := sealedEditOptions(t), uuid.NewString(), uuid.NewString()
	owner := sealedEditServer(t, options, workspace, node)
	if err := owner.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	other := sealedEditServer(t, options, workspace, node)
	var output bytes.Buffer
	other.output = &sshEventWriter{encoder: json.NewEncoder(&output), sealed: true}
	for _, operation := range []string{"prepare-close", "finish-close"} {
		output.Reset()
		other.handleSftpEdit(sshWireCommand{SessionID: "other", RequestID: operation, Operation: operation, Decision: "keep"})
		var event sshWireEvent
		if json.Unmarshal(output.Bytes(), &event) != nil || event.RequestID != operation || event.Error != "" || other.sealedEdits.release != nil || other.edits != nil {
			t.Fatal("empty close acquired a cache or blocked on another owner", event)
		}
	}
}
