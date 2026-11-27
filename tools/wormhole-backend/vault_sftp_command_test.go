package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSealedSFTPCommandContract(t *testing.T) {
	id := uuid.NewString()
	local := filepath.Join(t.TempDir(), "file")
	item := map[string]any{"source_path": local, "name": "file", "is_directory": false, "size": 12}
	cases := []map[string]any{
		{"type": "sftp-open"}, {"type": "sftp-close"},
		{"type": "sftp-open", "request_id": "open"},
		{"type": "sftp-list", "path": ""}, {"type": "sftp-list", "path": "/", "request_id": "list"},
		{"type": "sftp-local-list", "path": "", "request_id": "local"},
		{"type": "sftp-tree-list", "path": local, "pane": "local", "request_id": "tree"},
		{"type": "sftp-tree-list", "path": "/", "pane": "remote", "request_id": "tree"},
		{"type": "sftp-operation", "path": "/file", "pane": "remote", "request_id": "op", "operation": "file"},
		{"type": "sftp-operation", "path": "/dir", "pane": "remote", "request_id": "op", "operation": "mkdir"},
		{"type": "sftp-operation", "path": "/file", "pane": "remote", "request_id": "op", "operation": "delete"},
		{"type": "sftp-operation", "path": local, "pane": "local", "request_id": "op", "operation": "open"},
		{"type": "sftp-operation", "path": "/file", "destination_path": "/renamed", "pane": "remote", "request_id": "op", "operation": "rename"},
		{"type": "sftp-transfer", "transfer_id": "transfer", "direction": "local-to-remote", "destination_path": "/", "items": []any{item}},
		{"type": "sftp-transfer-decision", "transfer_id": "transfer", "item_id": "item", "decision": "skip", "apply_to_all": false},
		{"type": "sftp-transfer-decision", "transfer_id": "transfer", "item_id": "item", "decision": "overwrite", "apply_to_all": true},
		{"type": "sftp-transfer-cancel", "transfer_id": "transfer"},
		{"type": "sftp-transfer-cancel", "transfer_id": "transfer", "item_id": "item"},
	}
	for _, packet := range cases {
		packet["sessionId"] = id
		t.Run(packet["type"].(string), func(t *testing.T) {
			raw := vaultInput(t, packet)
			command, err := decodeSealedSSHCommand(raw, id)
			if err != nil || command.Type != packet["type"] || command.SessionID != id {
				t.Fatalf("valid command: %v", err)
			}
			if _, err := decodeSealedSSHCommand(raw, uuid.NewString()); err == nil {
				t.Fatal("foreign session accepted")
			}
			for field := range packet {
				changed := cloneSFTPPacket(packet)
				changed[field] = nil
				if _, err := decodeSealedSSHCommand(vaultInput(t, changed), id); err == nil {
					t.Fatalf("null %s accepted", field)
				}
				duplicate := bytes.Replace(raw, []byte(`"`+field+`":`), []byte(`"`+field+`":null,"`+field+`":`), 1)
				if _, err := decodeSealedSSHCommand(duplicate, id); err == nil {
					t.Fatalf("duplicate %s accepted", field)
				}
			}
			for _, field := range []string{"password", "data", "nodeId", "host", "publicKey", "source_session_id", "database", "editor_id", "mode"} {
				changed := cloneSFTPPacket(packet)
				changed[field] = "injected"
				if _, err := decodeSealedSSHCommand(vaultInput(t, changed), id); err == nil {
					t.Fatalf("injected %s accepted", field)
				}
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`[]`), []byte(`{"type":"sftp-edit"}`), []byte(`{"type":"sftp-open"} {}`)} {
		if _, err := decodeSealedSFTPCommand(raw, id); err == nil {
			t.Fatal("malformed command accepted")
		}
	}
}

func TestSealedSFTPListingFitsRelayFrame(t *testing.T) {
	entries := make([]sshSftpEntry, sshSftpMaxEntryCount)
	for i := range entries {
		entries[i] = sshSftpEntry{Name: strings.Repeat("\"", 128), FullPath: "/" + strings.Repeat("a", sshSftpMaxPathBytes-1)}
	}
	event := sshWireEvent{Type: "sftp.ready", SessionID: "session", Path: "/", Entries: entries}
	var out bytes.Buffer
	writer := &sshEventWriter{encoder: json.NewEncoder(&out), sealed: true}
	writer.write(event)
	if out.Len() >= vaultwire.MaxFrameBytes {
		t.Fatal("listing exceeded the relay frame")
	}
	var got sshWireEvent
	if json.Unmarshal(out.Bytes(), &got) != nil || !got.Truncated || len(got.Entries) == 0 || len(got.Entries) >= len(entries) {
		t.Fatal("listing was not visibly truncated")
	}
	if event.Truncated || len(event.Entries) != len(entries) {
		t.Fatal("writer mutated original event")
	}
	if got.Entries[0] != entries[0] {
		t.Fatal("entry contents changed")
	}
	small := sshWireEvent{Type: "sftp.ready", Entries: entries[:1], Truncated: true}
	bounded := boundSealedSFTPEntries(small)
	if !bounded.Truncated || len(bounded.Entries) != 1 {
		t.Fatal("existing truncation lost")
	}
	if got := boundSealedSFTPEntries(sshWireEvent{Type: "screen"}); got.Truncated || got.Entries != nil {
		t.Fatal("non-listing changed")
	}
}

func cloneSFTPPacket(packet map[string]any) map[string]any {
	copy := make(map[string]any, len(packet))
	for k, v := range packet {
		copy[k] = v
	}
	return copy
}

func TestSealedSFTPCommandInvalidValues(t *testing.T) {
	id := uuid.NewString()
	local := filepath.Join(t.TempDir(), "file")
	base := map[string]any{"type": "sftp-transfer", "sessionId": id, "transfer_id": "transfer", "direction": "local-to-remote", "destination_path": "/", "items": []any{map[string]any{"source_path": local, "name": "file", "is_directory": false, "size": 1}}}
	for field, values := range map[string][]any{
		"transfer_id": {"", "x\n", strings.Repeat("x", 129)}, "direction": {"remote-to-remote", ""},
		"destination_path": {"", "relative", "/bad\x00", strings.Repeat("/", sshSftpMaxPathBytes+1)},
		"items":            {[]any{}, make([]any, sshSftpMaxTransferItems+1), []any{nil}, []any{map[string]any{"name": "file"}}},
	} {
		for _, value := range values {
			packet := cloneSFTPPacket(base)
			packet[field] = value
			if _, err := decodeSealedSSHCommand(vaultInput(t, packet), id); err == nil {
				t.Errorf("invalid %s accepted", field)
			}
		}
	}
	for field, values := range map[string][]any{
		"source_path": {"", "relative"}, "name": {"../escape", ""}, "size": {-1, int64(sshSftpMaxSafeSize) + 1, 1.5}, "is_directory": {"false"}, "secret": {"injected"},
	} {
		for _, value := range values {
			item := map[string]any{"source_path": local, "name": "file", "is_directory": false, "size": 1}
			item[field] = value
			packet := cloneSFTPPacket(base)
			packet["items"] = []any{item}
			if _, err := decodeSealedSSHCommand(vaultInput(t, packet), id); err == nil {
				t.Errorf("invalid item %s accepted", field)
			}
		}
	}
	raw := vaultInput(t, base)
	for _, field := range []string{"source_path", "name", "size", "is_directory"} {
		bad := bytes.Replace(raw, []byte(`"`+field+`":`), []byte(`"`+field+`":null,"`+field+`":`), 1)
		if _, err := decodeSealedSSHCommand(bad, id); err == nil {
			t.Fatal("duplicate item field accepted")
		}
	}
	for _, packet := range []map[string]any{
		{"type": "sftp-operation", "pane": "remote", "path": "/", "request_id": "op", "operation": "open"},
		{"type": "sftp-operation", "pane": "remote", "path": "/", "request_id": "op", "operation": "unknown"},
		{"type": "sftp-operation", "pane": "remote", "path": "/", "request_id": "op", "operation": "rename"},
		{"type": "sftp-operation", "pane": "remote", "path": "/", "request_id": "op", "operation": "delete", "destination_path": "/another"},
		{"type": "sftp-tree-list", "pane": "wrong", "path": "/", "request_id": "tree"},
		{"type": "sftp-list", "path": "relative"},
		{"type": "sftp-local-list", "path": "relative", "request_id": "local"},
		{"type": "sftp-local-list", "path": local, "request_id": ""},
		{"type": "sftp-transfer-decision", "transfer_id": "t", "item_id": "i", "decision": "delete", "apply_to_all": false},
		{"type": "sftp-transfer-cancel", "transfer_id": "t", "item_id": "bad\x00"},
	} {
		packet["sessionId"] = id
		if _, err := decodeSealedSSHCommand(vaultInput(t, packet), id); err == nil {
			t.Fatalf("invalid command accepted: %s", packet["type"])
		}
	}
	// Missing required fields, including nested item fields, cannot become zero defaults.
	var packet map[string]json.RawMessage
	if json.Unmarshal(raw, &packet) != nil {
		t.Fatal("fixture")
	}
	for field := range packet {
		copy := make(map[string]any)
		for k, v := range packet {
			if k != field {
				copy[k] = v
			}
		}
		if _, err := decodeSealedSSHCommand(vaultInput(t, copy), id); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
	}
}
