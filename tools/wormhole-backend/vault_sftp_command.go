package main

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// File commands reuse the authenticated SSH transport. They cannot select a
// database, credential, route, editor executable, recipient key or another session.
func decodeSealedSFTPCommand(raw []byte, sessionID string) (sshWireCommand, error) {
	var c sshWireCommand
	var header struct {
		Type string `json:"type"`
	}
	if len(raw) > vaultwire.MaxFrameBytes || json.Unmarshal(raw, &header) != nil {
		return c, vaultwire.ErrProtocol
	}
	if header.Type == "sftp-edit" {
		return decodeSealedSFTPEdit(raw, sessionID)
	}
	fields := map[string]any{"type": &c.Type, "sessionId": &c.SessionID}
	required := []string{"type", "sessionId"}
	add := func(name string, target any, mandatory bool) {
		fields[name] = target
		if mandatory {
			required = append(required, name)
		}
	}
	var items []json.RawMessage
	switch header.Type {
	case "sftp-open":
		add("request_id", &c.RequestID, false)
	case "sftp-close":
	case "sftp-list", "sftp-local-list", "sftp-tree-list":
		add("request_id", &c.RequestID, header.Type != "sftp-list")
		add("path", &c.Path, true)
		if header.Type == "sftp-tree-list" {
			add("pane", &c.Pane, true)
		}
	case "sftp-operation":
		add("request_id", &c.RequestID, true)
		add("pane", &c.Pane, true)
		add("operation", &c.Operation, true)
		add("path", &c.Path, true)
		add("destination_path", &c.DestinationPath, false)
	case "sftp-transfer":
		add("transfer_id", &c.TransferID, true)
		add("direction", &c.Direction, true)
		add("destination_path", &c.DestinationPath, true)
		add("items", &items, true)
	case "sftp-transfer-decision":
		add("transfer_id", &c.TransferID, true)
		add("item_id", &c.ItemID, true)
		add("decision", &c.Decision, true)
		add("apply_to_all", &c.ApplyToAll, true)
	case "sftp-transfer-cancel":
		add("transfer_id", &c.TransferID, true)
		add("item_id", &c.ItemID, false)
	default:
		return c, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil || c.SessionID != sessionID {
		return sshWireCommand{}, vaultwire.ErrProtocol
	}
	valid := false
	switch c.Type {
	case "sftp-open", "sftp-close":
		valid = sealedSFTPIdentifier(c.RequestID, true)
	case "sftp-list":
		valid = sealedSFTPIdentifier(c.RequestID, true) && sealedSFTPPath(c.Path, "remote", true)
	case "sftp-local-list":
		valid = sealedSFTPIdentifier(c.RequestID, false) && sealedSFTPPath(c.Path, "local", true)
	case "sftp-tree-list":
		valid = sealedSFTPIdentifier(c.RequestID, false) && sealedSFTPPath(c.Path, c.Pane, false)
	case "sftp-operation":
		valid = sealedSFTPIdentifier(c.RequestID, false) && sealedSFTPPath(c.Path, c.Pane, false)
		switch c.Operation {
		case "mkdir", "file", "delete":
			valid = valid && c.DestinationPath == ""
		case "open":
			valid = valid && c.Pane == "local" && c.DestinationPath == ""
		case "rename":
			valid = valid && sealedSFTPPath(c.DestinationPath, c.Pane, false)
		default:
			valid = false
		}
	case "sftp-transfer":
		if len(items) == 0 || len(items) > sshSftpMaxTransferItems {
			break
		}
		for _, rawItem := range items {
			var item sshSftpTransferItem
			if decodeVaultObject(rawItem, map[string]any{"source_path": &item.SourcePath, "name": &item.Name, "is_directory": &item.IsDirectory, "size": &item.Size}, "source_path", "name", "is_directory", "size") != nil || item.Size > sshSftpMaxSafeSize {
				return sshWireCommand{}, vaultwire.ErrProtocol
			}
			c.Items = append(c.Items, item)
		}
		valid = sealedSFTPIdentifier(c.TransferID, false) && validateSftpTransferCommand(c) == nil
	case "sftp-transfer-decision":
		valid = sealedSFTPIdentifier(c.TransferID, false) && sealedSFTPIdentifier(c.ItemID, false) && (c.Decision == "overwrite" || c.Decision == "skip")
	case "sftp-transfer-cancel":
		valid = sealedSFTPIdentifier(c.TransferID, false) && sealedSFTPIdentifier(c.ItemID, true)
	}
	if !valid {
		return sshWireCommand{}, vaultwire.ErrProtocol
	}
	return c, nil
}

func sealedSFTPIdentifier(value string, empty bool) bool {
	return (empty || value != "") && len(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func sealedSFTPPath(value, pane string, empty bool) bool {
	if value == "" {
		return empty
	}
	var err error
	switch pane {
	case "local":
		_, err = normalizeLocalPath(value)
	case "remote":
		_, err = normalizeSftpPath(value)
	default:
		return false
	}
	return err == nil
}

// Entry counts alone do not bound a listing: 4096 legal long paths can exceed
// the relay's frame limit. Reserve half the frame for all other event fields.
func boundSealedSFTPEntries(event sshWireEvent) sshWireEvent {
	remaining := vaultwire.MaxFrameBytes / 2
	for _, edit := range event.Edits {
		encoded, _ := json.Marshal(edit)
		remaining -= len(encoded) + 1
		if remaining < 0 {
			// A partial prepare-close snapshot could conceal pending edits.
			event.Edits = nil
			event.Error = "edited file listing exceeds the safe response limit"
			return event
		}
	}
	for index, entry := range event.Entries {
		encoded, _ := json.Marshal(entry) // This fixed struct has no fallible JSON values.
		remaining -= len(encoded) + 1
		if remaining < 0 {
			event.Entries = event.Entries[:index]
			event.Truncated = true
			break
		}
	}
	return event
}
