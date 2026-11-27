package main

import (
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func decodeSealedSFTPEdit(raw []byte, sessionID string) (sshWireCommand, error) {
	var c sshWireCommand
	var header struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return c, vaultwire.ErrProtocol
	}
	fields := map[string]any{"type": &c.Type, "sessionId": &c.SessionID, "request_id": &c.RequestID, "operation": &c.Operation}
	required := []string{"type", "sessionId", "request_id", "operation"}
	add := func(name string, value any, mandatory bool) {
		fields[name] = value
		if mandatory {
			required = append(required, name)
		}
	}
	switch header.Operation {
	case "list", "prepare-close":
	case "finish-close":
		add("decision", &c.Decision, true)
	case "start":
		add("pane", &c.Pane, true)
		add("path", &c.Path, true)
		add("editor_id", &c.EditorID, false)
		add("allow_binary", &c.AllowBinary, false)
	case "recover", "reveal", "reload", "discard", "upload", "stop":
		add("edit_id", &c.EditID, true)
		if header.Operation == "reload" || header.Operation == "discard" {
			add("decision", &c.Decision, true)
		}
		if header.Operation == "upload" || header.Operation == "stop" {
			add("decision", &c.Decision, false)
			add("destination_path", &c.DestinationPath, false)
		}
	default:
		return c, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil || c.Type != "sftp-edit" || c.SessionID != sessionID || !sealedSFTPIdentifier(c.RequestID, false) {
		return sshWireCommand{}, vaultwire.ErrProtocol
	}
	valid := true
	switch c.Operation {
	case "start":
		valid = sealedSFTPPath(c.Path, c.Pane, false) && sealedSFTPIdentifier(c.EditorID, true)
	case "finish-close":
		valid = c.Decision == "keep"
	case "recover", "reveal", "reload", "discard", "upload", "stop":
		valid = vaultCredentialID(c.EditID)
		if c.Operation == "reload" || c.Operation == "discard" {
			valid = valid && c.Decision == "discard"
		}
		if c.Operation == "upload" || c.Operation == "stop" {
			valid = valid && (c.Decision == "" || c.Decision == "overwrite") && sealedSFTPPath(c.DestinationPath, "remote", true)
		}
	}
	if !valid {
		return sshWireCommand{}, vaultwire.ErrProtocol
	}
	return c, nil
}
