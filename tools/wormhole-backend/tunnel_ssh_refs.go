package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func preserveSSHJumpTrust(db *sql.DB, databasePath string, request *tunnelWriteRequest) error {
	if request.Kind != 7 {
		return nil
	}
	var next map[string]json.RawMessage
	_ = json.Unmarshal(request.Settings, &next)
	defer clearTunnelSettingsMap(next)
	if tunnelSettingString(next, "Mode") != "manual" {
		if request.ForgetJumpHostKeySha256 != "" {
			owner, pin := sshJumpHostKeyInfo(db, request.Kind, request.Settings)
			if owner == "" || pin != request.ForgetJumpHostKeySha256 {
				return errors.New("SSH jump host key changed; reload the tunnel before forgetting its pin")
			}
		}
		return nil
	}
	previous, err := readTunnelSettings(db, databasePath, request.ID)
	if err != nil && request.ForgetJumpHostKeySha256 != "" {
		return errors.New("SSH tunnel pin changed; reload the editor")
	}
	defer clearBytes(previous)
	var old map[string]json.RawMessage
	_ = json.Unmarshal(previous, &old)
	defer clearTunnelSettingsMap(old)
	oldPin := tunnelSettingString(old, "HostKeySha256")
	if request.ForgetJumpHostKeySha256 != "" {
		if oldPin != request.ForgetJumpHostKeySha256 {
			return errors.New("SSH tunnel pin changed; reload the editor")
		}
		delete(next, "HostKeySha256")
	} else {
		// The editor displays this field read-only. Only the backend confirmation flow may
		// establish trust; a stale editor must not restore a revoked pin or replace a newer one.
		same := true
		for _, key := range []string{"Mode", "Host", "Username", "CredentialId"} {
			same = same && tunnelSettingString(old, key) == tunnelSettingString(next, key)
		}
		if same && tunnelSettingNumber(old, "Port") == tunnelSettingNumber(next, "Port") && oldPin != "" {
			next["HostKeySha256"], _ = json.Marshal(oldPin)
		} else {
			delete(next, "HostKeySha256")
		}
	}
	request.Settings, err = json.Marshal(next)
	return err
}

// The editor can display an inherited connection pin without loading any credential.
func sshJumpHostKeyInfo(db *sql.DB, kind int64, raw json.RawMessage) (string, string) {
	if kind != 7 {
		return "", ""
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil {
		return "", ""
	}
	defer clearTunnelSettingsMap(settings)
	if tunnelSettingString(settings, "Mode") != "connection" {
		return "", ""
	}
	nodes, err := loadSSHNodes(db)
	if err != nil {
		return "", ""
	}
	id := normalizeID(tunnelSettingString(settings, "JumpConnectionId"))
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		node := nodes[id]
		if node == nil {
			break
		}
		if pin := strings.TrimSpace(node.knownHostFingerprint); pin != "" {
			return id, pin
		}
		id = node.parentID
	}
	return "", ""
}

func tunnelEndpointSummaryForDatabase(db *sql.DB, kind int64, raw json.RawMessage) string {
	if kind == 7 {
		var settings map[string]json.RawMessage
		_ = json.Unmarshal(raw, &settings)
		defer clearTunnelSettingsMap(settings)
		if tunnelSettingString(settings, "Mode") == "connection" {
			nodes, err := loadSSHNodes(db)
			if err == nil {
				if node := nodes[normalizeID(tunnelSettingString(settings, "JumpConnectionId"))]; node != nil {
					return sanitizeTunnelEndpoint(node.name)
				}
			}
			return ""
		}
	}
	return tunnelEndpointSummary(kind, raw)
}

// Deletions check references before opening their mutation transaction. Legacy/dangling
// references restored from a backup remain readable and fail closed when connected.
func rejectSSHJumpDeletion(databasePath string, nodeIDs map[string]bool, credentialID string) error {
	db, err := openDatabase(databasePath, true)
	if err != nil || db == nil {
		return err
	}
	defer db.Close()
	exists, err := tableExists(db, "TunnelConfigs")
	if err != nil || !exists {
		return err
	}
	rows, err := db.Query("SELECT Id, Name FROM TunnelConfigs WHERE Kind = 7;")
	if err != nil {
		return err
	}
	type reference struct{ id, name string }
	var refs []reference
	for rows.Next() {
		var ref reference
		if err := rows.Scan(&ref.id, &ref.name); err != nil {
			rows.Close()
			return err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		raw, err := readTunnelSettings(db, databasePath, ref.id)
		if err != nil {
			return err
		}
		var settings map[string]json.RawMessage
		err = json.Unmarshal(raw, &settings)
		clearBytes(raw)
		if err != nil {
			clearTunnelSettingsMap(settings)
			return err
		}
		jump := normalizeID(tunnelSettingString(settings, "JumpConnectionId"))
		credential := normalizeID(tunnelSettingString(settings, "CredentialId"))
		clearTunnelSettingsMap(settings)
		if nodeIDs[jump] || (credentialID != "" && credential == normalizeID(credentialID)) {
			return fmt.Errorf("used by SSH tunnel %s", ref.name)
		}
		if credentialID != "" && jump != "" {
			effective, err := resolveNodeCredentialID(db, jump, 0)
			if err != nil {
				// Restored dangling or non-SSH references have no effective SSH credential.
				if err.Error() == "connection was not found" || err.Error() == "connection protocol does not match the requested credential protocol" {
					continue
				}
				return err
			}
			if effective == normalizeID(credentialID) {
				return fmt.Errorf("used by SSH tunnel %s", ref.name)
			}
		}
	}
	return nil
}
