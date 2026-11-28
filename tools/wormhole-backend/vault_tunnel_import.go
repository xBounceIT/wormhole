package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultTunnelImportDisplay struct {
	WorkspaceID string             `json:"workspaceId"`
	EditorID    string             `json:"editorId"`
	ImportID    string             `json:"importId"`
	Kind        int                `json:"kind"`
	Bundle      vault.SealedBundle `json:"bundle"`
}

// Main supplies a freshly picked absolute path. The document never supplies a
// path and receives only a recipient-sealed public projection of this snapshot.
func (h *vaultFoundationHandler) stageTunnelImport(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 16*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var editor, id, tunnel, version, format, path string
	var kind int
	var rawKey json.RawMessage
	if decodeVaultObject(payload, map[string]any{"editorId": &editor, "importId": &id, "tunnelId": &tunnel, "rowVersion": &version, "kind": &kind, "format": &format, "path": &path, "publicKey": &rawKey}, "editorId", "importId", "tunnelId", "rowVersion", "kind", "format", "path", "publicKey") != nil {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, true)
	if err != nil || revision >= math.MaxInt64 || (tunnel == "") != (revision == 0) || (!vaultCredentialID(tunnel) && tunnel != "") || !vaultCredentialID(editor) || !vaultCredentialID(id) {
		return nil, vaultwire.ErrProtocol
	}
	var key []byte
	if len(rawKey) == 0 || rawKey[0] != '"' || json.Unmarshal(rawKey, &key) != nil || len(key) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	name, settings, err := readVaultTunnelImport(path, format, kind)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	defer clearTunnelSettingsMap(settings)
	target := localvault.TunnelImportTarget{TunnelID: tunnel, RowVersion: revision, Kind: kind}
	if kind == 9 {
		previous, e := h.owner.CurrentTunnelImport(ctx, editor, target)
		if e != nil {
			return h.domainResult(nil, e)
		}
		if previous != nil {
			old, e := decodeVaultTunnelSettings(previous)
			vault.Wipe(previous)
			if e != nil {
				return nil, e
			}
			defer clearTunnelSettingsMap(old)
			for field, value := range old {
				if _, supplied := settings[field]; !supplied {
					settings[field] = value
				}
			}
		}
	}
	configuration, err := json.Marshal(settings)
	defer vault.Wipe(configuration)
	if err != nil || len(configuration) > vault.MaxSecretBytes {
		return nil, vaultwire.ErrProtocol
	}
	projection, err := projectVaultTunnelSettings(vaultstore.TunnelMetadata{Name: name, Kind: kind}, settings)
	defer vault.Wipe(projection)
	if err != nil {
		return nil, err
	}
	descriptor, err := h.owner.ReadLocalPolicy(ctx)
	if err != nil {
		return h.domainResult(nil, err)
	}
	bundle, err := vault.SealTunnelImportDisplay(key, descriptor.Policy.WorkspaceID, editor, id, kind, projection)
	if err != nil {
		return nil, err
	}
	if err = h.owner.StageTunnelImport(ctx, editor, id, target, configuration); err != nil {
		return h.domainResult(nil, err)
	}
	return json.Marshal(vaultTunnelImportDisplay{WorkspaceID: descriptor.Policy.WorkspaceID, EditorID: editor, ImportID: id, Kind: kind, Bundle: bundle})
}

func (h *vaultFoundationHandler) discardTunnelImport(payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 512 {
		return nil, vaultwire.ErrProtocol
	}
	var editor, id string
	if decodeVaultObject(payload, map[string]any{"editorId": &editor, "importId": &id}, "editorId", "importId") != nil || !vaultCredentialID(editor) || (id != "" && !vaultCredentialID(id)) {
		return nil, vaultwire.ErrProtocol
	}
	h.owner.DiscardTunnelImport(editor, id)
	return json.RawMessage(`{"discarded":true}`), nil
}

// Parse only the selected format, without invoking legacy import functions that
// publish auxiliary files (in particular Azure's old key-reference store).
func readVaultTunnelImport(path, format string, kind int) (string, map[string]json.RawMessage, error) {
	maximum := int64(maxImportedProfileBytes)
	switch format {
	case "ipsec-cert", "ipsec-key", "ipsec-ca":
		if kind != 9 {
			return "", nil, vaultwire.ErrProtocol
		}
		maximum = 131072
	case "openvpn":
		if kind != 1 && kind != 3 && kind != 4 {
			return "", nil, vaultwire.ErrProtocol
		}
	case "watchguard":
		if kind != 3 {
			return "", nil, vaultwire.ErrProtocol
		}
		maximum = watchguardMaxBundleBytes
	case "azure":
		if kind != 5 {
			return "", nil, vaultwire.ErrProtocol
		}
		maximum = azureProfileMaxBytes
	case "cisco":
		if kind != 6 {
			return "", nil, vaultwire.ErrProtocol
		}
	default:
		return "", nil, vaultwire.ErrProtocol
	}
	if len(path) > 8192 || !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", nil, vaultwire.ErrProtocol
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return "", nil, vaultwire.ErrProtocol
	}
	contents, err := readBoundedRegularFile(path, maximum)
	defer vault.Wipe(contents)
	if err != nil || len(contents) == 0 {
		return "", nil, vaultwire.ErrProtocol
	}
	name := "Imported tunnel"
	settings := map[string]any{}
	switch format {
	case "ipsec-cert", "ipsec-key", "ipsec-ca":
		field := map[string]string{"ipsec-cert": "ClientCert", "ipsec-key": "ClientKey", "ipsec-ca": "CaCert"}[format]
		if !utf8.Valid(contents) || readVaultIPsecPEM(contents, field) != nil {
			return "", nil, vaultwire.ErrProtocol
		}
		settings[field] = string(contents)
		settings["AuthMethod"] = 1
	case "openvpn":
		if len(bytes.TrimSpace(contents)) == 0 || !utf8.Valid(contents) || bytes.ContainsRune(contents, 0) {
			return "", nil, vaultwire.ErrProtocol
		}
		settings["ProfileOvpn"] = string(contents)
		if kind == 4 {
			settings["Mode"] = 1
		}
		if kind == 3 {
			settings["AuthMode"] = 1
		}
	case "watchguard":
		profile, e := importWatchguardBundle(contents)
		if e != nil || !utf8.ValidString(profile) || strings.ContainsRune(profile, 0) {
			return "", nil, vaultwire.ErrProtocol
		}
		host, port, e := watchguardRemote(profile)
		if e != nil {
			return "", nil, vaultwire.ErrProtocol
		}
		settings = map[string]any{"Server": host, "Port": port, "ProfileOvpn": profile, "AuthMode": 1}
	case "azure":
		imported, e := parseAzureVPNProfile(contents)
		if e != nil {
			return "", nil, vaultwire.ErrProtocol
		}
		settings = imported.Settings
		if imported.Name != "" {
			name = imported.Name
		}
	case "cisco":
		imported, e := parseCiscoProfile(contents)
		if e != nil {
			return "", nil, vaultwire.ErrProtocol
		}
		settings = map[string]any{"Host": imported.Host, "Port": imported.Port, "Group": imported.Group}
		if imported.ProfileName != "" {
			name = imported.ProfileName
		}
	}
	if len(name) > 512 || utf8.RuneCountInString(name) > 128 || strings.ContainsRune(name, 0) {
		return "", nil, vaultwire.ErrProtocol
	}
	result := make(map[string]json.RawMessage, len(settings))
	for field, value := range settings {
		raw, e := json.Marshal(value)
		result[field] = raw
		if e != nil || !vaultTunnelEditorField(kind, field) || !validVaultTunnelEditorValue(kind, field, raw) {
			clearTunnelSettingsMap(result)
			return "", nil, vaultwire.ErrProtocol
		}
	}
	return name, result, nil
}
