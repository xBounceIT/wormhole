package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Main-only endpoint for its isolated editor. The ordinary app can select only
// a tunnel/revision, never a recipient key or a plaintext configuration.
func (h *vaultFoundationHandler) displayTunnelEditor(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var id, request, version string
	var keyJSON json.RawMessage
	if decodeVaultObject(raw, map[string]any{"tunnelId": &id, "requestId": &request, "rowVersion": &version, "publicKey": &keyJSON}, "tunnelId", "requestId", "rowVersion", "publicKey") != nil || !vaultCredentialID(id) || !vaultCredentialID(request) {
		return nil, vaultwire.ErrProtocol
	}
	var key []byte
	revision, err := vaultCredentialRevision(version, false)
	if err != nil || len(keyJSON) == 0 || keyJSON[0] != '"' || json.Unmarshal(keyJSON, &key) != nil || len(key) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	result, err := h.owner.SealTunnelEditor(ctx, id, request, revision, key, projectVaultTunnelEditor)
	return h.domainResult(result, err)
}

func projectVaultTunnelEditor(tunnel vaultstore.Tunnel, configuration []byte) ([]byte, error) {
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	return projectVaultTunnelSettings(tunnel.TunnelMetadata, settings)
}

func projectVaultTunnelSettings(tunnel vaultstore.TunnelMetadata, settings map[string]json.RawMessage) ([]byte, error) {
	public := make(map[string]json.RawMessage)
	present := make([]string, 0)
	for field, value := range settings {
		if !vaultTunnelEditorField(tunnel.Kind, field) {
			continue
		}
		if !vaultTunnelPublicEditorField(tunnel.Kind, field) {
			trimmed := bytes.TrimSpace(value)
			if !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte(`""`)) {
				present = append(present, field)
			}
			continue
		}
		if !validVaultTunnelPublicValue(tunnel.Kind, field, value) {
			return nil, vaultwire.ErrProtocol
		}
		public[field] = value
	}
	sort.Strings(present)
	result, err := json.Marshal(struct {
		Name     string                     `json:"name"`
		Kind     int                        `json:"kind"`
		Settings map[string]json.RawMessage `json:"settings"`
		Present  []string                   `json:"present"`
	}{tunnel.Name, tunnel.Kind, public, present})
	if err != nil || len(result) > 512*1024 {
		vault.Wipe(result)
		return nil, vaultwire.ErrProtocol
	}
	return result, nil
}

// Match the protected JavaScript reader, including lossless integers and Unicode.
// Shape validation runs first so the shared escape scanner has valid JSON bounds.
func validVaultTunnelPublicValue(kind int, field string, raw []byte) bool {
	if !validVaultTunnelEditorValue(kind, field, raw) || !validJSONUnicodeEscapes(raw) {
		return false
	}
	value := bytes.TrimSpace(raw)
	switch value[0] {
	case 'n', 't', 'f':
		return true
	case '"':
		var text string
		_ = json.Unmarshal(value, &text)
		return !strings.ContainsRune(text, 0)
	case '[':
		var values []string
		_ = json.Unmarshal(value, &values)
		for _, text := range values {
			if strings.ContainsRune(text, 0) {
				return false
			}
		}
		return true
	default:
		var number int64
		_ = json.Unmarshal(value, &number)
		return number >= -9007199254740991 && number <= 9007199254740991
	}
}

// Fail closed: only these non-secret provider fields can be displayed, and only
// in the sealed projection for the dedicated editor. Unknown legacy fields,
// keys, passwords, TOTP seeds, PEM contents and imported profiles stay native.
func vaultTunnelPublicEditorField(kind int, field string) bool {
	if !vaultTunnelEditorField(kind, field) {
		return false
	}
	const names = "InterfaceAddress Mtu Dns PeerPublicKey PeerEndpoint AllowedIps PersistentKeepaliveSeconds Username Host Port Realm UseSingleSignOn UseExternalBrowser SamlRedirectPort TrustServerCertificate ServerCertSha256Pin Server AuthMode Domain VerifyX509Name Mode Description UseOtp OpenVpnTransportOverride OpenVpnCompressionFramingOverride Servers Protocol TenantId Audience ApplicationId Issuer Group JumpConnectionId CredentialId HostKeySha256 KeepaliveSeconds RemoteGateways AuthMethod UserAuth SamlPort IkeVersion ExchangeMode AddressAssignment ManualAddress ManualDns Phase1Encryption Phase1Authentication Phase1Encryption2 Phase1Authentication2 DhGroups Phase1Lifetime LocalId RemoteId DeadPeerDetection NatTraversal EnableLocalLan Phase2Encryption Phase2Authentication Phase2Encryption2 Phase2Authentication2 Phase2TimeLifetime Phase2Lifetime Phase2ByteLifetime Phase2LifetimeKb ReplayDetection Pfs PfsGroup AutoProposals FallbackTunnelId"
	for _, name := range strings.Fields(names) {
		if name == field {
			return true
		}
	}
	return false
}
