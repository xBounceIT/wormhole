package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Editor changes are a base64-encoded JSON merge patch kept entirely in native
// memory. Omitted fields preserve stored values; null explicitly removes them.
// Switching provider starts with an empty configuration, never the old secrets.
// This endpoint returns only public identity/revision, never provider settings.
func (h *vaultFoundationHandler) editTunnel(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 6*1024*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var metadata, rawPatch json.RawMessage
	var version, editorID, importID string
	var forget bool
	defer func() { vault.Wipe(metadata); vault.Wipe(rawPatch) }()
	if decodeVaultObject(payload, map[string]any{"metadata": &metadata, "patch": &rawPatch, "rowVersion": &version, "forgetHostKey": &forget, "editorId": &editorID, "importId": &importID}, "metadata", "patch", "rowVersion", "forgetHostKey") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var m vaultstore.TunnelMetadata
	if len(metadata) > 4096 || decodeVaultObject(metadata, map[string]any{"id": &m.ID, "name": &m.Name, "kind": &m.Kind}, "id", "name", "kind") != nil {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, true)
	if err != nil || revision == math.MaxInt64 || (revision == 0) != (m.ID == "") {
		return nil, vaultwire.ErrProtocol
	}
	if (editorID == "") != (importID == "") || (editorID != "" && (!vaultCredentialID(editorID) || !vaultCredentialID(importID))) {
		return nil, vaultwire.ErrProtocol
	}
	originalID := m.ID
	if revision == 0 {
		m.ID = uuid.NewString()
	}
	m.Name = strings.TrimSpace(m.Name)
	if m.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	var patchBytes []byte
	defer func() { vault.Wipe(patchBytes) }()
	if len(rawPatch) == 0 || rawPatch[0] != '"' || json.Unmarshal(rawPatch, &patchBytes) != nil {
		return nil, vaultwire.ErrProtocol
	}
	patch, err := decodeVaultTunnelSettings(patchBytes)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(patch)
	for field, value := range patch {
		if !vaultTunnelEditorField(m.Kind, field) || field == "HostKeySha256" || !validVaultTunnelEditorValue(m.Kind, field, value) {
			return nil, vaultwire.ErrProtocol
		}
	}
	old := vaultstore.Tunnel{}
	settings := make(map[string]json.RawMessage)
	defer func() { clearTunnelSettingsMap(settings) }()
	if revision != 0 {
		old, err = h.owner.ReadTunnel(ctx, m.ID, 0)
		if err != nil {
			return h.domainResult(nil, err)
		}
		if old.RowVersion != revision {
			return nil, vaultstore.ErrConflict
		}
		if (old.Kind == m.Kind && (len(patch) != 0 || importID != "")) || (old.Kind == 8 && m.Kind == 8 && forget) {
			err = h.owner.WithTunnelConfiguration(ctx, m.ID, revision, func(configuration []byte) error {
				var e error
				settings, e = decodeVaultTunnelSettings(configuration)
				return e
			})
			if err != nil {
				return h.domainResult(nil, err)
			}
		}
	}
	// Metadata-only writes preserve the original encrypted record and DEK.
	if revision != 0 && old.Kind == m.Kind && len(patch) == 0 && !forget && importID == "" {
		if m.Name != old.Name {
			err = h.owner.WithTunnelConfiguration(ctx, m.ID, revision, func(configuration []byte) error {
				projection, e := projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: m}, configuration)
				vault.Wipe(projection)
				return e
			})
			if err != nil {
				return h.domainResult(nil, err)
			}
		}
		saved, e := h.owner.PutTunnel(ctx, m, nil, revision)
		return h.tunnelEditorResult(saved, e)
	}
	for _, value := range settings {
		defer vault.Wipe(value)
	}
	if importID != "" {
		imported, e := h.owner.ReadTunnelImport(ctx, editorID, importID, localvault.TunnelImportTarget{TunnelID: originalID, RowVersion: revision, Kind: m.Kind})
		defer vault.Wipe(imported)
		if e != nil {
			return h.domainResult(nil, e)
		}
		importedSettings, e := decodeVaultTunnelSettings(imported)
		if e != nil {
			return nil, e
		}
		defer clearTunnelSettingsMap(importedSettings)
		for field, value := range importedSettings {
			if !vaultTunnelEditorField(m.Kind, field) || field == "HostKeySha256" || !validVaultTunnelEditorValue(m.Kind, field, value) {
				return nil, vaultwire.ErrProtocol
			}
			if _, supplied := patch[field]; !supplied {
				patch[field] = value
			}
		}
	}

	// A pin belongs to the previous SSH identity. Edits may forget it but never
	// establish a new trust decision through an arbitrary settings patch.
	identityChanged := old.Kind != 8
	if m.Kind == 8 {
		for _, field := range []string{"Mode", "Host", "Port", "Username", "CredentialId", "JumpConnectionId"} {
			if _, supplied := patch[field]; !supplied {
				continue
			}
			if field == "Port" {
				identityChanged = identityChanged || tunnelSettingNumber(patch, field) != tunnelSettingNumber(settings, field)
			} else {
				identityChanged = identityChanged || tunnelSettingString(patch, field) != tunnelSettingString(settings, field)
			}
		}
	}
	for field, value := range patch {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			delete(settings, field)
		} else {
			settings[field] = value
		}
	}
	if forget && (m.Kind != 8 || old.Kind != 8 || tunnelSettingString(settings, "Mode") != "manual") {
		return nil, vaultwire.ErrProtocol
	}
	if m.Kind == 8 && (forget || identityChanged) {
		delete(settings, "HostKeySha256")
	}
	// Mode changes cannot retain incompatible references or a manual target.
	if m.Kind == 8 {
		if tunnelSettingString(settings, "Mode") == "connection" {
			for _, field := range []string{"Host", "Port", "Username", "CredentialId", "HostKeySha256"} {
				delete(settings, field)
			}
		} else {
			delete(settings, "JumpConnectionId")
		}
	}
	defer normalizeVaultTunnelEditorSettings(m.Kind, settings, patch)()
	if len(settings) > 128 || validateTunnelSettings(int64(m.Kind), settings) != nil {
		return nil, vaultwire.ErrProtocol
	}
	if m.Kind == 9 {
		if err := h.validateVaultIPsecFallback(ctx, m.ID, settings); err != nil {
			return nil, err
		}
	}
	// A successful edit must remain readable by the protected editor. Large
	// imported secret profiles are allowed; the redacted display has its own cap.
	projection, err := projectVaultTunnelSettings(m, settings)
	vault.Wipe(projection)
	if err != nil {
		return nil, err
	}
	configuration, err := json.Marshal(settings)
	defer vault.Wipe(configuration)
	if err != nil || len(configuration) > backendMaxTunnelRequestBytes {
		return nil, vaultwire.ErrProtocol
	}
	saved, err := h.owner.PutTunnel(ctx, m, configuration, revision)
	if err == nil && importID != "" {
		h.owner.DiscardTunnelImport(editorID, importID)
	}
	return h.tunnelEditorResult(saved, err)
}

func (h *vaultFoundationHandler) tunnelEditorResult(saved vaultstore.Tunnel, err error) (json.RawMessage, error) {
	return h.domainResult(struct {
		ID         string `json:"id"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{saved.ID, strconv.FormatUint(saved.RowVersion, 10), true}, err)
}

// Only fields supported by the provider editors/importers can be changed.
// Unrecognized legacy extensions survive ordinary edits without being exposed.
func vaultTunnelEditorField(kind int, field string) bool {
	var fields string
	switch kind {
	case 0:
		fields = "InterfacePrivateKey InterfaceAddress Mtu Dns PeerPublicKey PeerPresharedKey PeerEndpoint AllowedIps PersistentKeepaliveSeconds"
	case 1:
		fields = "ProfileOvpn Username Password"
	case 2:
		fields = "Host Port Username Password Realm UseSingleSignOn UseSamlCallback UseExternalBrowser SamlRedirectPort TotpSecret TrustServerCertificate ServerCertSha256Pin"
	case 3:
		fields = "Server Port AuthMode UseSingleSignOn Username Password Domain CaPem ClientCertPem ClientKeyPem ProfileOvpn VerifyX509Name TrustServerCertificate"
	case 4:
		fields = "Mode Server Port Description UseSingleSignOn UseOtp Username Password ProfileOvpn CaPem TrustServerCertificate OpenVpnTransportOverride OpenVpnCompressionFramingOverride AppToken"
	case 5:
		fields = "Servers Protocol TenantId Audience ApplicationId Issuer CaPem ServerSecretHex"
	case 6:
		fields = "Host Port Group Username Password TotpSecret SecondaryPassword TrustServerCertificate ServerCertSha256Pin"
	case 7:
		fields = "Host Port Username Password ServerCertSha256Pin Mtu"
	case 8:
		fields = "Mode JumpConnectionId Host Port Username CredentialId HostKeySha256 KeepaliveSeconds"
	case 9:
		fields = "Host Port RemoteGateways Description AuthMethod UserAuth Username SamlPort IkeVersion ExchangeMode AddressAssignment ManualAddress ManualDns Phase1Encryption Phase1Authentication Phase1Encryption2 Phase1Authentication2 DhGroups Phase1Lifetime LocalId RemoteId TrustServerCertificate DeadPeerDetection NatTraversal EnableLocalLan Phase2Encryption Phase2Authentication Phase2Encryption2 Phase2Authentication2 Phase2TimeLifetime Phase2Lifetime Phase2ByteLifetime Phase2LifetimeKb ReplayDetection Pfs PfsGroup AutoProposals FallbackTunnelId PreSharedKey Password ClientCert ClientKey CaCert"
	default:
		return false
	}
	for _, name := range strings.Fields(fields) {
		if name == field {
			return true
		}
	}
	return false
}

// Field shape is validated before merging. Semantic provider validation runs on
// the complete result, including required fields after explicit null removals.
func validVaultTunnelEditorValue(kind int, field string, raw []byte) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	if kind == 9 {
		return validVaultIPsecEditorValue(field, raw)
	}
	switch field {
	case "UseSingleSignOn", "UseSamlCallback", "UseExternalBrowser", "TrustServerCertificate", "UseOtp":
		var value bool
		return json.Unmarshal(raw, &value) == nil
	case "Port", "Mtu", "SamlRedirectPort", "AuthMode", "Protocol", "OpenVpnTransportOverride", "OpenVpnCompressionFramingOverride", "PersistentKeepaliveSeconds", "KeepaliveSeconds":
		var value int64
		return json.Unmarshal(raw, &value) == nil
	case "Mode":
		if kind != 8 {
			var value int64
			return json.Unmarshal(raw, &value) == nil
		}
	case "Servers", "Dns", "AllowedIps":
		if len(raw) > 0 && raw[0] == '[' {
			var values []json.RawMessage
			defer func() {
				for _, value := range values {
					vault.Wipe(value)
				}
			}()
			if json.Unmarshal(raw, &values) != nil || len(values) > 256 {
				return false
			}
			for _, value := range values {
				if len(value) < 2 || value[0] != '"' {
					return false
				}
			}
			return true
		}
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	if field == "Servers" || field == "Dns" || field == "AllowedIps" {
		count := 0
		for _, item := range strings.Split(value, ",") {
			if strings.TrimSpace(item) != "" {
				count++
				if count > 256 {
					return false
				}
			}
		}
	}
	return true
}

// Match the provider editor's normalization in Go. Only explicitly supplied
// password/TOTP values are reformatted; unrelated edits preserve stored secrets.
func normalizeVaultTunnelEditorSettings(kind int, settings, patch map[string]json.RawMessage) func() {
	var allocated [][]byte
	set := func(field string, value any) {
		raw, _ := json.Marshal(value)
		allocated = append(allocated, raw)
		settings[field] = raw
	}
	blank := func(field string) {
		if strings.TrimSpace(tunnelSettingString(settings, field)) == "" {
			delete(settings, field)
		}
	}
	transform := func(field string, fn func(string) string) {
		if _, supplied := patch[field]; supplied {
			if _, exists := settings[field]; exists {
				set(field, fn(tunnelSettingString(settings, field)))
			}
		}
	}
	trimPassword := func(field string) {
		transform(field, func(value string) string { return strings.TrimRight(value, "\r\n") })
	}
	compact := func(field string) {
		if _, supplied := patch[field]; !supplied {
			return
		}
		transform(field, func(value string) string {
			return strings.Map(func(r rune) rune {
				if unicode.IsSpace(r) || r == '\ufeff' {
					return -1
				}
				return r
			}, value)
		})
		blank(field)
	}
	for _, field := range []string{"AllowedIps", "Dns", "Servers"} {
		raw, exists := settings[field]
		if !exists || len(raw) == 0 || raw[0] != '"' {
			continue
		}
		var list []string
		for _, item := range strings.Split(tunnelSettingString(settings, field), ",") {
			if value := strings.TrimSpace(item); value != "" {
				list = append(list, value)
			}
		}
		if list == nil {
			list = []string{}
		}
		set(field, list)
	}
	switch kind {
	case 0:
		if _, supplied := patch["PeerPresharedKey"]; supplied {
			blank("PeerPresharedKey")
		}
	case 1:
		blank("Username")
		if _, supplied := patch["Password"]; supplied {
			blank("Password")
		}
	case 2:
		if tunnelSettingBool(settings, "UseSingleSignOn") {
			delete(settings, "Username")
			delete(settings, "Password")
			delete(settings, "TotpSecret")
			if tunnelSettingBool(settings, "UseExternalBrowser") {
				delete(settings, "Realm")
			}
		} else {
			delete(settings, "UseSamlCallback")
			trimPassword("Password")
		}
		blank("Realm")
		compact("TotpSecret")
		compact("ServerCertSha256Pin")
	case 3:
		// An explicit current auth mode replaces the old boolean representation.
		// Otherwise a migrated SSO flag could silently override a manual edit.
		if _, supplied := patch["AuthMode"]; supplied {
			delete(settings, "UseSingleSignOn")
		}
		trimPassword("Password")
		blank("Domain")
		if strings.TrimSpace(tunnelSettingString(settings, "VerifyX509Name")) == "" {
			set("VerifyX509Name", "/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server")
		}
	case 4:
		delete(settings, "UseSingleSignOn")
		trimPassword("Password")
		if _, exists := settings["Mode"]; !exists {
			mode := 0
			if strings.TrimSpace(tunnelSettingString(settings, "ProfileOvpn")) != "" {
				mode = 1
			}
			set("Mode", mode)
		}
		if strings.TrimSpace(tunnelSettingString(settings, "AppToken")) == "" {
			set("AppToken", "sslclient")
		}
	case 5:
		blank("ApplicationId")
		blank("Issuer")
		blank("CaPem")
		compact("ServerSecretHex")
	case 6:
		trimPassword("Password")
		trimPassword("SecondaryPassword")
		if _, supplied := patch["SecondaryPassword"]; supplied {
			blank("SecondaryPassword")
		}
		blank("Group")
		compact("TotpSecret")
		compact("ServerCertSha256Pin")
	case 7:
		trimPassword("Password")
		compact("ServerCertSha256Pin")
	case 9:
		// A mode switch must not silently reuse incompatible stored factors.
		if tunnelSettingNumber(settings, "AuthMethod") == 1 {
			delete(settings, "PreSharedKey")
		} else {
			for _, field := range []string{"ClientCert", "ClientKey", "CaCert"} {
				delete(settings, field)
			}
		}
		if fortinetUserAuth(settings) != 2 {
			delete(settings, "Password")
		}
		if fortinetUserAuth(settings) != 1 && fortinetUserAuth(settings) != 2 {
			delete(settings, "Username")
		}
	}
	return func() {
		for _, value := range allocated {
			vault.Wipe(value)
		}
	}
}
