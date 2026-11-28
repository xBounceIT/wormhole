package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Only the provider identity and display metadata cross the response channel.
// Endpoints, pins, provider settings and caches stay with their native owner.
type vaultTunnelView struct {
	vaultstore.TunnelMetadata
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
	RowVersion string `json:"rowVersion"`
}

func tunnelView(t vaultstore.Tunnel) vaultTunnelView {
	return vaultTunnelView{t.TunnelMetadata, t.CreatedAt, t.UpdatedAt, strconv.FormatUint(t.RowVersion, 10)}
}

func decodeVaultTunnelConfiguration(raw []byte, kind int) (configuration []byte, err error) {
	defer func() {
		if err != nil {
			vault.Wipe(configuration)
			configuration = nil
		}
	}()
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &configuration) != nil {
		return configuration, vaultwire.ErrProtocol
	}
	if err := validateVaultTunnelConfiguration(configuration, kind); err != nil {
		return configuration, err
	}
	return configuration, nil
}

func decodeVaultTunnelSettings(configuration []byte) (settings map[string]json.RawMessage, err error) {
	if len(configuration) == 0 || len(configuration) > backendMaxTunnelRequestBytes || !utf8.Valid(configuration) {
		return nil, vaultwire.ErrProtocol
	}
	// Provider settings retain their legacy JSON field names. Check duplicates
	// before invoking existing semantic validators; map decoding alone loses them.
	d := json.NewDecoder(bytes.NewReader(configuration))
	if token, e := d.Token(); e != nil || token != json.Delim('{') {
		return nil, vaultwire.ErrProtocol
	}
	settings = make(map[string]json.RawMessage)
	owned := settings
	defer func() {
		if err != nil {
			clearTunnelSettingsMap(owned)
		}
	}()
	for d.More() {
		if len(settings) >= 128 {
			return nil, vaultwire.ErrProtocol
		}
		token, e := d.Token()
		if e != nil {
			return nil, vaultwire.ErrProtocol
		}
		name, ok := token.(string)
		if !ok || name == "" || len(name) > 128 || strings.ContainsRune(name, 0) {
			return nil, vaultwire.ErrProtocol
		}
		if _, exists := settings[name]; exists {
			return nil, vaultwire.ErrProtocol
		}
		var value json.RawMessage
		e = d.Decode(&value)
		settings[name] = value
		if e != nil {
			return nil, vaultwire.ErrProtocol
		}
	}
	if token, e := d.Token(); e != nil || token != json.Delim('}') {
		return nil, vaultwire.ErrProtocol
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, vaultwire.ErrProtocol
	}
	return settings, nil
}

func validateVaultTunnelConfiguration(configuration []byte, kind int) error {
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return err
	}
	defer clearTunnelSettingsMap(settings)
	// A provider normalizer may replace/delete values; keep every old allocation
	// alive until cleanup, including passwords removed when enabling SSO.
	for _, value := range settings {
		defer vault.Wipe(value)
	}
	if kind < 0 || kind > 9 || validateTunnelSettings(int64(kind), settings) != nil {
		return vaultwire.ErrProtocol
	}
	return nil
}

func (h *vaultFoundationHandler) tunnel(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	var result any
	var err error
	switch operation {
	case "tunnel-list":
		var after string
		var limit int
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"after": &after, "limit": &limit}, "after", "limit") != nil || (after != "" && !vaultCredentialID(after)) || limit < 1 || limit > 128 {
			return nil, vaultwire.ErrProtocol
		}
		var values []vaultstore.Tunnel
		values, err = h.owner.ListTunnels(ctx, after, limit)
		views := make([]vaultTunnelView, 0, len(values))
		for _, v := range values {
			views = append(views, tunnelView(v))
		}
		result = struct {
			Tunnels []vaultTunnelView `json:"tunnels"`
		}{views}
	case "tunnel-read", "tunnel-delete":
		var id, version string
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) {
			return nil, vaultwire.ErrProtocol
		}
		revision, e := vaultCredentialRevision(version, operation == "tunnel-read")
		if e != nil || (operation == "tunnel-delete" && revision == math.MaxInt64) {
			return nil, vaultwire.ErrProtocol
		}
		if operation == "tunnel-read" {
			var value vaultstore.Tunnel
			value, err = h.owner.ReadTunnel(ctx, id, revision)
			result = tunnelView(value)
		} else {
			err = h.owner.DeleteTunnel(ctx, id, revision)
			result = struct {
				ID         string `json:"id"`
				RowVersion string `json:"rowVersion"`
				Deleted    bool   `json:"deleted"`
			}{id, strconv.FormatUint(revision+1, 10), true}
		}
	case "tunnel-save":
		var metadata, raw json.RawMessage
		var version string
		e := decodeVaultObject(payload, map[string]any{"metadata": &metadata, "configuration": &raw, "rowVersion": &version}, "metadata", "rowVersion")
		defer vault.Wipe(metadata)
		defer vault.Wipe(raw)
		if e != nil {
			return nil, e
		}
		revision, e := vaultCredentialRevision(version, true)
		if e != nil || revision == math.MaxInt64 {
			return nil, vaultwire.ErrProtocol
		}
		var m vaultstore.TunnelMetadata
		if len(metadata) > 4096 || decodeVaultObject(metadata, map[string]any{"id": &m.ID, "name": &m.Name, "kind": &m.Kind}, "id", "name", "kind") != nil || m.Validate() != nil {
			return nil, vaultwire.ErrProtocol
		}
		var configuration []byte
		if raw != nil {
			configuration, e = decodeVaultTunnelConfiguration(raw, m.Kind)
			defer vault.Wipe(configuration)
			if e != nil {
				return nil, e
			}
		}
		if revision == 0 && configuration == nil {
			return nil, vaultwire.ErrProtocol
		}
		if m.Kind == 9 && configuration != nil {
			settings, e := decodeVaultTunnelSettings(configuration)
			if e != nil {
				return nil, e
			}
			e = h.validateVaultIPsecFallback(ctx, m.ID, settings)
			clearTunnelSettingsMap(settings)
			if e != nil {
				return nil, e
			}
		}
		var value vaultstore.Tunnel
		value, err = h.owner.PutTunnel(ctx, m, configuration, revision)
		result = tunnelView(value)
	default:
		return nil, vaultwire.ErrProtocol
	}
	return h.domainResult(result, err)
}
