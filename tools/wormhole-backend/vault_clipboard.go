package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/secretclipboard"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// The UI selects a field, never plaintext or a TTL. Native resolution checks the
// exact revision again; policy and fresh authentication govern every copy.
func (h *vaultFoundationHandler) copyCredential(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 512 {
		return nil, vaultwire.ErrProtocol
	}
	var id, version, field string
	if decodeVaultObject(raw, map[string]any{"nodeId": &id, "rowVersion": &version, "field": &field}, "nodeId", "rowVersion", "field") != nil || !vaultCredentialID(id) || (field != "username" && field != "domain" && field != "secret") {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, false)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	ttl, err := h.clipboardTTL(ctx)
	if err != nil {
		return nil, err
	}
	err = h.owner.CopyConnectionCredential(ctx, id, revision, field, func(value []byte) error {
		return h.writeNativeClipboard(ctx, value, ttl)
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ExpiresInSeconds int `json:"expiresInSeconds"`
	}{int(ttl / time.Second)})
}

func (h *vaultFoundationHandler) writeNativeClipboard(ctx context.Context, value []byte, ttl time.Duration) error {
	if h.clipboard == nil {
		driver, err := secretclipboard.NewNative()
		if err != nil {
			return err
		}
		h.clipboard = secretclipboard.New(driver)
	}
	return h.clipboard.Copy(ctx, value, ttl)
}

// Both native clipboard publication and Linux sealed release use this policy.
func (h *vaultFoundationHandler) clipboardTTL(ctx context.Context) (time.Duration, error) {
	profile, err := h.owner.ReadSecurityProfile(ctx)
	if err != nil {
		return 0, err
	}
	return vaultClipboardLifetime(profile.Effective)
}

func vaultClipboardLifetime(profile vault.Profile) (time.Duration, error) {
	switch profile {
	case vault.Default:
		return 30 * time.Second, nil
	case vault.Standard:
		return 20 * time.Second, nil
	default:
		return 0, vault.ErrPolicy
	}
}
