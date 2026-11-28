package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type sharedCreateSlotSession interface {
	sharedRuntimeStateSession
	CreateCredentialSlotSupported(context.Context) (bool, error)
	WorkspaceImportBoundary(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, workspaceimport.Destination) (sharedpg.TrustState, *vault.BoundaryManifest, error)
	CreateCredentialSlot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, vault.BoundaryManifest, sharedpg.AdminCredentialSlot, *vault.UserKeys) (sharedpg.TrustState, string, error)
}

func decodeSharedCreateSlot(raw []byte) (slot sharedpg.AdminCredentialSlot, err error) {
	var id string
	if len(raw) > 8192 || decodeVaultObject(raw, map[string]any{"id": &id, "name": &slot.Name, "protocol": &slot.Protocol,
		"allowSelfService": &slot.AllowSelfService}, "id", "name", "protocol", "allowSelfService") != nil || !vaultCredentialID(id) {
		return slot, vaultwire.ErrProtocol
	}
	slot.ID = uuid.MustParse(id)
	if !slot.Valid() {
		return slot, vaultwire.ErrProtocol
	}
	return slot, nil
}

func (h *vaultFoundationHandler) sharedCreateCredentialSlot(ctx context.Context, raw []byte) (json.RawMessage, error) {
	slot, err := decodeSharedCreateSlot(raw)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedCreateSlotSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	var tls *sharedpg.VerifiedTLSBundle
	var manifest *vault.BoundaryManifest
	status := "unavailable"
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		runtime, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !runtime.Administrator || !c.tlsManaged || runtime.TLS != sharedpg.TLSVerified ||
			(runtime.Security.Effective != vault.Default && runtime.Security.Effective != vault.Standard) {
			return err
		}
		supported, err := session.CreateCredentialSlotSupported(ctx)
		if err != nil || !supported {
			status = "unsupported"
			return err
		}
		tls, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		next, selected, err := session.WorkspaceImportBoundary(ctx, *pending, tls, workspaceimport.Shared)
		if next.Revision != 0 {
			*pending = next
		}
		manifest = selected
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if manifest == nil {
			return nil
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrTrustState
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			next, result, err := session.CreateCredentialSlot(ctx, trust, tls, *manifest, slot, keys)
			if next.Revision != 0 && next.Revision != trust.Revision {
				if e := c.commitCatalogTrust(trust, next); e != nil {
					return e
				}
			}
			status = result
			return err
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	if status == "saved" {
		h.notifySharedCatalog()
	}
	return json.Marshal(map[string]string{"status": status})
}
