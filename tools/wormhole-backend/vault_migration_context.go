package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Native/protected-dialog-only hints. They do not select an authentication mode
// or authorize source access: begin freshly verifies the actual protected store.
func (h *vaultFoundationHandler) migrationSetupContext(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner != nil || h.shared != nil || h.enrollment != nil || h.databasePath == "" || len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if err := requireLegacyWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	info, err := os.Lstat(h.databasePath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, vault.ErrPolicy
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil || floor != vault.Default && floor != vault.Standard {
		return nil, vault.ErrPolicy
	}
	document, err := readLegacyMigrationAuth(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	methods := []string{}
	if document.Password != nil {
		methods = append(methods, "password")
	}
	if document.Pin != nil {
		methods = append(methods, "pin")
	}
	if len(methods) == 0 {
		methods = append(methods, "none")
	}
	return json.Marshal(struct {
		Methods []string `json:"methods"`
	}{methods})
}
