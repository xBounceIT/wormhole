package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This source is only an untrusted descriptor until confirmation opens its OS
// factor and authenticates it inside the forward-only scope. Never open SQLite
// or adopt an ordinary Owner here, even when the machine floor is Standard.
func (h *vaultFoundationHandler) unprotectedUpgradeEnrollmentSource(ctx context.Context) (vault.SlotFile, error) {
	if !h.migrationQuiesced || h.owner != nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil || h.databasePath == "" {
		return vault.SlotFile{}, vaultwire.ErrProtocol
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return vault.SlotFile{}, err
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return vault.SlotFile{}, err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return vault.SlotFile{}, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if floor != vault.Default && floor != vault.Standard {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if doc.Initializing || doc.Encrypted || doc.Migration != nil || doc.Rotation != nil || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected || doc.RootKeyVersion == math.MaxUint32 || doc.Sequence > math.MaxUint64-vault.RootRotationSequenceSpan || doc.FileEpoch == math.MaxUint64 {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	return doc, nil
}

func (h *vaultFoundationHandler) unprotectedUpgradeSetupContext(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	doc, err := h.unprotectedUpgradeEnrollmentSource(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		VaultID string `json:"vaultId"`
	}{doc.VaultID})
}

// Only the isolated native maintenance launch admits this enrollment. The new
// password/public recipient cannot select the source, mode or policy authority.
func (h *vaultFoundationHandler) beginUnprotectedUpgradeEnrollment(ctx context.Context, payload []byte) (_ json.RawMessage, resultErr error) {
	if len(payload) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	doc, err := h.unprotectedUpgradeEnrollmentSource(ctx)
	if err != nil {
		return nil, err
	}
	var passwordJSON, publicJSON json.RawMessage
	defer func() { vault.Wipe(passwordJSON); vault.Wipe(publicJSON) }()
	if decodeVaultObject(payload, map[string]any{"password": &passwordJSON, "publicKey": &publicJSON}, "password", "publicKey") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var password, publicKey []byte
	defer func() { vault.Wipe(password); vault.Wipe(publicKey) }()
	if len(passwordJSON) == 0 || passwordJSON[0] != '"' || len(publicJSON) == 0 || publicJSON[0] != '"' || json.Unmarshal(passwordJSON, &password) != nil || json.Unmarshal(publicJSON, &publicKey) != nil || len(password) == 0 || len(password) > 1024 || len(publicKey) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	vault.Wipe(passwordJSON)
	vault.Wipe(publicJSON)
	vault.Wipe(payload)
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	retained := false
	leaseAssigned := false
	defer func() {
		if !leaseAssigned {
			release()
		}
	}()
	// A previous process may have published only its journal before releasing
	// this lease. Recheck the complete admission, not just unchanged source slots.
	current, err := h.unprotectedUpgradeEnrollmentSource(ctx)
	if err != nil {
		return nil, err
	}
	if !sameRootRotationDocument(current, doc) {
		return nil, errVaultSlotConflict
	}
	material, err := securemem.New(32+76, true)
	if err != nil {
		return nil, err
	}
	p := newRootRotationEnrollment(doc, material)
	p.unprotectedUpgrade = true
	p.release = release
	leaseAssigned = true
	defer func() {
		if !retained {
			if closeErr := p.close(); closeErr != nil {
				h.enrollment = p
				retained = true
				resultErr = h.retire(errors.Join(resultErr, closeErr))
			}
		}
	}()
	result, err := p.prepare(ctx, password, publicKey)
	if err != nil {
		return nil, err
	}
	h.enrollment = p
	retained = true
	p.arm()
	return result, nil
}
