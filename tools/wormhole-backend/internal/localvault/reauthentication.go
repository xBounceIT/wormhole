package localvault

import (
	"context"
	"crypto/hmac"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// A wrong factor is recoverable. A failed checkpoint/policy authentication is
// not: callers must retire the owner for other authentication failures.
var ErrReauthentication = errors.New("vault_reauthentication_rejected")

// VerifyReauthentication borrows factors and never exports the resident root.
// It authenticates the current slot document before running its KDF. Success is
// scoped to the caller's single pending action; it creates no reusable grant.
func (o *Owner) VerifyReauthentication(ctx context.Context, document vault.SlotFile, slotID string, password, recovery, ask []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return vaultstore.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	i := o.store.Identity()
	if document.RootKeyID != i.Root.ID || document.RootKeyVersion != i.Root.Version || document.Encrypted != o.encrypted || document.Initializing || document.Migration != nil || document.Rotation != nil {
		return vault.ErrAuthentication
	}
	if err := o.root.With(func(root []byte) error {
		return vault.VerifySlotFile(root, document, i.WorkspaceID, i.FileID, o.slotFloor)
	}); err != nil {
		return err
	}
	o.slotFloor = document.Sequence
	o.profileFloor = max(o.profileFloor, document.ProfileSequence)
	p, _, err := o.readLocalPolicy(ctx)
	if err != nil {
		return err
	}
	if _, err := o.checkSecurityProfile(ctx, p, document); err != nil {
		return err
	}
	o.rememberSecuritySlots(document.Slots)
	var selected *vault.Slot
	for j := range document.Slots {
		if document.Slots[j].ID == slotID {
			selected = &document.Slots[j]
			break
		}
	}
	if selected == nil {
		return ErrReauthentication
	}
	var key []byte
	switch selected.Kind {
	case vault.SlotPassword:
		if len(password) < 1 || len(password) > 1024 || len(recovery) != 0 || (len(ask) != 0 && len(ask) != 32) {
			return ErrReauthentication
		}
		key, err = vault.OpenPasswordSlot(ctx, document.VaultID, *selected, password, ask)
	case vault.SlotRecovery:
		if len(password) != 0 || len(recovery) != 32 || len(ask) != 0 {
			return ErrReauthentication
		}
		key, err = vault.OpenRecoverySlot(document.VaultID, *selected, recovery)
	default:
		return ErrReauthentication
	}
	defer vault.Wipe(key)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrReauthentication
	}
	return o.root.With(func(root []byte) error {
		if !hmac.Equal(root, key) {
			return ErrReauthentication
		}
		return nil
	})
}
