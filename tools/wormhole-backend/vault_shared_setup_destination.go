package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedSetupDestination struct {
	owner   *vaultFoundationHandler
	release func()
}

func (d *sharedSetupDestination) closeOwner() error {
	if d.owner == nil {
		return nil
	}
	if err := d.owner.Close(); err != nil {
		return err
	}
	d.owner = nil
	return nil
}

func (d *sharedSetupDestination) close() error {
	if err := d.closeOwner(); err != nil {
		return err
	}
	d.release()
	return nil
}

// Select only after a live destination admission. The local native owner and
// its files remain independent until the application performs normal shutdown.
func (h *vaultFoundationHandler) selectLocalSharedDestination(ctx context.Context, input sharedInitialJoinInput) (result json.RawMessage, err error) {
	if ctx == nil || h.closed || h.owner == nil || h.sharedDestination != nil || h.sharedSelection != nil || !input.valid() {
		return nil, vaultwire.ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := localSharedWorkspaceDatabase(h.databasePath)
	directory := filepath.Dir(target)
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errSharedTrustStorage
	}
	identity, err := captureInitialJoinDirectory(directory)
	if err != nil {
		return nil, err
	}
	release, err := tryAcquireExclusiveFileLock(target + ".vault.lock")
	if err != nil {
		return nil, errWorkspaceInUse
	}
	destination := &vaultFoundationHandler{databasePath: target, userDataPath: h.userDataPath, sharedProtection: h.sharedProtection,
		sharedFactory: h.sharedFactory, sharedInvitationFactory: h.sharedInvitationFactory, sharedContinuationFactory: h.sharedContinuationFactory}
	owner := &sharedSetupDestination{owner: destination, release: release}
	h.sharedDestination = owner
	defer func() {
		if closeErr := owner.close(); closeErr != nil {
			result, err = nil, h.retire(errors.Join(err, closeErr))
		} else {
			h.sharedDestination = nil
		}
	}()
	if _, err := destination.admitSharedSetupDestination(ctx, input); err != nil {
		return nil, err
	}
	admitted := destination.shared
	if admitted == nil || admitted.selected == nil || admitted.controller == nil || !admitted.controller.Unlocked() {
		return nil, sharedpg.ErrSessionClosed
	}
	if input.importPlan != nil {
		if err := admitted.controller.publishSetupWorkspaceImport(ctx, h.owner, input.importPlan); err != nil {
			return nil, err
		}
	}
	anchor, err := readSharedStartupAnchor(sharedWorkspaceTrustPath(target), h.startupProtection())
	if err != nil || anchor.Binding != admitted.selected.options.Binding || anchor.VaultID != admitted.vaultID || anchor.FileID != admitted.fileID {
		return nil, errSharedTrustStorage
	}
	if err := owner.closeOwner(); err != nil {
		return nil, h.retire(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if current, err := captureInitialJoinDirectory(directory); err != nil || !os.SameFile(identity, current) {
		return nil, errSharedTrustConflict
	}
	if err := publishSharedWorkspaceSelection(h.databasePath, anchor, h.startupProtection()); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"switchOnRestart":true}`), nil
}

func (h *vaultFoundationHandler) admitSharedSetupDestination(ctx context.Context, input sharedInitialJoinInput) (json.RawMessage, error) {
	i := input.invitation.Enrollment.Context
	trustPath := sharedWorkspaceTrustPath(h.databasePath)
	slots, pending, err := h.describeSharedJoinStartup(ctx)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		join, err := readSharedJoinStartup(trustPath, h.startupProtection())
		if err != nil || join.Binding.WorkspaceID != i.WorkspaceID || join.Binding.UserID != i.UserID {
			return nil, sharedpg.ErrTrustState
		}
		operation := "shared-recover-enrollment"
		if pending.CanContinue {
			operation = "shared-continue-enrollment"
		}
		return h.unlockSharedSetupDestination(ctx, operation, slots, input)
	}
	slots, existing, err := h.describeSharedStartup(ctx)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		anchor, err := readSharedStartupAnchor(trustPath, h.startupProtection())
		if err != nil || anchor.Binding.WorkspaceID != i.WorkspaceID || anchor.Binding.UserID != i.UserID {
			return nil, sharedpg.ErrTrustState
		}
		return h.unlockSharedSetupDestination(ctx, "shared-unlock", slots, input)
	}
	return h.joinSharedInitialInput(ctx, input)
}

func (h *vaultFoundationHandler) unlockSharedSetupDestination(ctx context.Context, operation string, slots *vault.SlotFileDescriptor, input sharedInitialJoinInput) (json.RawMessage, error) {
	if slots != nil {
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				factors := vaultUnlockInput{VaultID: slots.VaultID, SlotID: slot.ID, Password: input.password, ASK: input.ask}
				return h.openSharedInput(ctx, operation, factors, input.appVersion, input.code, false, "")
			}
		}
	}
	return nil, sharedpg.ErrTrustState
}
