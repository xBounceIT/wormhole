package main

import (
	"context"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// OpenAccount binds the derivation owner's native facts to admission and unlock.
// AccountMaster and the authenticated enrollment root remain caller-owned; close
// the master immediately after this operation. No master is retained by the
// controller, which owns only its protected trust root and unlocked private pair.
func (c *sharedAdmissionController) OpenAccount(ctx context.Context, o sharedAdmissionOptions, root []byte, account *sharedpg.AccountMaster) error {
	return c.openAccount(ctx, o, root, account, false)
}

// OpenAccountFromSetup reopens an enrolled device using its protected endpoint.
// The root and binding must already be independently unlocked by native code.
// Caller Settings are ignored; current local floors and API requirements apply.
func (c *sharedAdmissionController) OpenAccountFromSetup(ctx context.Context, o sharedAdmissionOptions, root []byte, account *sharedpg.AccountMaster) error {
	return c.openAccount(ctx, o, root, account, true)
}

func (c *sharedAdmissionController) openAccount(ctx context.Context, o sharedAdmissionOptions, root []byte, account *sharedpg.AccountMaster, fromSetup bool) error {
	if account == nil || account.WorkspaceID() != o.Binding.WorkspaceID {
		return sharedpg.ErrConfiguration
	}
	opened := false
	err := account.Use(func(master []byte, preset vault.KDFPreset, askUsed bool) error {
		material, err := vault.DeriveKey(master, nil, vault.PurposeLogin)
		if err != nil {
			return err
		}
		defer vault.Wipe(material)
		if err := c.openWithDerivationSource(ctx, o, root, material, &sharedAccountDerivationFacts{preset: preset, askUsed: askUsed}, fromSetup); err != nil {
			return err
		}
		opened = true
		return c.Unlock(ctx, master, preset, askUsed)
	})
	if err != nil && opened {
		return errors.Join(err, c.Close(context.Background()))
	}
	if err == nil && !account.Locked() {
		c.memoryLockWarning.Store(true)
	}
	return err
}

// RecoverAccount uses the same derived owner without accepting separate preset
// or ASK assertions. Its result retains the remote-outcome/local-error semantics
// of RecoverPasswordChange. Close account after return, including error outcomes.
func (c *sharedAdmissionController) RecoverAccount(ctx context.Context, o sharedAdmissionOptions, account *sharedpg.AccountMaster, newRoot, oldRoot []byte, credential sharedPasswordRecoveryCredential) (result *sharedPasswordRecoveryResult, err error) {
	if account == nil || account.WorkspaceID() != o.Binding.WorkspaceID {
		return nil, sharedpg.ErrConfiguration
	}
	err = account.Use(func(master []byte, preset vault.KDFPreset, askUsed bool) error {
		var e error
		result, e = c.RecoverPasswordChange(ctx, o, master, newRoot, oldRoot, preset, askUsed, credential)
		return e
	})
	return result, err
}

// ChangeDeviceAccountPassword accepts only an aggregate prepared from the same
// native factors as its candidate. Both owners stay caller-owned for cleanup.
func (c *sharedAdmissionController) ChangeDeviceAccountPassword(ctx context.Context, previous, prepared *sharedpg.UnlockedDeviceAccount, source string) (receipt *sharedpg.PasswordChangeReceipt, err error) {
	if ctx == nil {
		return nil, sharedpg.ErrConfiguration
	}
	err = prepared.BorrowPasswordChange(previous, func(old, next *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, key, raw []byte, selection sharedpg.DeviceUnlockSelection) error {
		return root.Use(func(newRoot []byte) error {
			return old.Use(func(oldMaster []byte, oldPreset vault.KDFPreset, oldASK bool) error {
				return next.Use(func(newMaster []byte, preset vault.KDFPreset, ask bool) error {
					if preset != oldPreset || ask != oldASK {
						return sharedpg.ErrConfiguration
					}
					var e error
					receipt, e = c.ChangeDevicePassword(ctx, oldMaster, newMaster, newRoot, preset, ask, source, sharedDevicePasswordCandidate{key, raw, selection.VaultID, selection.FileID, selection.MinimumSequence})
					return e
				})
			})
		})
	})
	return receipt, err
}
