package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedDeviceOpenMode uint8

const (
	sharedDeviceOrdinary sharedDeviceOpenMode = iota + 1
	sharedDevicePasswordRecovery
)

// Native-only selection. Serialize all operations and Close. No factor, key or
// protected record from this owner belongs in a renderer response.
type sharedSelectedDevice struct {
	account *sharedpg.UnlockedDeviceAccount
	vaultID string
	options sharedAdmissionOptions
	mode    sharedDeviceOpenMode
	initial *sharedJoinStartup // protected public selection/ciphertext; never factors
}

func (s *sharedSelectedDevice) Close() error {
	if s == nil {
		return nil
	}
	return s.account.Close()
}

// The application chooses runtime.TrustPath and local floors. Identity and
// connection settings come only from protected native state. The explicit mode
// prevents falling back to ordinary admission when recovery fails.
// Always close a nonnil result, even if returned with a cleanup error.
func unlockSharedSelectedDevice(ctx context.Context, runtime sharedAdmissionOptions, slotID string, password, ask []byte, mode sharedDeviceOpenMode, protection sharedStartupProtection) (result *sharedSelectedDevice, err error) {
	if ctx == nil || !filepath.IsAbs(runtime.TrustPath) || (mode != sharedDeviceOrdinary && mode != sharedDevicePasswordRecovery) {
		return nil, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release, err := tryAcquireSharedFileLock(runtime.TrustPath + ".lock")
	if err != nil {
		return nil, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(runtime.TrustPath); err != nil {
		return nil, err
	}
	if err := requireNoSharedJoinStartup(runtime.TrustPath); err != nil {
		return nil, err
	}
	anchor, err := readSharedStartupAnchor(runtime.TrustPath, protection)
	if err != nil {
		return nil, err
	}
	policy, err := anchor.Trust.Policy()
	if err != nil {
		return nil, err
	}
	runtime.UserFloor = vault.EffectiveProfile(vault.Default, runtime.UserFloor, anchor.Trust.PersonalProfile())
	// The enrollment file can contain an older signed profile. Apply the last
	// independently trusted profile before deriving any keys from that file.
	if err := sharedAdmissionRuntimeProfile(vault.EffectiveProfile(runtime.OSFloor, policy.Profile, runtime.UserFloor)); err != nil {
		return nil, err
	}
	runtime.Binding = anchor.Binding
	runtime.Request.WorkspaceID, runtime.Request.UserID, runtime.Request.DeviceID = anchor.Binding.WorkspaceID, anchor.Binding.UserID, anchor.Binding.DeviceID
	runtime.MinimumRevision = max(runtime.MinimumRevision, anchor.Trust.Revision)
	runtime.Settings = sharedpg.Settings{}
	if runtime.Request.Validate() != nil {
		return nil, sharedpg.ErrConfiguration
	}
	selection := sharedpg.DeviceUnlockSelection{VaultID: anchor.VaultID, FileID: anchor.FileID, SlotID: slotID, MinimumSequence: anchor.MinimumSequence}
	s := &sharedSelectedDevice{vaultID: anchor.VaultID, options: runtime, mode: mode}
	defer func() {
		if err != nil {
			if cleanup := s.Close(); cleanup != nil {
				result, err = s, errors.Join(err, cleanup)
			} else {
				result = nil
			}
		}
	}()
	if mode == sharedDeviceOrdinary {
		if err = requireNoSharedTrustTransition(runtime.TrustPath); err != nil {
			return nil, err
		}
		raw, e := readSharedTrustBytes(sharedDeviceEnrollmentPath(runtime.TrustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
		if e != nil {
			return nil, e
		}
		s.account, err = sharedpg.OpenDeviceAccount(ctx, raw, selection, password, ask, runtime.OSFloor, runtime.UserFloor)
	} else {
		raw, e := readSharedTrustBytes(sharedTrustTransitionPath(runtime.TrustPath), sharedpg.MaxTrustRootTransitionBytes)
		if e != nil {
			return nil, e
		}
		s.account, err = sharedpg.OpenDeviceTransitionAccount(ctx, raw, selection, password, ask, runtime.OSFloor, runtime.UserFloor)
	}
	if err != nil {
		return nil, err
	}
	err = s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		if root.Binding() != anchor.Binding || master.LoginName() != anchor.LoginName {
			return sharedpg.ErrTrustState
		}
		if err := master.Use(func(_ []byte, preset vault.KDFPreset, askUsed bool) error {
			if preset != anchor.KDF || askUsed != anchor.ASKRequired {
				return sharedpg.ErrTrustState
			}
			return nil
		}); err != nil {
			return err
		}
		return root.Use(func(key []byte) error {
			var trust sharedpg.TrustState
			var e error
			if mode == sharedDeviceOrdinary {
				trust, e = readSharedTrustFile(runtime.TrustPath, key, anchor.Binding, runtime.MinimumRevision)
			} else {
				var pending sharedpg.TrustRootTransition
				pending, e = readSharedTrustRootTransition(runtime.TrustPath, key, anchor.Binding)
				trust = pending.ObservedTrust()
			}
			if e != nil {
				return e
			}
			if trust.Revision < runtime.MinimumRevision {
				return sharedpg.ErrTrustRollback
			}
			if reflect.DeepEqual(trust, anchor.Trust) {
				s.options.MinimumRevision = trust.Revision
				return nil
			}
			if trust.Revision <= anchor.Trust.Revision {
				return sharedpg.ErrTrustRollback
			}
			revision := trust.Revision
			trust.Revision = anchor.Trust.Revision + 1
			if err := anchor.Trust.ValidateAdvance(trust); err != nil {
				return err
			}
			s.options.UserFloor = vault.EffectiveProfile(vault.Default, runtime.UserFloor, trust.PersonalProfile())
			s.options.MinimumRevision = revision
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return s, ctx.Err()
}

func (s *sharedSelectedDevice) Open(ctx context.Context, c *sharedAdmissionController) error {
	if s == nil || c == nil || s.mode != sharedDeviceOrdinary {
		return sharedpg.ErrConfiguration
	}
	return s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error { return c.OpenAccountFromSetup(ctx, s.options, key, master) })
	})
}

func (s *sharedSelectedDevice) RecoverNewPassword(ctx context.Context, c *sharedAdmissionController) (result *sharedPasswordRecoveryResult, err error) {
	if s == nil || c == nil || s.mode != sharedDevicePasswordRecovery {
		return nil, sharedpg.ErrConfiguration
	}
	err = s.account.BorrowTransition(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, _ sharedpg.TrustRootTransition) error {
		return root.Use(func(key []byte) error {
			return master.Use(func(secret []byte, preset vault.KDFPreset, askUsed bool) error {
				var e error
				result, e = c.RecoverPasswordChangeFromSetup(ctx, s.options, secret, key, nil, preset, askUsed, sharedRecoveryNewPassword)
				return e
			})
		})
	})
	return result, err
}
