package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// Only the explicit enrollment-recovery operation uses this selection. The
// independent OS record pins the encrypted device and identity before a factor
// is derived. V2/v3 snapshots can restore missing staging after PW/ASK unlock;
// replacements remain refused and no snapshot establishes remote admission.
func unlockSharedJoiningDevice(ctx context.Context, runtime sharedAdmissionOptions, slotID string, password, ask []byte, protection sharedStartupProtection) (result *sharedSelectedDevice, err error) {
	if ctx == nil || !filepath.IsAbs(runtime.TrustPath) {
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
	if err := requireNoSharedTrustTransition(runtime.TrustPath); err != nil {
		return nil, err
	}
	initial, err := readSharedJoinStartup(runtime.TrustPath, protection)
	if err != nil {
		return nil, err
	}
	raw, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(runtime.TrustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil && !(initial.FormatVersion >= 2 && errors.Is(err, errSharedTrustMissing)) {
		return nil, err
	}
	if err == nil && !bytes.Equal(raw, initial.DeviceFile) {
		return nil, errSharedTrustConflict
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(initial.DeviceFile)
	if err != nil {
		return nil, err
	}
	runtime.Binding, runtime.MinimumRevision = initial.Binding, 1
	runtime.Request.WorkspaceID, runtime.Request.UserID, runtime.Request.DeviceID = initial.Binding.WorkspaceID, initial.Binding.UserID, initial.Binding.DeviceID
	runtime.Settings = sharedpg.Settings{}
	runtime.startupProtection = &protection
	if runtime.Request.Validate() != nil {
		return nil, sharedpg.ErrConfiguration
	}
	s := &sharedSelectedDevice{options: runtime, mode: sharedDeviceOrdinary, vaultID: slots.VaultID, initial: &initial}
	defer func() {
		if err != nil {
			if cleanup := s.Close(); cleanup != nil {
				result, err = s, errors.Join(err, cleanup)
			} else {
				result = nil
			}
		}
	}()
	s.account, err = sharedpg.OpenDeviceAccount(ctx, initial.DeviceFile, sharedpg.DeviceUnlockSelection{VaultID: slots.VaultID, FileID: slots.FileID, SlotID: slotID, MinimumSequence: slots.Sequence}, password, ask, runtime.OSFloor, runtime.UserFloor)
	if err != nil {
		return nil, err
	}
	err = s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		if root.Binding() != initial.Binding || master.LoginName() != initial.LoginName {
			return sharedpg.ErrTrustState
		}
		return ctx.Err()
	})
	return s, err
}

// A retained pending intent requires fresh native device/capsule proof. Absence
// of intent permits only already authenticated active local trust, followed by
// ordinary online admission. Neither path submits an invitation again.
func (s *sharedSelectedDevice) reconcileInitialEnrollment(ctx context.Context, c *sharedAdmissionController) error {
	if ctx == nil || s == nil || s.initial == nil || c == nil {
		return sharedpg.ErrConfiguration
	}
	return s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			if err := restoreSharedJoinStaging(ctx, s, key, master); err != nil {
				return err
			}
			_, err := readSharedPendingEnrollment(s.options.TrustPath, key, s.options.Binding)
			if errors.Is(err, errSharedTrustMissing) {
				trust, err := readSharedTrustFile(s.options.TrustPath, key, s.options.Binding, 1)
				if err != nil {
					return err
				}
				if trust.Enrollment == nil {
					return sharedpg.ErrTrustState
				}
				return ctx.Err()
			}
			if err != nil {
				return err
			}
			result, err := c.RecoverEnrollmentFromSetup(ctx, s.options, key, master)
			if err != nil {
				return err
			}
			if result == nil || !result.Confirmed {
				return sharedpg.ErrAdmissionResponse
			}
			return ctx.Err()
		})
	})
}
