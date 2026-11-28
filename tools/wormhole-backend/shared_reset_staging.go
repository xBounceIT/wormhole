package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var errSharedReenrollmentPending = errors.New("the registered device is waiting for account reactivation")

// The OS-protected selection and the unlocked device root must agree before
// restoring ciphertext or attempting either reset operation.
func (s *sharedSelectedDevice) reconcileAccountReset(ctx context.Context, code, ask []byte) error {
	if ctx == nil || s == nil || s.initial == nil || s.initial.FormatVersion != 4 || s.options.startupProtection == nil {
		return sharedpg.ErrConfiguration
	}
	o := s.options
	return s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
			if err != nil {
				return errSharedTrustConflict
			}
			defer release()
			if err := requireNoSharedTrustTransition(o.TrustPath); err != nil {
				return err
			}
			initial, err := readSharedJoinStartup(o.TrustPath, *o.startupProtection)
			if err != nil {
				return fmt.Errorf("read reset checkpoint: %w", err)
			}
			if !reflect.DeepEqual(initial, *s.initial) || initial.Binding != o.Binding || master.LoginName() != initial.LoginName {
				return errSharedTrustConflict
			}
			pending, err := sharedpg.OpenPendingResetDevice(key, o.Binding, initial.Pending)
			if err != nil {
				return err
			}
			current, err := readSharedTrustFile(o.TrustPath, key, o.Binding, 1)
			missingTrust := errors.Is(err, errSharedTrustMissing)
			if err != nil && !missingTrust {
				return fmt.Errorf("read reset device trust: %w", err)
			}
			missingIntent, err := restoreAccountResetPieces(ctx, o.TrustPath, initial, missingTrust)
			if err != nil {
				return fmt.Errorf("verify reset artifacts: %w", err)
			}
			if !missingTrust && missingIntent {
				if current.Enrollment == nil {
					return sharedpg.ErrTrustState
				}
				return ctx.Err()
			}

			confirm := func() (sharedpg.TrustState, error) {
				if len(pending.Certificate) != 0 {
					receipt, err := sharedpg.ReadPendingAccountReenrollmentReceipt(ctx, pending, o.Binding, master, o.OSFloor, o.UserFloor)
					if err != nil {
						return sharedpg.TrustState{}, err
					}
					if receipt.Suspended {
						return sharedpg.TrustState{}, errSharedReenrollmentPending
					}
				}
				return sharedpg.ConfirmPendingResetDevice(ctx, pending, o.Binding, master, o.OSFloor, o.UserFloor, o.Request.AppVersion)
			}
			state, err := confirm()
			if errors.Is(err, sharedpg.ErrAuthentication) && len(code) != 0 && missingTrust {
				resumed, prepareErr := sharedpg.ResumePreparedAccountReset(ctx, key, o.Binding, initial.Pending, master, code, ask, o.OSFloor, o.UserFloor)
				if prepareErr != nil {
					if resumed != nil {
						return errors.Join(prepareErr, resumed.Close())
					}
					return prepareErr
				}
				_, commitErr := resumed.Commit(ctx, func(sharedpg.PendingAccountReset) error {
					// Reconfirm the same durable pieces before the exact request is
					// resubmitted. Device and offer IDs can never be replaced.
					if _, err := restoreAccountResetPieces(ctx, o.TrustPath, initial, true); err != nil {
						return err
					}
					// Readback alone cannot settle a failed directory-rename sync.
					if err := privateFileDirectorySync(filepath.Dir(filepath.Dir(o.TrustPath))); err != nil {
						return errSharedTrustCommitUncertain
					}
					return ctx.Err()
				})
				if err := errors.Join(commitErr, resumed.Close()); err != nil {
					return err
				}
				state, err = confirm()
			}
			if err != nil {
				return err
			}
			if !missingTrust && !reflect.DeepEqual(current, state) {
				return errSharedTrustConflict
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := persistSharedTrustFile(o.TrustPath, key, o.Binding, state); err != nil {
				return fmt.Errorf("persist reset device trust: %w", err)
			}
			if err := os.Remove(sharedPendingEnrollmentPath(o.TrustPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errSharedEnrollmentCleanup
			}
			return privateFileDirectorySync(filepath.Dir(o.TrustPath))
		})
	})
}

// Called under the trust lock. A missing artifact may be restored only
// before active trust is published. Existing files always have to match.
func restoreAccountResetPieces(ctx context.Context, path string, initial sharedJoinStartup, missingTrust bool) (bool, error) {
	if missingTrust {
		// The ordinary selection owns its own trust floors. An earlier reset
		// journal cannot recreate files behind a published normal anchor.
		if _, err := os.Lstat(sharedStartupAnchorPath(path)); !errors.Is(err, os.ErrNotExist) {
			return false, errSharedTrustConflict
		}
	}
	files := []struct {
		path string
		raw  []byte
	}{
		{sharedDeviceEnrollmentPath(path), initial.DeviceFile},
		{sharedTransportSetupPath(path), initial.Transport},
		{sharedPendingEnrollmentPath(path), initial.Pending},
	}
	var missingFiles []int
	for i, file := range files {
		raw, missing, err := readSharedJoinPiece(file.path, int64(len(file.raw)))
		if err != nil {
			return false, err
		}
		if !missing {
			if !bytes.Equal(raw, file.raw) {
				return false, errSharedTrustConflict
			}
			continue
		}
		if !missingTrust {
			if i == len(files)-1 {
				return true, ctx.Err()
			}
			return false, errSharedTrustConflict
		}
		missingFiles = append(missingFiles, i)
	}
	for _, i := range missingFiles {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		file := files[i]
		if err := persistSharedTransitionBytes(file.path, file.raw); err != nil {
			return false, err
		}
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return false, errSharedTrustCommitUncertain
	}
	return false, ctx.Err()
}
