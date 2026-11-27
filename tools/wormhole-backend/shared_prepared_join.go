package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedInitialEnrollment interface {
	Borrow(func(*sharedpg.AccountMaster, *sharedpg.DeviceTrustRoot, *sharedpg.PreparedInvitationCommit) error) error
	BorrowDeviceStorage(func([]byte, vault.SlotFile, []byte) error) error
}

// Only an invocation-local view of borrowed native memory. Never retain it in
// the coordinator or its public cleanup metadata.
type sharedJoinDeviceStorage struct {
	root     []byte
	slots    vault.SlotFile
	envelope []byte
	startup  *sharedStartupProtection
}

// JoinPrepared claims this owner before borrowing preparation or writing files.
// Native preparation remains caller-owned; retain it if local cleanup needs
// retry, and Close it after use. No caller identity overrides the prepared device.
func (j *sharedInvitationJoin) JoinPrepared(ctx context.Context, o sharedAdmissionOptions, prepared *sharedpg.PreparedInitialEnrollment) (*sharedInvitationJoinResult, error) {
	protection := nativeSharedStartupProtection()
	return j.joinPreparedWithStartup(ctx, o, prepared, &protection)
}

func (j *sharedInvitationJoin) joinPrepared(ctx context.Context, o sharedAdmissionOptions, prepared sharedInitialEnrollment) (*sharedInvitationJoinResult, error) {
	return j.joinPreparedWithStartup(ctx, o, prepared, nil)
}

func (j *sharedInvitationJoin) joinPreparedWithStartup(ctx context.Context, o sharedAdmissionOptions, prepared sharedInitialEnrollment, protection *sharedStartupProtection) (*sharedInvitationJoinResult, error) {
	if ctx == nil || !filepath.IsAbs(o.TrustPath) || prepared == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return j.runJoin(ctx, func(ctx context.Context) (result *sharedInvitationJoinResult, err error) {
		err = prepared.BorrowDeviceStorage(func(storageRoot []byte, slots vault.SlotFile, envelope []byte) error {
			return prepared.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, commit *sharedpg.PreparedInvitationCommit) error {
				if master == nil || root == nil || commit == nil {
					return sharedpg.ErrConfiguration
				}
				o.Binding = root.Binding()
				o.MinimumRevision = 1
				o.Request.WorkspaceID, o.Request.UserID, o.Request.DeviceID = o.Binding.WorkspaceID, o.Binding.UserID, o.Binding.DeviceID
				if o.Request.Validate() != nil {
					return sharedpg.ErrConfiguration
				}
				return root.Use(func(key []byte) error {
					var e error
					result, e = j.joinLocked(ctx, o, key, master, commit, &sharedJoinDeviceStorage{storageRoot, slots, envelope, protection})
					return e
				})
			})
		})
		return result, err
	})
}

func (j *sharedInvitationJoin) stageDeviceLocked(o sharedAdmissionOptions, device *sharedJoinDeviceStorage) error {
	metadata, err := sharedpg.OpenDeviceEnrollment(device.root, device.slots, device.slots.VaultID, device.slots.FileID, device.slots.Sequence, device.envelope)
	if err != nil {
		return err
	}
	if metadata.Binding() != o.Binding {
		return sharedpg.ErrConfiguration
	}
	raw, err := stageSharedDeviceEnrollment(o.TrustPath, device.root, device.slots, device.envelope)
	if err == nil || errors.Is(err, errSharedTrustCommitUncertain) {
		j.preparation.deviceRaw = raw
	}
	if err != nil && !errors.Is(err, errSharedTrustCommitUncertain) {
		return err
	}
	return confirmSharedDeviceEnrollment(o.TrustPath, device.root, device.slots.VaultID, device.slots.FileID, device.slots.Sequence, raw)
}

func (j *sharedInvitationJoin) confirmDeviceWithIntentLocked(o sharedAdmissionOptions, root []byte, device *sharedJoinDeviceStorage, pending sharedpg.PendingEnrollment) error {
	return confirmSharedDeviceEnrollmentState(o.TrustPath, device.root, device.slots.VaultID, device.slots.FileID, device.slots.Sequence, j.preparation.deviceRaw, func() error {
		actual, err := readSharedPendingEnrollment(o.TrustPath, root, o.Binding)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, pending) {
			return errSharedTrustConflict
		}
		return nil
	})
}
