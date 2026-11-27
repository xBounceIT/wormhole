package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var errSharedInvitationPreparationCleanup = errors.New("shared_invitation_preparation_cleanup_unconfirmed")

// Native attempt metadata only, never a root/verifier/master. Ownership flags are
// set only when this attempt published a destination, including uncertain sync.
type sharedJoinPreparation struct {
	options                  sharedAdmissionOptions
	pending                  sharedpg.PendingEnrollment
	setupOwned, pendingOwned bool
	deviceRaw                []byte // exact ciphertext/slots only; nonempty proves this attempt published it
	startup                  *sharedJoinStartup
	startupProtection        *sharedStartupProtection
	directory                os.FileInfo // atomic publication identity, never a pathname assertion
}

// DiscardPreparation retries only local cleanup for this retained, never-submitted
// owner. It cannot clear an unknown remote outcome or adopt another attempt's files.
// The caller supplies its still-unlocked root; the owner does not retain that key.
func (j *sharedInvitationJoin) DiscardPreparation(ctx context.Context, root []byte) error {
	return j.discardDevicePreparation(ctx, root, nil)
}

// DiscardDevicePreparation retries never-submitted cleanup with both separately
// unlocked roots. Neither is retained after this call.
func (j *sharedInvitationJoin) DiscardDevicePreparation(ctx context.Context, root, storageRoot []byte) error {
	if len(storageRoot) != 32 {
		return sharedpg.ErrConfiguration
	}
	return j.discardDevicePreparation(ctx, root, storageRoot)
}

func (j *sharedInvitationJoin) discardDevicePreparation(ctx context.Context, root, storageRoot []byte) error {
	if ctx == nil || len(root) != 32 {
		return sharedpg.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := takeSharedAdmissionGate(ctx, j.gate); err != nil {
		return err
	}
	defer func() { <-j.gate }()
	if j.submitted {
		return errSharedTrustConflict
	}
	return j.discardPreparationWithDeviceLocked(root, storageRoot)
}

func (j *sharedInvitationJoin) discardPreparationWithDeviceLocked(root, storageRoot []byte) error {
	p := j.preparation
	if p == nil || (!p.setupOwned && !p.pendingOwned && len(p.deviceRaw) == 0 && p.startup == nil) {
		j.preparation = nil
		return nil
	}
	o := p.options
	if p.directory != nil {
		actual, err := captureInitialJoinDirectory(filepath.Dir(o.TrustPath))
		if err != nil || !os.SameFile(actual, p.directory) {
			return errSharedTrustConflict
		}
	}
	if len(p.deviceRaw) != 0 && len(storageRoot) != 32 {
		return sharedpg.ErrConfiguration
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(o.TrustPath); err != nil {
		return err
	}
	// Validate all owned destinations before deleting any. A competing observation,
	// unknown pending record, wrong root or changed configuration is never erased.
	startupExists := false
	if p.startup != nil {
		if p.startupProtection == nil {
			return errSharedTrustStorage
		}
		actual, e := readSharedJoinStartup(o.TrustPath, *p.startupProtection)
		if !errors.Is(e, errSharedTrustMissing) {
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(actual, *p.startup) {
				return errSharedTrustConflict
			}
			startupExists = true
		}
	}
	pendingExists := false
	if p.pendingOwned {
		actual, e := readSharedPendingEnrollment(o.TrustPath, root, o.Binding)
		if !errors.Is(e, errSharedTrustMissing) {
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(actual, p.pending) {
				return errSharedTrustConflict
			}
			pendingExists = true
		}
	} else if err := requireNoSharedPendingEnrollment(o.TrustPath); err != nil {
		return err
	}
	setupExists := false
	if p.setupOwned {
		current := p.pending.ObservedTrust()
		actual, e := readSharedTransportSetup(o, root, current)
		if !errors.Is(e, errSharedTrustMissing) {
			if e != nil {
				return e
			}
			encoded, e := sharedpg.EncodeTransportSnapshot(actual, current, o.OSFloor, o.UserFloor, o.Request.API)
			if e != nil {
				return e
			}
			expected, e := sharedpg.EncodeTransportSnapshot(o.Settings, current, o.OSFloor, o.UserFloor, o.Request.API)
			if e != nil {
				return e
			}
			if !bytes.Equal(encoded, expected) {
				return errSharedTrustConflict
			}
			setupExists = true
		}
	} else if len(p.deviceRaw) != 0 {
		_, e := os.Lstat(sharedTransportSetupPath(o.TrustPath))
		if e == nil {
			return errSharedTrustConflict
		}
		if !errors.Is(e, os.ErrNotExist) {
			return errSharedTrustStorage
		}
	}
	deviceExists := false
	if len(p.deviceRaw) != 0 {
		slots, envelope, e := sharedpg.DecodeDeviceEnrollmentFile(p.deviceRaw)
		if e != nil {
			return e
		}
		metadata, e := sharedpg.OpenDeviceEnrollment(storageRoot, slots, slots.VaultID, slots.FileID, slots.Sequence, envelope)
		if e != nil {
			return e
		}
		if metadata.Binding() != o.Binding {
			return errSharedTrustConflict
		}
		actual, e := readSharedTrustBytes(sharedDeviceEnrollmentPath(o.TrustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
		if !errors.Is(e, errSharedTrustMissing) {
			if e != nil {
				return e
			}
			if !bytes.Equal(actual, p.deviceRaw) {
				return errSharedTrustConflict
			}
			deviceExists = true
		}
	}
	if pendingExists {
		if err := os.Remove(sharedPendingEnrollmentPath(o.TrustPath)); err != nil {
			return errSharedInvitationPreparationCleanup
		}
	}
	if setupExists {
		if err := os.Remove(sharedTransportSetupPath(o.TrustPath)); err != nil {
			return errSharedInvitationPreparationCleanup
		}
	}
	if deviceExists {
		if err := os.Remove(sharedDeviceEnrollmentPath(o.TrustPath)); err != nil {
			return errSharedInvitationPreparationCleanup
		}
	}
	if startupExists {
		if err := os.Remove(sharedJoinStartupPath(o.TrustPath)); err != nil {
			return errSharedInvitationPreparationCleanup
		}
	}
	// Even absent files need a directory sync after a previous uncertain cleanup.
	if err := privateFileDirectorySync(filepath.Dir(o.TrustPath)); err != nil {
		return errSharedInvitationPreparationCleanup
	}
	j.preparation = nil
	return nil
}
