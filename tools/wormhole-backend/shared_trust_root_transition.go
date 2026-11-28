package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var (
	errSharedTrustTransitionPending           = errors.New("shared_workspace_password_transition_pending")
	errSharedTrustTransitionCleanup           = errors.New("shared_workspace_password_transition_cleanup_unconfirmed")
	errSharedDevicePasswordTransitionRequired = errors.New("shared_device_password_transition_required")
)

func sharedTrustTransitionPath(path string) string { return path + ".password-change" }

// Called under the same file lock used by staging/promotion. Freeze the exact
// old snapshot until the remote outcome has been reconciled.
func requireNoSharedTrustTransition(path string) error {
	_, err := os.Lstat(sharedTrustTransitionPath(path))
	if err == nil {
		return errSharedTrustTransitionPending
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustStorage
	}
	return nil
}

func readSharedTrustRootTransition(path string, newRoot []byte, binding sharedpg.TrustBinding) (sharedpg.TrustRootTransition, error) {
	raw, err := readSharedTrustBytes(sharedTrustTransitionPath(path), sharedpg.MaxTrustRootTransitionBytes)
	if err != nil {
		return sharedpg.TrustRootTransition{}, err
	}
	return sharedpg.OpenTrustRootTransition(newRoot, binding, raw)
}

// The returned record is also returned on uncertain staging durability, so the
// caller can confirm the exact expected record. Never submit SQL until staging
// or confirmation succeeds. Existing pending work must be reconciled, not replaced.
func stageSharedTrustRootTransition(path string, oldRoot, newRoot []byte, binding sharedpg.TrustBinding, expectedRevision uint64) (sharedpg.TrustRootTransition, error) {
	return stageSharedTrustRootTransitionWithDevice(path, oldRoot, newRoot, binding, expectedRevision, nil)
}

func stageSharedTrustRootTransitionWithDevice(path string, oldRoot, newRoot []byte, binding sharedpg.TrustBinding, expectedRevision uint64, device *sharedDevicePasswordCandidate) (sharedpg.TrustRootTransition, error) {
	if !filepath.IsAbs(path) {
		return sharedpg.TrustRootTransition{}, errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return sharedpg.TrustRootTransition{}, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(path); err != nil {
		return sharedpg.TrustRootTransition{}, err
	}
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return sharedpg.TrustRootTransition{}, err
	}
	// Legacy trust/setup-only journals cannot update a device password slot.
	// Refuse dispatch until its candidate is included in a recoverable transition.
	if device == nil {
		if _, err := os.Lstat(sharedDeviceEnrollmentPath(path)); err == nil {
			return sharedpg.TrustRootTransition{}, errSharedDevicePasswordTransitionRequired
		} else if !errors.Is(err, os.ErrNotExist) {
			return sharedpg.TrustRootTransition{}, errSharedTrustStorage
		}
	}
	previous, err := readSharedTrustBytes(path, sharedpg.MaxTrustStateBytes)
	if err != nil {
		return sharedpg.TrustRootTransition{}, err
	}
	setup, setupErr := readSharedTrustBytes(sharedTransportSetupPath(path), sharedpg.MaxTransportSnapshotBytes*2)
	var record sharedpg.TrustRootTransition
	var raw []byte
	if setupErr != nil && !errors.Is(setupErr, errSharedTrustMissing) {
		return sharedpg.TrustRootTransition{}, setupErr
	}
	if device != nil {
		previousDevice, e := readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
		if e != nil {
			return sharedpg.TrustRootTransition{}, e
		}
		record, raw, err = sharedpg.PrepareTrustRootTransitionWithDevice(oldRoot, newRoot, binding, previous, setup, device.storageRoot, previousDevice, device.next, device.vaultID, device.fileID, device.minimumSequence, expectedRevision)
	} else if errors.Is(setupErr, errSharedTrustMissing) {
		record, raw, err = sharedpg.PrepareTrustRootTransition(oldRoot, newRoot, binding, previous, expectedRevision)
	} else {
		record, raw, err = sharedpg.PrepareTrustRootTransitionWithSetup(oldRoot, newRoot, binding, previous, setup, expectedRevision)
	}
	if err != nil {
		return sharedpg.TrustRootTransition{}, err
	}
	return record, persistSharedTransitionBytes(sharedTrustTransitionPath(path), raw)
}

func persistSharedTransitionBytes(path string, raw []byte) error {
	if err := writePrivateFileAtomic(path, raw); err != nil {
		if privateFileDestinationWasReplaced(err) {
			return errSharedTrustCommitUncertain
		}
		return errSharedTrustStorage
	}
	return nil
}

func transitionBaseMatches(path string, record sharedpg.TrustRootTransition) error {
	raw, err := readSharedTrustBytes(path, sharedpg.MaxTrustStateBytes)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], record.PreviousDigest) {
		return errSharedTrustConflict
	}
	return nil
}

func confirmSharedTrustRootTransition(path string, newRoot []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustRootTransition) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	raw, err := readSharedTrustBytes(sharedTrustTransitionPath(path), sharedpg.MaxTrustRootTransitionBytes)
	if err != nil {
		return err
	}
	actual, err := sharedpg.OpenTrustRootTransition(newRoot, binding, raw)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errSharedTrustConflict
	}
	if err := transitionBaseMatches(path, actual); err != nil {
		return err
	}
	if err := transitionSetupMatches(path, actual, false); err != nil {
		return err
	}
	if err := transitionDeviceMatches(path, actual, false); err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedTrustTransitionPath(path), raw)
}

// Promotion is local only: the caller must first prove the remote password change
// committed (or reconcile an uncertain outcome). A pending record is NOT proof.
// Retrying promotion confirms local durability; it never retries a remote mutation.
func promoteSharedTrustRootTransition(path string, newRoot []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustRootTransition) error {
	return finishSharedTrustRootTransition(path, newRoot, newRoot, binding, expected, true)
}

// Reconciliation-only abort preserves signed observations under the original
// root before deleting the journal. The caller has independently proved noncommit.
func rollbackSharedTrustRootTransition(path string, newRoot, oldRoot []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustRootTransition) error {
	return finishSharedTrustRootTransition(path, newRoot, oldRoot, binding, expected, false)
}

func finishSharedTrustRootTransition(path string, journalRoot, destinationRoot []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustRootTransition, committed bool) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	var target sharedpg.TrustState
	var err error
	if committed {
		target, err = expected.PromotionState(binding)
	} else {
		target, err = expected.AbortState(binding)
	}
	if err != nil {
		return errSharedTrustConflict
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	actual, err := readSharedTrustRootTransition(path, journalRoot, binding)
	if errors.Is(err, errSharedTrustMissing) {
		// The prior attempt may have deleted the journal but failed directory sync.
		current, e := readSharedTrustFile(path, destinationRoot, binding, target.Revision)
		if e != nil || !reflect.DeepEqual(current, target) {
			return errSharedTrustConflict
		}
	} else {
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, expected) {
			return errSharedTrustConflict
		}
		if err := transitionBaseMatches(path, actual); err != nil {
			if err != errSharedTrustConflict {
				return err
			}
			current, e := readSharedTrustFile(path, destinationRoot, binding, actual.Previous.Revision)
			if e != nil || !actual.AcceptsDestination(binding, current, committed) {
				return errSharedTrustConflict
			}
		} else if !committed {
			current, e := readSharedTrustFile(path, destinationRoot, binding, actual.Previous.Revision)
			if e != nil || !reflect.DeepEqual(current, actual.Previous) {
				return errSharedTrustConflict
			}
		}
	}
	if err := transitionSetupMatches(path, expected, committed); err != nil {
		return err
	}
	if err := transitionDeviceMatches(path, expected, committed); err != nil {
		return err
	}
	if committed && expected.Device != nil {
		if err := persistSharedTransitionBytes(sharedDeviceEnrollmentPath(path), expected.Device.Next); err != nil {
			return err
		}
	}
	if committed && expected.Transport != nil {
		raw, err := expected.TransportCiphertext(destinationRoot, binding)
		if err != nil {
			return err
		}
		if err := persistSharedTransitionBytes(sharedTransportSetupPath(path), raw); err != nil {
			return err
		}
	}
	if err := persistSharedTrustFile(path, destinationRoot, binding, target); err != nil {
		return err
	}
	return removeSharedTrustTransition(path)
}

// Abort is valid only before SQL dispatch or after proof that it did not commit.
// It cannot erase a journal once the local destination has been promoted.
func abortSharedTrustRootTransition(path string, newRoot []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustRootTransition) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	// Observation-bearing records need rollbackSharedTrustRootTransition and the
	// old root so their authenticated floors survive journal deletion.
	if expected.Observed != nil {
		return errSharedTrustConflict
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := transitionDeviceMatches(path, expected, false); err != nil {
		return err
	}
	if err := transitionSetupMatches(path, expected, false); err != nil {
		return err
	}
	actual, err := readSharedTrustRootTransition(path, newRoot, binding)
	if errors.Is(err, errSharedTrustMissing) {
		// A previous abort may have removed the journal without confirming the
		// directory sync. Confirm only the unchanged source, never a promoted file.
		if err := transitionBaseMatches(path, expected); err != nil {
			return err
		}
		return removeSharedTrustTransition(path)
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errSharedTrustConflict
	}
	if err := transitionBaseMatches(path, actual); err != nil {
		return err
	}
	return removeSharedTrustTransition(path)
}

func removeSharedTrustTransition(path string) error {
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustTransitionCleanup
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return errSharedTrustTransitionCleanup
	}
	return nil
}
