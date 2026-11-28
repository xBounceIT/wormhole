package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var errSharedEnrollmentCleanup = errors.New("shared_workspace_enrollment_cleanup_unconfirmed")

// Implemented by native ConfirmedEnrollment, not by a pending/verified record.
// The interface permits file-fault tests without fabricating network credentials.
type sharedConfirmedEnrollment interface {
	ConfirmedActivation(sharedpg.TrustBinding, sharedpg.PendingEnrollment) (sharedpg.TrustState, error)
}

var _ sharedConfirmedEnrollment = (*sharedpg.ConfirmedEnrollment)(nil)

func promoteSharedEnrollment(path string, root []byte, b sharedpg.TrustBinding, expected sharedpg.PendingEnrollment, proof sharedConfirmedEnrollment) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	if proof == nil {
		return errSharedTrustConflict
	}
	target, err := proof.ConfirmedActivation(b, expected)
	if err != nil {
		return errSharedTrustConflict
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(path); err != nil {
		return err
	}
	actual, err := readSharedPendingEnrollment(path, root, b)
	missing := errors.Is(err, errSharedTrustMissing)
	if !missing {
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, expected) {
			return errSharedTrustConflict
		}
	}
	current, err := readSharedTrustFile(path, root, b, 1)
	if errors.Is(err, errSharedTrustMissing) {
		if missing {
			return errSharedTrustConflict
		}
	} else {
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, target) {
			// A prior publication may precede later journal observations. Accept
			// only the identical final selection and a valid monotonic advance.
			if missing || current.Enrollment == nil || !reflect.DeepEqual(current.Enrollment, target.Enrollment) || target.Revision <= current.Revision {
				return errSharedTrustConflict
			}
			normalized := target
			normalized.Revision = current.Revision + 1
			if current.ValidateAdvance(normalized) != nil {
				return errSharedTrustConflict
			}
		}
	}
	// Always republish, even after matching readback: a previous directory sync
	// may have failed. Never delete the journal before destination durability.
	if err := persistSharedTrustFile(path, root, b, target); err != nil {
		return err
	}
	if err := os.Remove(sharedPendingEnrollmentPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errSharedEnrollmentCleanup
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return errSharedEnrollmentCleanup
	}
	return nil
}

// Ordinary admission must not consume a partially published destination. Read
// the pending marker and trust under one shared lock, before any network login.
func readActiveSharedTrustFile(path string, root []byte, b sharedpg.TrustBinding, minimum uint64) (sharedpg.TrustState, error) {
	if !filepath.IsAbs(path) {
		return sharedpg.TrustState{}, errSharedTrustStorage
	}
	release, err := tryAcquireSharedFileLock(path + ".lock")
	if err != nil {
		return sharedpg.TrustState{}, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return sharedpg.TrustState{}, err
	}
	if err := requireNoSharedTrustTransition(path); err != nil {
		return sharedpg.TrustState{}, err
	}
	return readSharedTrustFile(path, root, b, minimum)
}
