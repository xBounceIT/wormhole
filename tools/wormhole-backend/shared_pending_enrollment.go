package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var errSharedEnrollmentPending = errors.New("shared_workspace_enrollment_pending")

func sharedPendingEnrollmentPath(path string) string { return path + ".enrollment" }

func requireNoSharedPendingEnrollment(path string) error {
	_, err := os.Lstat(sharedPendingEnrollmentPath(path))
	if err == nil {
		return errSharedEnrollmentPending
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustStorage
	}
	return nil
}

func requireMissingSharedTrust(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return errSharedTrustConflict
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustStorage
	}
	return requireNoSharedTrustTransition(path)
}

func readSharedPendingEnrollment(path string, root []byte, b sharedpg.TrustBinding) (sharedpg.PendingEnrollment, error) {
	raw, err := readSharedTrustBytes(sharedPendingEnrollmentPath(path), sharedpg.MaxPendingEnrollmentBytes)
	if err != nil {
		return sharedpg.PendingEnrollment{}, err
	}
	return sharedpg.OpenPendingEnrollment(root, b, raw)
}

// Stage is exclusive with ordinary trust creation and password transitions.
// A pending record is never replaced or implicitly retried. A durability error
// forbids SQL dispatch until exact-record confirmation succeeds.
func stageSharedPendingEnrollment(path string, root []byte, b sharedpg.TrustBinding, record sharedpg.PendingEnrollment) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	raw, err := sharedpg.SealPendingEnrollment(root, b, record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(path); err != nil {
		return err
	}
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedPendingEnrollmentPath(path), raw)
}

// Confirm re-authenticates the exact intended record under the same lock and
// republishes through the durable writer; readback alone does not resolve a failed
// directory sync. This confirms local durability only, never remote redemption.
func confirmSharedPendingEnrollment(path string, root []byte, b sharedpg.TrustBinding, expected sharedpg.PendingEnrollment) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(path); err != nil {
		return err
	}
	actual, err := readSharedPendingEnrollment(path, root, b)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errSharedTrustConflict
	}
	raw, err := sharedpg.SealPendingEnrollment(root, b, actual)
	if err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedPendingEnrollmentPath(path), raw)
}
