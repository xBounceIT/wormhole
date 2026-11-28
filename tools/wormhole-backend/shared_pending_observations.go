package main

import (
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// Persist every authenticated observation before consuming it. An exact next
// record also supports durable confirmation after an uncertain atomic replacement.
// Concurrent updates cannot erase a newer revocation, policy or TLS floor.
func writeSharedPendingObservation(path string, root []byte, b sharedpg.TrustBinding, expected, next sharedpg.PendingEnrollment) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	if err := expected.ValidateObservationAdvance(b, next); err != nil {
		return err
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
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) && !reflect.DeepEqual(actual, next) {
		return errSharedTrustConflict
	}
	raw, err := sharedpg.SealPendingEnrollment(root, b, next)
	if err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedPendingEnrollmentPath(path), raw)
}
