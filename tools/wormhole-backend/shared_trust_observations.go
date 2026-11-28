package main

import (
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// Persist observations before acting on them. Exact next-state readback also
// allows confirmation after uncertain replacement; a different concurrent journal
// cannot be overwritten. Destination validation belongs to finalization: observing
// a revocation must remain possible even if that destination was interrupted.
func writeSharedTrustObservation(path string, newRoot []byte, binding sharedpg.TrustBinding, expected, next sharedpg.TrustRootTransition) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	if err := expected.ValidateObservationAdvance(binding, next); err != nil {
		return err
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	actual, err := readSharedTrustRootTransition(path, newRoot, binding)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) && !reflect.DeepEqual(actual, next) {
		return errSharedTrustConflict
	}
	raw, err := sharedpg.SealTrustRootTransition(newRoot, binding, next)
	if err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedTrustTransitionPath(path), raw)
}
