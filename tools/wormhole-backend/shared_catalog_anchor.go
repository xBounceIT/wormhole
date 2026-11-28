package main

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Advance the OS-protected rollback anchor after native catalog observations.
// Slot selection and transport are inherited from the authenticated anchor;
// this cannot enroll a device, change its factors or manufacture a missing anchor.
func refreshSharedCatalogAnchor(ctx context.Context, path string, root []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustState, protection sharedStartupProtection) (sharedStartupAnchor, error) {
	if ctx == nil || !filepath.IsAbs(path) || expected.Revision == 0 || protection.protect == nil || protection.unprotect == nil {
		return sharedStartupAnchor{}, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return sharedStartupAnchor{}, err
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return sharedStartupAnchor{}, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return sharedStartupAnchor{}, err
	}
	if err := requireNoSharedTrustTransition(path); err != nil {
		return sharedStartupAnchor{}, err
	}
	current, err := readSharedTrustFile(path, root, binding, expected.Revision)
	if err != nil {
		return sharedStartupAnchor{}, err
	}
	if !reflect.DeepEqual(current, expected) {
		return sharedStartupAnchor{}, errSharedTrustConflict
	}
	previous, err := readSharedStartupAnchor(path, protection)
	if err != nil {
		return sharedStartupAnchor{}, err
	}
	if previous.Binding != binding {
		return sharedStartupAnchor{}, errSharedTrustConflict
	}
	next := previous
	if !reflect.DeepEqual(previous.Trust, current) {
		if previous.Revision == math.MaxInt64 {
			return sharedStartupAnchor{}, errSharedTrustConflict
		}
		next.Revision++
		next.Trust = current
		if current.TLSSequence > previous.Trust.TLSSequence {
			bundle, err := readSharedTLSCache(path, current)
			if err != nil {
				return sharedStartupAnchor{}, err
			}
			next.Transport, err = sharedpg.AdvanceTransportSnapshotTLS(previous.Transport, current, bundle)
			if err != nil {
				return sharedStartupAnchor{}, err
			}
		}
		if !startupAnchorAdvances(previous, next) || !next.valid(path) {
			return sharedStartupAnchor{}, errSharedTrustConflict
		}
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > maxSharedStartupAnchorBytes {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	defer vault.Wipe(raw)
	protected, err := protection.protect(sharedStartupAnchorPath(path), raw)
	if err != nil || len(protected) == 0 || len(protected) > maxSharedStartupAnchorBytes*2 {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	if err := ctx.Err(); err != nil {
		return sharedStartupAnchor{}, err
	}
	// Re-publishing an equal anchor is intentional durability confirmation.
	return next, persistSharedTransitionBytes(sharedStartupAnchorPath(path), protected)
}
