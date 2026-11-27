package main

import (
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// The native caller supplies an independently verified bundle. Advance the
// protected floor before the first connection, even if later admission fails.
func acceptSharedTLSBundle(o sharedAdmissionOptions, root []byte, current sharedpg.TrustState) (sharedpg.TrustState, error) {
	next, err := current.AdvanceTLS(o.Settings.TLSBundle)
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	err = publishSharedTLSCache(o.TrustPath, o.Settings.TLSBundle, func() error {
		return pruneSharedTLSCacheLocked(o, root, current, next.TLSDigest)
	}, func() error {
		var e error
		if next.Revision == current.Revision {
			e = confirmSharedTrustFile(o.TrustPath, root, o.Binding, next)
		} else {
			e = writeSharedTrustFile(o.TrustPath, root, o.Binding, next, current.Revision)
		}
		if errors.Is(e, errSharedTrustCommitUncertain) {
			e = confirmSharedTrustFile(o.TrustPath, root, o.Binding, next)
		}
		return e
	})
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	return next, nil
}
