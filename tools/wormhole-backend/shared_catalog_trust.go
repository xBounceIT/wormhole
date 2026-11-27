package main

import (
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// Persist authenticated observations before returning either accepted metadata
// or a revocation rejection. No metadata may be published on a storage failure.
func acceptSharedCatalogObservation(o sharedAdmissionOptions, root []byte, current sharedpg.TrustState, node sharedpg.UnverifiedTreeNode, author sharedpg.UnverifiedNodeAuthor) (sharedpg.TrustState, error) {
	next, verificationErr := current.AdvanceCatalog(node, author)
	if next.Revision == 0 {
		return sharedpg.TrustState{}, verificationErr
	}
	var err error
	if next.Revision == current.Revision {
		err = confirmSharedTrustFile(o.TrustPath, root, o.Binding, next)
	} else {
		err = writeSharedTrustFile(o.TrustPath, root, o.Binding, next, current.Revision)
	}
	if errors.Is(err, errSharedTrustCommitUncertain) {
		err = confirmSharedTrustFile(o.TrustPath, root, o.Binding, next)
	}
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	return next, verificationErr
}
