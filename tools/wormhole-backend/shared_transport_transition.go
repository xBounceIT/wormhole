package main

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// The source setup is immutable while the journal exists. Only committed local
// completion may also recognize the exact already-published target ciphertext.
func transitionSetupMatches(path string, record sharedpg.TrustRootTransition, allowTarget bool) error {
	raw, err := readSharedTrustBytes(sharedTransportSetupPath(path), sharedpg.MaxTransportSnapshotBytes*2)
	if record.Transport == nil {
		if errors.Is(err, errSharedTrustMissing) {
			return nil
		}
		if err != nil {
			return err
		}
		return errSharedTrustConflict
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if bytes.Equal(digest[:], record.Transport.PreviousDigest) || (allowTarget && bytes.Equal(raw, record.Transport.Next)) {
		return nil
	}
	return errSharedTrustConflict
}
