package main

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// Invocation-local native inputs. Never retain the borrowed storage root.
type sharedDevicePasswordCandidate struct {
	storageRoot     []byte
	next            []byte
	vaultID, fileID string
	minimumSequence uint64
}

func transitionDeviceMatches(path string, record sharedpg.TrustRootTransition, allowTarget bool) error {
	raw, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
	if record.Device == nil {
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
	if bytes.Equal(digest[:], record.Device.PreviousDigest) || (allowTarget && bytes.Equal(raw, record.Device.Next)) {
		return nil
	}
	return errSharedTrustConflict
}
