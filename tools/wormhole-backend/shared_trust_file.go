package main

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var (
	errSharedTrustMissing         = errors.New("shared_workspace_trust_missing")
	errSharedTrustStorage         = errors.New("shared_workspace_trust_storage_unavailable")
	errSharedTrustConflict        = errors.New("shared_workspace_trust_conflict")
	errSharedTrustCommitUncertain = errors.New("shared_workspace_trust_commit_uncertain")
)

// Native-only persistence. The application chooses the absolute device-local
// path; the unlocked enrollment supplies the key and identity binding.
func readSharedTrustFile(path string, key []byte, binding sharedpg.TrustBinding, minimumRevision uint64) (sharedpg.TrustState, error) {
	raw, err := readSharedTrustBytes(path, sharedpg.MaxTrustStateBytes)
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	return sharedpg.OpenTrustState(key, binding, raw, minimumRevision)
}

func readSharedTrustBytes(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errSharedTrustStorage
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errSharedTrustMissing
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, errSharedTrustStorage
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errSharedTrustStorage
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errSharedTrustStorage
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, errSharedTrustStorage
	}
	return raw, nil
}

// Creation (expected=0) is reserved for authenticated enrollment. An update must
// come from TrustState.Advance/AdvanceAccount/AdvanceTLS; it cannot replace pins or reduce floors.
// Uncertain durability requires authenticated readback, never blind retry/reset.
func writeSharedTrustFile(path string, key []byte, binding sharedpg.TrustBinding, next sharedpg.TrustState, expected uint64) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	if expected == math.MaxUint64 || next.Revision != expected+1 {
		return errSharedTrustConflict
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(path); err != nil {
		return err
	}
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return err
	}
	current, err := readSharedTrustFile(path, key, binding, 1)
	if errors.Is(err, errSharedTrustMissing) {
		if expected != 0 {
			return errSharedTrustConflict
		}
	} else if err != nil {
		return err
	} else {
		if current.Revision != expected {
			return errSharedTrustConflict
		}
		if err := current.ValidateAdvance(next); err != nil {
			return err
		}
	}
	return persistSharedTrustFile(path, key, binding, next)
}

// Confirmation authenticates exact expected state under the same exclusive lock
// and re-publishes it through the durable writer. Readback alone is not evidence
// that the previous directory-sync failure has been resolved. This cannot create
// a missing state or change its revision, pins, digest or policy sequence.
func confirmSharedTrustFile(path string, key []byte, binding sharedpg.TrustBinding, expected sharedpg.TrustState) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	if expected.Revision == 0 {
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
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return err
	}
	current, err := readSharedTrustFile(path, key, binding, expected.Revision)
	if err != nil {
		return err
	}
	// Compare the entire record, including future fields, rather than checking
	// only its counters and accidentally confirming a different authenticated pin.
	if !reflect.DeepEqual(current, expected) {
		return errSharedTrustConflict
	}
	return persistSharedTrustFile(path, key, binding, current)
}

// The caller holds the file lock and has validated creation/update/confirmation.
func persistSharedTrustFile(path string, key []byte, binding sharedpg.TrustBinding, state sharedpg.TrustState) error {
	raw, err := sharedpg.SealTrustState(key, binding, state)
	if err != nil {
		return err
	}
	if err := writePrivateFileAtomic(path, raw); err != nil {
		if privateFileDestinationWasReplaced(err) {
			return errSharedTrustCommitUncertain
		}
		return errSharedTrustStorage
	}
	return nil
}
