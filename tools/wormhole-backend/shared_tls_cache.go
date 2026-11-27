package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

const maxSharedTLSCacheEntries = 64

var errSharedTLSCacheFull = errors.New("shared_workspace_tls_cache_full")

func sharedTLSCachePath(trustPath string, digest []byte) (string, error) {
	if !filepath.IsAbs(trustPath) || len(digest) != sha256.Size {
		return "", errSharedTrustStorage
	}
	return filepath.Join(trustPath+".tls", hex.EncodeToString(digest)+".json"), nil
}

// The cache contains public signed metadata only. Immutable content-addressed
// names prevent concurrent older writers replacing a newer committed bundle.
// This standalone operation only stages a snapshot. Protected references must
// be committed through publishSharedTLSCache, which keeps the lock throughout.
// Retention is supplied separately and is disabled for password recovery.
func writeSharedTLSCache(trustPath string, bundle *sharedpg.VerifiedTLSBundle) error {
	return publishSharedTLSCache(trustPath, bundle, nil, nil)
}

// All publishers and retention use cache -> trust lock order. Keep the cache
// lock until the protected reference commits, not just until its file is written.
func publishSharedTLSCache(trustPath string, bundle *sharedpg.VerifiedTLSBundle, before, commit func() error) error {
	if !filepath.IsAbs(trustPath) || len(bundle.Pin().Digest) != sha256.Size {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(trustPath + ".tls-cache.lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	if err := writeSharedTLSCacheLocked(trustPath, bundle); err != nil {
		return err
	}
	if commit != nil {
		return commit()
	}
	return nil
}

func writeSharedTLSCacheLocked(trustPath string, bundle *sharedpg.VerifiedTLSBundle) error {
	raw := bundle.Encode()
	pin := bundle.Pin()
	path, err := sharedTLSCachePath(trustPath, pin.Digest)
	if err != nil || len(raw) == 0 || len(raw) > sharedpg.MaxTLSTrustBundleBytes {
		return errSharedTrustStorage
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], pin.Digest) {
		return errSharedTrustStorage
	}
	directory := filepath.Dir(path)
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errSharedTrustStorage
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errSharedTrustStorage
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, e := os.Open(directory)
		if e != nil {
			return errSharedTrustStorage
		}
		entries, e := file.ReadDir(maxSharedTLSCacheEntries + 1)
		_ = file.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			return errSharedTrustStorage
		}
		if len(entries) >= maxSharedTLSCacheEntries {
			return errSharedTLSCacheFull
		}
	} else if err != nil || !info.Mode().IsRegular() {
		return errSharedTrustStorage
	}
	// Rewriting the same content confirms durability after an interrupted prior
	// attempt. Readback alone would not resolve a failed directory sync.
	for attempt := 0; attempt < 2; attempt++ {
		err = writePrivateFileAtomic(path, raw)
		if err == nil {
			err = privateFileDirectorySync(filepath.Dir(directory))
		}
		if err == nil {
			return nil
		}
	}
	return errSharedTrustStorage
}

func readSharedTLSCache(trustPath string, state sharedpg.TrustState) (*sharedpg.VerifiedTLSBundle, error) {
	path, err := sharedTLSCachePath(trustPath, state.TLSDigest)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errSharedTrustStorage
	}
	raw, err := readSharedTrustBytes(path, sharedpg.MaxTLSTrustBundleBytes)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], state.TLSDigest) {
		return nil, sharedpg.ErrTrustRollback
	}
	return state.VerifyTLS(raw)
}

func loadSharedTLSCache(o *sharedAdmissionOptions, current sharedpg.TrustState) error {
	if o.Settings.TLSBundle != nil || current.TLSSequence == 0 || o.Settings.TLS != sharedpg.TLSVerified {
		return nil
	}
	bundle, err := readSharedTLSCache(o.TrustPath, current)
	if err != nil {
		return err
	}
	o.Settings.TLSBundle = bundle
	return nil
}
