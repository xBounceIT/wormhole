package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Caller holds the cache publication lock. Never prune during a password-root
// transition: its active destination might be encrypted under another root.
func pruneSharedTLSCacheLocked(o sharedAdmissionOptions, root []byte, expected sharedpg.TrustState, incoming []byte) error {
	path, err := sharedTLSCachePath(o.TrustPath, incoming)
	if err != nil {
		return err
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(o.TrustPath); err != nil {
		return err
	}
	current, err := readSharedTrustFile(o.TrustPath, root, o.Binding, expected.Revision)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, expected) {
		return errSharedTrustConflict
	}
	signer, err := uuid.Parse(current.SignerKeyID)
	if err != nil || signer.String() != current.SignerKeyID {
		return errSharedTrustStorage
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errSharedTrustStorage
	}
	file, err := os.Open(directory)
	if err != nil {
		return errSharedTrustStorage
	}
	entries, err := file.ReadDir(maxSharedTLSCacheEntries + 1)
	_ = file.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return errSharedTrustStorage
	}
	pin := sharedpg.TLSTrustPin{WorkspaceID: current.WorkspaceID, Signer: vault.KeyRef{ID: signer, Version: current.SignerKeyVersion}, Organisation: current.PublicKey, MinimumSequence: 1}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 69 || !strings.HasSuffix(name, ".json") {
			continue
		}
		digest, e := hex.DecodeString(name[:64])
		if e != nil || hex.EncodeToString(digest) != name[:64] || bytes.Equal(digest, current.TLSDigest) || bytes.Equal(digest, incoming) {
			continue
		}
		candidate := filepath.Join(directory, name)
		// Only direct regular files with a canonical owned name are eligible.
		if filepath.Dir(candidate) != directory || filepath.Base(candidate) != name {
			continue
		}
		raw, e := readSharedTrustBytes(candidate, sharedpg.MaxTLSTrustBundleBytes)
		if e != nil {
			continue
		}
		actual := sha256.Sum256(raw)
		if !bytes.Equal(actual[:], digest) {
			continue
		}
		bundle, e := sharedpg.DecodeTLSTrustBundle(raw)
		if e != nil {
			continue
		}
		if _, e := sharedpg.VerifyTLSTrustBundle(bundle, pin); e != nil {
			continue
		}
		if e := os.Remove(candidate); e != nil {
			return errSharedTrustStorage
		}
		removed = true
	}
	if removed && privateFileDirectorySync(directory) != nil {
		return errSharedTrustStorage
	}
	return nil
}
