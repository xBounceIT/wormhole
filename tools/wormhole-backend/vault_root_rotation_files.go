package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The fingerprint is private journal data. Stream ciphertext through one native
// directory handle; never load a database into RAM or follow a late path link.
func rootRotationFileFingerprint(ctx context.Context, f *legacyPublicationFS, path string, flush bool) (rootRotationFingerprint, error) {
	var result rootRotationFingerprint
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := f.verify(); err != nil {
		return result, err
	}
	name, err := f.relative(path)
	if err != nil {
		return result, err
	}
	closed := func() error {
		for _, suffix := range []string{"-journal", "-wal", "-shm"} {
			if _, err := f.root.Lstat(name + suffix); !errors.Is(err, os.ErrNotExist) {
				return errVaultSlotStorage
			}
		}
		return nil
	}
	if err := closed(); err != nil {
		return result, err
	}
	before, err := f.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 512 || before.Size() > 1<<40 {
		return result, errVaultSlotStorage
	}
	flags := os.O_RDONLY
	if flush {
		flags = os.O_RDWR
	}
	file, err := f.root.OpenFile(name, flags, 0)
	if err != nil {
		return result, errVaultSlotStorage
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || before.Size() != opened.Size() {
		return result, vault.ErrAuthentication
	}
	if flush && file.Sync() != nil {
		return result, errVaultSlotStorage
	}
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	defer vault.Wipe(buffer)
	remaining := before.Size()
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, err := io.ReadFull(file, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return result, errVaultSlotStorage
		}
		hash.Write(buffer[:n])
		remaining -= int64(n)
	}
	end, err := file.Stat()
	current, pathErr := f.root.Lstat(name)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(before, current) || !os.SameFile(before, end) || before.Size() != end.Size() || !before.ModTime().Equal(end.ModTime()) {
		return result, vault.ErrAuthentication
	}
	if err := closed(); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if file.Close() != nil {
		return result, errVaultSlotStorage
	}
	if err := f.verify(); err != nil {
		return result, err
	}
	return rootRotationFingerprint{Bytes: before.Size(), Digest: hex.EncodeToString(hash.Sum(nil))}, nil
}

func verifyRootRotationFile(ctx context.Context, f *legacyPublicationFS, path string, expected rootRotationFingerprint) error {
	actual, err := rootRotationFileFingerprint(ctx, f, path, false)
	if err != nil {
		return err
	}
	if actual != expected {
		return vault.ErrAuthentication
	}
	return nil
}

// No recursive deletion or overwrite. Recheck the opened identity immediately
// before unlinking, after authenticating the exact ciphertext fingerprint.
func removeRootRotationFile(ctx context.Context, f *legacyPublicationFS, path string, expected rootRotationFingerprint) error {
	before, err := f.lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !before.Mode().IsRegular() {
		return errVaultSlotStorage
	}
	if err := verifyRootRotationFile(ctx, f, path, expected); err != nil {
		return err
	}
	current, err := f.lstat(path)
	if err != nil || !os.SameFile(before, current) {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := f.relative(path)
	if err != nil {
		return err
	}
	if f.root.Remove(name) != nil || syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
		return errVaultSlotCommitUncertain
	}
	return nil
}
