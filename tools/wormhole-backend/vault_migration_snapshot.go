package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Caller holds workspace/stage ownership and has closed every SQLite connection.
// Verification authenticates the slot document before reading any database byte.
// This is a migration checkpoint, not authority to retire sources or unlock.
func verifyVaultMigrationSnapshot(ctx context.Context, path string, document vault.SlotFile, key []byte) error {
	if err := vault.VerifySlotFile(key, document, document.VaultID, document.FileID, document.Sequence); err != nil {
		return err
	}
	if document.Migration == nil || (document.Migration.Phase != vault.MigrationDomainsCopied && document.Migration.Phase != vault.MigrationRetiring && document.Migration.Phase != vault.MigrationPublishing) || document.Migration.Snapshot == nil {
		return vault.ErrPolicy
	}
	actual, err := vaultMigrationDatabaseDigest(ctx, path, document, key, false)
	if err != nil {
		return err
	}
	expected := document.Migration.Snapshot
	if expected.Bytes != actual.Bytes || !hmac.Equal(expected.Authentication, actual.Authentication) {
		return vault.ErrAuthentication
	}
	return nil
}

func vaultMigrationDatabaseDigest(ctx context.Context, path string, document vault.SlotFile, key []byte, flush bool) (*vault.MigrationSnapshot, error) {
	var expected *vault.MigrationSnapshot
	if document.Migration != nil {
		expected = document.Migration.Snapshot
	}
	return vaultMigrationDatabaseDigestExpected(ctx, path, document, key, flush, expected)
}

func vaultMigrationDatabaseDigestExpected(ctx context.Context, path string, document vault.SlotFile, key []byte, flush bool, expected *vault.MigrationSnapshot, roots ...*os.Root) (*vault.MigrationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := vault.VerifySlotFile(key, document, document.VaultID, document.FileID, document.Sequence); err != nil {
		return nil, err
	}
	if document.Migration == nil {
		return nil, vault.ErrPolicy
	}
	if len(roots) > 1 || len(roots) == 1 && (roots[0] == nil || filepath.Dir(path) != roots[0].Name()) {
		return nil, vault.ErrPolicy
	}
	lstat := os.Lstat
	openFile := os.OpenFile
	if len(roots) == 1 {
		lstat = func(p string) (os.FileInfo, error) { return roots[0].Lstat(filepath.Base(p)) }
		openFile = func(p string, flag int, mode os.FileMode) (*os.File, error) {
			return roots[0].OpenFile(filepath.Base(p), flag, mode)
		}
	}
	closed := func() error {
		for _, suffix := range []string{"-journal", "-wal", "-shm"} {
			if _, err := lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
				return errVaultSlotStorage
			}
		}
		return nil
	}
	if err := closed(); err != nil {
		return nil, err
	}
	info, err := lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 512 {
		return nil, errVaultSlotStorage
	}
	if !flush && expected != nil && expected.Bytes != info.Size() {
		return nil, vault.ErrAuthentication
	}
	flags := os.O_RDONLY
	if flush {
		flags = os.O_RDWR
	}
	file, err := openFile(path, flags, 0)
	if err != nil {
		return nil, errVaultSlotStorage
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errVaultSlotStorage
	}
	if flush {
		if err := file.Sync(); err != nil {
			return nil, errVaultSlotStorage
		}
	}
	subkey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-migration-database\x00"))
	// Validated UUIDs and the source binding have fixed widths (36/64 bytes).
	mac.Write([]byte(document.VaultID))
	mac.Write([]byte(document.FileID))
	mac.Write([]byte(document.RootKeyID))
	mac.Write([]byte(document.Migration.Binding))
	var numeric [12]byte
	binary.BigEndian.PutUint32(numeric[:4], document.RootKeyVersion)
	binary.BigEndian.PutUint64(numeric[4:], uint64(info.Size()))
	mac.Write(numeric[:])
	buffer := make([]byte, 64*1024)
	defer vault.Wipe(buffer)
	remaining := info.Size()
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := io.ReadFull(file, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return nil, errVaultSlotStorage
		}
		mac.Write(buffer[:n])
		remaining -= int64(n)
	}
	end, err := file.Stat()
	current, pathErr := lstat(path)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return nil, errVaultSlotStorage
	}
	if err := closed(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, errVaultSlotStorage
	}
	return &vault.MigrationSnapshot{Bytes: info.Size(), Authentication: mac.Sum(nil)}, nil
}

func requireClosedMigrationDatabase(path string) error {
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return errVaultSlotStorage
		}
	}
	return nil
}
