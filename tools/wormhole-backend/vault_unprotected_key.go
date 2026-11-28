package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const vaultUnprotectedKeyDomain = "wormhole/v1/unprotected-platform-key\x00"
const maxVaultUnprotectedKeyBlob = 4096

var errVaultUnprotectedKeyStorage = errors.New("vault_unprotected_key_unavailable")

// Native-only storage primitive. The publisher must hold workspace ownership
// and may reference the slot only after this succeeds. Only the dedicated
// Default operations open OS custody. An existing factor is never repaired.
func createVaultUnprotectedKey(ctx context.Context, databasePath, vaultID, slotID string) ([]byte, error) {
	return createVaultUnprotectedKeyWith(ctx, databasePath, vaultID, slotID, protectFileContents)
}

func openVaultUnprotectedKey(ctx context.Context, databasePath, vaultID, slotID string) ([]byte, error) {
	return openVaultUnprotectedKeyWith(ctx, databasePath, vaultID, slotID, unprotectFileContents)
}

func vaultUnprotectedKeyLocation(ctx context.Context, databasePath, vaultID, slotID string) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil || floor != vault.Default {
		return "", nil, vault.ErrPolicy
	}
	return vaultUnprotectedKeyIdentity(databasePath, vaultID, slotID)
}

// Identity alone grants no factor access. Authenticated forward retirement must
// locate the old ciphertext even when the current floor forbids OS-only unlock.
func vaultUnprotectedKeyIdentity(databasePath, vaultID, slotID string) (string, []byte, error) {
	v, ve := uuid.Parse(vaultID)
	s, se := uuid.Parse(slotID)
	if ve != nil || se != nil || v == uuid.Nil || s == uuid.Nil || v.String() != vaultID || s.String() != slotID || !filepath.IsAbs(databasePath) || filepath.Clean(databasePath) != databasePath {
		return "", nil, vault.ErrFormat
	}
	// A directory alias must not create a second keychain account for the same
	// physical factor. Migration adopts the canonical source at publication.
	directory, err := filepath.EvalSymlinks(filepath.Dir(databasePath))
	if err != nil {
		return "", nil, errVaultUnprotectedKeyStorage
	}
	header := append([]byte(vaultUnprotectedKeyDomain), v[:]...)
	header = append(header, s[:]...)
	path := filepath.Join(directory, ".wormhole-unprotected-"+vaultID+"-"+slotID)
	return path, header, nil
}

type vaultPlatformKeyTransform func(path string, input []byte) ([]byte, error)

func createVaultUnprotectedKeyWith(ctx context.Context, databasePath, vaultID, slotID string, protect vaultPlatformKeyTransform) (result []byte, resultErr error) {
	path, header, err := vaultUnprotectedKeyLocation(ctx, databasePath, vaultID, slotID)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	defer root.Close()
	name := filepath.Base(path)
	// Reserve before touching the OS key store. Concurrent creators must not
	// overwrite a keychain key while another creator seals its factor file.
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	original, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errVaultUnprotectedKeyStorage
	}
	retained := false
	defer func() {
		_ = file.Close()
		if !retained {
			// Remove only our own incomplete ciphertext, never a replacement.
			current, err := root.Lstat(name)
			if err != nil || !os.SameFile(original, current) || root.Remove(name) != nil {
				resultErr = errors.Join(resultErr, errVaultUnprotectedKeyStorage)
			}
		}
	}()
	plaintext := make([]byte, len(header)+32)
	defer vault.Wipe(plaintext)
	copy(plaintext, header)
	if _, err := rand.Read(plaintext[len(header):]); err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	protected, err := protect(path, plaintext)
	defer vault.Wipe(protected)
	if err != nil || len(protected) == 0 || len(protected) > maxVaultUnprotectedKeyBlob {
		return nil, errVaultUnprotectedKeyStorage
	}
	if _, _, err := vaultUnprotectedKeyLocation(ctx, databasePath, vaultID, slotID); err != nil {
		return nil, err
	}
	if _, err := file.Write(protected); err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	if err := file.Sync(); err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	if err := file.Close(); err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	if err := syncPrivateFileDirectory(filepath.Dir(path)); err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(original, current) || current.Size() != int64(len(protected)) {
		return nil, errVaultUnprotectedKeyStorage
	}
	if _, _, err := vaultUnprotectedKeyLocation(ctx, databasePath, vaultID, slotID); err != nil {
		return nil, err
	}
	retained = true
	return bytes.Clone(plaintext[len(header):]), nil
}

func openVaultUnprotectedKeyWith(ctx context.Context, databasePath, vaultID, slotID string, unprotect vaultPlatformKeyTransform) ([]byte, error) {
	path, header, err := vaultUnprotectedKeyLocation(ctx, databasePath, vaultID, slotID)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	defer root.Close()
	name := filepath.Base(path)
	original, err := root.Lstat(name)
	if err != nil || !original.Mode().IsRegular() || original.Size() <= 0 || original.Size() > maxVaultUnprotectedKeyBlob {
		return nil, errVaultUnprotectedKeyStorage
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errVaultUnprotectedKeyStorage
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(original, opened) || !opened.Mode().IsRegular() {
		return nil, errVaultUnprotectedKeyStorage
	}
	protected, err := io.ReadAll(io.LimitReader(file, maxVaultUnprotectedKeyBlob+1))
	defer vault.Wipe(protected)
	if err != nil || len(protected) == 0 || len(protected) > maxVaultUnprotectedKeyBlob {
		return nil, errVaultUnprotectedKeyStorage
	}
	plaintext, err := unprotect(path, protected)
	defer vault.Wipe(plaintext)
	if err != nil || len(plaintext) != len(header)+32 || !bytes.Equal(plaintext[:len(header)], header) {
		return nil, vault.ErrAuthentication
	}
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(original, current) {
		return nil, errVaultUnprotectedKeyStorage
	}
	if _, _, err := vaultUnprotectedKeyLocation(ctx, databasePath, vaultID, slotID); err != nil {
		return nil, err
	}
	return bytes.Clone(plaintext[len(header):]), nil
}
