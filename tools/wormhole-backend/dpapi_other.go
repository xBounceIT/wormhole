//go:build !windows

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

const protectedSecretEncoding = "windows-dpapi-v1"

const (
	authKeyringService       = "Wormhole App Authentication"
	authKeyringAccountPrefix = "document-key-v1:"
	fileKeyringService       = "Wormhole Protected Files"
	fileKeyringAccountPrefix = "file-key-v1:"
)

func protectSecret(string) (string, error) {
	return "", errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectSecret(string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectElectronSafeStorageSecret(string, string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectFile(path string) ([]byte, error) {
	protected, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clearBytes(protected)
	return unprotectFileContents(path, protected)
}

func unprotectFileContents(path string, protected []byte) ([]byte, error) {
	key, err := fileProtectionKey(path, false)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	return decryptAuthDocument(protected, key)
}

func protectFile(path string, plaintext []byte) error {
	protected, err := protectFileContents(path, plaintext)
	if err != nil {
		return err
	}
	defer clearBytes(protected)
	return writePrivateFileAtomic(path, protected)
}

func protectFileContents(path string, plaintext []byte) ([]byte, error) {
	key, err := fileProtectionKey(path, true)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	return encryptAuthDocument(plaintext, key)
}

func protectAuthDocument(storePath string, plaintext []byte) ([]byte, error) {
	key, err := authDocumentProtectionKey(storePath, true)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	return encryptAuthDocument(plaintext, key)
}

func unprotectAuthDocument(storePath string, protected []byte) ([]byte, error) {
	key, err := authDocumentProtectionKey(storePath, false)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	return decryptAuthDocument(protected, key)
}

func deleteAuthProtectionKey(storePath string) {
	// The verifier document is already gone at this point. A keychain cleanup failure cannot
	// recover any verifier, and must not turn a successfully disabled auth setting into an error.
	_ = desktopProtectedKeys.remove(authKeyringService, authKeyringAccount(storePath))
}

func authDocumentProtectionKey(storePath string, create bool) ([]byte, error) {
	return desktopProtectedKeys.protectionKey(authKeyringService, authKeyringAccount(storePath), create)
}

func fileProtectionKey(path string, create bool) ([]byte, error) {
	return desktopProtectedKeys.protectionKey(fileKeyringService, protectedFileKeyringAccount(path), create)
}

func deleteFileProtectionKey(path string) {
	_ = desktopProtectedKeys.remove(fileKeyringService, protectedFileKeyringAccount(path))
}

func authKeyringAccount(storePath string) string {
	return protectedPathAccount(authKeyringAccountPrefix, storePath)
}

func protectedFileKeyringAccount(path string) string {
	return protectedPathAccount(fileKeyringAccountPrefix, path)
}

func protectedPathAccount(prefix, path string) string {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		absolutePath = filepath.Clean(path)
	}
	pathBytes := []byte(filepath.Clean(absolutePath))
	sum := sha256.Sum256(pathBytes)
	clearBytes(pathBytes)
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
