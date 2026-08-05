//go:build !windows

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const protectedSecretEncoding = "windows-dpapi-v1"

const (
	authKeyringService       = "Wormhole App Authentication"
	authKeyringAccountPrefix = "document-key-v1:"
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

func unprotectFile(string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
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
	_ = keyring.Delete(authKeyringService, authKeyringAccount(storePath))
}

func authDocumentProtectionKey(storePath string, create bool) ([]byte, error) {
	account := authKeyringAccount(storePath)
	encoded, err := keyring.Get(authKeyringService, account)
	if err == nil {
		return decodeAuthProtectionKey(encoded)
	}
	if !errors.Is(err, keyring.ErrNotFound) || !create {
		return nil, fmt.Errorf("system keychain is unavailable: %w", err)
	}

	key := make([]byte, authProtectionKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("cannot generate an authentication protection key")
	}
	encoded = base64.RawStdEncoding.EncodeToString(key)
	if err := keyring.Set(authKeyringService, account, encoded); err != nil {
		clearBytes(key)
		return nil, fmt.Errorf("cannot store the authentication key in the system keychain: %w", err)
	}
	return key, nil
}

func decodeAuthProtectionKey(encoded string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != authProtectionKeyLength {
		clearBytes(key)
		return nil, errors.New("system keychain contains an invalid authentication key")
	}
	return key, nil
}

func authKeyringAccount(storePath string) string {
	absolutePath, err := filepath.Abs(storePath)
	if err != nil {
		absolutePath = filepath.Clean(storePath)
	}
	pathBytes := []byte(filepath.Clean(absolutePath))
	sum := sha256.Sum256(pathBytes)
	clearBytes(pathBytes)
	return authKeyringAccountPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
