package main

import (
	"errors"
	"strings"
)

// Electron's safeStorage-backed migration predates the Go DPAPI migration. Keep reading those
// rows so an already-completed migration does not strand the user's saved credentials.
const electronSafeStorageSecretEncoding = "electron-safe-storage-v1"
const electronSafeStoragePrefix = "v10"

var errUnsupportedSecretEncoding = errors.New("stored secret uses an unsupported encoding")

func unprotectStoredSecret(id, encoded, encoding string, electronUserDataPath ...string) ([]byte, error) {
	var secret []byte
	var err error
	switch strings.TrimSpace(encoding) {
	case protectedSecretEncoding:
		secret, err = unprotectSecret(encoded)
	case electronSafeStorageSecretEncoding:
		userDataPath := ""
		if len(electronUserDataPath) > 0 {
			userDataPath = electronUserDataPath[0]
		}
		secret, err = unprotectElectronSafeStorageSecret(encoded, userDataPath)
	default:
		secret, err = unprotectPlatformCredentialSecret(id, encoded, encoding)
	}
	if err != nil {
		return nil, err
	}
	if len(secret) > maxStoredCredentialBytes {
		return nil, errors.New("stored secret is too large")
	}
	return secret, nil
}
