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
	return unprotectStoredValue(id, encoded, encoding, maxStoredCredentialBytes, electronUserDataPath...)
}

// Password and historical tunnel rows share encodings, not plaintext limits.
func unprotectStoredValue(id, encoded, encoding string, maximum int, electronUserDataPath ...string) ([]byte, error) {
	if maximum < 1 || maximum > backendMaxTunnelRequestBytes {
		return nil, errors.New("stored secret size limit is invalid")
	}
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
		clearBytes(secret)
		return nil, err
	}
	if len(secret) > maximum {
		clearBytes(secret)
		return nil, errors.New("stored secret is too large")
	}
	return secret, nil
}
