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

func unprotectStoredSecret(encoded, encoding string, electronUserDataPath ...string) ([]byte, error) {
	switch strings.TrimSpace(encoding) {
	case protectedSecretEncoding:
		return unprotectSecret(encoded)
	case electronSafeStorageSecretEncoding:
		userDataPath := ""
		if len(electronUserDataPath) > 0 {
			userDataPath = electronUserDataPath[0]
		}
		return unprotectElectronSafeStorageSecret(encoded, userDataPath)
	default:
		return nil, errUnsupportedSecretEncoding
	}
}
