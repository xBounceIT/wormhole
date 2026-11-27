package main

import "errors"

// Deletion is authorized by the caller's persisted retirement intent. Validate
// any existing per-file key against the exact inventoried ciphertext before
// deleting it; a changed/unavailable keychain must not be treated as success.
func retireLegacyFileKeyChecked(protected []byte, load func() ([]byte, error), remove func() error, missing error) error {
	key, err := load()
	defer clearBytes(key)
	if errors.Is(err, missing) {
		return nil
	}
	if err != nil {
		return errVaultMigrationSource
	}
	plain, err := decryptAuthDocument(protected, key)
	clearBytes(plain)
	if err != nil {
		return errVaultMigrationSource
	}
	if err := remove(); err != nil && !errors.Is(err, missing) {
		return errVaultMigrationSource
	}
	remaining, err := load()
	clearBytes(remaining)
	if !errors.Is(err, missing) {
		return errVaultMigrationSource
	}
	return nil
}
