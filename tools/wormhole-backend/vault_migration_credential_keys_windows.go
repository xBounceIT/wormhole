//go:build windows

package main

import "context"

// Windows-owned DPAPI rows have no per-credential OS key to delete. Foreign
// keychain references cannot be retired on a Windows client.
func openMigrationCredentialStore(context.Context, legacyInventoryRow, int) (migrationCredentialStore, error) {
	return migrationCredentialStore{}, errUnsupportedSecretEncoding
}
