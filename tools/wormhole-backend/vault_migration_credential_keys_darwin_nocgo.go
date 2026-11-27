//go:build darwin && !cgo

package main

import "context"

func openMigrationCredentialStore(context.Context, legacyInventoryRow, int) (migrationCredentialStore, error) {
	return migrationCredentialStore{}, errUnsupportedSecretEncoding
}
