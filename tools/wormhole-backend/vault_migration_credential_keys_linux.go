//go:build linux

package main

import (
	"context"

	"github.com/godbus/dbus/v5"
)

func openMigrationCredentialStore(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
	deadline, cancel := context.WithTimeout(ctx, linuxSecretStoreTimeout)
	// Migration only uses the desktop's existing session bus. Connecting
	// through ConnectSessionBus may launch dbus-launch on a missing address.
	connection, err := dbus.SessionBusPrivateNoAutoStartup(dbus.WithContext(deadline))
	if err != nil {
		cancel()
		return migrationCredentialStore{}, errVaultMigrationSource
	}
	close := func() { connection.Close(); cancel() }
	if connection.Auth(nil) != nil || connection.Hello() != nil {
		close()
		return migrationCredentialStore{}, errVaultMigrationSource
	}
	store, err := migrationSecretServiceStore(row, maximum, func(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
		result := connection.Object("org.freedesktop.secrets", path).CallWithContext(ctx, method, 0, args...)
		return result.Body, result.Err
	}, close)
	if err != nil {
		close()
	}
	return store, err
}
