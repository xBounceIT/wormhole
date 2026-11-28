//go:build windows || (darwin && !cgo)

package main

import (
	"context"
	"errors"
	"testing"
)

func TestVaultMigrationCredentialKeysNativeUnsupported(t *testing.T) {
	store, err := openMigrationCredentialStore(context.Background(), legacyInventoryRow{}, 1024)
	if !errors.Is(err, errUnsupportedSecretEncoding) || store.Load != nil || store.Delete != nil || store.Close != nil {
		t.Fatal("foreign keychain access admitted", err)
	}
	f := newRetirementKeysFixture(t)
	if _, err := retireLegacyVaultSources(context.Background(), f.source, "", f.stage, f.key); err == nil {
		t.Fatal("foreign keychain references retired")
	}
	if len(f.values) != 2 {
		t.Fatal("foreign secret changed")
	}
}
