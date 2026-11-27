//go:build darwin && cgo

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
)

// Each entry has a fresh UUID. Cleanup can remove only entries created here.
// The native CI runner must provide an unlocked test keychain; no silent skip.
func TestVaultMigrationCredentialKeysNativeDarwin(t *testing.T) {
	ctx := context.Background()
	const otherValue = "larger than the migration limit"
	id := uuid.NewString()
	reference, encoding, err := storeCredentialSecret(id, "", otherValue)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteStoredCredentialSecret(id, reference, encoding)
	for _, value := range []string{"", " \x00native secret\n "} {
		id := uuid.NewString()
		reference, encoding, err := prepareCredentialSecretStorage(id)
		if err != nil || encoding != darwinKeychainEncoding {
			t.Fatal("native legacy reference changed", err)
		}
		reference, encoding, err = storeCredentialSecret(id, reference, value)
		if err != nil {
			t.Fatal("native test Keychain unavailable", err)
		}
		t.Cleanup(func() {
			if err := deleteStoredCredentialSecret(id, reference, encoding); err != nil {
				t.Error(err)
			}
		})
		row := legacyInventoryRow{ID: id, Reference: reference, Encoding: encoding}
		legacy, err := unprotectPlatformCredentialSecret(id, reference, encoding)
		if err != nil || !bytes.Equal(legacy, []byte(value)) {
			t.Fatal("native reader differs from legacy", err)
		}
		clearBytes(legacy)
		store, err := openMigrationCredentialStore(ctx, row, 1024)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Close)
		if err := store.Delete(ctx); err == nil {
			t.Fatal("deleted without selection")
		}
		got, present, err := store.Load(ctx)
		if err != nil || !present || !bytes.Equal(got, []byte(value)) {
			t.Fatal("native Keychain bytes changed", err)
		}
		clearBytes(got)
		// Re-reading must release the prior reference and select the same item.
		got, present, err = store.Load(ctx)
		clearBytes(got)
		if err != nil || !present {
			t.Fatal(err)
		}
		if err := store.Delete(ctx); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(ctx); err != nil {
			t.Fatal("uncertain deletion not repeatable", err)
		}
		if got, present, err := store.Load(ctx); err != nil || present || len(got) != 0 {
			t.Fatal("native absence not confirmed", err)
		}
		store.Close()
		store.Close()
		if _, _, err := store.Load(ctx); err == nil {
			t.Fatal("read closed store")
		}
		if err := store.Delete(ctx); err == nil {
			t.Fatal("deleted closed store")
		}
	}
	other, err := unprotectPlatformCredentialSecret(id, reference, encoding)
	if err != nil || !bytes.Equal(other, []byte(otherValue)) {
		t.Fatal("migration touched another credential in the same service", err)
	}
	clearBytes(other)
	row := legacyInventoryRow{ID: id, Reference: reference, Encoding: encoding}
	store, err := openMigrationCredentialStore(ctx, row, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if value, present, err := store.Load(ctx); err == nil || present || len(value) != 0 {
		t.Fatal("oversize native secret returned")
	}
	if err := store.Delete(ctx); err == nil {
		t.Fatal("failed native read authorized deletion")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := openMigrationCredentialStore(canceled, row, 1024); err == nil {
		t.Fatal("canceled open")
	}
	if _, _, err := store.Load(canceled); err == nil {
		t.Fatal("canceled read")
	}
	if err := store.Delete(canceled); err == nil {
		t.Fatal("canceled delete")
	}
	row.Reference = "invalid"
	if _, err := openMigrationCredentialStore(ctx, row, 1024); err == nil {
		t.Fatal("invalid reference")
	}
	for _, invalid := range []struct{ id, reference, encoding string }{
		{id, reference, "foreign"}, {"bad", reference, encoding}, {id, "bad", encoding},
	} {
		if value, err := unprotectPlatformCredentialSecret(invalid.id, invalid.reference, invalid.encoding); err == nil || len(value) != 0 {
			t.Fatal("invalid legacy reader accepted")
		}
		if invalid.encoding == encoding {
			if _, _, err := storeCredentialSecret(invalid.id, invalid.reference, "invalid"); err == nil {
				t.Fatal("invalid legacy store accepted")
			}
			if err := deleteStoredCredentialSecret(invalid.id, invalid.reference, encoding); err == nil {
				t.Fatal("invalid legacy delete accepted")
			}
		} else if err := deleteStoredCredentialSecret(invalid.id, invalid.reference, invalid.encoding); err != nil {
			t.Fatal("foreign legacy deletion changed", err)
		}
	}
}
