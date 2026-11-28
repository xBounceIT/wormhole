//go:build !windows

package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// The existing non-Windows TestMain installs an in-memory keyring. No OS account
// or user's stored key is touched by this adapter regression.
func TestVaultMigrationFileKeyNativeAdapter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original.token")
	protected, err := protectFileContents(path, []byte("original value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(fileKeyringService, protectedFileKeyringAccount(path), "invalid-base64"); err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyFileProtectionKey(path, protected); err == nil {
		t.Fatal("invalid stored key accepted")
	}
	if err := keyring.Set(fileKeyringService, protectedFileKeyringAccount(path), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyFileProtectionKey(path, protected); err == nil {
		t.Fatal("replacement key deleted")
	}
	deleteFileProtectionKey(path)
	protected, err = protectFileContents(path, []byte("replacement value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyFileProtectionKey(path, protected); err != nil {
		t.Fatal(err)
	}
	if value, err := unprotectFileContents(path, protected); err == nil || bytes.Equal(value, []byte("replacement value")) {
		t.Fatal("retired key still usable")
	}
	if err := retireLegacyFileProtectionKey(path, protected); err != nil {
		t.Fatal("missing-key retry rejected", err)
	}
}
