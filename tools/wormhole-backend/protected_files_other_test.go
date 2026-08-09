//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestProtectedFileUsesSystemKeyringKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel.secret")
	want := []byte("private tunnel payload")
	if err := protectFile(path, want); err != nil {
		t.Fatalf("protect file: %v", err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, want) {
		t.Fatal("protected file contains its plaintext payload")
	}
	got, err := unprotectFile(path)
	if err != nil {
		t.Fatalf("unprotect file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unprotected payload = %q, want %q", got, want)
	}
	deleteFileProtectionKey(path)
	if _, err := unprotectFile(path); err == nil {
		t.Fatal("protected file remained decryptable after its key was deleted")
	}
}
