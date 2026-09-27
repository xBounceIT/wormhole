//go:build !windows

package main

import (
	"bytes"
	"errors"
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

func TestBitwardenSessionResetRepairsCorruptKeyringEntry(t *testing.T) {
	for _, present := range []bool{false, true} {
		m := sessionTestManager(t)
		path := bitwardenSessionPath(m.databasePath)
		if present {
			if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := keyring.Set(fileKeyringService, protectedFileKeyringAccount(path), "corrupt-key"); err != nil {
			t.Fatal(err)
		}
		if err := m.setBitwardenSessionForGeneration("session-key", 0); err == nil {
			t.Fatal("corrupt keyring entry was accepted")
		}
		if err := m.resetBitwardenSession(); err != nil {
			t.Fatal(err)
		}
		if _, err := keyring.Get(fileKeyringService, protectedFileKeyringAccount(path)); !errors.Is(err, keyring.ErrNotFound) {
			t.Fatal("reset kept the corrupt protection key")
		}
		if err := m.setBitwardenSessionForGeneration("replacement-session", 0); err != nil {
			t.Fatal("reset did not recover protected storage", err)
		}
		m.clearBitwardenSession()
		m.restoreBitwardenSession(m.bitwardenGeneration())
		if m.bitwardenSession() != "replacement-session" {
			t.Fatal("replacement session did not restore")
		}
	}
}
