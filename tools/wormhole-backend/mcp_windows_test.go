//go:build windows

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMcpGetOrCreateTokenReadsElectronSafeStorageToken(t *testing.T) {
	// Mirrors the production shape on machines whose MCP token row was written by the
	// pre-DPAPI development build: an Electron-safeStorage payload that is only readable
	// through the Local State key of the Electron user-data directory.
	const expected = "legacy-safe-storage-token"
	key := []byte("01234567890123456789012345678901")
	userDataPath := t.TempDir()
	encoded := writeElectronSafeStorageFixture(t, userDataPath, expected, key)

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`,
		normalizeID(mcpTokenCredentialID),
		encoded,
		electronSafeStorageSecretEncoding,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	controller := newMcpController(&sshServer{
		databasePath:         databasePath,
		electronUserDataPath: userDataPath,
	})
	actual, err := controller.getOrCreateToken()
	if err != nil {
		t.Fatalf("getOrCreateToken could not read the safe-storage token: %v", err)
	}
	if actual != expected {
		t.Fatal("legacy safe-storage token changed")
	}

	// A successful legacy read must immediately remove the dependency on Electron's Local State
	// key. Future backend processes should be able to read the rewritten DPAPI value directly.
	second := newMcpController(&sshServer{databasePath: databasePath})
	reread, err := second.getOrCreateToken()
	if err != nil {
		t.Fatalf("getOrCreateToken could not read the migrated token: %v", err)
	}
	if reread != expected {
		t.Fatal("migrated token changed")
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var encoding string
	if err := database.QueryRow(
		"SELECT Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&encoding); err != nil {
		t.Fatal(err)
	}
	if encoding != protectedSecretEncoding {
		t.Fatalf("legacy token encoding was not migrated: got %q want %q", encoding, protectedSecretEncoding)
	}
}

func TestMcpGetOrCreateTokenRotatesElectronSafeStorageTokenWhenKeyChanged(t *testing.T) {
	const legacyToken = "legacy-safe-storage-token"
	userDataPath := t.TempDir()
	legacyKey := []byte("01234567890123456789012345678901")
	encoded := writeElectronSafeStorageFixture(t, userDataPath, legacyToken, legacyKey)
	currentKey := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	_ = writeElectronSafeStorageFixture(t, userDataPath, "current-profile-value", currentKey)

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`,
		normalizeID(mcpTokenCredentialID),
		encoded,
		electronSafeStorageSecretEncoding,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	controller := newMcpController(&sshServer{
		databasePath:         databasePath,
		electronUserDataPath: userDataPath,
	})
	rotated, err := controller.getOrCreateToken()
	if err != nil {
		t.Fatalf("getOrCreateToken did not recover from the stale safe-storage key: %v", err)
	}
	if rotated == "" || rotated == legacyToken {
		t.Fatalf("stale safe-storage token present = %t, changed = %t", rotated != "", rotated != legacyToken)
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var stored, encoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&stored, &encoding); err != nil {
		t.Fatal(err)
	}
	if encoding != protectedSecretEncoding {
		t.Fatalf("rotated token encoding = %q, want %q", encoding, protectedSecretEncoding)
	}
	plaintext, err := unprotectStoredSecret(mcpTokenCredentialID, stored, encoding)
	if err != nil {
		t.Fatalf("rotated token could not be decrypted: %v", err)
	}
	defer clearBytes(plaintext)
	if string(plaintext) != rotated {
		t.Fatal("stored rotated token does not match the live token")
	}
}
