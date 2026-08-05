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
		t.Fatalf("unexpected token: got %q want %q", actual, expected)
	}
}
