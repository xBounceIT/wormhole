//go:build linux

package main

import (
	"path/filepath"
	"testing"
)

func TestMcpTokenLifecycleUsesLinuxSecretService(t *testing.T) {
	stored := installLinuxCredentialStoreMock(t)

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	first := newMcpController(&sshServer{databasePath: databasePath})
	created, err := first.getOrCreateToken()
	if err != nil {
		t.Fatalf("first getOrCreateToken: %v", err)
	}
	if created == "" || len(stored) != 1 {
		t.Fatalf("created token present = %t, Secret Service entries = %d", created != "", len(stored))
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	var reference, encoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&reference, &encoding); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if encoding != linuxSecretServiceEncoding || reference == created {
		t.Fatalf("stored MCP token = encoding:%q reference:%q", encoding, reference)
	}

	second := newMcpController(&sshServer{databasePath: databasePath})
	reread, err := second.getOrCreateToken()
	if err != nil {
		t.Fatalf("second getOrCreateToken: %v", err)
	}
	if reread != created {
		t.Fatal("Linux MCP token round-trip mismatch")
	}

	regenerated, err := second.regenerateToken()
	if err != nil {
		t.Fatalf("regenerateToken: %v", err)
	}
	if regenerated == "" || regenerated == created || len(stored) != 1 {
		t.Fatalf(
			"regenerated token present = %t, changed = %t, Secret Service entries = %d",
			regenerated != "",
			regenerated != created,
			len(stored),
		)
	}
}
