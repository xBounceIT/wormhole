//go:build windows

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestCreateTunnelStoresPayloadInDpapiFileOnly(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY NOT NULL, Name TEXT NOT NULL, Kind INTEGER NOT NULL,
    CreatedAt TEXT NOT NULL, UpdatedAt TEXT NOT NULL
);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	details, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "native file store",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"private",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"vpn.example.test:51820"
        }`),
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := unprotectFile(legacyTunnelSecretPath(databasePath, details.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(plaintext) {
		t.Fatalf("decrypted tunnel payload is invalid: %q", plaintext)
	}

	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow(
		"SELECT COUNT(*) FROM CredentialSecrets WHERE Id = ?;", tunnelSecretID(details.ID),
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("CredentialSecrets contains %d tunnel payload rows, want 0", count)
	}
	if _, err := os.Stat(legacyTunnelSecretPath(databasePath, details.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteTunnelDoesNotDeadlockWithSingleDatabaseConnection(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY NOT NULL, Name TEXT NOT NULL, Kind INTEGER NOT NULL,
    CreatedAt TEXT NOT NULL, UpdatedAt TEXT NOT NULL
);
CREATE TABLE Nodes (Id TEXT PRIMARY KEY NOT NULL, TunnelConfigId TEXT NULL);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	details, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "delete me",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"private",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"vpn.example.test:51820"
        }`),
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- deleteTunnel(databasePath, tunnelDeleteRequest{ID: details.ID}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deleteTunnel deadlocked while checking the Nodes schema")
	}
}
