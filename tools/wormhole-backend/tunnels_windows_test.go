//go:build windows

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
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

func TestProviderCacheWriteDoesNotResurrectDataAfterConcurrentTunnelEdit(t *testing.T) {
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
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage(`{"Server":"old.example.test","Username":"alice","Password":"secret","Mode":0,"UseOtp":true}`)
	details, err := createTunnel(databasePath, tunnelWriteRequest{Name: "edited", Kind: 4, Settings: original})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadTunnelSnapshot(databasePath, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	var originalSettings map[string]json.RawMessage
	_ = json.Unmarshal(details.Settings, &originalSettings)
	updated := json.RawMessage(`{"Server":"new.example.test","Username":"alice","Password":"secret","Mode":0,"UseOtp":true}`)
	if _, err := updateTunnel(databasePath, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 4, Settings: updated}); err != nil {
		t.Fatal(err)
	}
	wrote := false
	err = persistTunnelCacheIfCurrent(snapshot, 4, providerCacheState(4, originalSettings), func() error {
		wrote = true
		return nil
	})
	if err == nil || wrote {
		t.Fatalf("stale cache write was accepted: err=%v wrote=%v", err, wrote)
	}
}

func TestProviderCacheInvalidationDoesNotDeleteDataAfterConcurrentTunnelEdit(t *testing.T) {
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
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage(`{"Server":"old.example.test","Username":"alice","Password":"secret","Mode":0,"UseOtp":true}`)
	details, err := createTunnel(databasePath, tunnelWriteRequest{Name: "edited", Kind: 4, Settings: original})
	if err != nil {
		t.Fatal(err)
	}
	staleSnapshot, err := loadTunnelSnapshot(databasePath, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	updated := json.RawMessage(`{"Server":"new.example.test","Username":"alice","Password":"secret","Mode":0,"UseOtp":true}`)
	if _, err := updateTunnel(databasePath, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 4, Settings: updated}); err != nil {
		t.Fatal(err)
	}
	cachePath := stormshieldCachePath(staleSnapshot)
	if err := writePrivateFileAtomic(cachePath, []byte("current-cache")); err != nil {
		t.Fatal(err)
	}
	removeProtectedTunnelFileIfCurrent(staleSnapshot, cachePath)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("stale invalidation removed the current cache: %v", err)
	}
	currentSnapshot, err := loadTunnelSnapshot(databasePath, details.ID)
	if err != nil {
		t.Fatal(err)
	}
	removeProtectedTunnelFileIfCurrent(currentSnapshot, cachePath)
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current invalidation did not remove the cache: %v", err)
	}
}
