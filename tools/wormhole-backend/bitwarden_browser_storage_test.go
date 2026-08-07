package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeBitwardenBrowserStorageJSONRequiresBoundedObject(t *testing.T) {
	normalized, err := normalizeBitwardenBrowserStorageJSON(`{"answer":42}`)
	if err != nil || normalized != `{"answer":42}` {
		t.Fatalf("normalize = %q, %v", normalized, err)
	}
	ordered := ` { "z": 9007199254740993, "a": "<value>" } `
	normalized, err = normalizeBitwardenBrowserStorageJSON(ordered)
	if err != nil || normalized != `{"z":9007199254740993,"a":"<value>"}` {
		t.Fatalf("ordering/precision changed: %q, %v", normalized, err)
	}
	for _, value := range []string{"", "null", "[]", "not-json"} {
		if _, err := normalizeBitwardenBrowserStorageJSON(value); err == nil {
			t.Fatalf("accepted invalid storage JSON %q", value)
		}
	}
	if _, err := normalizeBitwardenBrowserStorageJSON(
		`{"value":"` + strings.Repeat("x", bitwardenBrowserStorageMaxJSON) + `"}`,
	); err == nil {
		t.Fatal("accepted oversized storage JSON")
	}
}

func TestBitwardenBrowserStorageRejectsOversizedFilesAndRevisionMarkers(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(profile, bitwardenBrowserProfileRevisionFile)
	if err := os.WriteFile(marker, []byte(strings.Repeat("1", 65)), 0o600); err != nil {
		t.Fatal(err)
	}
	if revision := bitwardenBrowserProfileRevision(profile); revision != 0 {
		t.Fatalf("oversized revision marker was accepted: %d", revision)
	}

	storagePath := bitwardenBrowserStoragePath(filepath.Join(root, "wormhole.db"))
	file, err := os.Create(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(bitwardenBrowserStorageMaxProtected + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, state := readBitwardenBrowserStorageCandidate(storagePath); state != bitwardenBrowserStorageUnreadable {
		t.Fatalf("oversized protected storage state = %d", state)
	}
}

func TestBitwardenBrowserStorageSharesRevisionsWithoutPersistingSession(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "wormhole.db")
	profileA := filepath.Join(root, "profile-a")
	profileB := filepath.Join(root, "profile-b")
	manager := &vncManager{databasePath: databasePath}

	first, err := manager.captureBitwardenBrowserStorage(
		`{"local":"first"}`, `{"session":"live"}`, 0, profileA,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || first.ProfileRevision != 1 || first.Restore || !first.Durable {
		t.Fatalf("first capture = %+v", first)
	}

	restoreB, err := manager.readBitwardenBrowserStorage(profileB)
	if err != nil {
		t.Fatal(err)
	}
	if !restoreB.Restore || restoreB.ProfileRevision != 0 || restoreB.SessionJSON != `{"session":"live"}` {
		t.Fatalf("profile B restore = %+v", restoreB)
	}
	markedB, err := manager.captureBitwardenBrowserStorage(
		restoreB.LocalJSON, restoreB.SessionJSON, restoreB.Revision, profileB,
	)
	if err != nil {
		t.Fatal(err)
	}
	if markedB.Restore || markedB.ProfileRevision != 1 {
		t.Fatalf("profile B marker = %+v", markedB)
	}

	second, err := manager.captureBitwardenBrowserStorage(
		`{"local":"second"}`, `{"session":"new"}`, first.Revision, profileA,
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != 2 || second.ProfileRevision != 2 || second.Restore {
		t.Fatalf("second capture = %+v", second)
	}
	stale, err := manager.captureBitwardenBrowserStorage(
		`{"local":"stale"}`, `{"session":"stale"}`, markedB.Revision, profileB,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stale.LocalJSON != second.LocalJSON || stale.SessionJSON != second.SessionJSON || !stale.Restore {
		t.Fatalf("stale profile overwrote shared storage: %+v", stale)
	}

	restarted := &vncManager{databasePath: databasePath}
	afterRestart, err := restarted.readBitwardenBrowserStorage(filepath.Join(root, "profile-c"))
	if err != nil {
		t.Fatal(err)
	}
	if afterRestart.Revision != 2 || afterRestart.LocalJSON != second.LocalJSON ||
		afterRestart.SessionJSON != "{}" || !afterRestart.Restore || !afterRestart.Durable {
		t.Fatalf("restarted snapshot = %+v", afterRestart)
	}
}

func TestBitwardenBrowserStorageRecordIsWinUICompatible(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "wormhole.db")
	snapshot := bitwardenBrowserStorageSnapshot{
		Revision: 7, LocalJSON: `{"encrypted":"state"}`, SessionJSON: `{"ignored":true}`,
	}
	if _, err := persistBitwardenBrowserStorage(databasePath, snapshot); err != nil {
		t.Fatal(err)
	}
	plaintext, err := unprotectBitwardenBrowserStorage(bitwardenBrowserStoragePath(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(plaintext, &record); err != nil {
		t.Fatal(err)
	}
	if record["SchemaVersion"] != float64(1) || record["Revision"] != float64(7) ||
		record["LocalJson"] != `{"encrypted":"state"}` {
		t.Fatalf("persisted record = %#v", record)
	}
	if _, found := record["SessionJson"]; found {
		t.Fatal("session storage was persisted")
	}
	if _, err := os.Stat(bitwardenBrowserStoragePath(databasePath) + ".bak"); err != nil {
		t.Fatalf("recovery copy missing: %v", err)
	}
}

func TestBitwardenBrowserStorageDoesNotOverwriteUnreadablePersistentState(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "wormhole.db")
	profile := filepath.Join(root, "profile")
	storagePath := bitwardenBrowserStoragePath(databasePath)
	if err := os.WriteFile(storagePath, []byte("unreadable"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &vncManager{databasePath: databasePath}
	read, err := manager.readBitwardenBrowserStorage(profile)
	if err != nil {
		t.Fatal(err)
	}
	if read.Durable || manager.bitwardenBrowserLoaded {
		t.Fatalf("unreadable store was treated as loaded: %+v", read)
	}
	volatile, err := manager.captureBitwardenBrowserStorage(
		`{"local":"live"}`, `{"session":"live"}`, 0, profile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if volatile.Durable || volatile.Revision != 1 {
		t.Fatalf("volatile capture = %+v", volatile)
	}
	contents, err := os.ReadFile(storagePath)
	if err != nil || string(contents) != "unreadable" {
		t.Fatalf("unreadable persistent state was overwritten: %q, %v", contents, err)
	}

	if err := os.Remove(storagePath); err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.captureBitwardenBrowserStorage(
		volatile.LocalJSON, volatile.SessionJSON, volatile.Revision, profile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Durable || !manager.bitwardenBrowserLoaded || recovered.ProfileRevision == 0 {
		t.Fatalf("volatile capture was not persisted after recovery: %+v", recovered)
	}
}
