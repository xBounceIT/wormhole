package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBitwardenBrowserStorageWireFitsLineBudgetWithHTMLCharacters(t *testing.T) {
	value := `{"value":"` + strings.Repeat("<>&", 2*1024*1024) + `"}`
	snapshot := bitwardenBrowserStorageSnapshot{
		Revision: 1, LocalJSON: value, SessionJSON: value,
	}
	if _, err := normalizeBitwardenBrowserStorageJSON(value); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := newBackendLineWriter(&output).write(backendResponse{
		ID: "snapshot", OK: true, Result: snapshot,
	}); err != nil {
		t.Fatal(err)
	}
	if output.Len() >= backendLineLimit {
		t.Fatalf("valid storage response exceeds native line budget: %d bytes", output.Len())
	}
	var decoded struct {
		ID     string                          `json:"id"`
		Result bitwardenBrowserStorageSnapshot `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "snapshot" || decoded.Result != snapshot {
		t.Fatal("storage response changed in transit")
	}
}

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

func TestBitwardenBrowserStorageRoundTripsBoundedEncodedRecords(t *testing.T) {
	for _, tc := range []struct{ name, local string }{
		{"html", `{"value":"` + strings.Repeat("<>&", 1024*1024) + `"}`},
		{"escape-boundary", `{"value":"` + strings.Repeat(`\\`, (bitwardenBrowserStorageMaxJSON-12)/2) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeBitwardenBrowserStorageJSON(tc.local); err != nil {
				t.Fatal(err)
			}
			database := filepath.Join(t.TempDir(), "wormhole.db")
			snapshot := bitwardenBrowserStorageSnapshot{Revision: 9, LocalJSON: tc.local, SessionJSON: "{}"}
			if _, err := persistBitwardenBrowserStorage(database, snapshot); err != nil {
				t.Fatal(err)
			}
			actual, state := readBitwardenBrowserStorageCandidate(bitwardenBrowserStoragePath(database))
			if state != bitwardenBrowserStorageReadable || actual.LocalJSON != snapshot.LocalJSON || actual.Revision != snapshot.Revision {
				t.Fatalf("valid bounded snapshot was lost after protected encoding: state=%d revision=%d", state, actual.Revision)
			}
		})
	}
}

func TestBitwardenBrowserStorageReadsLegacyExpandedRecord(t *testing.T) {
	database := filepath.Join(t.TempDir(), "wormhole.db")
	local := `{"value":"` + strings.Repeat("<>&", 1024*1024) + `"}`
	legacy, err := json.Marshal(bitwardenBrowserStorageRecord{SchemaVersion: bitwardenBrowserStorageSchema, Revision: 4, LocalJson: local})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) <= 16*1024*1024 {
		t.Fatal("fixture does not exercise legacy expansion")
	}
	if err := protectBitwardenBrowserStorage(bitwardenBrowserStoragePath(database), legacy); err != nil {
		t.Fatal(err)
	}
	actual, state := readBitwardenBrowserStorageCandidate(bitwardenBrowserStoragePath(database))
	if state != bitwardenBrowserStorageReadable || actual.LocalJSON != local || actual.Revision != 4 {
		t.Fatal("valid legacy expanded record was lost")
	}
}

func TestBitwardenBrowserStorageRecoversTemporaryPersistenceFailures(t *testing.T) {
	for _, blocked := range []string{"primary", "backup"} {
		t.Run(blocked, func(t *testing.T) {
			root := t.TempDir()
			database, profile := filepath.Join(root, "wormhole.db"), filepath.Join(root, "profile")
			manager := &vncManager{databasePath: database}
			first, err := manager.captureBitwardenBrowserStorage(`{"account":"first"}`, `{"key":"old"}`, 0, profile)
			if err != nil {
				t.Fatal(err)
			}
			blockedPath := bitwardenBrowserStoragePath(database)
			if blocked == "backup" {
				blockedPath += ".bak"
			}
			if err := os.Remove(blockedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(blockedPath, 0o700); err != nil {
				t.Fatal(err)
			}
			latest, err := manager.captureBitwardenBrowserStorage(`{"account":"new"}`, `{"key":"live"}`, first.Revision, profile)
			if err != nil {
				t.Fatal(err)
			}
			if latest.Restore || latest.ProfileRevision != latest.Revision || latest.Durable != (blocked == "backup") {
				t.Fatal("persistence failure invalidated accepted live state or misreported durability")
			}
			if err := os.Remove(blockedPath); err != nil {
				t.Fatal(err)
			}
			repaired, err := manager.captureBitwardenBrowserStorage(latest.LocalJSON, latest.SessionJSON, latest.Revision, profile)
			if err != nil {
				t.Fatal(err)
			}
			if !repaired.Durable || repaired.Restore || repaired.Revision != latest.Revision {
				t.Fatal("unchanged live state could not repair persistence without changing its revision")
			}
			for _, file := range []string{bitwardenBrowserStoragePath(database), bitwardenBrowserStoragePath(database) + ".bak"} {
				stored, state := readBitwardenBrowserStorageCandidate(file)
				if state != bitwardenBrowserStorageReadable || stored.Revision != latest.Revision || stored.LocalJSON != latest.LocalJSON {
					t.Fatal("persistence recovery lost accepted state")
				}
			}
		})
	}
}

func TestBitwardenBrowserStorageTracksAcceptedProfileWithoutWritableMarker(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked-marker", true: "unreadable-store"}[unreadable], func(t *testing.T) {
			root := t.TempDir()
			database := filepath.Join(root, "wormhole.db")
			profile := filepath.Join(root, "profile")
			if err := os.MkdirAll(filepath.Join(profile, bitwardenBrowserProfileRevisionFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if unreadable {
				if err := os.WriteFile(bitwardenBrowserStoragePath(database), []byte("unreadable"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manager := &vncManager{databasePath: database}
			first, err := manager.captureBitwardenBrowserStorage(`{"account":"first"}`, `{"key":"live"}`, 0, profile)
			if err != nil {
				t.Fatal(err)
			}
			read, err := manager.readBitwardenBrowserStorage(profile)
			if err != nil {
				t.Fatal(err)
			}
			if read.Restore || read.ProfileRevision != first.Revision {
				t.Fatal("accepted live profile was treated as stale when its marker could not be written")
			}
			second, err := manager.captureBitwardenBrowserStorage(`{"account":"new-login"}`, `{"key":"new"}`, read.ProfileRevision, profile)
			if err != nil {
				t.Fatal(err)
			}
			if second.LocalJSON != `{"account":"new-login"}` || second.Restore {
				t.Fatal("new login was discarded despite originating from the accepted profile")
			}
		})
	}
}

func TestBitwardenBrowserStorageRejectsStaleVolatileWriter(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "wormhole.db")
	if err := os.WriteFile(bitwardenBrowserStoragePath(database), []byte("unreadable"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &vncManager{databasePath: database}
	profileA, profileB := filepath.Join(root, "a"), filepath.Join(root, "b")
	first, err := manager.captureBitwardenBrowserStorage(`{"account":"first"}`, `{"key":"old"}`, 0, profileA)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := manager.captureBitwardenBrowserStorage(`{}`, `{}`, first.Revision, profileB)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := manager.captureBitwardenBrowserStorage(first.LocalJSON, first.SessionJSON, first.Revision, profileA)
	if err != nil {
		t.Fatal(err)
	}
	if stale.LocalJSON != latest.LocalJSON || stale.SessionJSON != latest.SessionJSON || !stale.Restore {
		t.Fatal("stale volatile writer revived the session after logout")
	}
}

func TestBitwardenBrowserStorageVolatileRevisionExceedsExistingProfile(t *testing.T) {
	root := t.TempDir()
	database, profile := filepath.Join(root, "wormhole.db"), filepath.Join(root, "a")
	if err := os.WriteFile(bitwardenBrowserStoragePath(database), []byte("unreadable"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeBitwardenBrowserProfileRevision(profile, 20)
	manager := &vncManager{databasePath: database}
	current, err := manager.captureBitwardenBrowserStorage(`{}`, `{}`, 20, profile)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision <= 20 || current.ProfileRevision != current.Revision {
		t.Fatal("volatile revision moved behind an acknowledged persisted profile")
	}
	stale, err := manager.captureBitwardenBrowserStorage(`{"account":"stale"}`, `{"key":"old"}`, 19, filepath.Join(root, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if stale.Revision != current.Revision || stale.LocalJSON != current.LocalJSON || !stale.Restore {
		t.Fatal("lower persisted profile revision revived a logged-out session")
	}
}

func TestBitwardenBrowserStorageRecoveryRevisionExceedsExistingProfile(t *testing.T) {
	root := t.TempDir()
	database, profile := filepath.Join(root, "wormhole.db"), filepath.Join(root, "a")
	if _, err := persistBitwardenBrowserStorage(database, bitwardenBrowserStorageSnapshot{Revision: 2, LocalJSON: "{}", SessionJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	writeBitwardenBrowserProfileRevision(profile, 20)
	manager := &vncManager{databasePath: database}
	current, err := manager.captureBitwardenBrowserStorage(`{}`, `{}`, 20, profile)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision <= 20 || current.ProfileRevision != current.Revision {
		t.Fatal("recovered snapshot revision moved behind an acknowledged profile")
	}
	stale, err := manager.captureBitwardenBrowserStorage(`{"account":"stale"}`, `{"key":"old"}`, 19, filepath.Join(root, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if stale.Revision != current.Revision || stale.LocalJSON != current.LocalJSON || !stale.Restore {
		t.Fatal("lower profile revision revived a logged-out recovery snapshot")
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
