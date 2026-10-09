package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	bitwardenBrowserStorageSchema  = 1
	bitwardenBrowserStorageMaxJSON = 8 * 1024 * 1024
	// Legacy json.Marshal records expand HTML characters to six-byte escapes. Leave room for
	// that bounded representation and native protection overhead when recovering existing files.
	bitwardenBrowserStorageMaxProtected = 6*bitwardenBrowserStorageMaxJSON + 1024*1024
	bitwardenBrowserProfileRevisionFile = "wormhole-bitwarden-shared-storage-v1.txt"
)

type bitwardenBrowserStorageRecord struct {
	SchemaVersion int
	Revision      int64
	LocalJson     string
}

type bitwardenBrowserStorageSnapshot struct {
	Revision        int64  `json:"revision"`
	ProfileRevision int64  `json:"profileRevision"`
	Restore         bool   `json:"restore"`
	LocalJSON       string `json:"localJson"`
	SessionJSON     string `json:"sessionJson"`
	Durable         bool   `json:"durable"`
}

type bitwardenBrowserStorageReadState int

const (
	bitwardenBrowserStorageMissing bitwardenBrowserStorageReadState = iota
	bitwardenBrowserStorageReadable
	bitwardenBrowserStorageUnreadable
)

func validBitwardenBrowserProfilePath(profilePath string) bool {
	return profilePath != "" && len(profilePath) <= 4096 && filepath.IsAbs(profilePath) &&
		filepath.Clean(profilePath) == profilePath
}

func bitwardenBrowserProfileRevision(profilePath string) int64 {
	file, err := os.Open(filepath.Join(profilePath, bitwardenBrowserProfileRevisionFile))
	if err != nil {
		return 0
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(value) > 64 {
		return 0
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
	if err != nil || revision < 0 {
		return 0
	}
	return revision
}

func writeBitwardenBrowserProfileRevision(profilePath string, revision int64) {
	if revision <= 0 {
		return
	}
	_ = writePrivateFileAtomic(
		filepath.Join(profilePath, bitwardenBrowserProfileRevisionFile),
		[]byte(strconv.FormatInt(revision, 10)),
	)
}

func (m *vncManager) bitwardenBrowserStorageForProfile(
	snapshot bitwardenBrowserStorageSnapshot,
	profilePath string,
) bitwardenBrowserStorageSnapshot {
	profileRevision := max(bitwardenBrowserProfileRevision(profilePath), m.bitwardenBrowserProfileRevisions[profilePath])
	snapshot.ProfileRevision = profileRevision
	snapshot.Restore = snapshot.Revision > profileRevision
	return snapshot
}

func bitwardenBrowserStoragePath(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "bitwarden-browser-storage.dpapi")
}

func normalizeBitwardenBrowserStorageJSON(value string) (string, error) {
	if len(value) == 0 || len(value) > bitwardenBrowserStorageMaxJSON {
		return "", errors.New("Bitwarden browser storage payload is invalid")
	}
	trimmed := bytes.TrimSpace([]byte(value))
	if len(trimmed) < 2 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return "", errors.New("Bitwarden browser storage must be a JSON object")
	}
	var normalized bytes.Buffer
	if err := json.Compact(&normalized, trimmed); err != nil {
		return "", errors.New("Bitwarden browser storage could not be encoded")
	}
	return normalized.String(), nil
}

// Apply only a profile's edits since its last capture. A background refresh in another
// profile must not turn an unchanged, older account list into a new logout snapshot.
// Conflicting updates keep the latest shared value; deletions remain deletions, including
// when a stale profile refreshes a token that has since been removed by logout.
func mergeBitwardenBrowserStorageJSON(base, incoming, current string) (string, error) {
	var before, after, latest map[string]json.RawMessage
	for _, entry := range []struct {
		value string
		out   *map[string]json.RawMessage
	}{{base, &before}, {incoming, &after}, {current, &latest}} {
		if err := json.Unmarshal([]byte(entry.value), entry.out); err != nil || *entry.out == nil {
			return "", errors.New("Bitwarden browser storage merge requires JSON objects")
		}
	}
	for key, value := range after {
		if !bytes.Equal(value, before[key]) && bytes.Equal(latest[key], before[key]) {
			latest[key] = value
		}
	}
	for key := range before {
		if _, exists := after[key]; !exists {
			// A real logout must remove even a token concurrently refreshed by another profile.
			delete(latest, key)
		}
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(latest); err != nil {
		return "", errors.New("Bitwarden browser storage merge could not be encoded")
	}
	return normalizeBitwardenBrowserStorageJSON(strings.TrimSpace(encoded.String()))
}

func equalBitwardenBrowserStorageJSON(left, right string) bool {
	if left == right {
		return true
	}
	var a, b map[string]json.RawMessage
	if json.Unmarshal([]byte(left), &a) != nil || json.Unmarshal([]byte(right), &b) != nil || len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if !bytes.Equal(value, b[key]) {
			return false
		}
	}
	return true
}

func readBitwardenBrowserStorageCandidate(path string) (
	bitwardenBrowserStorageSnapshot,
	bitwardenBrowserStorageReadState,
) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return bitwardenBrowserStorageSnapshot{}, bitwardenBrowserStorageMissing
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > bitwardenBrowserStorageMaxProtected {
		return bitwardenBrowserStorageSnapshot{}, bitwardenBrowserStorageUnreadable
	}
	plaintext, err := unprotectBitwardenBrowserStorage(path)
	if err != nil {
		return bitwardenBrowserStorageSnapshot{}, bitwardenBrowserStorageUnreadable
	}
	var record bitwardenBrowserStorageRecord
	if err := json.Unmarshal(plaintext, &record); err != nil ||
		record.SchemaVersion != bitwardenBrowserStorageSchema || record.Revision <= 0 {
		return bitwardenBrowserStorageSnapshot{}, bitwardenBrowserStorageUnreadable
	}
	localJSON, err := normalizeBitwardenBrowserStorageJSON(record.LocalJson)
	if err != nil {
		return bitwardenBrowserStorageSnapshot{}, bitwardenBrowserStorageUnreadable
	}
	return bitwardenBrowserStorageSnapshot{
		Revision: record.Revision, LocalJSON: localJSON, SessionJSON: "{}", Durable: true,
	}, bitwardenBrowserStorageReadable
}

func readPersistedBitwardenBrowserStorage(databasePath string) (
	bitwardenBrowserStorageSnapshot,
	bool,
	bool,
) {
	path := bitwardenBrowserStoragePath(databasePath)
	primary, primaryState := readBitwardenBrowserStorageCandidate(path)
	backup, backupState := readBitwardenBrowserStorageCandidate(path + ".bak")
	if backupState == bitwardenBrowserStorageReadable &&
		(primaryState != bitwardenBrowserStorageReadable || backup.Revision > primary.Revision) {
		return backup, true, true
	}
	if primaryState == bitwardenBrowserStorageReadable {
		return primary, true,
			backupState != bitwardenBrowserStorageReadable || backup.Revision != primary.Revision || backup.LocalJSON != primary.LocalJSON
	}
	if primaryState == bitwardenBrowserStorageMissing && backupState == bitwardenBrowserStorageMissing {
		return bitwardenBrowserStorageSnapshot{
			LocalJSON: "{}", SessionJSON: "{}", Durable: true,
		}, true, false
	}
	return bitwardenBrowserStorageSnapshot{
		LocalJSON: "{}", SessionJSON: "{}",
	}, false, false
}

func persistBitwardenBrowserStorage(
	databasePath string,
	snapshot bitwardenBrowserStorageSnapshot,
) (bool, error) {
	record := bitwardenBrowserStorageRecord{
		SchemaVersion: bitwardenBrowserStorageSchema,
		Revision:      snapshot.Revision,
		LocalJson:     snapshot.LocalJSON,
	}
	var plaintext bytes.Buffer
	encoder := json.NewEncoder(&plaintext)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return false, fmt.Errorf("could not encode shared Bitwarden browser storage: %w", err)
	}
	path := bitwardenBrowserStoragePath(databasePath)
	if err := protectBitwardenBrowserStorage(path, plaintext.Bytes()); err != nil {
		return false, fmt.Errorf("could not protect shared Bitwarden browser storage: %w", err)
	}
	protected, err := os.ReadFile(path)
	if err != nil {
		return false, nil
	}
	if err := writePrivateFileAtomic(path+".bak", protected); err != nil {
		return false, nil
	}
	return true, nil
}
