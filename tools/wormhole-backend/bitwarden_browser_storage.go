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
	bitwardenBrowserStorageSchema       = 1
	bitwardenBrowserStorageMaxJSON      = 8 * 1024 * 1024
	bitwardenBrowserStorageMaxProtected = 16 * 1024 * 1024
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

func bitwardenBrowserStorageForProfile(
	snapshot bitwardenBrowserStorageSnapshot,
	profilePath string,
) bitwardenBrowserStorageSnapshot {
	profileRevision := bitwardenBrowserProfileRevision(profilePath)
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
	if primaryState == bitwardenBrowserStorageReadable {
		backup, backupState := readBitwardenBrowserStorageCandidate(path + ".bak")
		return primary, true,
			backupState != bitwardenBrowserStorageReadable || backup.Revision != primary.Revision
	}
	backup, backupState := readBitwardenBrowserStorageCandidate(path + ".bak")
	if backupState == bitwardenBrowserStorageReadable {
		return backup, true, true
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
	plaintext, err := json.Marshal(record)
	if err != nil {
		return false, fmt.Errorf("could not encode shared Bitwarden browser storage: %w", err)
	}
	path := bitwardenBrowserStoragePath(databasePath)
	if err := protectBitwardenBrowserStorage(path, plaintext); err != nil {
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
