package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBackupOperationsHonorCancellationBeforeSideEffects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "workspace.db")
	destination := filepath.Join(directory, "backup.json")
	request := backupRequest{Path: destination}

	if _, err := exportBackupContext(ctx, databasePath, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export returned %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled export created destination: %v", err)
	}
	if _, err := importBackupContext(ctx, databasePath, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled import returned %v", err)
	}
}

func TestBackupValueConversionsCoverSQLiteRepresentations(t *testing.T) {
	for _, test := range []struct {
		value any
		want  int64
		ok    bool
	}{
		{value: int64(7), want: 7, ok: true},
		{value: int(8), want: 8, ok: true},
		{value: true, want: 1, ok: true},
		{value: false, want: 0, ok: true},
		{value: []byte("9"), want: 9, ok: true},
		{value: "10", want: 10, ok: true},
		{value: "invalid", ok: false},
		{value: 1.5, ok: false},
	} {
		got, ok := backupDatabaseInteger(test.value)
		if got != test.want || ok != test.ok {
			t.Fatalf("integer(%#v) = %d,%v want %d,%v", test.value, got, ok, test.want, test.ok)
		}
	}

	columns := []backupColumn{
		{DB: "Name", JSON: "name", Kind: backupString},
		{DB: "Bytes", JSON: "bytes", Kind: backupString},
		{DB: "Count", JSON: "count", Kind: backupInteger},
		{DB: "Enabled", JSON: "enabled", Kind: backupBoolean},
	}
	values := []any{"name", []byte("bytes"), "12", int64(1)}
	for index, column := range columns {
		encoded, err := backupJSONValue(column, values[index])
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("JSON value %s = %s, %v", column.DB, encoded, err)
		}
	}
	if _, err := backupJSONValue(backupColumn{DB: "Count", JSON: "count", Kind: backupInteger}, "invalid"); err == nil {
		t.Fatal("invalid backup integer was accepted")
	}
	if _, err := backupJSONValue(backupColumn{DB: "Enabled", JSON: "enabled", Kind: backupBoolean}, struct{}{}); err == nil {
		t.Fatal("invalid backup boolean was accepted")
	}
}

func TestBackupObjectAccessorsAndDatabaseValues(t *testing.T) {
	object := backupObject{
		"name":    json.RawMessage(`"value"`),
		"count":   json.RawMessage(`12`),
		"enabled": json.RawMessage(`true`),
		"numeric": json.RawMessage(`2`),
		"null":    json.RawMessage(`null`),
		"invalid": json.RawMessage(`{`),
	}
	if backupObjectString(object, "name") != "value" || backupObjectString(object, "missing") != "" || backupObjectString(object, "invalid") != "" {
		t.Fatalf("unexpected string accessors for %#v", object)
	}
	if value := backupObjectOptionalString(object, "name"); value == nil || *value != "value" {
		t.Fatalf("optional string = %#v", value)
	}
	if backupObjectOptionalString(object, "null") != nil || backupObjectOptionalString(object, "invalid") != nil {
		t.Fatal("invalid optional string was returned")
	}
	if value, ok := backupObjectInteger(object, "count"); !ok || value != 12 {
		t.Fatalf("integer = %d,%v", value, ok)
	}
	if _, ok := backupObjectInteger(object, "invalid"); ok {
		t.Fatal("invalid object integer was accepted")
	}
	if value, ok := backupObjectBoolean(object, "enabled"); !ok || !value {
		t.Fatalf("boolean = %v,%v", value, ok)
	}
	if value, ok := backupObjectBoolean(object, "numeric"); !ok || !value {
		t.Fatalf("numeric boolean = %v,%v", value, ok)
	}
	if _, ok := backupObjectBoolean(object, "invalid"); ok {
		t.Fatal("invalid object boolean was accepted")
	}

	setBackupObjectValue(object, "added", "text")
	if backupObjectString(object, "added") != "text" {
		t.Fatal("backup value was not set")
	}
	setBackupObjectValue(object, "added", nil)
	if _, exists := object["added"]; exists {
		t.Fatal("nil backup value was not removed")
	}

	for _, test := range []struct {
		column backupColumn
		want   any
	}{
		{column: backupColumn{JSON: "name", Kind: backupString}, want: "value"},
		{column: backupColumn{JSON: "count", Kind: backupInteger}, want: int64(12)},
		{column: backupColumn{JSON: "enabled", Kind: backupBoolean}, want: int64(1)},
		{column: backupColumn{JSON: "numeric", Kind: backupBoolean}, want: int64(1)},
		{column: backupColumn{JSON: "missing", Kind: backupString, Required: true, Default: "fallback"}, want: "fallback"},
		{column: backupColumn{JSON: "invalid", Kind: backupInteger, Required: true, Default: int64(3)}, want: int64(3)},
		{column: backupColumn{JSON: "missing", Kind: backupString}, want: nil},
	} {
		if got := backupDatabaseValue(object, test.column); got != test.want {
			t.Fatalf("database value for %#v = %#v, want %#v", test.column, got, test.want)
		}
	}
}

func TestBackupIdentifiersGuidsAndPayloadNormalization(t *testing.T) {
	valid := "00112233-4455-6677-8899-aabbccddeeff"
	if got, ok := canonicalBackupID("  " + strings.ToUpper(valid) + " "); !ok || got != valid {
		t.Fatalf("canonical id = %q,%v", got, ok)
	}
	for _, invalid := range []string{"", "00112233_4455-6677-8899-aabbccddeeff", "g0112233-4455-6677-8899-aabbccddeeff"} {
		if _, ok := canonicalBackupID(invalid); ok {
			t.Fatalf("invalid backup id %q was accepted", invalid)
		}
	}
	if got := backupDotNetGuidFromBytes([]byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); got != valid {
		t.Fatalf(".NET guid = %q", got)
	}
	if got := backupDotNetGuidFromBytes([]byte{1, 2}); got != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("short .NET guid = %q", got)
	}

	payload := backupPayload{}
	normalizeBackupPayloadLists(&payload)
	encoded, err := json.Marshal(payload)
	if err != nil || bytes.Contains(encoded, []byte("null")) {
		t.Fatalf("normalized payload = %s, %v", encoded, err)
	}
	node := backupObject{"id": json.RawMessage(`"node"`)}
	payload.Nodes = []*backupObject{nil, &node}
	payload.Passwords = []*backupPasswordEntry{nil, {CredentialID: "credential"}}
	if dropped := filterBackupNulls(&payload); dropped != 2 || len(payload.Nodes) != 1 || len(payload.Passwords) != 1 {
		t.Fatalf("filtered payload dropped=%d nodes=%d passwords=%d", dropped, len(payload.Nodes), len(payload.Passwords))
	}
}

func TestOperationProgressInterpolationIsBounded(t *testing.T) {
	for _, test := range []struct {
		completed, total, expected int
	}{
		{-1, 4, 10},
		{2, 4, 50},
		{9, 4, 90},
		{0, 0, 90},
	} {
		if got := progressBetween(10, 90, test.completed, test.total); got != test.expected {
			t.Fatalf("progressBetween(%d, %d) = %d, want %d", test.completed, test.total, got, test.expected)
		}
	}
}

const (
	backupTestFolderID     = "11111111-1111-4111-8111-111111111111"
	backupTestNodeID       = "22222222-2222-4222-8222-222222222222"
	backupTestCredentialID = "33333333-3333-4333-8333-333333333333"
	backupTestKeyID        = "44444444-4444-4444-8444-444444444444"
	backupTestTunnelID     = "55555555-5555-4555-8555-555555555555"
)

func TestBackupPlaintextRoundTripIsLegacyCompatible(t *testing.T) {
	installBackupTestSecretStore(t)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source := openBackupTestDatabase(t, sourcePath)
	seedBackupTestDatabase(t, source, sourcePath)
	removeBackupTestSshKeyCredential(t, source, sourcePath)
	source.Close()

	backupPath := filepath.Join(t.TempDir(), "wormhole-backup.json")
	exported, err := exportBackup(sourcePath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if exported.Encrypted || exported.NodeCount != 2 || exported.CredentialCount != 1 ||
		exported.TunnelCount != 1 || exported.PasswordCount != 2 ||
		exported.PrivateKeyCount != 0 || exported.TunnelPayloadCount != 1 {
		t.Fatalf("unexpected export summary: %#v", exported)
	}
	contents, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte(`"schemaVersion": 2`)) ||
		!bytes.Contains(contents, []byte(`"encryption": "none"`)) ||
		!bytes.Contains(contents, []byte(`"host": "server.example.com"`)) ||
		!bytes.Contains(contents, []byte(`"password": "hunter2"`)) {
		t.Fatalf("plaintext backup does not use the WinUI schema:\n%s", contents)
	}
	inspected, err := inspectBackup(backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Encrypted || inspected.SchemaVersion != backupCurrentSchemaVersion || inspected.ExportedAt == "" {
		t.Fatalf("unexpected inspect result: %#v", inspected)
	}

	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	result, err := importBackup(destinationPath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if result.NodesImported != 2 || result.CredentialsImported != 1 || result.TunnelsImported != 1 ||
		result.PasswordsImported != 2 || result.PrivateKeysImported != 0 || result.TunnelPayloadsImported != 1 {
		t.Fatalf("unexpected import summary: %#v", result)
	}
	destination := openBackupTestDatabase(t, destinationPath)
	defer destination.Close()
	var parentID, host string
	if err := destination.QueryRow("SELECT ParentId, Host FROM Nodes WHERE Id = ?;", backupTestNodeID).Scan(&parentID, &host); err != nil {
		t.Fatal(err)
	}
	if parentID != backupTestFolderID || host != "server.example.com" {
		t.Fatalf("imported node parent/host = %q/%q", parentID, host)
	}
	password, found, err := readBackupPassword(destination, backupTestCredentialID)
	if err != nil || !found || password != "hunter2" {
		t.Fatalf("credential password = %q, %t, %v", password, found, err)
	}
	inline, found, err := readBackupPassword(destination, backupTestNodeID)
	if err != nil || !found || inline != "inline-secret" {
		t.Fatalf("inline password = %q, %t, %v", inline, found, err)
	}
	tunnel, err := unprotectFile(legacyTunnelSecretPath(destinationPath, backupTestTunnelID))
	if err != nil || !bytes.Equal(tunnel, []byte(`{"PrivateKey":"vpn-secret"}`)) {
		t.Fatalf("tunnel payload = %q, %v", tunnel, err)
	}
	clearBytes(tunnel)

	// Re-import uses merge-by-ID and must never roll a locally rotated password back.
	if err := storeBackupPassword(destination, backupTestCredentialID, "rotated-locally"); err != nil {
		t.Fatal(err)
	}
	reimported, err := importBackup(destinationPath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if reimported.NodesSkipped != 2 || reimported.CredentialsSkipped != 1 || reimported.TunnelsSkipped != 1 {
		t.Fatalf("unexpected merge summary: %#v", reimported)
	}
	password, found, err = readBackupPassword(destination, backupTestCredentialID)
	if err != nil || !found || password != "rotated-locally" {
		t.Fatalf("merge overwrote the existing password: %q, %t, %v", password, found, err)
	}
}

func TestBackupRequiresEncryptionBeforeReadingSshPrivateKeys(t *testing.T) {
	installBackupTestSecretStore(t)
	databasePath := filepath.Join(t.TempDir(), "source.db")
	database := openBackupTestDatabase(t, databasePath)
	seedBackupTestDatabase(t, database, databasePath)
	database.Close()

	previousUnprotect := backupUnprotectStoredSecret
	secretReads := 0
	var secretReadsLock sync.Mutex
	backupUnprotectStoredSecret = func(id, encoded, encoding string, legacyPaths ...string) ([]byte, error) {
		secretReadsLock.Lock()
		secretReads++
		secretReadsLock.Unlock()
		return previousUnprotect(id, encoded, encoding, legacyPaths...)
	}
	t.Cleanup(func() { backupUnprotectStoredSecret = previousUnprotect })

	backupPath := filepath.Join(t.TempDir(), "plaintext.json")
	_, err := exportBackup(databasePath, backupRequest{Path: backupPath})
	if !errors.Is(err, errBackupPrivateKeyPasswordRequired) {
		t.Fatalf("plaintext SSH key backup error = %v", err)
	}
	secretReadsLock.Lock()
	reads := secretReads
	secretReadsLock.Unlock()
	if reads != 0 {
		t.Fatalf("plaintext SSH key backup read %d protected secrets", reads)
	}
	if _, statErr := os.Stat(backupPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plaintext SSH key backup wrote output: %v", statErr)
	}
}

func TestPopulateBackupPayloadSnapshotsSshKeyAndPassphraseAgainstConcurrentReplacement(t *testing.T) {
	installBackupTestSecretStore(t)
	databasePath := filepath.Join(t.TempDir(), "source.db")
	database := openBackupTestDatabase(t, databasePath)
	seedBackupTestDatabase(t, database, databasePath)
	database.Close()

	passphraseRead := make(chan struct{})
	continueExport := make(chan struct{})
	defer func() {
		select {
		case <-continueExport:
		default:
			close(continueExport)
		}
	}()
	previousUnprotect := backupUnprotectStoredSecret
	var pauseOnce sync.Once
	backupUnprotectStoredSecret = func(id, encoded, encoding string, legacyPaths ...string) ([]byte, error) {
		secret, err := previousUnprotect(id, encoded, encoding, legacyPaths...)
		if id == backupTestKeyID && err == nil {
			pauseOnce.Do(func() {
				close(passphraseRead)
				<-continueExport
			})
		}
		return secret, err
	}
	t.Cleanup(func() { backupUnprotectStoredSecret = previousUnprotect })

	previousStageProtect := credentialPrivateKeyStageProtect
	replacementStaged := make(chan struct{}, 1)
	credentialPrivateKeyStageProtect = func(finalPath, pendingPath string, plaintext []byte) error {
		if err := previousStageProtect(finalPath, pendingPath, plaintext); err != nil {
			return err
		}
		replacementStaged <- struct{}{}
		return nil
	}
	t.Cleanup(func() { credentialPrivateKeyStageProtect = previousStageProtect })

	payload := newBackupPayload()
	exportDone := make(chan error, 1)
	go func() {
		exportDone <- populateBackupPayloadContext(context.Background(), databasePath, payload, nil, true)
	}()
	select {
	case <-passphraseRead:
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not reach the SSH key passphrase")
	}

	replacementPath := filepath.Join(t.TempDir(), "replacement.pem")
	if err := os.WriteFile(replacementPath, testSshPrivateKey(t, "replacement-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateDone := make(chan error, 1)
	go func() {
		_, err := updateCredential(databasePath, credentialUpdateRequest{
			ID: backupTestKeyID,
			credentialCreateRequest: credentialCreateRequest{
				Name: "alice-key", Protocol: "ssh", Kind: "sshKey", Username: "alice",
				Passphrase: "replacement-passphrase", PrivateKeyPath: replacementPath,
			},
		})
		updateDone <- err
	}()

	select {
	case <-replacementStaged:
		close(continueExport)
		t.Fatal("SSH key replacement reached staging during the backup snapshot")
	case err := <-updateDone:
		close(continueExport)
		t.Fatalf("SSH key replacement did not wait for the backup snapshot: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(continueExport)
	select {
	case err := <-exportDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not finish after releasing its snapshot")
	}
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH key replacement did not resume after the backup snapshot")
	}

	var passphrase string
	for _, entry := range payload.Passwords {
		if entry.CredentialID == backupTestKeyID {
			passphrase = entry.Password
		}
	}
	var privateKey []byte
	for _, entry := range payload.PrivateKeys {
		if entry.CredentialID == backupTestKeyID {
			decoded, decodeErr := base64.StdEncoding.DecodeString(entry.DataB64)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			privateKey = decoded
		}
	}
	defer clearBytes(privateKey)
	if passphrase != "key-passphrase" || !bytes.Equal(privateKey, []byte("private-key-material")) {
		t.Fatalf("backup SSH key snapshot = passphrase:%q key:%q", passphrase, privateKey)
	}
}

func TestBackupEncryptedRoundTripAndWrongPasswordFailBeforeWrites(t *testing.T) {
	installBackupTestSecretStore(t)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source := openBackupTestDatabase(t, sourcePath)
	seedBackupTestDatabase(t, source, sourcePath)
	source.Close()

	backupPath := filepath.Join(t.TempDir(), "encrypted.json")
	exported, err := exportBackup(sourcePath, backupRequest{Path: backupPath, Password: "Cafe\u0301 password"})
	if err != nil {
		t.Fatal(err)
	}
	if !exported.Encrypted {
		t.Fatal("encrypted export reported plaintext")
	}
	contents, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte("hunter2")) || bytes.Contains(contents, []byte("server.example.com")) ||
		bytes.Contains(contents, []byte("private-key-material")) {
		t.Fatal("encrypted backup leaked plaintext metadata or secrets")
	}
	var envelope backupDocument
	if err := json.Unmarshal(contents, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Payload != nil || envelope.EncryptedPayload == nil ||
		envelope.EncryptedPayload.KDF != backupKDFPBKDF2SHA256 ||
		envelope.EncryptedPayload.Iterations != backupPBKDF2Iterations {
		t.Fatalf("unexpected WinUI encryption envelope: %#v", envelope)
	}

	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	_, err = importBackup(destinationPath, backupRequest{Path: backupPath})
	if !errors.Is(err, errBackupPasswordRequired) {
		t.Fatalf("missing password error = %v", err)
	}
	if _, statErr := os.Stat(destinationPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing-password import wrote destination state: %v", statErr)
	}
	_, err = importBackup(destinationPath, backupRequest{Path: backupPath, Password: "wrong"})
	if !errors.Is(err, errBackupBadPassword) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, statErr := os.Stat(destinationPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("wrong-password import wrote destination state: %v", statErr)
	}
	// The composed spelling must unlock a file written with the decomposed spelling.
	result, err := importBackup(destinationPath, backupRequest{Path: backupPath, Password: "Caf\u00e9 password"})
	if err != nil {
		t.Fatal(err)
	}
	if result.NodesImported != 2 || result.PasswordsImported != 3 {
		t.Fatalf("unexpected encrypted import result: %#v", result)
	}
}

func TestBackupReimportRepairsMissingAndCorruptSecrets(t *testing.T) {
	installBackupTestSecretStore(t)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source := openBackupTestDatabase(t, sourcePath)
	seedBackupTestDatabase(t, source, sourcePath)
	source.Close()
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	const backupPassword = "repair-test-password"
	if _, err := exportBackup(sourcePath, backupRequest{Path: backupPath, Password: backupPassword}); err != nil {
		t.Fatal(err)
	}

	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	if _, err := importBackup(destinationPath, backupRequest{Path: backupPath, Password: backupPassword}); err != nil {
		t.Fatal(err)
	}
	destination := openBackupTestDatabase(t, destinationPath)
	if _, err := destination.Exec(
		"DELETE FROM CredentialSecrets WHERE lower(Id) IN (lower(?), lower(?));",
		backupTestCredentialID, backupTestNodeID,
	); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	if err := storeBackupPassword(destination, backupTestKeyID, "rotated-key-passphrase"); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	destination.Close()
	keyPath := credentialPrivateKeyPath(destinationPath, backupTestKeyID)
	if err := os.WriteFile(keyPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(keyPath, backupMaxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(legacyTunnelSecretPath(destinationPath, backupTestTunnelID), []byte("not-json")); err != nil {
		t.Fatal(err)
	}

	result, err := importBackup(destinationPath, backupRequest{Path: backupPath, Password: backupPassword})
	if err != nil {
		t.Fatal(err)
	}
	if result.PasswordsImported != 3 || result.PrivateKeysImported != 1 || result.TunnelPayloadsImported != 1 {
		t.Fatalf("recovery summary = %#v", result)
	}
	warnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(warnings, "Existing private key") || !strings.Contains(warnings, "Existing tunnel payload") {
		t.Fatalf("recovery warnings = %s", warnings)
	}
	destination = openBackupTestDatabase(t, destinationPath)
	defer destination.Close()
	password, found, err := readBackupPassword(destination, backupTestCredentialID)
	if err != nil || !found || password != "hunter2" {
		t.Fatalf("recovered credential password = %q, %t, %v", password, found, err)
	}
	inline, found, err := readBackupPassword(destination, backupTestNodeID)
	if err != nil || !found || inline != "inline-secret" {
		t.Fatalf("recovered inline password = %q, %t, %v", inline, found, err)
	}
	passphrase, found, err := readBackupPassword(destination, backupTestKeyID)
	if err != nil || !found || passphrase != "key-passphrase" {
		t.Fatalf("recovered SSH key passphrase = %q, %t, %v", passphrase, found, err)
	}
	key, err := unprotectFile(credentialPrivateKeyPath(destinationPath, backupTestKeyID))
	if err != nil || !bytes.Equal(key, []byte("private-key-material")) {
		t.Fatalf("recovered private key = %q, %v", key, err)
	}
	clearBytes(key)
	tunnel, found, err := readBackupTunnelSettings(destination, destinationPath, backupTestTunnelID)
	if err != nil || !found || !bytes.Equal(tunnel, []byte(`{"PrivateKey":"vpn-secret"}`)) {
		t.Fatalf("recovered tunnel = %q, %t, %v", tunnel, found, err)
	}
	clearBytes(tunnel)
}

func TestBackupKeyRepairClearsPassphraseMissingFromSnapshot(t *testing.T) {
	installBackupTestSecretStore(t)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source := openBackupTestDatabase(t, sourcePath)
	seedBackupTestDatabase(t, source, sourcePath)
	if _, err := source.Exec(
		"DELETE FROM CredentialSecrets WHERE lower(Id) = lower(?);",
		backupTestKeyID,
	); err != nil {
		source.Close()
		t.Fatal(err)
	}
	source.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.json")
	const backupPassword = "repair-without-passphrase"
	if _, err := exportBackup(sourcePath, backupRequest{Path: backupPath, Password: backupPassword}); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	if _, err := importBackup(destinationPath, backupRequest{Path: backupPath, Password: backupPassword}); err != nil {
		t.Fatal(err)
	}
	destination := openBackupTestDatabase(t, destinationPath)
	if err := storeBackupPassword(destination, backupTestKeyID, "stale-local-passphrase"); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	destination.Close()
	keyPath := credentialPrivateKeyPath(destinationPath, backupTestKeyID)
	if err := os.Truncate(keyPath, backupMaxFileBytes+1); err != nil {
		t.Fatal(err)
	}

	result, err := importBackup(destinationPath, backupRequest{Path: backupPath, Password: backupPassword})
	if err != nil {
		t.Fatal(err)
	}
	if result.PrivateKeysImported != 1 {
		t.Fatalf("key repair summary = %#v", result)
	}
	destination = openBackupTestDatabase(t, destinationPath)
	defer destination.Close()
	passphrase, found, err := readBackupPassword(destination, backupTestKeyID)
	if err != nil || found || passphrase != "" {
		t.Fatalf("passphrase absent from repaired snapshot = %q, %t, %v", passphrase, found, err)
	}
	key, err := unprotectFile(keyPath)
	if err != nil || !bytes.Equal(key, []byte("private-key-material")) {
		t.Fatalf("repaired private key = %q, %v", key, err)
	}
	clearBytes(key)
}

func TestBackupDecryptsWinUIAesGcmVector(t *testing.T) {
	// Independently generated with the .NET APIs used by BackupService: NFC-normalized UTF-8
	// password, Rfc2898DeriveBytes.Pbkdf2(SHA-256, 600k), and AesGcm with a 16-byte tag.
	// Keeping this fixed vector proves compatibility without relying on Go encrypting and then
	// decrypting its own output.
	sealed := backupEncryptedPayload{
		KDF:           backupKDFPBKDF2SHA256,
		Iterations:    backupPBKDF2Iterations,
		SaltB64:       "AAECAwQFBgcICQoLDA0ODw==",
		NonceB64:      "EBESExQVFhcYGRob",
		CiphertextB64: "wSc8G0ZLhyi9Qdjpstd+gsJ4Z7Tam7y+wuZrzbyg16CB/Kjn0AEiuI8e7VGbpCVy2wt/sVtmUI3QZcbXwG1Yuo/ibjaVv23IBCGZtEtnkfDLw7IfXpmPsqb/7031Z9Kmt4Y80A+eAKW16tvou80Y/EaQ991O4YV/8LWtq9C+/b8mvUb8dB5O6T3nr0di+HGQiQ==",
		TagB64:        "AHJK7duQnoKzDU3y3fB/GQ==",
	}
	plaintext, err := unsealBackupPayload(sealed, "Caf\u00e9 password")
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(plaintext)
	want := `{"nodes":[],"credentials":[],"tunnels":[],"bitwardenCredentialCache":[],"passwords":[],"inlinePasswords":[],"privateKeys":[],"tunnelPayloads":[]}`
	if string(plaintext) != want {
		t.Fatalf("WinUI payload = %s", plaintext)
	}
}

func TestBackupImportRepairsLegacyTreeAndDanglingReferences(t *testing.T) {
	installBackupTestSecretStore(t)
	missingID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	cycleA := "66666666-6666-4666-8666-666666666666"
	cycleB := "77777777-7777-4777-8777-777777777777"
	document := map[string]any{
		"schemaVersion": 1,
		"app":           "Wormhole",
		"exportedAt":    time.Now().UTC().Format(time.RFC3339Nano),
		"encryption":    "none",
		"payload": map[string]any{
			"nodes": []any{
				map[string]any{
					"id": backupTestNodeID, "parentId": backupTestFolderID, "name": "leaf-first",
					"kind": 1, "sortOrder": 2, "protocol": 2, "credentialId": missingID,
					"credentialMode": 2, "tunnelEnabled": true, "tunnelConfigId": missingID,
				},
				map[string]any{"id": backupTestFolderID, "name": "folder", "kind": 0, "sortOrder": 1},
				map[string]any{"id": cycleA, "parentId": cycleB, "name": "cycle-a", "kind": 0, "sortOrder": 3},
				map[string]any{"id": cycleB, "parentId": cycleA, "name": "cycle-b", "kind": 0, "sortOrder": 4},
			},
			"credentials": []any{}, "tunnels": []any{}, "passwords": []any{},
			"privateKeys": []any{}, "tunnelPayloads": []any{},
		},
	}
	contents, _ := json.Marshal(document)
	backupPath := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(backupPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	result, err := importBackup(destinationPath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if result.NodesImported != 4 {
		t.Fatalf("legacy nodes imported = %d", result.NodesImported)
	}
	joinedWarnings := strings.Join(result.Warnings, "\n")
	for _, expected := range []string{"unsupported protocol", "missing credential", "missing tunnel", "tunneling disabled", "Cycle detected"} {
		if !strings.Contains(joinedWarnings, expected) {
			t.Fatalf("warnings missing %q:\n%s", expected, joinedWarnings)
		}
	}
	database := openBackupTestDatabase(t, destinationPath)
	defer database.Close()
	var parent sql.NullString
	var protocol int64
	var credentialID, tunnelID sql.NullString
	var tunnelEnabled int64
	if err := database.QueryRow(`
SELECT ParentId, Protocol, CredentialId, TunnelConfigId, TunnelEnabled
FROM Nodes WHERE Id = ?;`, backupTestNodeID).Scan(&parent, &protocol, &credentialID, &tunnelID, &tunnelEnabled); err != nil {
		t.Fatal(err)
	}
	if !parent.Valid || parent.String != backupTestFolderID || protocol != 0 || credentialID.Valid || tunnelID.Valid || tunnelEnabled != 0 {
		t.Fatalf("legacy leaf was not normalized: parent=%#v protocol=%d credential=%#v tunnel=%#v enabled=%d",
			parent, protocol, credentialID, tunnelID, tunnelEnabled)
	}
}

func TestBackupRejectsOversizedAndMalformedEncryptedFiles(t *testing.T) {
	tooLarge := filepath.Join(t.TempDir(), "too-large.json")
	file, err := os.Create(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(backupMaxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := inspectBackup(backupRequest{Path: tooLarge}); err == nil {
		t.Fatal("oversized backup was accepted")
	}

	malformed := backupDocument{
		SchemaVersion: 2,
		App:           "Wormhole",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Encryption:    backupEncryptionAESGCM,
		EncryptedPayload: &backupEncryptedPayload{
			KDF: backupKDFPBKDF2SHA256, Iterations: backupPBKDF2Iterations,
			SaltB64:       base64.StdEncoding.EncodeToString(make([]byte, 16)),
			NonceB64:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
			CiphertextB64: "", TagB64: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		},
	}
	contents, _ := json.Marshal(malformed)
	malformedPath := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformedPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importBackup(filepath.Join(t.TempDir(), "destination.db"), backupRequest{Path: malformedPath, Password: "password"}); err == nil || !strings.Contains(err.Error(), "malformed nonce, tag, salt, or ciphertext") {
		t.Fatalf("malformed envelope error = %v", err)
	}
}

func TestBackupRejectsUnboundedEnvelopeMetadataWithoutReflectingIt(t *testing.T) {
	marker := "unsupported\n" + strings.Repeat("x", 2048)
	document := backupDocument{
		SchemaVersion: backupCurrentSchemaVersion,
		App:           "Wormhole",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Encryption:    marker,
		Payload:       newBackupPayload(),
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unsupported.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBackup(backupRequest{Path: path}); err == nil ||
		strings.Contains(err.Error(), marker) || err.Error() != "Backup file uses unsupported encryption." {
		t.Fatalf("unsupported marker error = %v", err)
	}

	document.Encryption = backupEncryptionNone
	document.ExportedAt = strings.Repeat("2", 129)
	contents, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBackup(backupRequest{Path: path}); err == nil ||
		err.Error() != "Backup file has invalid export metadata." {
		t.Fatalf("unbounded exportedAt error = %v", err)
	}
}

func TestBackupExportProtectsTheDatabaseAndSiblingFiles(t *testing.T) {
	installBackupTestSecretStore(t)
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "wormhole.db")
	database := openBackupTestDatabase(t, databasePath)
	seedBackupTestDatabase(t, database, databasePath)
	database.Close()

	for _, reserved := range []string{
		databasePath,
		databasePath + "-journal",
		databasePath + "-shm",
		databasePath + "-wal",
		credentialPrivateKeyLockPath(databasePath),
		credentialPrivateKeyPath(databasePath, backupTestKeyID),
	} {
		if _, err := exportBackup(databasePath, backupRequest{Path: reserved}); err == nil ||
			!strings.Contains(err.Error(), "cannot be Wormhole workspace storage") {
			t.Fatalf("reserved workspace destination %q error = %v", reserved, err)
		}
	}
	aliasDirectory := filepath.Join(t.TempDir(), "database-alias")
	if err := os.Symlink(directory, aliasDirectory); err == nil {
		aliasedJournal := filepath.Join(aliasDirectory, filepath.Base(databasePath)+"-journal")
		if _, err := exportBackup(databasePath, backupRequest{Path: aliasedJournal}); err == nil ||
			!strings.Contains(err.Error(), "cannot be Wormhole workspace storage") {
			t.Fatalf("aliased database companion destination %q error = %v", aliasedJournal, err)
		}
	}
	database = openBackupTestDatabase(t, databasePath)
	var nodeCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM Nodes;").Scan(&nodeCount); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if nodeCount != 2 {
		t.Fatalf("database was damaged by self-export: nodes=%d", nodeCount)
	}

	backupPath := filepath.Join(directory, "backup.json")
	siblingPath := backupPath + ".tmp"
	const siblingContents = "unrelated user file"
	if err := os.WriteFile(siblingPath, []byte(siblingContents), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exportBackup(databasePath, backupRequest{Path: backupPath, Password: "file-safety-password"}); err != nil {
		t.Fatal(err)
	}
	sibling, err := os.ReadFile(siblingPath)
	if err != nil || string(sibling) != siblingContents {
		t.Fatalf("sibling temporary file changed: %q, %v", sibling, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, ".wormhole-backup-*.tmp"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v, %v", leftovers, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if permissions := info.Mode().Perm(); permissions != 0o600 {
			t.Fatalf("backup permissions = %o, want 600", permissions)
		}
	}
}

func TestBackupWorkspaceStoragePathUsesPlatformCaseRules(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "wormhole.db")
	caseVariant := filepath.Join(directory, "KEYS", "credential.dpapi")
	wantReserved := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	if reserved := isBackupWorkspaceStoragePath(databasePath, caseVariant); reserved != wantReserved {
		t.Fatalf("case-variant key path reserved = %t, want %t on %s", reserved, wantReserved, runtime.GOOS)
	}
	if !isBackupWorkspaceStoragePath(
		databasePath,
		filepath.Join(directory, "keys", "nested", "credential.dpapi"),
	) {
		t.Fatal("nested protected key path was not reserved")
	}
	if isBackupWorkspaceStoragePath(
		databasePath,
		filepath.Join(directory, "keys-sibling", "credential.dpapi"),
	) {
		t.Fatal("key-directory sibling was treated as protected storage")
	}
}

func TestBackupExportCanonicalizesLegacySQLiteTimestamps(t *testing.T) {
	installBackupTestSecretStore(t)
	databasePath := filepath.Join(t.TempDir(), "source.db")
	database := openBackupTestDatabase(t, databasePath)
	seedBackupTestDatabase(t, database, databasePath)
	removeBackupTestSshKeyCredential(t, database, databasePath)
	if _, err := database.Exec(`
UPDATE Nodes SET CreatedAt = '2026-08-07 10:11:12.1234567', UpdatedAt = '2026-08-07 10:12:13';
UPDATE CredentialProfiles SET CreatedAt = '2026-08-07T10:13:14.7654321';
UPDATE TunnelConfigs SET CreatedAt = '2026-08-07 10:14:15.1234567+02:00', UpdatedAt = '2026-08-07 10:15:16.1234567 +02:00';`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	backupPath := filepath.Join(t.TempDir(), "legacy-timestamps.json")
	if _, err := exportBackup(databasePath, backupRequest{Path: backupPath}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var document backupDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if document.Payload == nil {
		t.Fatal("exported payload was missing")
	}
	for _, objects := range [][]*backupObject{
		document.Payload.Nodes,
		document.Payload.Credentials,
		document.Payload.Tunnels,
	} {
		for _, object := range objects {
			for _, field := range []string{"createdAt", "updatedAt"} {
				value := backupObjectString(*object, field)
				if value == "" {
					continue
				}
				if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
					t.Fatalf("%s was not canonical JSON time: %q (%v)", field, value, err)
				}
			}
		}
	}
}

func TestBackupExportRejectsFilesItCannotImport(t *testing.T) {
	document := backupDocument{
		SchemaVersion: backupCurrentSchemaVersion,
		App:           "Wormhole",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Encryption:    backupEncryptionNone,
		Payload:       newBackupPayload(),
	}
	encoded, err := encodeBackupDocument(document, 32)
	if err == nil || !strings.Contains(err.Error(), "safety limit") || encoded != nil {
		t.Fatalf("oversized export result = %q, %v", encoded, err)
	}
}

func TestBackupImportSkipsMismatchedAndOversizedSecrets(t *testing.T) {
	installBackupTestSecretStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := newBackupPayload()
	oversizedKeyID := "66666666-6666-4666-8666-666666666666"
	credential := backupTestObject(map[string]any{
		"id": backupTestCredentialID, "name": "oversized-password", "kind": 0,
		"protocol": 0, "secretProvider": 0, "bitwardenFieldPath": "   ", "createdAt": "not-a-timestamp",
	})
	tunnel := backupTestObject(map[string]any{
		"id": backupTestTunnelID, "name": "malformed-tunnel", "kind": 0,
		"createdAt": now, "updatedAt": now,
	})
	payload.Credentials = append(payload.Credentials, &credential)
	oversizedKeyCredential := backupTestObject(map[string]any{
		"id": oversizedKeyID, "name": "oversized-key", "kind": 1,
		"protocol": 0, "secretProvider": 0, "createdAt": now,
	})
	payload.Credentials = append(payload.Credentials, &oversizedKeyCredential)
	payload.Tunnels = append(payload.Tunnels, &tunnel)
	payload.Passwords = append(payload.Passwords, &backupPasswordEntry{
		CredentialID: backupTestCredentialID,
		Password:     strings.Repeat("p", maxStoredCredentialBytes+1),
	})
	payload.PrivateKeys = append(payload.PrivateKeys,
		&backupPrivateKeyEntry{
			CredentialID: backupTestCredentialID,
			DataB64:      base64.StdEncoding.EncodeToString([]byte("not-for-a-password-profile")),
		},
		&backupPrivateKeyEntry{
			CredentialID: oversizedKeyID,
			DataB64:      base64.StdEncoding.EncodeToString(make([]byte, maxSshPrivateKeyBytes+1)),
		},
	)
	payload.TunnelPayloads = append(payload.TunnelPayloads, &backupTunnelPayloadEntry{
		TunnelConfigID: backupTestTunnelID,
		DataB64:        base64.StdEncoding.EncodeToString([]byte("not-json")),
	})
	backupPath := writeBackupTestPayload(t, payload)
	databasePath := filepath.Join(t.TempDir(), "destination.db")
	result, err := importBackup(databasePath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialsImported != 2 || result.TunnelsImported != 1 ||
		result.PasswordsImported != 0 || result.PrivateKeysImported != 0 ||
		result.TunnelPayloadsImported != 0 {
		t.Fatalf("unexpected bounded import result: %#v", result)
	}
	warnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(warnings, "protected-store limit") ||
		!strings.Contains(warnings, "did not match a local SSH key profile") ||
		!strings.Contains(warnings, "was malformed") {
		t.Fatalf("missing bounded-secret warnings: %s", warnings)
	}
	database := openBackupTestDatabase(t, databasePath)
	defer database.Close()
	var bitwardenFieldPath, createdAt string
	if err := database.QueryRow(
		"SELECT BitwardenFieldPath, CreatedAt FROM CredentialProfiles WHERE Id = ?;", backupTestCredentialID,
	).Scan(&bitwardenFieldPath, &createdAt); err != nil || bitwardenFieldPath != "login.password" {
		t.Fatalf("credential normalization = %q/%q, %v", bitwardenFieldPath, createdAt, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		t.Fatalf("credential timestamp was not canonicalized: %q, %v", createdAt, err)
	}
	if _, found, err := readBackupPassword(database, backupTestCredentialID); err != nil || found {
		t.Fatalf("oversized password was stored: found=%t err=%v", found, err)
	}
	if _, err := os.Stat(legacyTunnelSecretPath(databasePath, backupTestTunnelID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed tunnel payload was stored: %v", err)
	}
}

func TestBackupBitwardenCacheUsesLegacyLastEntryWinsNormalization(t *testing.T) {
	database := openBackupTestDatabase(t, filepath.Join(t.TempDir(), "destination.db"))
	defer database.Close()
	first := backupTestObject(map[string]any{
		"itemId": " item-1 ", "name": "Old name", "username": "old-user",
		"sshCredentialId": "61111111-1111-4111-8111-111111111111",
		"rdpCredentialId": "62222222-2222-4222-8222-222222222222",
		"vncCredentialId": "63333333-3333-4333-8333-333333333333",
	})
	second := backupTestObject(map[string]any{
		"itemId": "item-1", "name": " New name ", "username": "  ",
		"sshCredentialId": "71111111-1111-4111-8111-111111111111",
		"rdpCredentialId": "72222222-2222-4222-8222-222222222222",
		"vncCredentialId": "73333333-3333-4333-8333-333333333333",
		"lastSeenSyncUtc": "invalid", "updatedAtUtc": "invalid",
	})
	state := &backupImportState{resolvableCredentials: map[string]struct{}{}}
	if err := importBackupBitwardenCache(database, []*backupObject{&first, &second}, state); err != nil {
		t.Fatal(err)
	}
	var count int
	var name string
	var username sql.NullString
	var lastSeen, updated string
	if err := database.QueryRow(`
SELECT COUNT(*), Name, Username, LastSeenSyncUtc, UpdatedAtUtc
FROM BitwardenCredentialCache WHERE ItemId = ?;`, "item-1").Scan(&count, &name, &username, &lastSeen, &updated); err != nil {
		t.Fatal(err)
	}
	if count != 1 || name != "New name" || username.Valid || lastSeen == "" || updated == "" {
		t.Fatalf("cache row was not normalized: count=%d name=%q username=%#v timestamps=%q/%q",
			count, name, username, lastSeen, updated)
	}
	if _, err := time.Parse(time.RFC3339Nano, lastSeen); err != nil {
		t.Fatalf("last-seen timestamp was not canonicalized: %q, %v", lastSeen, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, updated); err != nil {
		t.Fatalf("updated timestamp was not canonicalized: %q, %v", updated, err)
	}
	for _, id := range []string{
		"61111111-1111-4111-8111-111111111111",
		"62222222-2222-4222-8222-222222222222",
		"63333333-3333-4333-8333-333333333333",
	} {
		if _, exists := state.resolvableCredentials[id]; exists {
			t.Fatalf("discarded Bitwarden credential id remained resolvable: %s", id)
		}
	}
	for _, id := range []string{
		"71111111-1111-4111-8111-111111111111",
		"72222222-2222-4222-8222-222222222222",
		"73333333-3333-4333-8333-333333333333",
	} {
		if _, exists := state.resolvableCredentials[id]; !exists {
			t.Fatalf("winning Bitwarden credential id was not resolvable: %s", id)
		}
	}
}

func TestBackupPreservesEarlyElectronTunnelSecretFallback(t *testing.T) {
	installBackupTestSecretStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertTunnel := func(database *sql.DB) {
		t.Helper()
		if err := insertBackupObject(database, "TunnelConfigs", backupTunnelColumns, backupTestObject(map[string]any{
			"id": backupTestTunnelID, "name": "fallback-vpn", "kind": 0,
			"createdAt": now, "updatedAt": now,
		})); err != nil {
			t.Fatal(err)
		}
	}
	storeFallback := func(database *sql.DB, value string) {
		t.Helper()
		secretID := tunnelSecretID(backupTestTunnelID)
		encoded, encoding, err := credentialSecretStore(secretID, value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`, secretID, encoded, encoding, now); err != nil {
			t.Fatal(err)
		}
	}

	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source := openBackupTestDatabase(t, sourcePath)
	insertTunnel(source)
	storeFallback(source, `{"source":"secret"}`)
	source.Close()
	backupPath := filepath.Join(t.TempDir(), "fallback-backup.json")
	result, err := exportBackup(sourcePath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if result.TunnelPayloadCount != 1 {
		t.Fatalf("fallback tunnel payload count = %d", result.TunnelPayloadCount)
	}

	destinationPath := filepath.Join(t.TempDir(), "destination.db")
	destination := openBackupTestDatabase(t, destinationPath)
	insertTunnel(destination)
	storeFallback(destination, `{"local":"rotated"}`)
	destination.Close()
	imported, err := importBackup(destinationPath, backupRequest{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	if imported.TunnelPayloadsImported != 0 || imported.TunnelsSkipped != 1 {
		t.Fatalf("fallback secret was unexpectedly overwritten: %#v", imported)
	}
	destination = openBackupTestDatabase(t, destinationPath)
	defer destination.Close()
	settings, found, err := readBackupTunnelSettings(destination, destinationPath, backupTestTunnelID)
	if err != nil || !found || string(settings) != `{"local":"rotated"}` {
		t.Fatalf("fallback tunnel secret = %q, %t, %v", settings, found, err)
	}
	clearBytes(settings)
}

func TestBackupWarningsAreBounded(t *testing.T) {
	result := backupImportResult{Warnings: []string{}}
	addBackupWarning(&result, "line one\n"+strings.Repeat("é", backupMaxImportWarningBytes))
	if len(result.Warnings) != 1 || len(result.Warnings[0]) > backupMaxImportWarningBytes ||
		!strings.HasSuffix(result.Warnings[0], "...") || strings.ContainsAny(result.Warnings[0], "\r\n\t") {
		t.Fatalf("warning was not safely truncated: bytes=%d", len(result.Warnings[0]))
	}
	for index := 1; index < backupMaxImportWarnings+5; index++ {
		addBackupWarning(&result, "warning")
	}
	if len(result.Warnings) != backupMaxImportWarnings ||
		result.Warnings[backupMaxImportWarnings-1] != "6 additional import warnings were omitted." {
		t.Fatalf("warning list was not capped: count=%d final=%q",
			len(result.Warnings), result.Warnings[backupMaxImportWarnings-1])
	}
}

func TestBackupSecretReadsUseBoundedConcurrency(t *testing.T) {
	const readCount = 12
	var lock sync.Mutex
	active := 0
	maximum := 0
	err := runBackupSecretReads(readCount, func(int) error {
		lock.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		lock.Unlock()
		time.Sleep(10 * time.Millisecond)
		lock.Lock()
		active--
		lock.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if maximum <= 1 || maximum > backupSecretExportConcurrency {
		t.Fatalf("secret read concurrency = %d", maximum)
	}
}

func openBackupTestDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureBackupSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database
}

func seedBackupTestDatabase(t *testing.T, database *sql.DB, databasePath string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	objects := []struct {
		table   string
		columns []backupColumn
		object  backupObject
	}{
		{table: "Nodes", columns: backupNodeColumns, object: backupTestObject(map[string]any{
			"id": backupTestFolderID, "name": "Servers", "kind": 0, "sortOrder": 0,
			"createdAt": now, "updatedAt": now,
		})},
		{table: "Nodes", columns: backupNodeColumns, object: backupTestObject(map[string]any{
			"id": backupTestNodeID, "parentId": backupTestFolderID, "name": "Production", "kind": 1,
			"sortOrder": 1, "protocol": 0, "host": "server.example.com", "port": 22,
			"credentialId": backupTestCredentialID, "credentialMode": 2, "useInlinePassword": true,
			"tunnelEnabled": true, "tunnelConfigId": backupTestTunnelID,
			"createdAt": now, "updatedAt": now,
		})},
		{table: "CredentialProfiles", columns: backupCredentialColumns, object: backupTestObject(map[string]any{
			"id": backupTestCredentialID, "name": "alice", "username": "alice", "kind": 0,
			"protocol": 0, "secretProvider": 0, "bitwardenFieldPath": "login.password", "createdAt": now,
		})},
		{table: "CredentialProfiles", columns: backupCredentialColumns, object: backupTestObject(map[string]any{
			"id": backupTestKeyID, "name": "alice-key", "username": "alice", "kind": 1,
			"privateKeyFileName": "id_ed25519", "protocol": 0, "secretProvider": 0,
			"bitwardenFieldPath": "login.password", "createdAt": now,
		})},
		{table: "TunnelConfigs", columns: backupTunnelColumns, object: backupTestObject(map[string]any{
			"id": backupTestTunnelID, "name": "office-vpn", "kind": 0, "createdAt": now, "updatedAt": now,
		})},
	}
	for _, item := range objects {
		if err := insertBackupObject(database, item.table, item.columns, item.object); err != nil {
			t.Fatal(err)
		}
	}
	if err := storeBackupPassword(database, backupTestCredentialID, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := storeBackupPassword(database, backupTestNodeID, "inline-secret"); err != nil {
		t.Fatal(err)
	}
	if err := storeBackupPassword(database, backupTestKeyID, "key-passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(credentialPrivateKeyPath(databasePath, backupTestKeyID), []byte("private-key-material")); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(legacyTunnelSecretPath(databasePath, backupTestTunnelID), []byte(`{"PrivateKey":"vpn-secret"}`)); err != nil {
		t.Fatal(err)
	}
}

func removeBackupTestSshKeyCredential(t *testing.T, database *sql.DB, databasePath string) {
	t.Helper()
	if _, err := database.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = lower(?);", backupTestKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM CredentialProfiles WHERE lower(Id) = lower(?);", backupTestKeyID); err != nil {
		t.Fatal(err)
	}
	if err := deleteCredentialPrivateKey(databasePath, backupTestKeyID); err != nil {
		t.Fatal(err)
	}
}

func backupTestObject(values map[string]any) backupObject {
	object := backupObject{}
	for key, value := range values {
		encoded, _ := json.Marshal(value)
		object[key] = encoded
	}
	return object
}

func writeBackupTestPayload(t *testing.T, payload *backupPayload) string {
	t.Helper()
	document := backupDocument{
		SchemaVersion: backupCurrentSchemaVersion,
		App:           "Wormhole",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Encryption:    backupEncryptionNone,
		Payload:       payload,
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installBackupTestSecretStore(t *testing.T) {
	t.Helper()
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	previousUnprotect := backupUnprotectStoredSecret
	credentialSecretStore = func(_ string, password string) (string, string, error) {
		return base64.StdEncoding.EncodeToString([]byte(password)), "backup-test-v1", nil
	}
	credentialSecretDelete = func(string, string, string) error { return nil }
	backupUnprotectStoredSecret = func(_ string, encoded, encoding string, _ ...string) ([]byte, error) {
		if encoding != "backup-test-v1" {
			return nil, errUnsupportedSecretEncoding
		}
		return base64.StdEncoding.DecodeString(encoded)
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
		backupUnprotectStoredSecret = previousUnprotect
	})
}
