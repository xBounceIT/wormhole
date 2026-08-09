package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxCredentialNameLength     = 256
	maxCredentialUsernameLength = 512
	maxCredentialDomainLength   = 512
	maxStoredCredentialPassword = 4096
	maxStoredCredentialBytes    = maxStoredCredentialPassword * utf8.UTFMax
	maxBitwardenItemIDLength    = 512
	maxBitwardenItemNameLength  = 1024
)

type credentialCreateRequest struct {
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Username           string `json:"username"`
	Domain             string `json:"domain"`
	Password           string `json:"password"`
	Provider           string `json:"provider"`
	BitwardenItemID    string `json:"bitwardenItemId"`
	BitwardenItemName  string `json:"bitwardenItemName"`
	BitwardenFieldPath string `json:"bitwardenFieldPath"`
}

type credentialUpdateRequest struct {
	ID string `json:"id"`
	credentialCreateRequest
}

type credentialDeleteRequest struct {
	ID string `json:"id"`
}

type normalizedCredentialDraft struct {
	name          string
	protocol      string
	protocolValue int64
	username      string
	domain        string
	password      string
	provider      int64
	itemID        string
	itemName      string
	fieldPath     string
}

// These indirections let the database transaction and validation behavior be covered on every
// platform. Production implementations always use the operating system's protected store.
var credentialSecretStore = storeCredentialSecret
var credentialSecretDelete = deleteStoredCredentialSecret

func createCredential(databasePath string, request credentialCreateRequest) (credentialRecord, error) {
	draft, err := normalizeCredentialDraft(request, false)
	if err != nil {
		return credentialRecord{}, err
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return credentialRecord{}, err
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		return credentialRecord{}, err
	}
	if exists, err := credentialNameExists(database, draft.name, ""); err != nil {
		return credentialRecord{}, err
	} else if exists {
		return credentialRecord{}, errors.New("a credential with this name already exists")
	}

	id, err := newCredentialID()
	if err != nil {
		return credentialRecord{}, errors.New("could not allocate a credential identifier")
	}
	var encoded, encoding string
	if draft.provider == 0 {
		encoded, encoding, err = credentialSecretStore(id, draft.password)
		if err != nil {
			return credentialRecord{}, errors.New("could not protect the credential password")
		}
	}

	tx, err := database.Begin()
	if err != nil {
		if draft.provider == 0 && draft.password != "" {
			_ = credentialSecretDelete(id, encoded, encoding)
		}
		return credentialRecord{}, fmt.Errorf("could not start credential save: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
			if draft.provider == 0 && draft.password != "" {
				_ = credentialSecretDelete(id, encoded, encoding)
			}
		}
	}()

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`
INSERT INTO CredentialProfiles
    (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, SecretProvider,
     BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
VALUES (?, ?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, ?);`,
		id, draft.name, nullableCredentialField(draft.username), nullableCredentialField(draft.domain),
		draft.protocolValue, draft.provider, nullableCredentialField(draft.itemID),
		nullableCredentialField(draft.itemName), draft.fieldPath, createdAt); err != nil {
		return credentialRecord{}, normalizeCredentialWriteError(err)
	}
	if draft.provider == 0 {
		if err := upsertCredentialSecret(tx, id, encoded, encoding); err != nil {
			return credentialRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return credentialRecord{}, fmt.Errorf("could not save credential: %w", err)
	}
	committed = true
	return credentialRecord{
		ID: id, Name: draft.name, Protocol: draft.protocol, Username: displayCredentialUsername(draft.username),
		Kind: "password", Domain: draft.domain, Provider: providerName(draft.provider), CanEdit: true, CanDelete: true,
		BitwardenItemID: draft.itemID, BitwardenItemName: draft.itemName,
	}, nil
}

func updateCredential(databasePath string, request credentialUpdateRequest) (credentialRecord, error) {
	id := normalizeID(request.ID)
	if !validCredentialID(id) {
		return credentialRecord{}, errors.New("credential id is invalid")
	}
	draft, err := normalizeCredentialDraft(request.credentialCreateRequest, true)
	if err != nil {
		return credentialRecord{}, err
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return credentialRecord{}, err
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		return credentialRecord{}, err
	}

	var kind, provider int64
	err = database.QueryRow(
		"SELECT COALESCE(Kind, 0), COALESCE(SecretProvider, 0) FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
		id,
	).Scan(&kind, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return credentialRecord{}, errors.New("credential was not found")
	}
	if err != nil {
		return credentialRecord{}, fmt.Errorf("could not read credential: %w", err)
	}
	if kind != 0 || (provider != 0 && provider != 1) {
		return credentialRecord{}, errors.New("only password credentials can be edited in Wormhole")
	}
	if draft.provider == 0 && draft.password == "" && provider != 0 {
		return credentialRecord{}, errors.New("a password is required when changing to local storage")
	}
	if exists, err := credentialNameExists(database, draft.name, id); err != nil {
		return credentialRecord{}, err
	} else if exists {
		return credentialRecord{}, errors.New("a credential with this name already exists")
	}
	var previousEncoded, previousEncoding sql.NullString
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
		id,
	).Scan(&previousEncoded, &previousEncoding)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return credentialRecord{}, fmt.Errorf("could not read credential secret: %w", err)
	}
	if draft.provider == 0 && draft.password == "" &&
		(!previousEncoded.Valid || !previousEncoding.Valid) {
		return credentialRecord{}, errors.New("the stored credential password is missing; enter it again")
	}

	var encoded, encoding string
	if draft.provider == 0 && draft.password != "" {
		encoded, encoding, err = credentialSecretStore(id, draft.password)
		if err != nil {
			return credentialRecord{}, errors.New("could not protect the credential password")
		}
	}
	tx, err := database.Begin()
	if err != nil {
		if draft.provider == 0 && draft.password != "" {
			_ = credentialSecretDelete(id, encoded, encoding)
		}
		return credentialRecord{}, fmt.Errorf("could not start credential update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
			if draft.provider == 0 && draft.password != "" {
				_ = credentialSecretDelete(id, encoded, encoding)
			}
		}
	}()
	result, err := tx.Exec(`
UPDATE CredentialProfiles
SET Name = ?, Username = ?, Domain = ?, Protocol = ?, SecretProvider = ?,
    BitwardenItemId = ?, BitwardenItemName = ?, BitwardenFieldPath = ?
WHERE lower(Id) = ? AND COALESCE(Kind, 0) = 0 AND COALESCE(SecretProvider, 0) IN (0, 1);`,
		draft.name, nullableCredentialField(draft.username), nullableCredentialField(draft.domain),
		draft.protocolValue, draft.provider, nullableCredentialField(draft.itemID),
		nullableCredentialField(draft.itemName), draft.fieldPath, id)
	if err != nil {
		return credentialRecord{}, normalizeCredentialWriteError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return credentialRecord{}, fmt.Errorf("could not update credential: %w", err)
	}
	if count == 0 {
		return credentialRecord{}, errors.New("credential is no longer an editable local password")
	}
	if draft.provider == 0 {
		if draft.password != "" {
			if err := upsertCredentialSecret(tx, id, encoded, encoding); err != nil {
				return credentialRecord{}, err
			}
		}
	} else if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", id); err != nil {
		return credentialRecord{}, fmt.Errorf("could not remove the obsolete local credential secret: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return credentialRecord{}, fmt.Errorf("could not update credential: %w", err)
	}
	committed = true
	if (draft.provider != 0 || draft.password != "") && previousEncoded.Valid && previousEncoding.Valid &&
		(previousEncoded.String != encoded || previousEncoding.String != encoding) {
		_ = credentialSecretDelete(id, previousEncoded.String, previousEncoding.String)
	}
	return credentialRecord{
		ID: id, Name: draft.name, Protocol: draft.protocol, Username: displayCredentialUsername(draft.username),
		Kind: "password", Domain: draft.domain, Provider: providerName(draft.provider), CanEdit: true, CanDelete: true,
		BitwardenItemID: draft.itemID, BitwardenItemName: draft.itemName,
	}, nil
}

func deleteCredential(databasePath string, request credentialDeleteRequest) error {
	id := normalizeID(request.ID)
	if !validCredentialID(id) {
		return errors.New("credential id is invalid")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		return err
	}

	tx, err := database.Begin()
	if err != nil {
		return fmt.Errorf("could not start credential deletion: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var kind, provider int64
	err = tx.QueryRow(
		"SELECT COALESCE(Kind, 0), COALESCE(SecretProvider, 0) FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
		id,
	).Scan(&kind, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("credential was not found")
	}
	if err != nil {
		return fmt.Errorf("could not read credential: %w", err)
	}
	if (kind != 0 && kind != 1) || (provider != 0 && provider != 1) {
		return errors.New("credential type cannot be deleted in Wormhole")
	}
	var encoded, encoding sql.NullString
	err = tx.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;", id,
	).Scan(&encoded, &encoding)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("could not read credential secret: %w", err)
	}
	result, err := tx.Exec(`
DELETE FROM CredentialProfiles
WHERE lower(Id) = ?
  AND COALESCE(Kind, 0) IN (0, 1)
  AND COALESCE(SecretProvider, 0) IN (0, 1);`, id)
	if err != nil {
		return fmt.Errorf("could not delete credential: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("could not delete credential: %w", err)
	}
	if count == 0 {
		return errors.New("credential was not found or is read-only")
	}
	if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", id); err != nil {
		return fmt.Errorf("could not delete credential secret: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not delete credential: %w", err)
	}
	committed = true
	// The profile and its database reference are gone even if a platform keychain cleanup is
	// unavailable. Do not report that as a failed deletion or leave a stale card in the UI.
	if encoded.Valid && encoding.Valid {
		_ = credentialSecretDelete(id, encoded.String, encoding.String)
	}
	if kind == 1 && provider == 0 {
		_ = deleteCredentialPrivateKey(databasePath, id)
	}
	return nil
}

func deleteCredentialPrivateKey(databasePath, id string) error {
	fileName := strings.ReplaceAll(normalizeID(id), "-", "") + ".dpapi"
	err := os.Remove(filepath.Join(filepath.Dir(databasePath), "keys", fileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func normalizeCredentialDraft(
	request credentialCreateRequest,
	allowMissingLocalPassword bool,
) (normalizedCredentialDraft, error) {
	name := strings.TrimSpace(request.Name)
	username := strings.TrimSpace(request.Username)
	domain := strings.TrimSpace(request.Domain)
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	providerName := strings.ToLower(strings.TrimSpace(request.Provider))
	provider := int64(0)
	if providerName == "bitwarden" {
		provider = 1
	} else if providerName != "" && providerName != "local" {
		return normalizedCredentialDraft{}, errors.New("credential provider is invalid")
	}
	itemID := strings.TrimSpace(request.BitwardenItemID)
	itemName := strings.TrimSpace(request.BitwardenItemName)

	if name == "" || !validCredentialText(name, maxCredentialNameLength) {
		return normalizedCredentialDraft{}, errors.New("credential name is invalid")
	}
	if !validCredentialText(username, maxCredentialUsernameLength) {
		return normalizedCredentialDraft{}, errors.New("credential username is invalid")
	}
	if !validCredentialText(domain, maxCredentialDomainLength) {
		return normalizedCredentialDraft{}, errors.New("credential domain is invalid")
	}
	if provider == 0 {
		if (!allowMissingLocalPassword && request.Password == "") ||
			utf8.RuneCountInString(request.Password) > maxStoredCredentialPassword {
			return normalizedCredentialDraft{}, errors.New("credential password is invalid")
		}
		itemID = ""
		itemName = ""
	} else {
		if itemID == "" || !validCredentialText(itemID, maxBitwardenItemIDLength) {
			return normalizedCredentialDraft{}, errors.New("Bitwarden item id is invalid")
		}
		if !validCredentialText(itemName, maxBitwardenItemNameLength) {
			return normalizedCredentialDraft{}, errors.New("Bitwarden item name is invalid")
		}
	}

	protocolValue := int64(0)
	switch protocol {
	case "ssh":
		if username == "" {
			return normalizedCredentialDraft{}, errors.New("SSH credentials need a username")
		}
	case "rdp":
		protocolValue = 1
		if username == "" || domain == "" {
			return normalizedCredentialDraft{}, errors.New("RDP credentials need a username and domain")
		}
	case "vnc":
		protocolValue = 6
		username = ""
		domain = ""
	default:
		return normalizedCredentialDraft{}, errors.New("credential protocol is invalid")
	}
	if protocol != "rdp" {
		domain = ""
	}
	return normalizedCredentialDraft{
		name: name, protocol: protocol, protocolValue: protocolValue, username: username, domain: domain,
		password: request.Password, provider: provider, itemID: itemID, itemName: itemName,
		fieldPath: "login.password",
	}, nil
}

func ensureCredentialWriteSchema(database *sql.DB) error {
	if _, err := database.Exec(`
CREATE TABLE IF NOT EXISTS CredentialProfiles (
    Id                    TEXT PRIMARY KEY NOT NULL,
    Name                  TEXT NOT NULL,
    Username              TEXT NULL,
    Domain                TEXT NULL,
    Kind                  INTEGER NOT NULL DEFAULT 0,
    PrivateKeyFileName    TEXT NULL,
    Protocol              INTEGER NOT NULL DEFAULT 0,
    SecretProvider        INTEGER NOT NULL DEFAULT 0,
    BitwardenItemId       TEXT NULL,
    BitwardenItemName     TEXT NULL,
    BitwardenFieldPath    TEXT NOT NULL DEFAULT 'login.password',
    CreatedAt             TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS UX_CredentialProfiles_Name ON CredentialProfiles(Name);
CREATE TABLE IF NOT EXISTS CredentialSecrets (
    Id        TEXT PRIMARY KEY NOT NULL,
    Secret    TEXT NOT NULL,
    Encoding  TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("could not create credential storage: %w", err)
	}

	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return err
	}
	missing := []struct {
		name string
		sql  string
	}{
		{"Username", "ALTER TABLE CredentialProfiles ADD COLUMN Username TEXT NULL;"},
		{"Domain", "ALTER TABLE CredentialProfiles ADD COLUMN Domain TEXT NULL;"},
		{"Kind", "ALTER TABLE CredentialProfiles ADD COLUMN Kind INTEGER NOT NULL DEFAULT 0;"},
		{"PrivateKeyFileName", "ALTER TABLE CredentialProfiles ADD COLUMN PrivateKeyFileName TEXT NULL;"},
		{"Protocol", "ALTER TABLE CredentialProfiles ADD COLUMN Protocol INTEGER NOT NULL DEFAULT 0;"},
		{"SecretProvider", "ALTER TABLE CredentialProfiles ADD COLUMN SecretProvider INTEGER NOT NULL DEFAULT 0;"},
		{"BitwardenItemId", "ALTER TABLE CredentialProfiles ADD COLUMN BitwardenItemId TEXT NULL;"},
		{"BitwardenItemName", "ALTER TABLE CredentialProfiles ADD COLUMN BitwardenItemName TEXT NULL;"},
		{"BitwardenFieldPath", "ALTER TABLE CredentialProfiles ADD COLUMN BitwardenFieldPath TEXT NOT NULL DEFAULT 'login.password';"},
		{"CreatedAt", "ALTER TABLE CredentialProfiles ADD COLUMN CreatedAt TEXT NOT NULL DEFAULT '';"},
	}
	for _, column := range missing {
		if _, exists := columns[column.name]; exists {
			continue
		}
		if _, err := database.Exec(column.sql); err != nil {
			return fmt.Errorf("could not update credential storage: %w", err)
		}
	}
	return nil
}

func upsertCredentialSecret(tx *sql.Tx, id, encoded, encoding string) error {
	// Old .NET/imported databases can contain upper-case GUID text even though every runtime
	// lookup normalizes ids. Remove every case variant first so a replacement cannot leave two
	// logically identical rows and make a later LIMIT 1 read return the stale secret.
	if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", normalizeID(id)); err != nil {
		return fmt.Errorf("could not replace credential secret: %w", err)
	}
	_, err := tx.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`,
		id, encoded, encoding, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("could not store credential secret: %w", err)
	}
	return nil
}

func credentialNameExists(database *sql.DB, name, excludingID string) (bool, error) {
	var present int
	query := "SELECT 1 FROM CredentialProfiles WHERE Name = ?"
	args := []any{name}
	if excludingID != "" {
		query += " AND lower(Id) <> ?"
		args = append(args, normalizeID(excludingID))
	}
	query += " LIMIT 1;"
	err := database.QueryRow(query, args...).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("could not validate credential name: %w", err)
	}
	return present == 1, nil
}

func normalizeCredentialWriteError(err error) error {
	if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed: credentialprofiles.name") {
		return errors.New("a credential with this name already exists")
	}
	return fmt.Errorf("could not save credential: %w", err)
}

func validCredentialText(value string, maximum int) bool {
	if utf8.RuneCountInString(value) > maximum {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func validCredentialID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func newCredentialID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func newCredentialSecretReference(id string) (string, error) {
	normalizedID := normalizeID(id)
	if !validCredentialID(normalizedID) {
		return "", errors.New("credential id is invalid")
	}
	nonce, err := newCredentialID()
	if err != nil {
		return "", err
	}
	return normalizedID + ":" + nonce, nil
}

func credentialSecretAccount(id, encoded string) (string, error) {
	normalizedID := normalizeID(id)
	reference := strings.ToLower(strings.TrimSpace(encoded))
	if !validCredentialID(normalizedID) {
		return "", errors.New("credential id is invalid")
	}
	if reference == normalizedID {
		return "credential:" + normalizedID, nil
	}
	prefix := normalizedID + ":"
	if !strings.HasPrefix(reference, prefix) || !validCredentialID(strings.TrimPrefix(reference, prefix)) {
		return "", errors.New("credential id is invalid")
	}
	return "credential:" + reference, nil
}

func nullableCredentialField(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func displayCredentialUsername(value string) string {
	if value == "" {
		return "No username"
	}
	return value
}
