package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const (
	maxCredentialNameLength            = 256
	maxCredentialUsernameLength        = 512
	maxCredentialDomainLength          = 512
	maxStoredCredentialPassword        = 4096
	maxStoredCredentialBytes           = maxStoredCredentialPassword * utf8.UTFMax
	maxBitwardenItemIDLength           = 512
	maxBitwardenItemNameLength         = 1024
	maxSshPrivateKeyBytes              = 1024 * 1024
	maxProtectedSshKeyBytes            = maxSshPrivateKeyBytes + (64 * 1024)
	credentialPrivateKeyPendingSuffix  = ".pending"
	credentialPrivateKeyDeletingSuffix = ".deleting"
	credentialPrivateKeyCreate         = "create"
	credentialPrivateKeyReplace        = "replace"
	credentialPrivateKeyDelete         = "delete"
	credentialPrivateKeyLockFileName   = ".credential-private-keys.lock"
)

const credentialPrivateKeyOperationsTableSQL = `
CREATE TABLE IF NOT EXISTS CredentialPrivateKeyOperations (
    CredentialId    TEXT PRIMARY KEY NOT NULL,
    OperationKind   TEXT NOT NULL CHECK (OperationKind IN ('create', 'replace', 'delete')),
    ProtectedSha256 TEXT NOT NULL,
    CreatedAtUtc    TEXT NOT NULL
);`

type credentialCreateRequest struct {
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Kind               string `json:"kind"`
	Username           string `json:"username"`
	Domain             string `json:"domain"`
	Password           string `json:"password"`
	Passphrase         string `json:"passphrase"`
	ClearPassphrase    bool   `json:"clearPassphrase"`
	PrivateKeyPath     string `json:"privateKeyPath"`
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
	name               string
	protocol           string
	protocolValue      int64
	kind               int64
	kindName           string
	username           string
	domain             string
	password           string
	passphrase         string
	clearPassphrase    bool
	privateKeyPath     string
	privateKeyFileName string
	provider           int64
	itemID             string
	itemName           string
	fieldPath          string
}

// These indirections let the database transaction and validation behavior be covered on every
// platform. Production implementations always use the operating system's protected store.
var credentialSecretStore = storeCredentialSecret
var credentialSecretDelete = deleteStoredCredentialSecret
var credentialPrivateKeyUnprotect = unprotectSshPrivateKey
var credentialPrivateKeyStageProtect = protectCredentialPrivateKeyStage
var credentialPrivateKeyPromote = os.Rename
var credentialPrivateKeyPendingRemove = os.Remove
var credentialPrivateKeyProtectionDelete = deleteFileProtectionKey

func createCredential(databasePath string, request credentialCreateRequest) (credentialRecord, error) {
	if strings.EqualFold(strings.TrimSpace(request.Provider), "bitwarden") {
		return credentialRecord{}, errors.New("Bitwarden credential profiles cannot be created manually")
	}
	draft, err := normalizeCredentialDraft(request, false)
	if err != nil {
		return credentialRecord{}, err
	}
	if draft.kind == 1 {
		release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
		if err != nil {
			return credentialRecord{}, err
		}
		defer release()
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
	var privateKey []byte
	if draft.kind == 1 {
		privateKey, err = readAndValidateSshPrivateKey(draft.privateKeyPath, draft.passphrase)
		if err != nil {
			return credentialRecord{}, err
		}
		defer clearBytes(privateKey)
	}

	secretValue := draft.password
	if draft.kind == 1 {
		secretValue = draft.passphrase
	}
	var encoded, encoding string
	if draft.provider == 0 && secretValue != "" {
		encoded, encoding, err = credentialSecretStore(id, secretValue)
		if err != nil {
			return credentialRecord{}, errors.New("could not protect the credential secret")
		}
	}
	var stagedPrivateKey *stagedCredentialPrivateKeyWrite
	tx, err := database.Begin()
	if err != nil {
		if encoded != "" {
			_ = credentialSecretDelete(id, encoded, encoding)
		}
		return credentialRecord{}, fmt.Errorf("could not start credential save: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
			if encoded != "" {
				_ = credentialSecretDelete(id, encoded, encoding)
			}
			if stagedPrivateKey != nil {
				stagedPrivateKey.rollbackCreation()
			}
		}
	}()

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`
INSERT INTO CredentialProfiles
    (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, SecretProvider,
     BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		id, draft.name, nullableCredentialField(draft.username), nullableCredentialField(draft.domain),
		draft.kind, nullableCredentialField(draft.privateKeyFileName), draft.protocolValue, draft.provider, nullableCredentialField(draft.itemID),
		nullableCredentialField(draft.itemName), draft.fieldPath, createdAt); err != nil {
		return credentialRecord{}, normalizeCredentialWriteError(err)
	}
	// The profile insert acquires SQLite's write lock before any protected file is staged.
	// Startup recovery uses BEGIN IMMEDIATE, so it cannot mistake this live stage for an orphan.
	if draft.kind == 1 {
		stagedPrivateKey, err = stageCredentialPrivateKeyWrite(databasePath, id, privateKey)
		if err != nil {
			_ = deleteCredentialPrivateKey(databasePath, id)
			return credentialRecord{}, errors.New("could not protect the SSH private key")
		}
	}
	if encoded != "" {
		if err := upsertCredentialSecret(tx, id, encoded, encoding); err != nil {
			return credentialRecord{}, err
		}
	}
	if stagedPrivateKey != nil {
		if err := recordCredentialPrivateKeyCreation(tx, stagedPrivateKey); err != nil {
			return credentialRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return credentialRecord{}, fmt.Errorf("could not save credential: %w", err)
	}
	committed = true
	if stagedPrivateKey != nil {
		if err := finalizeCredentialPrivateKeyWrite(database, stagedPrivateKey); err != nil {
			return credentialRecord{}, err
		}
	}
	return credentialRecord{
		ID: id, Name: draft.name, Protocol: draft.protocol, Username: displayCredentialUsername(draft.username),
		Kind: draft.kindName, Domain: draft.domain, Provider: providerName(draft.provider), CanEdit: true, CanDelete: true,
		BitwardenItemID: draft.itemID, BitwardenItemName: draft.itemName,
		PrivateKeyFileName: draft.privateKeyFileName,
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
	if draft.kind == 1 {
		release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
		if err != nil {
			return credentialRecord{}, err
		}
		defer release()
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
	var previousKeyFileName sql.NullString
	err = database.QueryRow(
		"SELECT COALESCE(Kind, 0), COALESCE(SecretProvider, 0), PrivateKeyFileName FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
		id,
	).Scan(&kind, &provider, &previousKeyFileName)
	if errors.Is(err, sql.ErrNoRows) {
		return credentialRecord{}, errors.New("credential was not found")
	}
	if err != nil {
		return credentialRecord{}, fmt.Errorf("could not read credential: %w", err)
	}
	if kind != draft.kind {
		return credentialRecord{}, errors.New("credential authentication type cannot be changed")
	}
	if (kind == 0 && provider != 0 && provider != 1) || (kind == 1 && provider != 0) || (kind != 0 && kind != 1) {
		return credentialRecord{}, errors.New("credential type cannot be edited in Wormhole")
	}
	if kind == 0 && draft.provider == 0 && draft.password == "" && provider != 0 {
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
	if kind == 0 && draft.provider == 0 && draft.password == "" &&
		(!previousEncoded.Valid || !previousEncoding.Valid) {
		return credentialRecord{}, errors.New("the stored credential password is missing; enter it again")
	}

	var privateKey []byte
	if kind == 1 && draft.privateKeyPath != "" {
		privateKey, err = readAndValidateSshPrivateKey(draft.privateKeyPath, draft.passphrase)
	} else if kind == 1 && draft.passphrase != "" {
		privateKey, err = credentialPrivateKeyUnprotect(credentialPrivateKeyPath(databasePath, id))
		if err == nil {
			err = validateSshPrivateKey(privateKey, draft.passphrase)
		}
		if err != nil {
			clearBytes(privateKey)
			return credentialRecord{}, errors.New("could not validate the stored SSH private key with that passphrase")
		}
	}
	defer clearBytes(privateKey)

	secretValue := draft.password
	if kind == 1 {
		secretValue = draft.passphrase
	}
	replaceSecret := draft.provider == 0 && secretValue != ""
	clearSecret := draft.provider != 0 || (kind == 1 &&
		(draft.clearPassphrase || (draft.privateKeyPath != "" && draft.passphrase == "")))
	var encoded, encoding string
	if replaceSecret {
		encoded, encoding, err = credentialSecretStore(id, secretValue)
		if err != nil {
			return credentialRecord{}, errors.New("could not protect the credential secret")
		}
	}
	tx, err := database.Begin()
	if err != nil {
		if replaceSecret {
			_ = credentialSecretDelete(id, encoded, encoding)
		}
		return credentialRecord{}, fmt.Errorf("could not start credential update: %w", err)
	}
	committed := false
	var stagedReplacement *stagedCredentialPrivateKeyWrite
	defer func() {
		if !committed {
			_ = tx.Rollback()
			if stagedReplacement != nil {
				stagedReplacement.rollback()
			}
			if replaceSecret {
				_ = credentialSecretDelete(id, encoded, encoding)
			}
		}
	}()
	var result sql.Result
	if kind == 0 {
		result, err = tx.Exec(`
UPDATE CredentialProfiles
SET Name = ?, Username = ?, Domain = ?, Protocol = ?, SecretProvider = ?,
    PrivateKeyFileName = NULL, BitwardenItemId = ?, BitwardenItemName = ?, BitwardenFieldPath = ?
WHERE lower(Id) = ? AND COALESCE(Kind, 0) = 0 AND COALESCE(SecretProvider, 0) IN (0, 1);`,
			draft.name, nullableCredentialField(draft.username), nullableCredentialField(draft.domain),
			draft.protocolValue, draft.provider, nullableCredentialField(draft.itemID),
			nullableCredentialField(draft.itemName), draft.fieldPath, id)
	} else {
		result, err = tx.Exec(`
UPDATE CredentialProfiles
SET Name = ?, Username = ?, Domain = NULL, Protocol = 0, SecretProvider = 0,
    PrivateKeyFileName = CASE WHEN ? <> '' THEN ? ELSE PrivateKeyFileName END,
    BitwardenItemId = NULL, BitwardenItemName = NULL, BitwardenFieldPath = ''
WHERE lower(Id) = ? AND COALESCE(Kind, 0) = 1 AND COALESCE(SecretProvider, 0) = 0;`,
			draft.name, nullableCredentialField(draft.username), draft.privateKeyFileName,
			draft.privateKeyFileName, id)
	}
	if err != nil {
		return credentialRecord{}, normalizeCredentialWriteError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return credentialRecord{}, fmt.Errorf("could not update credential: %w", err)
	}
	if count == 0 {
		return credentialRecord{}, errors.New("credential is no longer editable")
	}
	if kind == 1 {
		if err := rejectPendingCredentialPrivateKeyOperation(tx, id); err != nil {
			return credentialRecord{}, err
		}
	}
	if replaceSecret {
		if err := upsertCredentialSecret(tx, id, encoded, encoding); err != nil {
			return credentialRecord{}, err
		}
	} else if clearSecret {
		if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", id); err != nil {
			return credentialRecord{}, fmt.Errorf("could not remove the obsolete credential secret: %w", err)
		}
	}
	if kind == 1 && draft.privateKeyPath != "" {
		stagedReplacement, err = stageCredentialPrivateKeyWrite(databasePath, id, privateKey)
		if err != nil {
			return credentialRecord{}, errors.New("could not protect the SSH private key")
		}
		if err := recordCredentialPrivateKeyReplacement(tx, stagedReplacement); err != nil {
			return credentialRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return credentialRecord{}, fmt.Errorf("could not update credential: %w", err)
	}
	committed = true
	if stagedReplacement != nil {
		if err := finalizeCredentialPrivateKeyWrite(database, stagedReplacement); err != nil {
			return credentialRecord{}, err
		}
	}
	secretChanged := replaceSecret || clearSecret
	if secretChanged && previousEncoded.Valid && previousEncoding.Valid &&
		(previousEncoded.String != encoded || previousEncoding.String != encoding) {
		_ = credentialSecretDelete(id, previousEncoded.String, previousEncoding.String)
	}
	keyFileName := draft.privateKeyFileName
	if keyFileName == "" {
		keyFileName = credentialPrivateKeyDisplayName(nullableString(previousKeyFileName))
	}
	return credentialRecord{
		ID: id, Name: draft.name, Protocol: draft.protocol, Username: displayCredentialUsername(draft.username),
		Kind: draft.kindName, Domain: draft.domain, Provider: providerName(draft.provider), CanEdit: true, CanDelete: true,
		BitwardenItemID: draft.itemID, BitwardenItemName: draft.itemName,
		PrivateKeyFileName: keyFileName,
	}, nil
}

func deleteCredential(databasePath string, request credentialDeleteRequest) error {
	id := normalizeID(request.ID)
	if !validCredentialID(id) {
		return errors.New("credential id is invalid")
	}
	release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
	if err != nil {
		return err
	}
	defer release()
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
	var stagedKey *stagedCredentialPrivateKeyDeletion
	defer func() {
		if !committed {
			_ = tx.Rollback()
			if stagedKey != nil {
				_ = stagedKey.rollback()
			}
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
	if kind == 1 && provider == 0 {
		if err := rejectPendingCredentialPrivateKeyOperation(tx, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", id); err != nil {
		return fmt.Errorf("could not delete credential secret: %w", err)
	}
	if kind == 1 && provider == 0 {
		stagedKey, err = stageCredentialPrivateKeyDeletion(databasePath, id)
		if err != nil {
			return errors.New("could not delete the protected SSH private key")
		}
		if err := recordCredentialPrivateKeyDeletion(tx, stagedKey); err != nil {
			return err
		}
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
	if stagedKey != nil {
		finalizeCredentialPrivateKeyDeletion(database, stagedKey)
	}
	return nil
}

type stagedCredentialPrivateKeyDeletion struct {
	id         string
	finalPath  string
	stagedPath string
	digest     string
	staged     bool
}

var credentialPrivateKeyStageDelete = os.Rename

func stageCredentialPrivateKeyDeletion(databasePath, id string) (*stagedCredentialPrivateKeyDeletion, error) {
	finalPath := credentialPrivateKeyPath(databasePath, id)
	stagedPath := finalPath + credentialPrivateKeyDeletingSuffix
	deletion := &stagedCredentialPrivateKeyDeletion{
		id: normalizeID(id), finalPath: finalPath, stagedPath: stagedPath,
	}
	if _, err := os.Lstat(stagedPath); err == nil {
		return nil, errors.New("an SSH private key deletion is already pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	protected, err := readBoundedRegularFile(finalPath, maxProtectedSshKeyBytes)
	if errors.Is(err, os.ErrNotExist) {
		return deletion, nil
	}
	if err != nil {
		return nil, err
	}
	deletion.digest = credentialPrivateKeyDigest(protected)
	clearBytes(protected)
	if err := credentialPrivateKeyStageDelete(finalPath, stagedPath); err != nil {
		return nil, err
	}
	deletion.staged = true
	if err := verifyCredentialPrivateKeyDigest(stagedPath, deletion.digest); err != nil {
		if rollbackErr := deletion.rollback(); rollbackErr != nil {
			return nil, fmt.Errorf("SSH private key deletion staging changed and could not be restored: %w", err)
		}
		return nil, err
	}
	return deletion, nil
}

func (staged *stagedCredentialPrivateKeyDeletion) rollback() error {
	if !staged.staged {
		return nil
	}
	if _, err := os.Lstat(staged.finalPath); err == nil {
		return errors.New("protected SSH private key already exists during deletion rollback")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := verifyCredentialPrivateKeyDigest(staged.stagedPath, staged.digest); err != nil {
		return err
	}
	if err := credentialPrivateKeyPromote(staged.stagedPath, staged.finalPath); err != nil {
		return verifyCredentialPrivateKeyDigest(staged.finalPath, staged.digest)
	}
	return verifyCredentialPrivateKeyDigest(staged.finalPath, staged.digest)
}

func recordCredentialPrivateKeyDeletion(tx *sql.Tx, staged *stagedCredentialPrivateKeyDeletion) error {
	if err := recordCredentialPrivateKeyOperation(
		tx, staged.id, credentialPrivateKeyDelete, staged.digest,
	); err != nil {
		return fmt.Errorf("could not journal the SSH private key deletion: %w", err)
	}
	return nil
}

func finalizeCredentialPrivateKeyDeletion(database *sql.DB, staged *stagedCredentialPrivateKeyDeletion) {
	if err := removeCommittedCredentialPrivateKeyDeletion(staged); err != nil {
		return
	}
	_, _ = database.Exec(
		"DELETE FROM CredentialPrivateKeyOperations WHERE lower(CredentialId) = ?;",
		staged.id,
	)
}

func removeCommittedCredentialPrivateKeyDeletion(staged *stagedCredentialPrivateKeyDeletion) error {
	if _, err := os.Lstat(staged.finalPath); err == nil {
		return errors.New("protected SSH private key still exists after committed deletion")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if staged.digest != "" {
		if err := verifyCredentialPrivateKeyDigest(staged.stagedPath, staged.digest); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := credentialPrivateKeyPendingRemove(staged.stagedPath); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if _, err := os.Lstat(staged.stagedPath); err == nil {
		return errors.New("unexpected protected SSH private key deletion stage")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	credentialPrivateKeyProtectionDelete(staged.finalPath)
	return nil
}

func deleteCredentialPrivateKey(databasePath, id string) error {
	path := credentialPrivateKeyPath(databasePath, id)
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		credentialPrivateKeyProtectionDelete(path)
		return nil
	}
	return err
}

func credentialPrivateKeyPath(databasePath, id string) string {
	fileName := strings.ReplaceAll(normalizeID(id), "-", "") + ".dpapi"
	return filepath.Join(filepath.Dir(databasePath), "keys", fileName)
}

func readAndValidateSshPrivateKey(path, passphrase string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("SSH private key path is invalid")
	}
	contents, err := readBoundedRegularFile(path, maxSshPrivateKeyBytes)
	if err != nil || len(contents) == 0 {
		clearBytes(contents)
		return nil, errors.New("SSH private key is invalid or too large")
	}
	if err := validateSshPrivateKey(contents, passphrase); err != nil {
		clearBytes(contents)
		return nil, err
	}
	return contents, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		clearBytes(contents)
		return nil, err
	}
	if int64(len(contents)) > maximum {
		clearBytes(contents)
		return nil, errors.New("file exceeded the safety limit")
	}
	return contents, nil
}

func unprotectSshPrivateKey(path string) ([]byte, error) {
	protected, err := readBoundedRegularFile(path, maxProtectedSshKeyBytes)
	if err != nil {
		return nil, err
	}
	defer clearBytes(protected)
	plaintext, err := unprotectFileContents(path, protected)
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > maxSshPrivateKeyBytes {
		clearBytes(plaintext)
		return nil, errors.New("stored SSH private key is invalid")
	}
	return plaintext, nil
}

func validateSshPrivateKey(contents []byte, passphrase string) error {
	if _, err := ssh.ParsePrivateKey(contents); err == nil {
		if passphrase != "" {
			return errors.New("the SSH private key is not encrypted; leave the passphrase blank")
		}
		return nil
	} else {
		var missingPassphrase *ssh.PassphraseMissingError
		if !errors.As(err, &missingPassphrase) {
			return errors.New("the selected file is not a supported SSH private key")
		}
	}
	if passphrase == "" {
		// Saving an encrypted key without its passphrase is supported. The runtime prompts for the
		// passphrase on each connection attempt without returning the key to the renderer.
		return nil
	}
	passphraseBytes := []byte(passphrase)
	defer clearBytes(passphraseBytes)
	if _, err := ssh.ParsePrivateKeyWithPassphrase(contents, passphraseBytes); err != nil {
		return errors.New("the SSH private key passphrase is incorrect")
	}
	return nil
}

type stagedCredentialPrivateKeyWrite struct {
	id          string
	finalPath   string
	pendingPath string
	digest      string
}

type pendingCredentialPrivateKeyOperation struct {
	id            string
	operationKind string
	digest        string
}

func stageCredentialPrivateKeyWrite(
	databasePath, id string,
	plaintext []byte,
) (*stagedCredentialPrivateKeyWrite, error) {
	finalPath := credentialPrivateKeyPath(databasePath, id)
	pendingPath := finalPath + credentialPrivateKeyPendingSuffix
	if _, err := os.Lstat(pendingPath); err == nil {
		return nil, errors.New("an SSH private key replacement is already pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := credentialPrivateKeyStageProtect(finalPath, pendingPath, plaintext); err != nil {
		_ = credentialPrivateKeyPendingRemove(pendingPath)
		return nil, err
	}
	protected, err := readBoundedRegularFile(pendingPath, maxProtectedSshKeyBytes)
	if err != nil {
		_ = credentialPrivateKeyPendingRemove(pendingPath)
		return nil, err
	}
	digest := credentialPrivateKeyDigest(protected)
	clearBytes(protected)
	return &stagedCredentialPrivateKeyWrite{
		id: normalizeID(id), finalPath: finalPath, pendingPath: pendingPath, digest: digest,
	}, nil
}

func protectCredentialPrivateKeyStage(finalPath, pendingPath string, plaintext []byte) error {
	protected, err := protectFileContents(finalPath, plaintext)
	if err != nil {
		return err
	}
	defer clearBytes(protected)
	return writePrivateFileAtomic(pendingPath, protected)
}

func (staged *stagedCredentialPrivateKeyWrite) rollback() {
	_ = credentialPrivateKeyPendingRemove(staged.pendingPath)
}

func (staged *stagedCredentialPrivateKeyWrite) rollbackCreation() {
	staged.rollback()
	credentialPrivateKeyProtectionDelete(staged.finalPath)
}

func recordCredentialPrivateKeyCreation(
	tx *sql.Tx,
	staged *stagedCredentialPrivateKeyWrite,
) error {
	if err := recordCredentialPrivateKeyOperation(
		tx, staged.id, credentialPrivateKeyCreate, staged.digest,
	); err != nil {
		return fmt.Errorf("could not journal the SSH private key creation: %w", err)
	}
	return nil
}

func recordCredentialPrivateKeyReplacement(
	tx *sql.Tx,
	staged *stagedCredentialPrivateKeyWrite,
) error {
	if err := recordCredentialPrivateKeyOperation(
		tx, staged.id, credentialPrivateKeyReplace, staged.digest,
	); err != nil {
		return fmt.Errorf("could not journal the SSH private key replacement: %w", err)
	}
	return nil
}

func recordCredentialPrivateKeyOperation(tx *sql.Tx, id, operationKind, digest string) error {
	_, err := tx.Exec(`
INSERT INTO CredentialPrivateKeyOperations
    (CredentialId, OperationKind, ProtectedSha256, CreatedAtUtc)
VALUES (?, ?, ?, ?);`, id, operationKind, digest, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func rejectPendingCredentialPrivateKeyOperation(tx *sql.Tx, id string) error {
	var pending int
	if err := tx.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM CredentialPrivateKeyOperations WHERE lower(CredentialId) = ?);",
		id,
	).Scan(&pending); err != nil {
		return fmt.Errorf("could not inspect pending SSH private key work: %w", err)
	}
	if pending != 0 {
		return errors.New("the SSH private key is still being finalized; try again")
	}
	return nil
}

func finalizeCredentialPrivateKeyWrite(
	database *sql.DB,
	staged *stagedCredentialPrivateKeyWrite,
) error {
	if err := promoteOrVerifyCredentialPrivateKey(staged); err != nil {
		return errors.New("could not activate the SSH private key write")
	}
	if _, err := database.Exec(
		"DELETE FROM CredentialPrivateKeyOperations WHERE lower(CredentialId) = ?;",
		staged.id,
	); err != nil {
		return fmt.Errorf("could not finish the SSH private key write: %w", err)
	}
	return nil
}

func promoteOrVerifyCredentialPrivateKey(staged *stagedCredentialPrivateKeyWrite) error {
	protected, err := readBoundedRegularFile(staged.pendingPath, maxProtectedSshKeyBytes)
	if err == nil {
		digest := credentialPrivateKeyDigest(protected)
		clearBytes(protected)
		if digest != staged.digest {
			return errors.New("pending SSH private key digest does not match")
		}
		if err := credentialPrivateKeyPromote(staged.pendingPath, staged.finalPath); err != nil {
			return verifyCredentialPrivateKeyDigest(staged.finalPath, staged.digest)
		}
		return verifyCredentialPrivateKeyDigest(staged.finalPath, staged.digest)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return verifyCredentialPrivateKeyDigest(staged.finalPath, staged.digest)
}

func verifyCredentialPrivateKeyDigest(path, expected string) error {
	protected, err := readBoundedRegularFile(path, maxProtectedSshKeyBytes)
	if err != nil {
		return err
	}
	defer clearBytes(protected)
	if credentialPrivateKeyDigest(protected) != expected {
		return errors.New("protected SSH private key digest does not match")
	}
	return nil
}

func credentialPrivateKeyDigest(protected []byte) string {
	digest := sha256.Sum256(protected)
	return hex.EncodeToString(digest[:])
}

func acquireCredentialPrivateKeyLock(databasePath string) (func(), error) {
	directory := filepath.Dir(filepath.Clean(databasePath))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("could not prepare SSH private key storage")
	}
	release, err := acquireExclusiveFileLock(credentialPrivateKeyLockPath(databasePath))
	if err != nil {
		return nil, errors.New("could not lock SSH private key storage")
	}
	return release, nil
}

func credentialPrivateKeyLockPath(databasePath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(databasePath)), credentialPrivateKeyLockFileName)
}

func acquireRecoveredCredentialPrivateKeyLock(databasePath string) (func(), error) {
	release, err := acquireCredentialPrivateKeyLock(databasePath)
	if err != nil {
		return nil, err
	}
	if err := recoverCredentialPrivateKeyOperationsUnlocked(databasePath); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func recoverCredentialPrivateKeyOperations(databasePath string) error {
	release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
	if err != nil {
		return err
	}
	release()
	return nil
}

func recoverCredentialPrivateKeyOperationsUnlocked(databasePath string) error {
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		return err
	}
	return recoverCredentialPrivateKeyOperationsWithDatabase(database, databasePath)
}

func recoverCredentialPrivateKeyOperationsWithDatabase(database *sql.DB, databasePath string) error {
	ctx := context.Background()
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("could not open SSH private key recovery: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE;"); err != nil {
		return fmt.Errorf("could not lock SSH private key recovery: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(ctx, "ROLLBACK;")
		}
	}()

	rows, err := connection.QueryContext(ctx, `
SELECT CredentialId, OperationKind, ProtectedSha256
FROM CredentialPrivateKeyOperations
ORDER BY CredentialId;`)
	if err != nil {
		return fmt.Errorf("could not inspect SSH private key recovery: %w", err)
	}
	operations := make([]pendingCredentialPrivateKeyOperation, 0)
	for rows.Next() {
		var operation pendingCredentialPrivateKeyOperation
		if err := rows.Scan(&operation.id, &operation.operationKind, &operation.digest); err != nil {
			_ = rows.Close()
			return fmt.Errorf("could not read SSH private key recovery: %w", err)
		}
		operation.id = normalizeID(operation.id)
		if !validCredentialID(operation.id) ||
			(operation.operationKind != credentialPrivateKeyCreate &&
				operation.operationKind != credentialPrivateKeyReplace &&
				operation.operationKind != credentialPrivateKeyDelete) {
			_ = rows.Close()
			return errors.New("SSH private key recovery record is invalid")
		}
		if operation.digest != "" {
			decodedDigest, decodeErr := hex.DecodeString(operation.digest)
			if decodeErr != nil || len(decodedDigest) != sha256.Size {
				_ = rows.Close()
				return errors.New("SSH private key recovery record is invalid")
			}
			operation.digest = hex.EncodeToString(decodedDigest)
		}
		if operation.operationKind != credentialPrivateKeyDelete && operation.digest == "" {
			_ = rows.Close()
			return errors.New("SSH private key recovery record is invalid")
		}
		operations = append(operations, operation)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("could not read SSH private key recovery: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("could not close SSH private key recovery: %w", err)
	}
	for _, operation := range operations {
		finalPath := credentialPrivateKeyPath(databasePath, operation.id)
		if operation.operationKind != credentialPrivateKeyDelete {
			staged := &stagedCredentialPrivateKeyWrite{
				id: operation.id, finalPath: finalPath,
				pendingPath: finalPath + credentialPrivateKeyPendingSuffix, digest: operation.digest,
			}
			if err := promoteOrVerifyCredentialPrivateKey(staged); err != nil {
				return errors.New("could not recover an SSH private key write")
			}
		} else {
			staged := &stagedCredentialPrivateKeyDeletion{
				id: operation.id, finalPath: finalPath,
				stagedPath: finalPath + credentialPrivateKeyDeletingSuffix,
				digest:     operation.digest, staged: operation.digest != "",
			}
			if err := removeCommittedCredentialPrivateKeyDeletion(staged); err != nil {
				return errors.New("could not recover an SSH private key deletion")
			}
		}
		if _, err := connection.ExecContext(
			ctx,
			"DELETE FROM CredentialPrivateKeyOperations WHERE lower(CredentialId) = ?;",
			operation.id,
		); err != nil {
			return fmt.Errorf("could not complete SSH private key recovery: %w", err)
		}
	}
	if err := recoverOrphanedCredentialPrivateKeyStages(databasePath); err != nil {
		return errors.New("could not clean interrupted SSH private key staging")
	}
	if _, err := connection.ExecContext(ctx, "COMMIT;"); err != nil {
		return fmt.Errorf("could not commit SSH private key recovery: %w", err)
	}
	committed = true
	return nil
}

func recoverOrphanedCredentialPrivateKeyStages(databasePath string) error {
	directory := filepath.Join(filepath.Dir(databasePath), "keys")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if strings.HasSuffix(entry.Name(), ".dpapi"+credentialPrivateKeyPendingSuffix) {
			finalPath := strings.TrimSuffix(path, credentialPrivateKeyPendingSuffix)
			_, finalErr := os.Lstat(finalPath)
			if finalErr != nil && !errors.Is(finalErr, os.ErrNotExist) {
				return finalErr
			}
			if err := credentialPrivateKeyPendingRemove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if errors.Is(finalErr, os.ErrNotExist) {
				credentialPrivateKeyProtectionDelete(finalPath)
			}
			continue
		}
		if strings.HasSuffix(entry.Name(), ".dpapi"+credentialPrivateKeyDeletingSuffix) {
			finalPath := strings.TrimSuffix(path, credentialPrivateKeyDeletingSuffix)
			protected, err := readBoundedRegularFile(path, maxProtectedSshKeyBytes)
			if err != nil {
				return err
			}
			digest := credentialPrivateKeyDigest(protected)
			clearBytes(protected)
			staged := &stagedCredentialPrivateKeyDeletion{
				finalPath: finalPath, stagedPath: path, digest: digest, staged: true,
			}
			if err := staged.rollback(); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeCredentialDraft(
	request credentialCreateRequest,
	updating bool,
) (normalizedCredentialDraft, error) {
	name := strings.TrimSpace(request.Name)
	username := strings.TrimSpace(request.Username)
	domain := strings.TrimSpace(request.Domain)
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	kindName := strings.ToLower(strings.TrimSpace(request.Kind))
	if kindName == "" {
		kindName = "password"
	}
	kind := int64(0)
	if kindName == "sshkey" {
		kind = 1
	} else if kindName != "password" {
		return normalizedCredentialDraft{}, errors.New("credential authentication type is invalid")
	}
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
	if kind == 1 {
		if protocol != "ssh" || provider != 0 || request.Password != "" || domain != "" || itemID != "" || itemName != "" {
			return normalizedCredentialDraft{}, errors.New("SSH key credentials must use local SSH authentication")
		}
		if utf8.RuneCountInString(request.Passphrase) > maxStoredCredentialPassword {
			return normalizedCredentialDraft{}, errors.New("SSH private key passphrase is invalid")
		}
		if request.ClearPassphrase && (!updating || request.Passphrase != "") {
			return normalizedCredentialDraft{}, errors.New("SSH private key passphrase update is invalid")
		}
		privateKeyPath := request.PrivateKeyPath
		if !updating && privateKeyPath == "" {
			return normalizedCredentialDraft{}, errors.New("SSH private key is required")
		}
		if privateKeyPath != "" && !filepath.IsAbs(privateKeyPath) {
			return normalizedCredentialDraft{}, errors.New("SSH private key path is invalid")
		}
		if username == "" {
			return normalizedCredentialDraft{}, errors.New("SSH credentials need a username")
		}
		privateKeyFileName := ""
		if privateKeyPath != "" {
			privateKeyFileName = credentialPrivateKeyDisplayName(filepath.Base(privateKeyPath))
		}
		return normalizedCredentialDraft{
			name: name, protocol: "ssh", protocolValue: 0, kind: 1, kindName: "sshKey",
			username: username, passphrase: request.Passphrase, clearPassphrase: request.ClearPassphrase,
			privateKeyPath:     privateKeyPath,
			privateKeyFileName: privateKeyFileName, provider: 0,
		}, nil
	}
	if request.Passphrase != "" || request.ClearPassphrase || request.PrivateKeyPath != "" {
		return normalizedCredentialDraft{}, errors.New("password credentials cannot include an SSH private key")
	}
	if provider == 0 {
		if (!updating && request.Password == "") ||
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
		name: name, protocol: protocol, protocolValue: protocolValue, kind: 0, kindName: "password", username: username, domain: domain,
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
	if _, err := database.Exec(credentialPrivateKeyOperationsTableSQL); err != nil {
		return fmt.Errorf("could not create SSH private key recovery storage: %w", err)
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

func credentialPrivateKeyDisplayName(value string) string {
	if value == "" || validCredentialText(value, maxCredentialNameLength) {
		return value
	}
	return "SSH private key"
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
