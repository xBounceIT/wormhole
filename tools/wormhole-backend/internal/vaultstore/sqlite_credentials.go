package vaultstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
)

var _ CredentialStore = (*SQLite)(nil)

func (s *SQLite) migrateCredentials(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, credentialSchema); err != nil {
		return storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SchemaVersion=2 WHERE Singleton=1 AND SchemaVersion=1;`)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

// SQL bounds values before copying them into Go. Encrypted metadata is reserved
// for the profile-aware codec; never silently interpret it as plaintext here.
const credentialColumns = `substr(Id,1,37),substr(COALESCE(OwnerUserId,''),1,37),substr(Name,1,1025),substr(Protocol,1,16),substr(Kind,1,16),substr(Username,1,2049),substr(Domain,1,2049),substr(SecretProvider,1,16),substr(BitwardenItemId,1,2049),substr(BitwardenItemName,1,4097),substr(BitwardenFieldPath,1,2049),substr(PrivateKeyFileName,1,1025),substr(CertificateFileName,1,1025),RowVersion,Deleted,substr(SecretManifest,1,2049),substr(Seal,1,33),EncryptedMetadata IS NULL AND MetadataKeyId IS NULL AND NameBlindIndex IS NULL,CASE WHEN CreatedAt IS NULL THEN NULL ELSE CAST(COALESCE(substr(CAST(CreatedAt AS BLOB),1,129),X'') AS TEXT) END`

type scanner interface{ Scan(...any) error }

func scanCredential(row scanner) (Credential, error) {
	var c Credential
	var manifest []byte
	var plain bool
	err := row.Scan(&c.ID, &c.OwnerUserID, &c.Name, &c.Protocol, &c.Kind, &c.Username, &c.Domain, &c.Provider, &c.BitwardenItemID, &c.BitwardenItemName, &c.BitwardenFieldPath, &c.PrivateKeyName, &c.CertificateName, &c.RowVersion, &c.Deleted, &manifest, &c.Seal, &plain, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrMissing
	}
	if err != nil {
		return Credential{}, storeError(err)
	}
	if !plain || len(manifest) > 2048 || json.Unmarshal(manifest, &c.Fields) != nil {
		return Credential{}, ErrFormat
	}
	canonical, _ := json.Marshal(c.Fields)
	if !bytes.Equal(canonical, manifest) || c.Validate() != nil {
		return Credential{}, ErrFormat
	}
	return c, nil
}

func (s *SQLite) ReadCredential(ctx context.Context, id string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Credential{}, ErrClosed
	}
	if !validID(id) {
		return Credential{}, ErrFormat
	}
	return scanCredential(s.db.QueryRowContext(ctx, `SELECT `+credentialColumns+` FROM CredentialProfiles WHERE Id=?;`, id))
}

// Pages are ordered by immutable IDs, never names. A caller can restart a scan
// after an aggregate mutation; no mutable cursor or implicit offset is retained.
func (s *SQLite) ListCredentials(ctx context.Context, after string, limit int) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if (after != "" && !validID(after)) || limit < 1 || limit > 128 {
		return nil, ErrFormat
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialColumns+` FROM CredentialProfiles WHERE Deleted=0 AND Id>? ORDER BY Id LIMIT ?;`, after, limit)
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	result := make([]Credential, 0, limit)
	for rows.Next() {
		value, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(err)
	}
	return result, nil
}

func fieldsByName(fields []CredentialField) map[string]CredentialField {
	result := make(map[string]CredentialField, len(fields))
	for _, f := range fields {
		result[f.Field] = f
	}
	return result
}

func (s *SQLite) WriteCredential(ctx context.Context, value Credential, secrets []Secret, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if value.Validate() != nil || expected >= math.MaxInt64 || value.RowVersion != expected+1 || len(secrets) > 4 {
		return ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	previous, err := scanCredential(tx.QueryRowContext(ctx, `SELECT `+credentialColumns+` FROM CredentialProfiles WHERE Id=?;`, value.ID))
	if errors.Is(err, ErrMissing) {
		if expected != 0 || value.Deleted {
			return ErrConflict
		}
	} else if err != nil {
		return err
	} else if previous.RowVersion != expected || previous.Deleted || value.CreatedAt != previous.CreatedAt {
		return ErrConflict
	}
	if value.Deleted || (expected != 0 && value.Protocol != previous.Protocol) {
		var referenced bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM Nodes WHERE Deleted=0 AND (CredentialId=? OR RdpGatewayCredentialId=?));`, value.ID, value.ID).Scan(&referenced); err != nil {
			return storeError(err)
		}
		if referenced {
			return ErrConflict
		}
	}
	if err := s.writeAggregateFields(ctx, tx, "credential", value.ID, previous.Fields, value.Fields, secrets); err != nil {
		return err
	}
	manifest, _ := json.Marshal(value.Fields)
	var owner any
	if value.OwnerUserID != "" {
		owner = value.OwnerUserID
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO CredentialProfiles(Id,OwnerUserId,Name,Protocol,Kind,Username,Domain,SecretProvider,BitwardenItemId,BitwardenItemName,BitwardenFieldPath,PrivateKeyFileName,CertificateFileName,RowVersion,Deleted,SecretManifest,Seal,CreatedAt)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(Id) DO UPDATE SET OwnerUserId=excluded.OwnerUserId,Name=excluded.Name,Protocol=excluded.Protocol,Kind=excluded.Kind,Username=excluded.Username,Domain=excluded.Domain,SecretProvider=excluded.SecretProvider,BitwardenItemId=excluded.BitwardenItemId,BitwardenItemName=excluded.BitwardenItemName,BitwardenFieldPath=excluded.BitwardenFieldPath,PrivateKeyFileName=excluded.PrivateKeyFileName,CertificateFileName=excluded.CertificateFileName,RowVersion=excluded.RowVersion,Deleted=excluded.Deleted,SecretManifest=excluded.SecretManifest,Seal=excluded.Seal;`, value.ID, owner, value.Name, value.Protocol, value.Kind, value.Username, value.Domain, value.Provider, value.BitwardenItemID, value.BitwardenItemName, value.BitwardenFieldPath, value.PrivateKeyName, value.CertificateName, value.RowVersion, value.Deleted, manifest, value.Seal, value.CreatedAt)
	if err != nil {
		var coded interface{ Code() int }
		if errors.As(err, &coded) && coded.Code() == 2067 {
			return ErrConflict
		}
		return storeError(err)
	}
	if err := requireOne(result, nil); err != nil {
		return err
	}
	return commitChange(ctx, tx)
}
