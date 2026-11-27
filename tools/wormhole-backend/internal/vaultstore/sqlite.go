package vaultstore

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/encvfs"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

//go:embed credentials.sql
var credentialSchema string

//go:embed tunnels.sql
var tunnelSchema string

//go:embed nodes.sql
var nodeSchema string

//go:embed local_state.sql
var localStateSchema string

const SchemaVersion = 6

type SQLite struct {
	mu        sync.Mutex
	db        *sql.Conn
	pool      *sql.DB
	identity  Identity
	encrypted *encvfs.Database
}

var _ Store = (*SQLite)(nil)

// OpenSQLite is called only after authenticating the slot file and key-check.
// create is exclusive and never overwrites or repairs an existing database.
// The service also holds its OS ownership lock. SQLite's retained exclusive
// lock independently prevents legacy processes from reading this open database.
func OpenSQLite(ctx context.Context, path string, identity Identity, create bool) (*SQLite, error) {
	return openSQLite(ctx, path, identity, create, nil)
}

// OpenSQLiteEncrypted uses a root borrowed from an already authenticated
// slot file. It registers only the derived page key and never tries plaintext.
func OpenSQLiteEncrypted(ctx context.Context, path string, identity Identity, create bool, root []byte) (*SQLite, error) {
	pageKey, err := vault.DeriveKey(root, []byte(identity.WorkspaceID), vault.PurposeSQLite)
	if err != nil {
		return nil, ErrFormat
	}
	defer vault.Wipe(pageKey)
	return openSQLite(ctx, path, identity, create, pageKey)
}

func openSQLite(ctx context.Context, path string, identity Identity, create bool, pageKey []byte) (_ *SQLite, resultErr error) {
	if !validID(identity.WorkspaceID) || !validID(identity.FileID) || !identity.Root.Valid() {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, ErrStorage
	}
	store := &SQLite{identity: identity}
	var created os.FileInfo
	defer func() {
		if resultErr == nil {
			return
		}
		if err := store.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		if created != nil {
			if current, err := os.Lstat(absolute); err == nil && os.SameFile(created, current) {
				_ = os.Remove(absolute)
			}
		}
	}()
	if create {
		file, err := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			return nil, ErrConflict
		}
		if err != nil {
			return nil, ErrStorage
		}
		created, err = file.Stat()
		if closeErr := file.Close(); err != nil || closeErr != nil {
			return nil, ErrStorage
		}
	} else {
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissing
		}
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrStorage
		}
	}
	if pageKey != nil {
		if err := store.registerPageKey(absolute, pageKey); err != nil {
			return nil, err
		}
	}
	if err := store.open(ctx, absolute, create); err != nil {
		return nil, err
	}
	return store, nil
}

// registerPageKey consumes the borrowed scratch key. The registration owns its
// locked copy until the store closes every SQLite handle.
func (s *SQLite) registerPageKey(absolute string, pageKey []byte) error {
	registration, err := encvfs.Register(absolute, pageKey)
	vault.Wipe(pageKey)
	if errors.Is(err, encvfs.ErrBusy) {
		return ErrBusy
	}
	if err != nil {
		return ErrStorage
	}
	s.encrypted = registration
	return nil
}

func (s *SQLite) open(ctx context.Context, absolute string, create bool) error {
	uriPath := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{"mode": {"rw"}, "_pragma": {"foreign_keys(1)", "busy_timeout(1000)", "locking_mode(EXCLUSIVE)", "synchronous(FULL)", "temp_store(MEMORY)"}}
	if s.encrypted != nil {
		uri = s.encrypted.URI()
		query = uri.Query()
		query.Add("_pragma", "foreign_keys(1)")
		query.Add("_pragma", "busy_timeout(1000)")
	}
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return ErrStorage
	}
	s.pool = db
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return storeError(err)
	}
	s.db = conn
	// Acquiring and committing an exclusive transaction retains the lock until
	// Close because locking_mode is EXCLUSIVE, even between individual requests.
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE; COMMIT;"); err != nil {
		return storeError(err)
	}
	if create {
		return s.initialize(ctx)
	}
	return s.checkIdentity(ctx)
}

func storeError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) && (coded.Code()&255 == 5 || coded.Code()&255 == 6) {
		return ErrBusy
	}
	return ErrStorage
}

func (s *SQLite) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schema+credentialSchema+tunnelSchema+nodeSchema+credentialProvenanceSchema+localStateSchema); err != nil {
		return storeError(err)
	}
	i := s.identity
	if _, err := tx.ExecContext(ctx, `INSERT INTO WorkspaceMeta (Singleton,WorkspaceId,FileId,SchemaVersion,RootKeyId,RootKeyVersion) VALUES(1,?,?,?,?,?);`, i.WorkspaceID, i.FileID, SchemaVersion, i.Root.ID, i.Root.Version); err != nil {
		return storeError(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO Keys (KeyId,KeyVersion,Kind,OwnerId,Suite) VALUES(?,?,'vault',?,?);`, i.Root.ID, i.Root.Version, i.WorkspaceID, vault.SuiteAES256GCM); err != nil {
		return storeError(err)
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

func (s *SQLite) checkIdentity(ctx context.Context) error {
	var got Identity
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT substr(WorkspaceId,1,37),substr(FileId,1,37),SchemaVersion,substr(RootKeyId,1,37),RootKeyVersion FROM WorkspaceMeta WHERE Singleton=1;`).Scan(&got.WorkspaceID, &got.FileID, &version, &got.Root.ID, &got.Root.Version)
	if err != nil {
		return storeError(err)
	}
	if version > SchemaVersion {
		return ErrVersion
	}
	if version < 1 || got != s.identity {
		return ErrIdentity
	}
	if version == 1 {
		if err := s.migrateCredentials(ctx); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if err := s.migrateTunnels(ctx); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if err := s.migrateNodes(ctx); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		if err := s.migrateCredentialProvenance(ctx); err != nil {
			return err
		}
		version = 5
	}
	if version == 5 {
		return s.migrateLocalState(ctx)
	}
	return nil
}

func (s *SQLite) Identity() Identity { return s.identity }

// CheckForeignKeys rejects an inconsistent import source without returning row
// identifiers or database diagnostics. The caller also owns the vault lock for
// the catalog capture that follows.
func (s *SQLite) CheckForeignKeys(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	var valid bool
	if err := s.db.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check);`).Scan(&valid); err != nil {
		return storeError(err)
	}
	if !valid {
		return ErrFormat
	}
	return nil
}

// ValidateInitialization rejects replay of a formerly valid pending marker onto
// a workspace that has accepted user writes. Only the new, empty key graph can
// be resumed/finalized by the bootstrap journal.
func (s *SQLite) ValidateInitialization(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	return s.validateInitialization(ctx, s.db)
}

type initializationReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLite) validateInitialization(ctx context.Context, reader initializationReader) error {
	var pristine bool
	err := reader.QueryRowContext(ctx, `SELECT ChangeSeq=0
 AND (SELECT count(*) FROM CredentialProfiles)=0
 AND (SELECT count(*) FROM TunnelConfigs)=0
 AND (SELECT count(*) FROM Nodes)=0
 AND (SELECT count(*) FROM LocalState)=0
 AND (SELECT count(*) FROM SecretValues)=0
 AND (SELECT count(*) FROM KeyCopies)=0
 AND (SELECT count(*) FROM Keys)=1
 AND EXISTS(SELECT 1 FROM Keys WHERE KeyId=? AND KeyVersion=? AND Kind='vault' AND Status='active' AND OwnerId=? AND RowVersion=1)
 FROM WorkspaceMeta WHERE Singleton=1;`, s.identity.Root.ID, s.identity.Root.Version, s.identity.WorkspaceID).Scan(&pristine)
	if err != nil {
		return storeError(err)
	}
	if !pristine {
		return ErrConflict
	}
	return nil
}

func (s *SQLite) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	if s.pool != nil {
		err = errors.Join(err, s.pool.Close())
		s.pool = nil
	}
	if s.encrypted != nil {
		if releaseErr := s.encrypted.Close(); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		} else {
			s.encrypted = nil
		}
	}
	if err != nil {
		return ErrStorage
	}
	return nil
}

func (s *SQLite) ReadSecret(ctx context.Context, ref SecretRef) (Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Secret{}, ErrClosed
	}
	return s.readSecret(ctx, s.db, ref)
}

type secretQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLite) readSecret(ctx context.Context, query secretQuery, ref SecretRef) (Secret, error) {
	if !ref.Valid() {
		return Secret{}, ErrFormat
	}
	var value Secret
	value.Ref = ref
	var envelope []byte
	// Bound before SQLite copies data into Go; validation rejects the extra byte.
	err := query.QueryRowContext(ctx, `SELECT substr(v.DekId,1,37),v.DekVersion,substr(v.Envelope,1,6291457),v.RowVersion,substr(c.HolderKeyId,1,37),c.HolderKeyVersion,substr(c.IssuerKeyId,1,37),c.IssuerKeyVersion,c.Suite,substr(c.Enc,1,13),substr(c.Ciphertext,1,49),substr(c.Signature,1,33)
 FROM SecretValues v JOIN Keys k ON k.KeyId=v.DekId AND k.KeyVersion=v.DekVersion
 JOIN KeyCopies c ON c.KeyId=v.DekId AND c.KeyVersion=v.DekVersion
 WHERE v.OwnerKind=? AND v.OwnerId=? AND v.Field=? AND k.Kind='dek' AND k.Status='active' AND c.HolderKeyId=? AND c.HolderKeyVersion=?;`, ref.OwnerKind, ref.OwnerID, ref.Field, s.identity.Root.ID, s.identity.Root.Version).Scan(
		&value.DEK.ID, &value.DEK.Version, &envelope, &value.RowVersion, &value.Copy.Holder.ID, &value.Copy.Holder.Version, &value.Copy.Issuer.ID, &value.Copy.Issuer.Version, &value.Copy.Envelope.SuiteID, &value.Copy.Envelope.Nonce, &value.Copy.Envelope.Ciphertext, &value.Copy.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrMissing
	}
	if err != nil {
		return Secret{}, storeError(err)
	}
	if len(envelope) > 6*1024*1024 || json.Unmarshal(envelope, &value.Envelope) != nil {
		return Secret{}, ErrFormat
	}
	value.Copy.Key = value.DEK
	value.Copy.Envelope.FormatVersion = vault.FormatVersion
	value.Copy.Envelope.KeyID = value.Copy.Holder.ID
	value.Copy.Envelope.KeyVersion = value.Copy.Holder.Version
	if !value.valid(s.identity) {
		return Secret{}, ErrFormat
	}
	return value, nil
}

func (s *SQLite) WriteSecret(ctx context.Context, value Secret, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if !value.valid(s.identity) || expected >= math.MaxInt64 || value.RowVersion != expected+1 {
		return ErrFormat
	}
	// Local state always belongs to a sealed chunk manifest, never a standalone
	// raw secret. Only WriteLocalState can install or mutate these records.
	if value.Ref.OwnerKind == "local-state" {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if value.Ref.OwnerKind == "credential" {
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM CredentialProfiles WHERE Id=?);`, value.Ref.OwnerID).Scan(&owned); err != nil {
			return storeError(err)
		}
		if owned {
			return ErrConflict
		}
	}
	if value.Ref.OwnerKind == "tunnel" {
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM TunnelConfigs WHERE Id=?);`, value.Ref.OwnerID).Scan(&owned); err != nil {
			return storeError(err)
		}
		if owned {
			return ErrConflict
		}
	}
	if value.Ref.OwnerKind == "node" {
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM Nodes WHERE Id=?);`, value.Ref.OwnerID).Scan(&owned); err != nil {
			return storeError(err)
		}
		if owned {
			return ErrConflict
		}
	}
	if err := s.writeSecret(ctx, tx, value, expected); err != nil {
		return err
	}
	return commitChange(ctx, tx)
}

func (s *SQLite) writeSecret(ctx context.Context, tx *sql.Tx, value Secret, expected uint64) error {
	var previous KeyRef
	var revision uint64
	err := tx.QueryRowContext(ctx, `SELECT substr(DekId,1,37),DekVersion,RowVersion FROM SecretValues WHERE OwnerKind=? AND OwnerId=? AND Field=?;`, value.Ref.OwnerKind, value.Ref.OwnerID, value.Ref.Field).Scan(&previous.ID, &previous.Version, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 || value.DEK.Version != 1 {
			return ErrConflict
		}
	} else if err != nil {
		return storeError(err)
	} else {
		if revision != expected || previous.Version == math.MaxUint32 || value.DEK.ID != previous.ID || value.DEK.Version != previous.Version+1 {
			return ErrConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE Keys SET Status='retired',RowVersion=RowVersion+1 WHERE KeyId=? AND KeyVersion=? AND Kind='dek' AND Status='active' AND RowVersion < 9223372036854775807;`, previous.ID, previous.Version)
		if err != nil {
			return storeError(err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return ErrConflict
		}
	}
	envelope, err := insertSecretMaterial(ctx, tx, value)
	if err != nil {
		return err
	}
	if err := requireOne(tx.ExecContext(ctx, `INSERT INTO SecretValues(OwnerKind,OwnerId,Field,DekId,DekVersion,Envelope,RowVersion) VALUES(?,?,?,?,?,?,?) ON CONFLICT(OwnerKind,OwnerId,Field) DO UPDATE SET DekId=excluded.DekId,DekVersion=excluded.DekVersion,Envelope=excluded.Envelope,RowVersion=excluded.RowVersion;`, value.Ref.OwnerKind, value.Ref.OwnerID, value.Ref.Field, value.DEK.ID, value.DEK.Version, envelope, value.RowVersion)); err != nil {
		return err
	}
	return nil
}

// A DEK's OwnerId is its stable logical-secret ID, not an aggregate ID. Both
// ordinary writes and unpublished root rotation install the same key material.
func insertSecretMaterial(ctx context.Context, tx *sql.Tx, value Secret) ([]byte, error) {
	if err := requireOne(tx.ExecContext(ctx, `INSERT INTO Keys(KeyId,KeyVersion,Kind,OwnerId,Suite) VALUES(?,?,'dek',?,?);`, value.DEK.ID, value.DEK.Version, value.DEK.ID, vault.SuiteAES256GCM)); err != nil {
		return nil, err
	}
	c := value.Copy
	if err := requireOne(tx.ExecContext(ctx, `INSERT INTO KeyCopies(KeyId,KeyVersion,HolderKeyId,HolderKeyVersion,Suite,Enc,Ciphertext,IssuerKeyId,IssuerKeyVersion,Signature) VALUES(?,?,?,?,?,?,?,?,?,?);`, c.Key.ID, c.Key.Version, c.Holder.ID, c.Holder.Version, c.Envelope.SuiteID, c.Envelope.Nonce, c.Envelope.Ciphertext, c.Issuer.ID, c.Issuer.Version, c.Signature)); err != nil {
		return nil, err
	}
	envelope, err := json.Marshal(value.Envelope)
	if err != nil {
		return nil, ErrFormat
	}
	return envelope, nil
}

func commitChange(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET ChangeSeq=ChangeSeq+1 WHERE Singleton=1 AND ChangeSeq < 9223372036854775807;`)
	if err != nil {
		return storeError(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

// A trigger or a damaged schema must not turn an ignored write into success.
func requireOne(result sql.Result, err error) error {
	if err != nil {
		return storeError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return nil
}
