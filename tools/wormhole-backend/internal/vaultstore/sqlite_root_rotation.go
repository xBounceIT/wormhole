package vaultstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/encvfs"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// RootRotationTarget owns a separately reserved copy of the workspace.
// Transforming it leaves the live workspace untouched.
type RootRotationTarget struct {
	store   *SQLite
	rotated bool
}

var _ RootRotationStore = (*SQLite)(nil)

// SettleRootRotationSource lets SQLite recover any surviving journal from a
// killed owner. Switching back to DELETE checkpoints a surviving WAL as well.
func (s *SQLite) SettleRootRotationSource(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	for _, want := range []string{"wal", "delete"} {
		var mode string
		if err := s.db.QueryRowContext(ctx, "PRAGMA main.journal_mode="+want).Scan(&mode); err != nil {
			return storeError(err)
		}
		if mode != want {
			return ErrStorage
		}
	}
	return nil
}

func (s *SQLite) BeginRootRotation(ctx context.Context, path string) (*RootRotationTarget, error) {
	return s.beginRootRotation(ctx, path, nil)
}

// BeginEncryptedRootRotation consumes the derived destination page key. A
// plaintext source may be upgraded, and an encrypted source stays encrypted.
func (s *SQLite) BeginEncryptedRootRotation(ctx context.Context, path string, pageKey []byte) (*RootRotationTarget, error) {
	defer vault.Wipe(pageKey)
	if len(pageKey) != 32 {
		return nil, ErrFormat
	}
	return s.beginRootRotation(ctx, path, pageKey)
}

func (s *SQLite) beginRootRotation(ctx context.Context, path string, pageKey []byte) (_ *RootRotationTarget, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if s.encrypted != nil && pageKey == nil {
		return nil, ErrFormat
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkRootRotationGraph(ctx, s.db, s.identity); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, ErrStorage
	}
	defer root.Close()
	name := filepath.Base(path)
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, ErrStorage
	}
	original, err := file.Stat()
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, ErrStorage
	}
	retained := false
	copy := &SQLite{identity: s.identity}
	defer func() {
		if !retained {
			if err := copy.Close(); err != nil {
				resultErr = errors.Join(resultErr, err)
				return
			}
			current, err := root.Lstat(name)
			if err != nil || !os.SameFile(original, current) || root.Remove(name) != nil {
				resultErr = errors.Join(resultErr, ErrStorage)
			}
		}
	}()
	destination := path
	if pageKey != nil {
		if err := copy.registerPageKey(path, pageKey); err != nil {
			return nil, err
		}
		uri := copy.encrypted.URI()
		destination = uri.String()
		if _, err := s.db.ExecContext(ctx, "PRAGMA main.page_size="+strconv.Itoa(encvfs.PageSize)); err != nil {
			return nil, storeError(err)
		}
	}
	// SQLite writes a consistent compact copy of the current encrypted values.
	// The reserved empty destination belongs to this operation, never a user file.
	if _, err := s.db.ExecContext(ctx, `VACUUM main INTO ?;`, destination); err != nil {
		return nil, storeError(err)
	}
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(original, current) {
		return nil, ErrStorage
	}
	if err := copy.open(ctx, path, false); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	retained = true
	return &RootRotationTarget{store: copy}, nil
}

func (t *RootRotationTarget) Close() error {
	if t == nil || t.store == nil {
		return nil
	}
	return t.store.Close()
}

type rotationQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var rootRotationTables = [...]string{"WorkspaceMeta", "Keys", "KeyCopies", "SecretValues", "CredentialProfiles", "TunnelConfigs", "Nodes", "LocalState"}

func rootRotationShape(ctx context.Context, q rotationQuery, table string) (string, error) {
	var shape string
	// Bound even a corrupt declared column/default before copying schema into Go.
	err := q.QueryRowContext(ctx, `SELECT json_group_array(json_array(substr(name,1,129),substr(type,1,65),"notnull",substr(dflt_value,1,257),pk,hidden)) FROM pragma_table_xinfo(?);`, table).Scan(&shape)
	if err != nil {
		return "", storeError(err)
	}
	return shape, nil
}

// Derive the supported shape from the actual versioned DDL, including ALTER
// migrations, rather than maintaining a second list of metadata/secret columns.
var expectedRootRotationShapes = sync.OnceValues(func() (map[string]string, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, ErrStorage
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, schema+credentialSchema+tunnelSchema+nodeSchema+credentialProvenanceSchema+localStateSchema); err != nil {
		return nil, ErrStorage
	}
	shapes := make(map[string]string, len(rootRotationTables))
	for _, table := range rootRotationTables {
		shape, err := rootRotationShape(ctx, db, table)
		if err != nil {
			return nil, err
		}
		shapes[table] = shape
	}
	return shapes, nil
})

// Reject state this local codec cannot preserve, rather than silently dropping
// an unknown table, trigger, key family or orphan current DEK during rotation.
func checkRootRotationGraph(ctx context.Context, q rotationQuery, identity Identity) error {
	var valid bool
	err := q.QueryRowContext(ctx, `SELECT
	 (SELECT count(*) FROM WorkspaceMeta)=1 AND
 EXISTS(SELECT 1 FROM WorkspaceMeta WHERE Singleton=1 AND WorkspaceId=? AND FileId=? AND RootKeyId=? AND RootKeyVersion=? AND SchemaVersion=? AND ResolverVersion=1) AND
 NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE type IN ('view','trigger') OR
  (type='table' AND name NOT IN ('WorkspaceMeta','Keys','KeyCopies','SecretValues','CredentialProfiles','TunnelConfigs','Nodes','LocalState','sqlite_stat1','sqlite_stat4'))) AND
 EXISTS(SELECT 1 FROM Keys WHERE KeyId=? AND KeyVersion=? AND Kind='vault' AND OwnerId=? AND Status='active' AND Suite=1) AND
 NOT EXISTS(SELECT 1 FROM Keys k WHERE Suite<>1 OR RowVersion<1 OR OwnerId IS NULL OR PublicKey IS NOT NULL OR CertSignerKeyId IS NOT NULL OR CertSignerKeyVersion IS NOT NULL OR CertSignature IS NOT NULL OR
  NOT ((Kind='vault' AND KeyId=? AND KeyVersion=? AND OwnerId=? AND Status='active') OR
   (Kind='dek' AND OwnerId=KeyId AND EXISTS(SELECT 1 FROM SecretValues v WHERE v.DekId=k.KeyId AND
     ((v.DekVersion=k.KeyVersion AND k.Status='active') OR (v.DekVersion>k.KeyVersion AND k.Status='retired')))))) AND
 NOT EXISTS(SELECT 1 FROM KeyCopies WHERE HolderKeyId<>? OR HolderKeyVersion<>? OR IssuerKeyId<>? OR IssuerKeyVersion<>? OR Suite<>1 OR length(Enc)<>12 OR length(Ciphertext)<>48 OR length(Signature)<>32) AND
 NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check) AND
 NOT EXISTS(SELECT 1 FROM SecretValues GROUP BY DekId,DekVersion HAVING count(*)<>1) AND
 NOT EXISTS(SELECT 1 FROM SecretValues v WHERE OwnerKind='local-state' AND NOT EXISTS(SELECT 1 FROM LocalState l WHERE l.Id=v.OwnerId)) AND
 (SELECT count(*) FROM SecretValues)+(SELECT count(*) FROM CredentialProfiles)+(SELECT count(*) FROM TunnelConfigs)+(SELECT count(*) FROM Nodes)+(SELECT count(*) FROM LocalState)<=?;`,
		identity.WorkspaceID, identity.FileID, identity.Root.ID, identity.Root.Version, SchemaVersion,
		identity.Root.ID, identity.Root.Version, identity.WorkspaceID,
		identity.Root.ID, identity.Root.Version, identity.WorkspaceID,
		identity.Root.ID, identity.Root.Version, identity.Root.ID, identity.Root.Version,
		MaxRootRotationRecords).Scan(&valid)
	if err != nil {
		return storeError(err)
	}
	if !valid {
		return ErrFormat
	}
	expected, err := expectedRootRotationShapes()
	if err != nil {
		return err
	}
	for _, table := range rootRotationTables {
		shape, err := rootRotationShape(ctx, q, table)
		if err != nil {
			return err
		}
		if shape != expected[table] {
			return ErrVersion
		}
	}
	return nil
}

func (t *RootRotationTarget) Rotate(ctx context.Context, next Identity, transforms RootRotationTransforms) (RootRotationCounts, error) {
	if t == nil || t.store == nil {
		return RootRotationCounts{}, ErrClosed
	}
	s := t.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return RootRotationCounts{}, ErrClosed
	}
	old := s.identity
	if t.rotated || !transforms.valid() || old.Root.Version == math.MaxUint32 || next.WorkspaceID != old.WorkspaceID || next.FileID != old.FileID || next.Root.ID != old.Root.ID || next.Root.Version != old.Root.Version+1 {
		return RootRotationCounts{}, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return RootRotationCounts{}, err
	}
	// Keep the rollback journal on disk during the rewrite. The encrypted
	// VFS permits DELETE and removes the journal at commit.
	journalMode := "truncate"
	if s.encrypted != nil {
		journalMode = "delete"
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode="+journalMode).Scan(&mode); err != nil || mode != journalMode {
		return RootRotationCounts{}, ErrStorage
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA secure_delete=ON;`); err != nil {
		return RootRotationCounts{}, storeError(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RootRotationCounts{}, storeError(err)
	}
	defer tx.Rollback()
	if err := checkRootRotationGraph(ctx, tx, old); err != nil {
		return RootRotationCounts{}, err
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE Keys SET Status='retired',RowVersion=RowVersion+1 WHERE KeyId=? AND KeyVersion=? AND Status='active' AND RowVersion<9223372036854775807;`, old.Root.ID, old.Root.Version)); err != nil {
		return RootRotationCounts{}, err
	}
	if err := requireOne(tx.ExecContext(ctx, `INSERT INTO Keys(KeyId,KeyVersion,Kind,OwnerId,Suite) VALUES(?,?,'vault',?,1);`, next.Root.ID, next.Root.Version, next.WorkspaceID)); err != nil {
		return RootRotationCounts{}, err
	}
	counts, profile, err := s.transformRootRotation(ctx, tx, next, transforms, false)
	if err != nil {
		return RootRotationCounts{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM KeyCopies WHERE HolderKeyId<>? OR HolderKeyVersion<>?; DELETE FROM Keys WHERE Status='retired';`, next.Root.ID, next.Root.Version); err != nil {
		return RootRotationCounts{}, storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET RootKeyId=?,RootKeyVersion=?,SignedProfile=? WHERE Singleton=1 AND RootKeyId=? AND RootKeyVersion=?;`, next.Root.ID, next.Root.Version, profile, old.Root.ID, old.Root.Version)); err != nil {
		return RootRotationCounts{}, err
	}
	if err := checkRootRotationGraph(ctx, tx, next); err != nil {
		return RootRotationCounts{}, err
	}
	if err := commitChange(ctx, tx); err != nil {
		return RootRotationCounts{}, err
	}
	// Even if compaction subsequently fails, this target is in the new epoch and
	// cannot replay transforms. It stays unpublished; the source was not modified.
	s.identity = next
	t.rotated = true
	if _, err := s.db.ExecContext(ctx, `VACUUM;`); err != nil {
		return RootRotationCounts{}, storeError(err)
	}
	// Leave no persistent journal beside the closed publishable copy.
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE;`).Scan(&mode); err != nil || mode != "delete" {
		return RootRotationCounts{}, ErrStorage
	}
	return counts, nil
}

// Audit reopens every record through the native owner, including standalone
// fields and tombstones. It performs no SQL writes and can verify either epoch.
func (t *RootRotationTarget) Audit(ctx context.Context, transforms RootRotationTransforms) (RootRotationCounts, error) {
	if t == nil || t.store == nil {
		return RootRotationCounts{}, ErrClosed
	}
	return t.store.AuditRootRotation(ctx, transforms)
}

func (s *SQLite) AuditRootRotation(ctx context.Context, transforms RootRotationTransforms) (RootRotationCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return RootRotationCounts{}, ErrClosed
	}
	if !transforms.valid() {
		return RootRotationCounts{}, ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RootRotationCounts{}, storeError(err)
	}
	defer tx.Rollback()
	if err := checkRootRotationGraph(ctx, tx, s.identity); err != nil {
		return RootRotationCounts{}, err
	}
	counts, _, err := s.transformRootRotation(ctx, tx, s.identity, transforms, true)
	return counts, err
}

// Validate every signed manifest against all its encrypted fields, including
// empty tombstones. Standalone native fields are rotated independently as well.
func (s *SQLite) rootRotationFields(ctx context.Context, tx *sql.Tx, kind, id string, fields []SecretField) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM SecretValues WHERE OwnerKind=? AND OwnerId=?;`, kind, id).Scan(&count); err != nil {
		return storeError(err)
	}
	if count != len(fields) {
		return ErrFormat
	}
	for _, field := range fields {
		value, err := s.readSecret(ctx, tx, SecretRef{kind, id, field.Field})
		if err != nil {
			return err
		}
		if value.RowVersion != field.Version || (!field.Present && len(value.Envelope.Ciphertext) != 16) {
			return ErrFormat
		}
	}
	return nil
}

func rotationRows[T any](ctx context.Context, tx *sql.Tx, table, columns string, scan func(scanner) (T, error), use func(T) (string, error)) (int, error) {
	last, count := "", 0
	for {
		value, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM `+table+` WHERE Id>? ORDER BY Id LIMIT 1;`, last))
		if errors.Is(err, ErrMissing) {
			return count, nil
		}
		if err != nil {
			return 0, err
		}
		id, err := use(value)
		if err != nil {
			return 0, err
		}
		if id <= last || !validID(id) || count >= MaxRootRotationRecords {
			return 0, ErrFormat
		}
		last, count = id, count+1
	}
}

func rotationSeal(ctx context.Context, tx *sql.Tx, table, id string, seal, previous []byte, err error, audit bool) error {
	if err != nil {
		return err
	}
	if len(seal) != 32 {
		return ErrFormat
	}
	if audit {
		if !bytes.Equal(seal, previous) {
			return ErrFormat
		}
		return nil
	}
	return requireOne(tx.ExecContext(ctx, `UPDATE `+table+` SET Seal=? WHERE Id=?;`, seal, id))
}

func (s *SQLite) transformRootRotation(ctx context.Context, tx *sql.Tx, next Identity, t RootRotationTransforms, audit bool) (counts RootRotationCounts, profile []byte, resultErr error) {
	var err error
	counts.Credentials, err = rotationRows(ctx, tx, "CredentialProfiles", credentialColumns, scanCredential, func(c Credential) (string, error) {
		if err := s.rootRotationFields(ctx, tx, "credential", c.ID, c.Fields); err != nil {
			return "", err
		}
		seal, err := t.Credential(c)
		return c.ID, rotationSeal(ctx, tx, "CredentialProfiles", c.ID, seal, c.Seal, err, audit)
	})
	if err != nil {
		return counts, nil, err
	}
	counts.Tunnels, err = rotationRows(ctx, tx, "TunnelConfigs", tunnelColumns, scanTunnel, func(v Tunnel) (string, error) {
		if err := s.rootRotationFields(ctx, tx, "tunnel", v.ID, []SecretField{{Field: "settings", Version: v.ConfigurationVersion, Present: !v.Deleted}}); err != nil {
			return "", err
		}
		seal, err := t.Tunnel(v)
		return v.ID, rotationSeal(ctx, tx, "TunnelConfigs", v.ID, seal, v.Seal, err, audit)
	})
	if err != nil {
		return counts, nil, err
	}
	counts.Nodes, err = rotationRows(ctx, tx, "Nodes", nodeColumns, scanNode, func(v Node) (string, error) {
		if err := s.rootRotationFields(ctx, tx, "node", v.ID, v.Fields); err != nil {
			return "", err
		}
		seal, err := t.Node(v)
		if err := rotationSeal(ctx, tx, "Nodes", v.ID, seal, v.Seal, err, audit); err != nil {
			return "", err
		}
		if audit {
			return v.ID, nil
		}
		return v.ID, requireOne(tx.ExecContext(ctx, `UPDATE Nodes SET SealSignerKeyId=?,SealSignerKeyVersion=? WHERE Id=?;`, next.Root.ID, next.Root.Version, v.ID))
	})
	if err != nil {
		return counts, nil, err
	}
	counts.LocalStates, err = rotationRows(ctx, tx, "LocalState", localStateColumns, scanLocalState, func(v LocalState) (string, error) {
		if err := s.rootRotationFields(ctx, tx, "local-state", v.ID, v.Fields); err != nil {
			return "", err
		}
		seal, err := t.LocalState(v)
		return v.ID, rotationSeal(ctx, tx, "LocalState", v.ID, seal, v.Seal, err, audit)
	})
	if err != nil {
		return counts, nil, err
	}
	counts.Secrets, err = s.rotateRootSecrets(ctx, tx, next, t.Secret, audit)
	if err != nil {
		return counts, nil, err
	}
	var kind string
	var length int
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT typeof(SignedProfile),COALESCE(length(SignedProfile),0),substr(SignedProfile,1,?) FROM WorkspaceMeta WHERE Singleton=1;`, vault.MaxLocalPolicyBytes+1).Scan(&kind, &length, &raw); err != nil {
		return counts, nil, storeError(err)
	}
	if kind != "blob" || length < 1 || length > vault.MaxLocalPolicyBytes || len(raw) != length {
		return counts, nil, ErrFormat
	}
	profile, err = t.Profile(raw)
	if err == nil && (len(profile) == 0 || len(profile) > vault.MaxLocalPolicyBytes) {
		err = ErrFormat
	}
	if err == nil && audit && !bytes.Equal(profile, raw) {
		err = ErrFormat
	}
	return counts, profile, err
}

func (s *SQLite) rotateRootSecrets(ctx context.Context, tx *sql.Tx, next Identity, transform func(Secret) (Secret, error), audit bool) (int, error) {
	last, count := SecretRef{}, 0
	for {
		var ref SecretRef
		err := tx.QueryRowContext(ctx, `SELECT substr(OwnerKind,1,17),substr(OwnerId,1,37),substr(Field,1,129) FROM SecretValues WHERE (OwnerKind,OwnerId,Field)>(?,?,?) ORDER BY OwnerKind,OwnerId,Field LIMIT 1;`, last.OwnerKind, last.OwnerID, last.Field).Scan(&ref.OwnerKind, &ref.OwnerID, &ref.Field)
		if errors.Is(err, sql.ErrNoRows) {
			return count, nil
		}
		if err != nil {
			return 0, storeError(err)
		}
		if !ref.Valid() || count >= MaxRootRotationRecords {
			return 0, ErrFormat
		}
		old, err := s.readSecret(ctx, tx, ref)
		if err != nil {
			return 0, err
		}
		var stored []byte
		if err := tx.QueryRowContext(ctx, `SELECT substr(Envelope,1,6291457) FROM SecretValues WHERE OwnerKind=? AND OwnerId=? AND Field=?;`, ref.OwnerKind, ref.OwnerID, ref.Field).Scan(&stored); err != nil {
			return 0, storeError(err)
		}
		canonical, _ := json.Marshal(old.Envelope)
		if !bytes.Equal(stored, canonical) || (!audit && old.DEK.Version == math.MaxUint32) {
			return 0, ErrFormat
		}
		value, err := transform(old)
		if err != nil {
			return 0, err
		}
		version := old.DEK.Version
		if !audit {
			version++
		}
		if !value.valid(next) || value.Ref != ref || value.RowVersion != old.RowVersion || value.DEK.ID != old.DEK.ID || value.DEK.Version != version || len(value.Envelope.Ciphertext) != len(old.Envelope.Ciphertext) {
			return 0, ErrFormat
		}
		if audit {
			last, count = ref, count+1
			continue
		}
		if err := requireOne(tx.ExecContext(ctx, `UPDATE Keys SET Status='retired',RowVersion=RowVersion+1 WHERE KeyId=? AND KeyVersion=? AND Status='active' AND RowVersion<9223372036854775807;`, old.DEK.ID, old.DEK.Version)); err != nil {
			return 0, err
		}
		envelope, err := insertSecretMaterial(ctx, tx, value)
		if err != nil {
			return 0, err
		}
		if err := requireOne(tx.ExecContext(ctx, `UPDATE SecretValues SET DekVersion=?,Envelope=? WHERE OwnerKind=? AND OwnerId=? AND Field=? AND DekId=? AND DekVersion=? AND RowVersion=?;`, value.DEK.Version, envelope, ref.OwnerKind, ref.OwnerID, ref.Field, old.DEK.ID, old.DEK.Version, old.RowVersion)); err != nil {
			return 0, err
		}
		last, count = ref, count+1
	}
}
