package vaultstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var _ LocalStateStore = (*SQLite)(nil)

func (s *SQLite) migrateLocalState(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, localStateSchema); err != nil {
		return storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SchemaVersion=6 WHERE Singleton=1 AND SchemaVersion=5;`)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

const localStateColumns = `substr(Id,1,37),substr(Kind,1,33),substr(ScopeId,1,37),Size,RowVersion,Deleted,substr(SecretManifest,1,2049),substr(Seal,1,33)`

func scanLocalState(row scanner) (LocalState, error) {
	var value LocalState
	var manifest []byte
	err := row.Scan(&value.ID, &value.Kind, &value.ScopeID, &value.Size, &value.RowVersion, &value.Deleted, &manifest, &value.Seal)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalState{}, ErrMissing
	}
	if err != nil {
		return LocalState{}, storeError(err)
	}
	if len(manifest) > 2048 || json.Unmarshal(manifest, &value.Fields) != nil {
		return LocalState{}, ErrFormat
	}
	canonical, _ := json.Marshal(value.Fields)
	if !bytes.Equal(canonical, manifest) || value.Validate() != nil {
		return LocalState{}, ErrFormat
	}
	return value, nil
}

func (s *SQLite) ReadLocalState(ctx context.Context, kind, scope string) (LocalState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return LocalState{}, ErrClosed
	}
	if !LocalStateKind(kind) || !validID(scope) {
		return LocalState{}, ErrFormat
	}
	return scanLocalState(s.db.QueryRowContext(ctx, `SELECT `+localStateColumns+` FROM LocalState WHERE Kind=? AND ScopeId=?;`, kind, scope))
}

func (s *SQLite) ListLocalStates(ctx context.Context, after string, limit int) ([]LocalState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if (after != "" && !validID(after)) || limit < 1 || limit > 128 {
		return nil, ErrFormat
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+localStateColumns+` FROM LocalState WHERE Deleted=0 AND Id>? ORDER BY Id LIMIT ?;`, after, limit)
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	result := make([]LocalState, 0, limit)
	for rows.Next() {
		v, err := scanLocalState(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(err)
	}
	return result, nil
}

func (s *SQLite) WriteLocalState(ctx context.Context, value LocalState, secrets []Secret, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if value.Validate() != nil || expected >= math.MaxInt64 || value.RowVersion != expected+1 || len(secrets) != len(value.Fields) {
		return ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	previous, err := scanLocalState(tx.QueryRowContext(ctx, `SELECT `+localStateColumns+` FROM LocalState WHERE Kind=? AND ScopeId=?;`, value.Kind, value.ScopeID))
	if errors.Is(err, ErrMissing) {
		if expected != 0 || value.Deleted {
			return ErrConflict
		}
	} else if err != nil {
		return err
	} else if previous.RowVersion != expected || previous.ID != value.ID || (previous.Deleted && value.Deleted) {
		return ErrConflict
	}
	// The byte count and chunk boundaries are authenticated metadata. Verify
	// ciphertext sizes too, so readback cannot concatenate an alternate framing.
	for i, secret := range secrets {
		want := 0
		if i < value.ActiveChunks() {
			want = min(vault.MaxSecretBytes, value.Size-i*vault.MaxSecretBytes)
		}
		if secret.Ref.Field != LocalStateChunkField(i) || len(secret.Envelope.Ciphertext) != want+16 {
			return ErrFormat
		}
	}
	if err := s.writeAggregateFields(ctx, tx, "local-state", value.ID, previous.Fields, value.Fields, secrets); err != nil {
		return err
	}
	manifest, _ := json.Marshal(value.Fields)
	var result sql.Result
	if expected == 0 {
		// A missing natural key does not authorize adopting another primary ID,
		// even if that aggregate's secret rows were removed or damaged.
		result, err = tx.ExecContext(ctx, `INSERT INTO LocalState(Id,Kind,ScopeId,Size,RowVersion,Deleted,SecretManifest,Seal) VALUES(?,?,?,?,?,?,?,?);`, value.ID, value.Kind, value.ScopeID, value.Size, value.RowVersion, value.Deleted, manifest, value.Seal)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE LocalState SET Size=?,RowVersion=?,Deleted=?,SecretManifest=?,Seal=? WHERE Id=? AND Kind=? AND ScopeId=? AND RowVersion=?;`, value.Size, value.RowVersion, value.Deleted, manifest, value.Seal, value.ID, value.Kind, value.ScopeID, expected)
	}
	if err := requireOne(result, err); err != nil {
		return err
	}
	return commitChange(ctx, tx)
}
