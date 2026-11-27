package vaultstore

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ProfileStore persists an opaque authenticated document, never an authority to
// select policy. expected is the exact previously authenticated stored document;
// nil permits only initial insertion, not replacement or deletion.
type ProfileStore interface {
	Store
	ReadProfile(context.Context) ([]byte, error)
	WriteProfile(context.Context, []byte, []byte) error
}

func (s *SQLite) ReadProfile(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	var kind string
	var size sql.NullInt64
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT typeof(SignedProfile),length(SignedProfile),substr(SignedProfile,1,?) FROM WorkspaceMeta WHERE Singleton=1`, vault.MaxLocalPolicyBytes+1).Scan(&kind, &size, &raw)
	if err != nil {
		return nil, storeError(err)
	}
	if kind == "null" {
		return nil, ErrMissing
	}
	if kind != "blob" || !size.Valid || size.Int64 < 1 || size.Int64 > vault.MaxLocalPolicyBytes || len(raw) != int(size.Int64) {
		return nil, ErrFormat
	}
	return raw, nil
}

func (s *SQLite) WriteProfile(ctx context.Context, raw, expected []byte) error {
	return s.writeProfile(ctx, raw, expected, false)
}

// SeedProfile is reserved for the authenticated new-workspace initialization
// journal. It requires the pristine key graph and is part of initial state, not
// a user mutation. Ordinary updates always advance ChangeSeq.
func (s *SQLite) SeedProfile(ctx context.Context, raw []byte) error {
	return s.writeProfile(ctx, raw, nil, true)
}

func (s *SQLite) writeProfile(ctx context.Context, raw, expected []byte, initial bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if len(raw) == 0 || len(raw) > vault.MaxLocalPolicyBytes || (expected != nil && len(expected) == 0) || len(expected) > vault.MaxLocalPolicyBytes {
		return ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if initial {
		if err := s.validateInitialization(ctx, tx); err != nil {
			return err
		}
	}
	// database/sql binds a nil []byte as SQL NULL. IS compares exact BLOB content
	// and permits that initial NULL, without SQL NULL equality's three-valued logic.
	delta := 1
	if initial {
		delta = 0
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SignedProfile=?,ChangeSeq=ChangeSeq+? WHERE Singleton=1 AND SignedProfile IS ? AND ChangeSeq < 9223372036854775807`, raw, delta, expected)); err != nil {
		return err
	}
	var stored []byte
	var kind string
	if err := tx.QueryRowContext(ctx, `SELECT typeof(SignedProfile),substr(SignedProfile,1,?) FROM WorkspaceMeta WHERE Singleton=1`, vault.MaxLocalPolicyBytes+1).Scan(&kind, &stored); err != nil {
		return storeError(err)
	}
	// Triggers must not silently substitute an unauthenticated policy on success.
	if kind != "blob" || !bytes.Equal(stored, raw) {
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

var _ ProfileStore = (*SQLite)(nil)
