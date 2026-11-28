package vaultstore

import (
	"context"
	"database/sql"
)

// writeAggregateFields keeps credential and node field changes atomic with their metadata.
func (s *SQLite) writeAggregateFields(ctx context.Context, tx *sql.Tx, kind, id string, previous, next []SecretField, secrets []Secret) error {
	oldFields := fieldsByName(previous)
	newFields := fieldsByName(next)
	// Reject undeclared or missing values rather than accidentally adopting a
	// pre-existing standalone secret or concealing an inconsistent aggregate.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM SecretValues WHERE OwnerKind=? AND OwnerId=?;`, kind, id).Scan(&count); err != nil {
		return storeError(err)
	}
	if count != len(oldFields) {
		return ErrConflict
	}
	for name, field := range oldFields {
		var version uint64
		if err := tx.QueryRowContext(ctx, `SELECT RowVersion FROM SecretValues WHERE OwnerKind=? AND OwnerId=? AND Field=?;`, kind, id, name).Scan(&version); err != nil {
			return storeError(err)
		}
		if version != field.Version {
			return ErrConflict
		}
		if _, ok := newFields[name]; !ok {
			return ErrFormat
		}
	}
	changed := make(map[string]bool, len(secrets))
	for _, secret := range secrets {
		name := secret.Ref.Field
		field, ok := newFields[name]
		old := oldFields[name]
		if !ok || changed[name] || secret.Ref.OwnerKind != kind || secret.Ref.OwnerID != id || !secret.valid(s.identity) || field.Version != old.Version+1 || secret.RowVersion != field.Version || (!field.Present && len(secret.Envelope.Ciphertext) != 16) {
			return ErrFormat
		}
		changed[name] = true
		if err := s.writeSecret(ctx, tx, secret, old.Version); err != nil {
			return err
		}
	}
	for name, field := range newFields {
		if !changed[name] && field != oldFields[name] {
			return ErrFormat
		}
	}
	return nil
}
