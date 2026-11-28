package vaultstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
)

var _ TunnelStore = (*SQLite)(nil)

func (s *SQLite) migrateTunnels(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, tunnelSchema); err != nil {
		return storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SchemaVersion=3 WHERE Singleton=1 AND SchemaVersion=2;`)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

const tunnelColumns = `substr(Id,1,37),substr(Name,1,513),Kind,substr(CreatedAt,1,31),substr(UpdatedAt,1,31),RowVersion,ConfigurationVersion,Deleted,substr(Seal,1,33),EncryptedMetadata IS NULL AND MetadataKeyId IS NULL AND NameBlindIndex IS NULL`

func scanTunnel(row scanner) (Tunnel, error) {
	var t Tunnel
	var plain bool
	err := row.Scan(&t.ID, &t.Name, &t.Kind, &t.CreatedAt, &t.UpdatedAt, &t.RowVersion, &t.ConfigurationVersion, &t.Deleted, &t.Seal, &plain)
	if errors.Is(err, sql.ErrNoRows) {
		return Tunnel{}, ErrMissing
	}
	if err != nil {
		return Tunnel{}, storeError(err)
	}
	if !plain || t.Validate() != nil {
		return Tunnel{}, ErrFormat
	}
	return t, nil
}

func (s *SQLite) ReadTunnel(ctx context.Context, id string) (Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Tunnel{}, ErrClosed
	}
	if !validID(id) {
		return Tunnel{}, ErrFormat
	}
	return scanTunnel(s.db.QueryRowContext(ctx, `SELECT `+tunnelColumns+` FROM TunnelConfigs WHERE Id=?;`, id))
}

func (s *SQLite) ListTunnels(ctx context.Context, after string, limit int) ([]Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if (after != "" && !validID(after)) || limit < 1 || limit > 128 {
		return nil, ErrFormat
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+tunnelColumns+` FROM TunnelConfigs WHERE Deleted=0 AND Id>? ORDER BY Id LIMIT ?;`, after, limit)
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	result := make([]Tunnel, 0, limit)
	for rows.Next() {
		value, err := scanTunnel(rows)
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

func (s *SQLite) WriteTunnel(ctx context.Context, value Tunnel, secret *Secret, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if value.Validate() != nil || expected >= math.MaxInt64 || value.RowVersion != expected+1 {
		return ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	old, err := scanTunnel(tx.QueryRowContext(ctx, `SELECT `+tunnelColumns+` FROM TunnelConfigs WHERE Id=?;`, value.ID))
	if errors.Is(err, ErrMissing) {
		if expected != 0 || value.Deleted {
			return ErrConflict
		}
	} else if err != nil {
		return err
	} else if old.RowVersion != expected || old.Deleted || value.CreatedAt != old.CreatedAt {
		return ErrConflict
	}
	if value.Deleted {
		var referenced bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM Nodes WHERE Deleted=0 AND TunnelConfigId=?);`, value.ID).Scan(&referenced); err != nil {
			return storeError(err)
		}
		if referenced {
			return ErrConflict
		}
	}
	// Refuse orphan fields or an attempt to adopt a pre-existing secret. There
	// is exactly one field, even after deletion; tombstones retain its version.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM SecretValues WHERE OwnerKind='tunnel' AND OwnerId=?;`, value.ID).Scan(&count); err != nil {
		return storeError(err)
	}
	if (expected == 0 && count != 0) || (expected != 0 && count != 1) {
		return ErrConflict
	}
	if expected != 0 {
		var version uint64
		if err := tx.QueryRowContext(ctx, `SELECT RowVersion FROM SecretValues WHERE OwnerKind='tunnel' AND OwnerId=? AND Field='settings';`, value.ID).Scan(&version); err != nil {
			return storeError(err)
		}
		if version != old.ConfigurationVersion {
			return ErrConflict
		}
	}
	if secret == nil {
		if expected == 0 || value.Deleted || value.Kind != old.Kind || value.ConfigurationVersion != old.ConfigurationVersion {
			return ErrFormat
		}
	} else {
		if !secret.valid(s.identity) || secret.Ref != (SecretRef{OwnerKind: "tunnel", OwnerID: value.ID, Field: "settings"}) || value.ConfigurationVersion != old.ConfigurationVersion+1 || secret.RowVersion != value.ConfigurationVersion || (value.Deleted && len(secret.Envelope.Ciphertext) != 16) || (!value.Deleted && len(secret.Envelope.Ciphertext) == 16) {
			return ErrFormat
		}
		if err := s.writeSecret(ctx, tx, *secret, old.ConfigurationVersion); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO TunnelConfigs(Id,Name,Kind,CreatedAt,UpdatedAt,RowVersion,ConfigurationVersion,Deleted,Seal) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(Id) DO UPDATE SET Name=excluded.Name,Kind=excluded.Kind,UpdatedAt=excluded.UpdatedAt,RowVersion=excluded.RowVersion,ConfigurationVersion=excluded.ConfigurationVersion,Deleted=excluded.Deleted,Seal=excluded.Seal;`, value.ID, value.Name, value.Kind, value.CreatedAt, value.UpdatedAt, value.RowVersion, value.ConfigurationVersion, value.Deleted, value.Seal)
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
