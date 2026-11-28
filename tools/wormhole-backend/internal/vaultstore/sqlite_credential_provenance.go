package vaultstore

import "context"

// Empty means unknown for vaults created before provenance was retained. Never
// replace it with migration time or alter their authenticated record bytes.
const credentialProvenanceSchema = `ALTER TABLE CredentialProfiles ADD COLUMN CreatedAt TEXT NOT NULL DEFAULT '';`

func (s *SQLite) migrateCredentialProvenance(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, credentialProvenanceSchema); err != nil {
		return storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SchemaVersion=5 WHERE Singleton=1 AND SchemaVersion=4;`)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}
