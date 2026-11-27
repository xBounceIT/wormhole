package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type migrationDatabaseIntercept struct {
	*sql.DB
	cancel    context.CancelFunc
	oversized bool
}

func (r migrationDatabaseIntercept) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if r.cancel != nil && strings.HasPrefix(query, "SELECT +") {
		r.cancel()
	}
	return rows, err
}

func (r migrationDatabaseIntercept) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if r.oversized && query == "PRAGMA main.page_count" {
		query = "SELECT 9223372036854775807"
	}
	return r.DB.QueryRowContext(ctx, query, args...)
}

func TestVaultMigrationDatabaseCancellationAndSizeAdmission(t *testing.T) {
	db, _ := snapshotDatabase(t)
	key := bytes.Repeat([]byte{4}, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, reader := range []resolverCaptureReader{
		{ctx, migrationDatabaseIntercept{DB: db, cancel: cancel}},
		{context.Background(), migrationDatabaseIntercept{DB: db, oversized: true}},
	} {
		if digest, err := captureLegacyDatabaseState(reader, key); err == nil || digest != nil {
			t.Fatal("partial or oversized snapshot returned")
		}
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("fixture did not reach table scan")
	}
	if digest, err := captureLegacyDatabaseState(resolverCaptureReader{context.Background(), db}, key); err != nil || len(digest) != 32 {
		t.Fatal("cancelled scan left source unusable", err)
	}
}

func TestVaultMigrationDatabaseBindsAllStoredTypesAndSchema(t *testing.T) {
	db, _ := snapshotDatabase(t)
	reader := resolverCaptureReader{context.Background(), db}
	key := bytes.Repeat([]byte{1}, 32)
	legacyVaultSQL(t, db, `CREATE TABLE "quote""table" ("quote""column" BLOB, number, day DATE, flag BOOLEAN)`)
	legacyVaultSQL(t, db, `INSERT INTO "quote""table" VALUES(NULL, 3.25, '2026-10-31', 2)`)
	digest := func() []byte {
		t.Helper()
		value, err := captureLegacyDatabaseState(reader, key)
		if err != nil || len(value) != 32 {
			t.Fatal(value, err)
		}
		return value
	}
	first := digest()
	if !bytes.Equal(first, digest()) {
		t.Fatal("unchanged checkpoint is unstable")
	}
	for _, value := range []any{"", []byte{}, "a\x00b", []byte("a\x00b"), int64(-7), 3.125} {
		legacyVaultSQL(t, db, `UPDATE "quote""table" SET "quote""column"=?`, value)
		next := digest()
		if bytes.Equal(first, next) {
			t.Fatalf("source type or bytes ignored: %T", value)
		}
		first = next
	}
	for _, statement := range []string{
		`UPDATE "quote""table" SET day='2026-10-31 00:00:00'`,
		`UPDATE "quote""table" SET flag=3`,
		`CREATE VIEW unused_view AS SELECT 1`,
		`CREATE INDEX checkpoint_index ON "quote""table"(number)`,
		`PRAGMA user_version=17`,
		`PRAGMA application_id=32`,
		`DELETE FROM "quote""table"`,
	} {
		legacyVaultSQL(t, db, statement)
		next := digest()
		if bytes.Equal(first, next) {
			t.Fatal("source mutation ignored", statement)
		}
		first = next
	}
	key[0]++
	if bytes.Equal(first, digest()) {
		t.Fatal("database commitment does not depend on key")
	}
}

func TestVaultMigrationDatabaseReadsCommittedWAL(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSQL(t, db, "PRAGMA journal_mode=WAL")
	legacyVaultSQL(t, db, "PRAGMA wal_autocheckpoint=0")
	legacyVaultSQL(t, db, "PRAGMA wal_checkpoint(TRUNCATE)")
	reader := resolverCaptureReader{context.Background(), db}
	key := bytes.Repeat([]byte{2}, 32)
	before, err := captureLegacyDatabaseState(reader, key)
	if err != nil {
		t.Fatal(err)
	}
	fileBefore, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `CREATE TABLE wal_only (value TEXT)`)
	legacyVaultSQL(t, db, `INSERT INTO wal_only VALUES('not in the main file')`)
	after, err := captureLegacyDatabaseState(reader, key)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("committed WAL edits ignored", err)
	}
	fileAfter, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(fileBefore, fileAfter) {
		t.Fatal("fixture must change only WAL", err)
	}
}

func TestVaultMigrationDatabaseBoundaries(t *testing.T) {
	db, _ := snapshotDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := bytes.Repeat([]byte{3}, 32)
	for _, reader := range []resolverCaptureReader{{ctx, db}, {context.Background(), db}} {
		factor := key
		if reader.ctx.Err() == nil {
			factor = nil
		}
		if raw, err := captureLegacyDatabaseState(reader, factor); err == nil || raw != nil {
			t.Fatal("invalid input accepted")
		}
	}
	reader := resolverCaptureReader{context.Background(), db}
	for _, query := range []string{"SELECT 1, NULL, 'secret', x'0001'", "SELECT * FROM absent_table"} {
		budget := int64(10)
		if err := hashLegacyMigrationRows(reader, sha256.New(), query, &budget); err == nil {
			t.Fatal("exceeded budget or SQL failure accepted")
		}
	}
	for _, budget := range []int64{18, 28, 38, 48, 58} {
		// Charge query, columns, row framing, value and terminator independently.
		if err := hashLegacyMigrationRows(reader, sha256.New(), "SELECT 'long secret value'", &budget); err == nil {
			t.Fatal("small output budget accepted")
		}
	}
	if _, err := legacyMigrationTableQuery(reader, "missing"); err == nil {
		t.Fatal("missing table accepted")
	}
	legacyVaultSQL(t, db, `CREATE TABLE computed(value TEXT, derived TEXT AS (value || 'copy'))`)
	if _, err := captureLegacyDatabaseState(reader, key); err == nil {
		t.Fatal("generated expressions executed")
	}
	legacyVaultSQL(t, db, "DROP TABLE computed")
	legacyVaultSQL(t, db, `CREATE VIRTUAL TABLE virtual_source USING fts5(value)`)
	if _, err := captureLegacyDatabaseState(reader, key); err == nil {
		t.Fatal("virtual table evaluated")
	}
	legacyVaultSQL(t, db, "DROP TABLE virtual_source")
	columns := make([]string, 129)
	for i := range columns {
		columns[i] = `"` + strings.Repeat("x", i+1) + `" TEXT`
	}
	legacyVaultSQL(t, db, "CREATE TABLE wide("+strings.Join(columns, ",")+")")
	if _, err := captureLegacyDatabaseState(reader, key); err == nil {
		t.Fatal("wide schema accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLegacyDatabaseState(reader, key); err == nil {
		t.Fatal("closed database accepted")
	}
	if _, err := legacyMigrationTableQuery(reader, "wide"); err == nil {
		t.Fatal("closed reader accepted")
	}
}

func TestVaultMigrationInventoryRejectsNonResolverSourceDrift(t *testing.T) {
	db, source, document, key, plan, ids := migrationStageFixture(t)
	ctx := context.Background()
	stage, err := stageLegacyVaultDomains(ctx, source, "", document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	defer owner.Close()
	reader := resolverCaptureReader{ctx, db}
	verify := func() error {
		return verifyLegacySourceInventory(reader, source, "", document.VaultID, key, owner)
	}
	if err := verify(); err != nil {
		t.Fatal("fresh stage rejected", err)
	}
	legacyVaultSQL(t, db, `UPDATE Nodes SET Notes='changed after staging' WHERE Id=?`, ids[2])
	if err := withLegacyResolverMigration(ctx, db, document.VaultID, plan, func(reserved resolverCaptureReader, _ legacyResolverBaseline) error {
		return verifyLegacySourceInventory(reserved, source, "", document.VaultID, key, owner)
	}); err != vault.ErrAuthentication {
		t.Fatal("unchanged resolver fingerprint accepted changed notes", err)
	}
	if err := owner.WithNodeField(ctx, ids[2], "notes", 2, equalLegacyVaultValue([]byte("private stage note"))); err != nil {
		t.Fatal("source verification mutated staged notes", err)
	}
	legacyVaultSQL(t, db, `UPDATE Nodes SET Notes='private stage note' WHERE Id=?`, ids[2])
	if err := verify(); err != nil {
		t.Fatal("restored source rejected", err)
	}
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Name='renamed after staging' WHERE Id=?`, ids[0])
	if err := verify(); err != vault.ErrAuthentication {
		t.Fatal("credential metadata drift accepted", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// Restaging remains the recovery path; it recopies, reseals and verifies all
	// current content before advancing the authenticated domains-copied marker.
	if _, err := stageLegacyVaultDomains(ctx, source, "", document, key, plan); err != nil {
		t.Fatal("could not restage changed non-resolver metadata", err)
	}
	owner = openNativeMigrationStage(t, stage.Path, key)
	defer owner.Close()
	if err := verify(); err != nil {
		t.Fatal("restaged inventory rejected", err)
	}
}

func TestVaultMigrationInventoryRequiresDatabaseCommitment(t *testing.T) {
	db, source := snapshotDatabase(t)
	h := vaultCredentialFixture(t)
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{1}, 32)
	reader := resolverCaptureReader{context.Background(), db}
	current, err := captureLegacySourceInventory(reader, source, "", doc.VaultID, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]any
	if json.Unmarshal(current, &old) != nil {
		t.Fatal("invalid inventory")
	}
	old["version"] = 1
	delete(old, "databaseMac")
	raw, _ := json.Marshal(old)
	if _, err := h.owner.PutLocalState(reader.ctx, migrationSourceInventoryKind, doc.VaultID, raw, 0); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacySourceInventory(reader, source, "", doc.VaultID, key, h.owner); err != vault.ErrAuthentication {
		t.Fatal("old inventory authorized source verification", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacySourceInventory(reader, source, "", doc.VaultID, key, h.owner); err == nil {
		t.Fatal("unreadable source accepted")
	}
}
