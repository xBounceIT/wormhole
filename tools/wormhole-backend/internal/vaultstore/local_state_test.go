package vaultstore

import (
	"context"
	"database/sql"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func localStateRecord(s *SQLite) (LocalState, []Secret) {
	v := LocalState{ID: uuid.NewString(), Kind: "azure-refresh", ScopeID: uuid.NewString(), Size: 16, RowVersion: 1, Fields: []SecretField{{Field: "chunk00", Version: 1, Present: true}}, Seal: make([]byte, 32)}
	secret := record(s)
	secret.Ref = SecretRef{OwnerKind: "local-state", OwnerID: v.ID, Field: "chunk00"}
	return v, []Secret{secret}
}

func TestLocalStateValidation(t *testing.T) {
	s, _ := database(t)
	v, _ := localStateRecord(s)
	for _, change := range []func(*LocalState){
		func(v *LocalState) { v.ID = "bad" }, func(v *LocalState) { v.ScopeID = "bad" }, func(v *LocalState) { v.Kind = "unknown" }, func(v *LocalState) { v.Size = -1 }, func(v *LocalState) { v.Size = MaxLocalStateBytes + 1 }, func(v *LocalState) { v.RowVersion = 0 }, func(v *LocalState) { v.RowVersion = math.MaxUint64 }, func(v *LocalState) { v.Seal = nil }, func(v *LocalState) { v.Fields = nil }, func(v *LocalState) { v.Fields = make([]SecretField, MaxLocalStateChunks+1) }, func(v *LocalState) { v.Deleted = true }, func(v *LocalState) { v.Size = vault.MaxSecretBytes + 1 }, func(v *LocalState) { v.Fields[0].Field = "chunk01" }, func(v *LocalState) { v.Fields[0].Version = 0 }, func(v *LocalState) { v.Fields[0].Version = math.MaxUint64 }, func(v *LocalState) { v.Fields[0].Present = false },
	} {
		bad := v
		bad.Fields = append([]SecretField{}, v.Fields...)
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid metadata accepted", bad)
		}
	}
	for _, kind := range []string{"migration-retirement", "migration-source-inventory", "bitwarden-cli", "mcp-token", "azure-refresh", "azure-legacy", "watchguard-cache", "watchguard-legacy", "stormshield-cache", "stormshield-legacy", "azure-import", "bitwarden-browser", "vpn-sso", "legacy-secret", "legacy-tunnel-row", "legacy-private-key", "legacy-tunnel-file", "legacy-browser-file"} {
		v.Kind = kind
		if v.Validate() != nil {
			t.Fatal(kind)
		}
	}
	v.Size, v.Deleted, v.Fields[0].Present = 0, true, false
	if v.Validate() != nil || v.ActiveChunks() != 0 {
		t.Fatal("valid tombstone rejected")
	}
}

func TestLocalStateStoreAtomicCASAndTombstones(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	v, secrets := localStateRecord(s)
	if err := s.WriteSecret(ctx, secrets[0], 0); err != ErrConflict {
		t.Fatal("raw local state accepted", err)
	}
	if err := s.WriteLocalState(ctx, v, secrets, 0); err != nil {
		t.Fatal(err)
	}
	read, err := s.ReadLocalState(ctx, v.Kind, v.ScopeID)
	if err != nil || !reflect.DeepEqual(read, v) {
		t.Fatal(read, err)
	}
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal("state accepted as pristine")
	}
	if err := s.WriteLocalState(ctx, v, secrets, 0); err != ErrConflict {
		t.Fatal("duplicate create", err)
	}
	old := v
	v.RowVersion = 2
	v.Fields = append([]SecretField{}, v.Fields...)
	v.Fields[0].Version = 2
	v.Fields[0].Present = false
	v.Deleted = true
	v.Size = 0
	secrets[0] = next(secrets[0])
	secrets[0].Envelope.Ciphertext = make([]byte, 16)
	exec(t, s, `CREATE TRIGGER fail BEFORE UPDATE ON LocalState BEGIN SELECT RAISE(IGNORE); END;`)
	if err := s.WriteLocalState(ctx, v, secrets, 1); err == nil {
		t.Fatal("ignored metadata write committed")
	}
	got, err := s.ReadLocalState(ctx, old.Kind, old.ScopeID)
	if err != nil || !reflect.DeepEqual(got, old) {
		t.Fatal("partial write", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	count(t, s, "SELECT count(*) FROM Keys WHERE Kind='dek' AND Status='active'", 1)
	exec(t, s, "DROP TRIGGER fail")
	if err := s.WriteLocalState(ctx, v, secrets, 1); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListLocalStates(ctx, "", 128)
	if err != nil || len(page) != 0 {
		t.Fatal("deleted state listed", err)
	}
	deleted, err := s.ReadLocalState(ctx, v.Kind, v.ScopeID)
	if err != nil || !deleted.Deleted {
		t.Fatal("tombstone lost", err)
	}
	v.RowVersion = 3
	v.Fields[0].Version = 3
	secrets[0] = next(secrets[0])
	if err := s.WriteLocalState(ctx, v, secrets, 2); err != ErrConflict {
		t.Fatal("repeated deletion", err)
	}
	v.Deleted = false
	v.Fields[0].Present = true
	v.Size = 16
	secrets[0].Envelope.Ciphertext = make([]byte, 32)
	if err := s.WriteLocalState(ctx, v, secrets, 2); err != nil {
		t.Fatal("could not restore state", err)
	}
	page, err = s.ListLocalStates(ctx, "", 1)
	if err != nil || len(page) != 1 || page[0].RowVersion != 3 {
		t.Fatal(page, err)
	}
	page, err = s.ListLocalStates(ctx, v.ID, 1)
	if err != nil || len(page) != 0 {
		t.Fatal("cursor not exclusive")
	}
}

func TestLocalStateStoreRejectsInvalidWritesAndReads(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	v, secrets := localStateRecord(s)
	if _, err := s.ReadLocalState(ctx, v.Kind, v.ScopeID); err != ErrMissing {
		t.Fatal(err)
	}
	for _, change := range []func(*LocalState, *[]Secret){
		func(v *LocalState, _ *[]Secret) { v.Kind = "bad" }, func(v *LocalState, _ *[]Secret) { v.RowVersion = 2 }, func(_ *LocalState, s *[]Secret) { *s = nil }, func(v *LocalState, _ *[]Secret) { v.ID = uuid.NewString() }, func(_ *LocalState, s *[]Secret) { (*s)[0].Ref.Field = "chunk01" }, func(_ *LocalState, s *[]Secret) { (*s)[0].Envelope.Ciphertext = make([]byte, 17) }, func(v *LocalState, _ *[]Secret) { v.Fields[0].Version = 2 },
	} {
		bad := v
		bad.Fields = append([]SecretField{}, v.Fields...)
		ss := append([]Secret{}, secrets...)
		change(&bad, &ss)
		if err := s.WriteLocalState(ctx, bad, ss, 0); err == nil {
			t.Fatal("invalid write accepted")
		}
	}
	if err := s.WriteLocalState(ctx, v, secrets, math.MaxUint64); err != ErrFormat {
		t.Fatal(err)
	}
	if err := s.WriteLocalState(ctx, v, secrets, 0); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ kind, scope string }{{"bad", v.ScopeID}, {v.Kind, "bad"}} {
		if _, err := s.ReadLocalState(ctx, bad.kind, bad.scope); err != ErrFormat {
			t.Fatal(err)
		}
	}
	for _, bad := range []struct {
		after string
		limit int
	}{{"bad", 1}, {"", 0}, {"", 129}} {
		if _, err := s.ListLocalStates(ctx, bad.after, bad.limit); err != ErrFormat {
			t.Fatal(err)
		}
	}
	for _, manifest := range []string{"invalid", `[]`, strings.Repeat(" ", 2049), `[ {"field":"chunk00","version":1,"present":true}]`} {
		exec(t, s, "UPDATE LocalState SET SecretManifest=?", manifest)
		if _, err := s.ReadLocalState(ctx, v.Kind, v.ScopeID); err != ErrFormat {
			t.Fatal("bad manifest accepted", err)
		}
		if _, err := s.ListLocalStates(ctx, "", 1); err != ErrFormat {
			t.Fatal("bad manifest listed", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadLocalState(ctx, v.Kind, v.ScopeID); err != ErrClosed {
		t.Fatal(err)
	}
	if _, err := s.ListLocalStates(ctx, "", 1); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteLocalState(ctx, v, secrets, 0); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestLocalStateCreateCannotAdoptDamagedIdentity(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	old, values := localStateRecord(s)
	if err := s.WriteLocalState(ctx, old, values, 0); err != nil {
		t.Fatal(err)
	}
	// A damaged aggregate is not an unused identity. A new natural key must
	// never adopt its primary ID or repair it under a different seal.
	exec(t, s, "DELETE FROM SecretValues; DELETE FROM KeyCopies; DELETE FROM Keys WHERE Kind='dek';")
	value, secrets := localStateRecord(s)
	value.ID = old.ID
	secrets[0].Ref.OwnerID = old.ID
	if err := s.WriteLocalState(ctx, value, secrets, 0); err == nil {
		t.Fatal("new scope silently adopted damaged aggregate ID")
	}
	read, err := s.ReadLocalState(ctx, old.Kind, old.ScopeID)
	if err != nil || !reflect.DeepEqual(read, old) {
		t.Fatal("old metadata overwritten", err)
	}
	count(t, s, "SELECT count(*) FROM SecretValues", 0)
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
}

func TestLocalStateSchemaUpgradePreservesCiphertextAndRollsBack(t *testing.T) {
	for _, failure := range []string{"", "IGNORE", "ABORT,'fixture'"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			s, path := database(t)
			value := record(s)
			if err := s.WriteSecret(ctx, value, 0); err != nil {
				t.Fatal(err)
			}
			// Reconstruct the old CHECK constraint, not just its version number.
			old := schema[strings.Index(schema, "CREATE TABLE SecretValues ("):]
			old = strings.Replace(old, "CREATE TABLE SecretValues (", "CREATE TABLE SecretValuesOld (", 1)
			exec(t, s, "DROP TABLE LocalState;"+old+`INSERT INTO SecretValuesOld SELECT * FROM SecretValues; DROP TABLE SecretValues; ALTER TABLE SecretValuesOld RENAME TO SecretValues; UPDATE WorkspaceMeta SET SchemaVersion=5;`)
			if failure != "" {
				exec(t, s, `CREATE TRIGGER fail BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE(`+failure+`); END;`)
			}
			id := s.identity
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenSQLite(ctx, path, id, false)
			if failure != "" {
				if err == nil || opened != nil {
					t.Fatal("partial upgrade accepted")
				}
				db, openErr := sql.Open("sqlite", path)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer db.Close()
				var version, tables int
				if err := db.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&version); err != nil || version != 5 {
					t.Fatal("version escaped rollback", err)
				}
				if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('LocalState','SecretValuesV6')").Scan(&tables); err != nil || tables != 0 {
					t.Fatal("table escaped rollback", err)
				}
				if _, err := db.Exec("DROP TRIGGER fail"); err != nil {
					t.Fatal(err)
				}
				db.Close()
				opened, err = OpenSQLite(ctx, path, id, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			got, err := opened.ReadSecret(ctx, value.Ref)
			if err != nil || !reflect.DeepEqual(got, value) {
				t.Fatal("ciphertext changed during upgrade", err)
			}
			count(t, opened, "SELECT SchemaVersion FROM WorkspaceMeta", 6)
			count(t, opened, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
			state, secrets := localStateRecord(opened)
			if err := opened.WriteLocalState(ctx, state, secrets, 0); err != nil {
				t.Fatal("upgraded CHECK rejects local state", err)
			}
		})
	}
}
