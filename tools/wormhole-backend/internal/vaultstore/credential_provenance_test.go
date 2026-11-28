package vaultstore

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialProvenanceRoundTripImmutableAndBounds(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	c := credential()
	c.CreatedAt = "2024-03-01T12:34:56.1234567+01:00"
	if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(ctx, path, s.identity, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ReadCredential(ctx, c.ID)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatal("provenance round trip failed", err)
	}
	c.RowVersion++
	c.CreatedAt = "2026-10-30T12:00:00Z"
	if err := s.WriteCredential(ctx, c, nil, 1); err != ErrConflict {
		t.Fatal("creation time replaced", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	for _, bad := range []string{"a\x00b", strings.Repeat("x", 129), string([]byte{255})} {
		c.CreatedAt = bad
		if c.Validate() != ErrFormat {
			t.Fatal("invalid provenance accepted")
		}
		if _, err := s.db.ExecContext(ctx, "UPDATE CredentialProfiles SET CreatedAt=?", bad); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadCredential(ctx, c.ID); err != ErrFormat {
			t.Fatal("invalid stored provenance accepted", err)
		}
	}
}

func TestCredentialProvenanceSchemaUpgradeAtomicity(t *testing.T) {
	ctx := context.Background()
	for _, failure := range []string{"", "ABORT,'forced'", "IGNORE", "existing"} {
		t.Run(failure, func(t *testing.T) {
			s, path := database(t)
			c := credential()
			if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
				t.Fatal(err)
			}
			if failure != "existing" {
				exec(t, s, "ALTER TABLE CredentialProfiles DROP COLUMN CreatedAt")
			}
			exec(t, s, "DROP TABLE LocalState; UPDATE WorkspaceMeta SET SchemaVersion=4")
			if failure != "" && failure != "existing" {
				exec(t, s, "CREATE TRIGGER fail BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE("+failure+"); END;")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenSQLite(ctx, path, s.identity, false)
			if failure == "" {
				if err != nil {
					t.Fatal(err)
				}
				defer opened.Close()
				got, err := opened.ReadCredential(ctx, c.ID)
				if err != nil || !reflect.DeepEqual(got, c) {
					t.Fatal("upgrade changed existing aggregate", err)
				}
				count(t, opened, "SELECT SchemaVersion FROM WorkspaceMeta", SchemaVersion)
				count(t, opened, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
				return
			}
			if err == nil || opened != nil {
				t.Fatal("partial upgrade accepted")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, columns int
			if err := db.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&version); err != nil || version != 4 {
				t.Fatal("version escaped rollback", err)
			}
			if err := db.QueryRow("SELECT count(*) FROM pragma_table_info('CredentialProfiles') WHERE name='CreatedAt'").Scan(&columns); err != nil {
				t.Fatal(err)
			}
			want := 0
			if failure == "existing" {
				want = 1
			}
			if columns != want {
				t.Fatal("column escaped rollback")
			}
			if failure != "existing" {
				if _, err := db.Exec("DROP TRIGGER fail"); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				retried, err := OpenSQLite(ctx, path, s.identity, false)
				if err != nil {
					t.Fatal("rolled-back upgrade could not resume", err)
				}
				defer retried.Close()
				got, err := retried.ReadCredential(ctx, c.ID)
				if err != nil || !reflect.DeepEqual(got, c) {
					t.Fatal("resumed upgrade changed credential", err)
				}
				count(t, retried, "SELECT SchemaVersion FROM WorkspaceMeta", SchemaVersion)
			}
		})
	}
	s, _ := database(t)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.migrateCredentialProvenance(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled migration continued", err)
	}
}
