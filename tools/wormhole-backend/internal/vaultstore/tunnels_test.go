package vaultstore

import (
	"context"
	"database/sql"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func tunnel(s *SQLite) (Tunnel, Secret) {
	id := uuid.NewString()
	t := Tunnel{TunnelMetadata: TunnelMetadata{ID: id, Name: "VPN " + id, Kind: 1}, CreatedAt: "2026-10-30T00:00:00Z", UpdatedAt: "2026-10-30T00:00:00Z", RowVersion: 1, ConfigurationVersion: 1, Seal: make([]byte, 32)}
	v := record(s)
	v.Ref = SecretRef{OwnerKind: "tunnel", OwnerID: id, Field: "settings"}
	return t, v
}

func TestTunnelAggregateVersioningAndDeletion(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	v, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, v, &secret, 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadTunnel(ctx, v.ID)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, next(secret), 1); err != ErrConflict {
		t.Fatal("primitive bypass", err)
	}
	v.Name = "renamed"
	v.RowVersion++
	if err := s.WriteTunnel(ctx, v, nil, 1); err != nil {
		t.Fatal(err)
	}
	v.RowVersion++
	v.ConfigurationVersion++
	secret = next(secret)
	if err := s.WriteTunnel(ctx, v, &secret, 2); err != nil {
		t.Fatal(err)
	}
	v.RowVersion++
	v.ConfigurationVersion++
	v.Deleted = true
	secret = next(secret)
	secret.Envelope.Ciphertext = make([]byte, 16)
	if err := s.WriteTunnel(ctx, v, &secret, 3); err != nil {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 4)
	if values, err := s.ListTunnels(ctx, "", 128); err != nil || len(values) != 0 {
		t.Fatal(err)
	}
	if got, err := s.ReadTunnel(ctx, v.ID); err != nil || !got.Deleted {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(ctx, v, nil, 3); err != ErrConflict {
		t.Fatal("stale delete", err)
	}
	v.RowVersion++
	v.Deleted = false
	if err := s.WriteTunnel(ctx, v, nil, 4); err != ErrConflict {
		t.Fatal("resurrected tombstone", err)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=0")
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal("initialization marker replay", err)
	}
}

func TestTunnelAggregateRollback(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"Keys", "KeyCopies", "SecretValues", "TunnelConfigs", "WorkspaceMeta"} {
		for _, failure := range []string{"ABORT,'forced'", "IGNORE"} {
			t.Run(table+failure, func(t *testing.T) {
				s, _ := database(t)
				v, secret := tunnel(s)
				action := "INSERT"
				if table == "WorkspaceMeta" {
					action = "UPDATE"
				}
				exec(t, s, "CREATE TRIGGER fail BEFORE "+action+" ON "+table+" BEGIN SELECT RAISE("+failure+"); END;")
				if err := s.WriteTunnel(ctx, v, &secret, 0); err == nil {
					t.Fatal("partial aggregate accepted")
				}
				count(t, s, "SELECT count(*) FROM Keys", 1)
				count(t, s, "SELECT count(*) FROM KeyCopies", 0)
				count(t, s, "SELECT count(*) FROM SecretValues", 0)
				count(t, s, "SELECT count(*) FROM TunnelConfigs", 0)
				count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
			})
		}
	}
	s, _ := database(t)
	v, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, v, &secret, 0); err != nil {
		t.Fatal(err)
	}
	original := secret
	v.RowVersion++
	v.ConfigurationVersion++
	secret = next(secret)
	exec(t, s, "CREATE TRIGGER fail BEFORE UPDATE ON TunnelConfigs BEGIN SELECT RAISE(ABORT,'forced'); END;")
	if err := s.WriteTunnel(ctx, v, &secret, 1); err == nil {
		t.Fatal("partial update accepted")
	}
	got, err := s.ReadSecret(ctx, original.Ref)
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("prior key retired after rollback", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
}

func TestTunnelAggregateRejectsInconsistentConfiguration(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(*Tunnel, *Secret){
		"kind": func(v *Tunnel, s *Secret) { v.Kind = 10 }, "seal": func(v *Tunnel, s *Secret) { v.Seal = nil }, "revision": func(v *Tunnel, s *Secret) { v.RowVersion = 3 },
		"owner": func(v *Tunnel, s *Secret) { s.Ref.OwnerID = uuid.NewString() }, "field": func(v *Tunnel, s *Secret) { s.Ref.Field = "other" }, "credential": func(v *Tunnel, s *Secret) { s.Ref.OwnerKind = "credential" },
		"config revision": func(v *Tunnel, s *Secret) { v.ConfigurationVersion = 2 }, "secret revision": func(v *Tunnel, s *Secret) { s.RowVersion = 2 }, "envelope": func(v *Tunnel, s *Secret) { s.Envelope.Nonce = nil }, "empty active": func(v *Tunnel, s *Secret) { s.Envelope.Ciphertext = make([]byte, 16) },
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := database(t)
			v, secret := tunnel(s)
			change(&v, &secret)
			if err := s.WriteTunnel(ctx, v, &secret, 0); err == nil {
				t.Fatal("invalid aggregate accepted")
			}
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
		})
	}
	s, _ := database(t)
	v, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, v, nil, 0); err != ErrFormat {
		t.Fatal(err)
	}
	v.Deleted = true
	if err := s.WriteTunnel(ctx, v, &secret, 0); err != ErrConflict {
		t.Fatal(err)
	}
	v.Deleted = false
	if err := s.WriteSecret(ctx, secret, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(ctx, v, &secret, 0); err != ErrConflict {
		t.Fatal("orphan adopted", err)
	}
	s2, _ := database(t)
	v, secret = tunnel(s2)
	if err := s2.WriteTunnel(ctx, v, &secret, 0); err != nil {
		t.Fatal(err)
	}
	v.RowVersion++
	for name, mutate := range map[string]func(*Tunnel){"created": func(v *Tunnel) { v.CreatedAt = "2026-10-29T00:00:00Z" }, "kind": func(v *Tunnel) { v.Kind = 2 }, "config": func(v *Tunnel) { v.ConfigurationVersion++ }, "deleted": func(v *Tunnel) { v.Deleted = true }} {
		t.Run(name, func(t *testing.T) {
			changed := v
			mutate(&changed)
			if err := s2.WriteTunnel(ctx, changed, nil, 1); err == nil {
				t.Fatal("inconsistent metadata allowed")
			}
		})
	}
	for _, query := range []string{"UPDATE SecretValues SET RowVersion=2", "UPDATE SecretValues SET Field='other'", "DELETE FROM SecretValues"} {
		t.Run(query, func(t *testing.T) {
			s, _ := database(t)
			v, secret := tunnel(s)
			if err := s.WriteTunnel(ctx, v, &secret, 0); err != nil {
				t.Fatal(err)
			}
			exec(t, s, query)
			v.RowVersion++
			if err := s.WriteTunnel(ctx, v, nil, 1); err == nil {
				t.Fatal("inconsistent field allowed")
			}
		})
	}
}

func TestTunnelPagesConflictsAndBounds(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	first, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, first, &secret, 0); err != nil {
		t.Fatal(err)
	}
	duplicate, other := tunnel(s)
	duplicate.Name = first.Name
	if err := s.WriteTunnel(ctx, duplicate, &other, 0); err != ErrConflict {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	for i := 0; i < 3; i++ {
		v, secret := tunnel(s)
		if err := s.WriteTunnel(ctx, v, &secret, 0); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListTunnels(ctx, "", 2)
	if err != nil || len(page) != 2 {
		t.Fatal(err)
	}
	end, err := s.ListTunnels(ctx, page[1].ID, 2)
	if err != nil || len(end) != 2 || end[0].ID <= page[1].ID {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 0, 129} {
		if _, err := s.ListTunnels(ctx, "", n); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := s.ListTunnels(ctx, "bad", 1); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ReadTunnel(ctx, "bad"); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ReadTunnel(ctx, uuid.NewString()); err != ErrMissing {
		t.Fatal(err)
	}
	first.RowVersion++
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.WriteTunnel(ctx, first, nil, 1) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrConflict {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal(winners)
	}
	first.RowVersion++
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=9223372036854775807")
	if err := s.WriteTunnel(ctx, first, nil, 2); err != ErrConflict {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ListTunnels(cancelled, "", 1); err == nil {
		t.Fatal("cancel ignored")
	}
	if err := s.WriteTunnel(cancelled, first, nil, 2); err == nil {
		t.Fatal("cancel ignored")
	}
	s.Close()
	if _, err := s.ReadTunnel(ctx, first.ID); err != ErrClosed {
		t.Fatal(err)
	}
	if _, err := s.ListTunnels(ctx, "", 1); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(ctx, first, nil, 2); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestTunnelValidationAndStorageCorruption(t *testing.T) {
	s, _ := database(t)
	v, secret := tunnel(s)
	for _, mutate := range []func(*Tunnel){
		func(v *Tunnel) { v.ID = "bad" }, func(v *Tunnel) { v.Name = " " }, func(v *Tunnel) { v.Name = strings.Repeat("a", 129) }, func(v *Tunnel) { v.Name = "a\x00" }, func(v *Tunnel) { v.Name = "\xff" }, func(v *Tunnel) { v.Kind = -1 }, func(v *Tunnel) { v.RowVersion = 0 }, func(v *Tunnel) { v.RowVersion = math.MaxUint64 }, func(v *Tunnel) { v.ConfigurationVersion = 0 }, func(v *Tunnel) { v.CreatedAt = "bad" }, func(v *Tunnel) { v.UpdatedAt = "2026-10-30T00:00:00+02:00" }, func(v *Tunnel) { v.UpdatedAt = "2026-10-30T00:00:00.000Z" },
	} {
		c := v
		mutate(&c)
		if c.Validate() != ErrFormat {
			t.Fatal("invalid tunnel accepted")
		}
	}
	if err := s.WriteTunnel(context.Background(), v, &secret, 0); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE TunnelConfigs SET EncryptedMetadata=x'00'")
	if _, err := s.ReadTunnel(context.Background(), v.ID); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ListTunnels(context.Background(), "", 1); err != ErrFormat {
		t.Fatal(err)
	}
	exec(t, s, "DROP TABLE TunnelConfigs")
	if _, err := s.ListTunnels(context.Background(), "", 1); err != ErrStorage {
		t.Fatal(err)
	}
	if _, err := s.ReadTunnel(context.Background(), v.ID); err != ErrStorage {
		t.Fatal(err)
	}
	v.RowVersion++
	if err := s.WriteTunnel(context.Background(), v, nil, 1); err != ErrStorage {
		t.Fatal(err)
	}
}

func TestTunnelSchemaUpgradeAndFailureAtomicity(t *testing.T) {
	ctx := context.Background()
	for _, failure := range []string{"", "existing", "ABORT,'forced'", "IGNORE"} {
		t.Run(failure, func(t *testing.T) {
			s, path := database(t)
			c := credential()
			if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
				t.Fatal(err)
			}
			if failure != "existing" {
				exec(t, s, "DROP TABLE TunnelConfigs")
			}
			exec(t, s, "DROP TABLE LocalState; DROP TABLE Nodes; ALTER TABLE CredentialProfiles DROP COLUMN CreatedAt; UPDATE WorkspaceMeta SET SchemaVersion=2")
			if failure != "" && failure != "existing" {
				exec(t, s, "CREATE TRIGGER fail BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE("+failure+"); END;")
			}
			s.Close()
			opened, err := OpenSQLite(ctx, path, s.identity, false)
			if failure == "" {
				if err != nil {
					t.Fatal(err)
				}
				defer opened.Close()
				count(t, opened, "SELECT SchemaVersion FROM WorkspaceMeta", SchemaVersion)
				count(t, opened, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
				got, err := opened.ReadCredential(ctx, c.ID)
				if err != nil || !reflect.DeepEqual(got, c) {
					t.Fatal(err)
				}
				v, secret := tunnel(opened)
				if err := opened.WriteTunnel(ctx, v, &secret, 0); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || opened != nil {
				t.Fatal("migration did not fail")
			}
			raw, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			var version, count int
			if err := raw.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&version); err != nil || version != 2 {
				t.Fatal("partial version promotion", err)
			}
			if err := raw.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='TunnelConfigs'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if failure == "existing" {
				want = 1
			}
			if count != want {
				t.Fatal("partial DDL publication")
			}
		})
	}
}
