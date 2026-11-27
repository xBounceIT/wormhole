package vaultstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func credential() Credential {
	id := uuid.NewString()
	return Credential{CredentialMetadata: CredentialMetadata{ID: id, Name: "Account " + id, Protocol: "ssh", Kind: "password", Provider: "local", Username: "user"}, RowVersion: 1, Fields: []CredentialField{}, Seal: make([]byte, 32)}
}

func credentialSecret(s *SQLite, c *Credential, field string) Secret {
	v := record(s)
	v.Ref = SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: field}
	c.Fields = append(c.Fields, CredentialField{Field: field, Version: 1, Present: true})
	return v
}

func TestCredentialAggregateCASAndFieldTombstones(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	c := credential()
	v := credentialSecret(s, &c, "password")
	if err := s.WriteCredential(ctx, c, []Secret{v}, 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadCredential(ctx, c.ID)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("aggregate mismatch: %v", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, next(v), 1); err != ErrConflict {
		t.Fatal("standalone bypass", err)
	}
	c.RowVersion++
	c.Name = "Renamed"
	if err := s.WriteCredential(ctx, c, nil, 1); err != nil {
		t.Fatal(err)
	}
	c.RowVersion++
	c.Fields[0].Version++
	c.Fields[0].Present = false
	v = next(v)
	v.Envelope.Ciphertext = make([]byte, 16)
	if err := s.WriteCredential(ctx, c, []Secret{v}, 2); err != nil {
		t.Fatal(err)
	}
	c.RowVersion++
	c.Fields[0].Version++
	c.Fields[0].Present = true
	v = next(v)
	v.Envelope.Ciphertext = make([]byte, 32)
	if err := s.WriteCredential(ctx, c, []Secret{v}, 3); err != nil {
		t.Fatal(err)
	}
	if c.Fields[0].Version != 3 {
		t.Fatal("field floor reset")
	}
	c.RowVersion++
	c.Deleted = true
	c.Fields[0].Version++
	c.Fields[0].Present = false
	v = next(v)
	v.Envelope.Ciphertext = make([]byte, 16)
	if err := s.WriteCredential(ctx, c, []Secret{v}, 4); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListCredentials(ctx, "", 128)
	if err != nil || len(page) != 0 {
		t.Fatal(page, err)
	}
	if got, err := s.ReadCredential(ctx, c.ID); err != nil || !got.Deleted {
		t.Fatal(got, err)
	}
	c.Deleted = false
	c.RowVersion++
	if err := s.WriteCredential(ctx, c, nil, 5); err != ErrConflict {
		t.Fatal("resurrect", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 5)
	count(t, s, "SELECT count(*) FROM Keys WHERE Kind='dek' AND Status='retired'", 3)
}

func TestCredentialWriteRollsBackEveryPart(t *testing.T) {
	for _, failing := range []string{"CredentialProfiles", "KeyCopies", "SecretValues", "WorkspaceMeta"} {
		t.Run(failing, func(t *testing.T) {
			s, _ := database(t)
			c := credential()
			c.Kind = "sshKey"
			pass := credentialSecret(s, &c, "passphrase")
			key := credentialSecret(s, &c, "privateKey")
			event := "INSERT"
			if failing == "WorkspaceMeta" {
				event = "UPDATE"
			}
			exec(t, s, "CREATE TRIGGER fail BEFORE "+event+" ON "+failing+" BEGIN SELECT RAISE(ABORT,'private diagnostic'); END;")
			if err := s.WriteCredential(context.Background(), c, []Secret{pass, key}, 0); err != ErrStorage {
				t.Fatal(err)
			}
			for _, table := range []string{"CredentialProfiles", "SecretValues", "KeyCopies"} {
				count(t, s, "SELECT count(*) FROM "+table, 0)
			}
			count(t, s, "SELECT count(*) FROM Keys", 1)
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
		})
	}
	s, _ := database(t)
	c := credential()
	v := credentialSecret(s, &c, "password")
	if err := s.WriteCredential(context.Background(), c, []Secret{v}, 0); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "CREATE TRIGGER fail BEFORE UPDATE ON CredentialProfiles BEGIN SELECT RAISE(ABORT,'private diagnostic'); END;")
	updated := c
	updated.RowVersion++
	updated.Fields = []CredentialField{{"password", 2, true}}
	if err := s.WriteCredential(context.Background(), updated, []Secret{next(v)}, 1); err != ErrStorage {
		t.Fatal(err)
	}
	got, err := s.ReadSecret(context.Background(), v.Ref)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal("partially rotated field", err)
	}
	count(t, s, "SELECT count(*) FROM Keys WHERE Status='retired'", 0)
}

func TestCredentialIgnoredWritesCannotPublishPartialAggregates(t *testing.T) {
	for _, table := range []string{"Keys", "KeyCopies", "SecretValues", "CredentialProfiles"} {
		t.Run(table, func(t *testing.T) {
			s, _ := database(t)
			c := credential()
			v := credentialSecret(s, &c, "password")
			exec(t, s, "CREATE TRIGGER ignore_write BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(IGNORE); END;")
			if err := s.WriteCredential(context.Background(), c, []Secret{v}, 0); err != ErrConflict {
				t.Fatal(err)
			}
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
			count(t, s, "SELECT count(*) FROM CredentialProfiles", 0)
			count(t, s, "SELECT count(*) FROM SecretValues", 0)
			count(t, s, "SELECT count(*) FROM KeyCopies", 0)
			count(t, s, "SELECT count(*) FROM Keys", 1)
		})
	}
}

func TestCredentialManifestCannotDropOrAdoptSecrets(t *testing.T) {
	for _, mode := range []string{"drop", "undeclared", "duplicate", "wrong-owner", "wrong-kind", "invalid-envelope", "skip-version", "presence-only", "nonempty-tombstone", "orphan", "missing", "stale-field", "new-without-value"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := database(t)
			c := credential()
			v := credentialSecret(s, &c, "password")
			if err := s.WriteCredential(ctx, c, []Secret{v}, 0); err != nil {
				t.Fatal(err)
			}
			c.RowVersion = 2
			c.Fields = []CredentialField{{"password", 2, true}}
			updates := []Secret{next(v)}
			want := ErrFormat
			switch mode {
			case "drop":
				c.Fields = nil
				updates = nil
			case "undeclared":
				updates[0].Ref.Field = "privateKey"
			case "duplicate":
				updates = append(updates, updates[0])
			case "wrong-owner":
				updates[0].Ref.OwnerID = uuid.NewString()
			case "wrong-kind":
				updates[0].Ref.OwnerKind = "node"
			case "invalid-envelope":
				updates[0].Copy.Signature = nil
			case "skip-version":
				c.Fields[0].Version = 3
			case "presence-only":
				c.Fields[0] = CredentialField{"password", 1, false}
				updates = nil
			case "nonempty-tombstone":
				c.Fields[0].Present = false
			case "orphan":
				exec(t, s, "INSERT INTO SecretValues SELECT OwnerKind,OwnerId,'orphan',DekId,DekVersion,Envelope,RowVersion FROM SecretValues")
				want = ErrConflict
			case "missing":
				exec(t, s, "DELETE FROM SecretValues")
				want = ErrConflict
			case "stale-field":
				exec(t, s, "UPDATE SecretValues SET RowVersion=8")
				want = ErrConflict
			case "new-without-value":
				c.Fields = []CredentialField{{"certificate", 1, false}, {"password", 1, true}}
				updates = nil
			}
			if err := s.WriteCredential(ctx, c, updates, 1); err != want {
				t.Fatalf("want %v got %v", want, err)
			}
			count(t, s, "SELECT RowVersion FROM CredentialProfiles", 1)
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
		})
	}
}

func TestCredentialConcurrentEditsAndPagination(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	c := credential()
	if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	c.RowVersion = 2
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() { results <- s.WriteCredential(ctx, c, nil, 1) })
	}
	group.Wait()
	close(results)
	ok, conflict := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if err == ErrConflict {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal(ok, conflict)
	}
	for range 3 {
		if err := s.WriteCredential(ctx, credential(), nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListCredentials(ctx, "", 2)
	if err != nil || len(page) != 2 || page[0].ID >= page[1].ID {
		t.Fatal(page, err)
	}
	next, err := s.ListCredentials(ctx, page[1].ID, 2)
	if err != nil || len(next) != 2 || next[0].ID <= page[1].ID {
		t.Fatal(next, err)
	}
	empty, err := s.ListCredentials(ctx, next[1].ID, 2)
	if err != nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=9223372036854775807")
	c.RowVersion = 3
	if err := s.WriteCredential(ctx, c, nil, 2); err != ErrConflict {
		t.Fatal(err)
	}
	count(t, s, "SELECT max(RowVersion) FROM CredentialProfiles", 2)
}

func TestCredentialSchemaUpgradePreservesCiphertext(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	v := record(s)
	if err := s.WriteSecret(ctx, v, 0); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "DROP TABLE LocalState; DROP TABLE Nodes; DROP TABLE TunnelConfigs; DROP TABLE CredentialProfiles; UPDATE WorkspaceMeta SET SchemaVersion=1;")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenSQLite(ctx, path, identity(), false); err != ErrIdentity || other != nil {
		t.Fatal(err)
	}
	opened, err := OpenSQLite(ctx, path, s.identity, false)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	count(t, opened, "SELECT SchemaVersion FROM WorkspaceMeta", SchemaVersion)
	got, err := opened.ReadSecret(ctx, v.Ref)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal("changed pre-migration ciphertext", err)
	}
	c := credential()
	c.ID = v.Ref.OwnerID
	if err := opened.WriteCredential(ctx, c, nil, 0); err != ErrConflict {
		t.Fatal("adopted standalone secret", err)
	}
	count(t, opened, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
}

func TestCredentialSchemaMigrationDoesNotRepairOrPartiallyPublish(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	exec(t, s, "DROP TABLE LocalState; UPDATE WorkspaceMeta SET SchemaVersion=1")
	s.Close()
	if opened, err := OpenSQLite(ctx, path, s.identity, false); err != ErrStorage || opened != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var version int
	if err := raw.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&version); err != nil || version != 1 {
		t.Fatal(version, err)
	}
}

func TestCredentialNamesRemainUniquePerOwnerAndCollisionRollsBackFields(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	first := credential()
	second := credential()
	firstSecret := credentialSecret(s, &first, "password")
	if err := s.WriteCredential(ctx, first, []Secret{firstSecret}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCredential(ctx, second, nil, 0); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.Name = second.Name
	changed.RowVersion = 2
	changed.Fields = []CredentialField{{"password", 2, true}}
	if err := s.WriteCredential(ctx, changed, []Secret{next(firstSecret)}, 1); err != ErrConflict {
		t.Fatal(err)
	}
	got, err := s.ReadSecret(ctx, firstSecret.Ref)
	if err != nil || !reflect.DeepEqual(got, firstSecret) {
		t.Fatal("name conflict rotated a field", err)
	}
	personal := credential()
	personal.Name = second.Name
	personal.OwnerUserID = uuid.NewString()
	if err := s.WriteCredential(ctx, personal, nil, 0); err != nil {
		t.Fatal(err)
	}
	duplicate := personal
	duplicate.ID = uuid.NewString()
	if err := s.WriteCredential(ctx, duplicate, nil, 0); err != ErrConflict {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 3)
}

func TestCredentialMigrationRollsBackDDLWhenVersionUpdateFails(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	exec(t, s, "DROP TABLE LocalState; DROP TABLE Nodes; DROP TABLE TunnelConfigs; DROP TABLE CredentialProfiles; UPDATE WorkspaceMeta SET SchemaVersion=1; CREATE TRIGGER fail BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE(ABORT,'failure'); END;")
	s.Close()
	if opened, err := OpenSQLite(ctx, path, s.identity, false); err != ErrStorage || opened != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var count int
	if err := raw.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='CredentialProfiles'").Scan(&count); err != nil || count != 0 {
		t.Fatal("partially published migration", count, err)
	}
	if err := raw.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestCredentialMetadataPreventsInitializationMarkerReplay(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	if err := s.WriteCredential(ctx, credential(), nil, 0); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=0")
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal("accepted old initialization marker over metadata", err)
	}
}

func TestCredentialValidationAndStorageFailures(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	valid := credential()
	for _, mutate := range []func(*Credential){
		func(c *Credential) { c.ID = "invalid" }, func(c *Credential) { c.OwnerUserID = "invalid" }, func(c *Credential) { c.Name = " " }, func(c *Credential) { c.Username = "\x00" }, func(c *Credential) { c.Domain = string([]byte{255}) }, func(c *Credential) { c.Name = strings.Repeat("x", 1025) }, func(c *Credential) { c.RowVersion = 0 }, func(c *Credential) { c.Seal = nil }, func(c *Credential) { c.Protocol = "ftp" }, func(c *Credential) { c.Kind = "unknown" }, func(c *Credential) { c.Provider = "unknown" }, func(c *Credential) { c.Kind = "sshKey"; c.Protocol = "rdp" }, func(c *Credential) { c.BitwardenItemID = "local-cannot-reference-remote" }, func(c *Credential) { c.Provider = "bitwarden" }, func(c *Credential) { c.Fields = []CredentialField{{"token", 1, true}} }, func(c *Credential) { c.Fields = []CredentialField{{"password", 0, true}} }, func(c *Credential) { c.Fields = []CredentialField{{"password", math.MaxUint64, true}} }, func(c *Credential) { c.Fields = []CredentialField{{"password", 1, true}, {"password", 1, true}} }, func(c *Credential) { c.Fields = []CredentialField{{"password", 1, true}}; c.Deleted = true }, func(c *Credential) { c.Fields = []CredentialField{{"passphrase", 1, true}} }, func(c *Credential) {
			c.Provider = "bitwarden"
			c.BitwardenItemID = "id"
			c.Fields = []CredentialField{{"password", 1, true}}
		},
	} {
		c := valid
		mutate(&c)
		if err := s.WriteCredential(ctx, c, nil, 0); err != ErrFormat {
			t.Fatal("accepted invalid aggregate", err)
		}
	}
	remote := credential()
	remote.Provider = "bitwarden"
	remote.BitwardenItemID = "item"
	remote.OwnerUserID = uuid.NewString()
	if err := s.WriteCredential(ctx, remote, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadCredential(ctx, "bad"); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ReadCredential(ctx, uuid.NewString()); err != ErrMissing {
		t.Fatal(err)
	}
	for _, limit := range []int{0, 129} {
		if _, err := s.ListCredentials(ctx, "", limit); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := s.ListCredentials(ctx, "bad", 1); err != ErrFormat {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ReadCredential(cancelled, remote.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.ListCredentials(cancelled, "", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.WriteCredential(cancelled, valid, nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE CredentialProfiles SET SecretManifest='[{\"field\":\"password\",\"version\":1,\"present\":true,\"extra\":false}]'")
	if _, err := s.ReadCredential(ctx, remote.ID); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ListCredentials(ctx, "", 1); err != ErrFormat {
		t.Fatal(err)
	}
	exec(t, s, "DROP TABLE CredentialProfiles")
	if _, err := s.ReadCredential(ctx, remote.ID); err != ErrStorage {
		t.Fatal(err)
	}
	if _, err := s.ListCredentials(ctx, "", 1); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.WriteCredential(ctx, valid, nil, 0); err != ErrStorage {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.ReadCredential(ctx, remote.ID); err != ErrClosed {
		t.Fatal(err)
	}
	if _, err := s.ListCredentials(ctx, "", 1); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteCredential(ctx, valid, nil, 0); err != ErrClosed {
		t.Fatal(err)
	}
}
