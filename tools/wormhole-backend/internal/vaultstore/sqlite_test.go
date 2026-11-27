package vaultstore

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSQLiteEncryptedOpenKeepsIdentityAndReleasesRegistration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault #%.db")
	id := identity()
	root := bytes.Repeat([]byte{0x72}, 32)
	if s, err := OpenSQLiteEncrypted(ctx, path, id, true, root[:31]); s != nil || err != ErrFormat {
		t.Fatalf("invalid root accepted: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid root reserved a file")
	}
	s, err := OpenSQLiteEncrypted(ctx, path, id, true, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	count(t, s, "PRAGMA foreign_keys", 1)
	if competing, err := OpenSQLiteEncrypted(ctx, path, id, false, root); competing != nil || err != ErrBusy {
		t.Fatalf("competing encrypted open: %v", err)
	}
	stage := filepath.Join(filepath.Dir(path), "staged.db")
	if target, err := s.BeginRootRotation(ctx, stage); target != nil || err != ErrFormat {
		t.Fatalf("ordinary rotation of encrypted database: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("ordinary rotation created a staging file")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.encrypted != nil {
		t.Fatal("closed store retained its page-key registration")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongID := id
	wrongID.FileID = uuid.NewString()
	if s, err := OpenSQLiteEncrypted(ctx, path, wrongID, false, root); s != nil || err != ErrIdentity {
		t.Fatalf("wrong file identity accepted: %v", err)
	}
	if s, err := OpenSQLiteEncrypted(ctx, path, id, false, bytes.Repeat([]byte{0x73}, 32)); s != nil || err != ErrStorage {
		t.Fatalf("wrong root accepted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed open changed the database: %v", err)
	}
	reopened, err := OpenSQLiteEncrypted(ctx, path, id, false, root)
	if err != nil {
		t.Fatal("failure retained registration", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteRotationConvertsNonDefaultPageSize(t *testing.T) {
	for _, journal := range []string{"delete", "wal"} {
		t.Run(journal, func(t *testing.T) {
			ctx := context.Background()
			source, path := database(t)
			exec(t, source, "PRAGMA page_size=8192; VACUUM;")
			exec(t, source, "PRAGMA journal_mode="+journal)
			count(t, source, "PRAGMA page_size", 8192)
			dest := filepath.Join(filepath.Dir(path), "encrypted.db")
			invalid := bytes.Repeat([]byte{9}, 31)
			if _, err := source.BeginEncryptedRootRotation(ctx, dest, invalid); err != ErrFormat || !bytes.Equal(invalid, make([]byte, 31)) {
				t.Fatalf("invalid page key was not refused and wiped: %v", err)
			}
			key := bytes.Repeat([]byte{7}, 32)
			target, err := source.BeginEncryptedRootRotation(ctx, dest, key)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if !bytes.Equal(key, make([]byte, 32)) {
				t.Fatal("destination key remained in caller memory")
			}
			count(t, source, "PRAGMA page_size", 8192)
			count(t, target.store, "PRAGMA page_size", 4096)
		})
	}
}

func TestSQLiteSettlesEncryptedSourceWAL(t *testing.T) {
	ctx := context.Background()
	id := identity()
	root := bytes.Repeat([]byte{0x46}, 32)
	path := filepath.Join(t.TempDir(), "wal-source.db")
	s, err := OpenSQLiteEncrypted(ctx, path, id, true, root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exec(t, s, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
	value := record(s)
	if err := s.WriteSecret(ctx, value, 0); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("fixture did not write a pending WAL: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.SettleRootRotationSource(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recovery touched the source: %v", err)
	}
	if err := s.SettleRootRotationSource(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.SettleRootRotationSource(ctx); err != ErrClosed {
		t.Fatalf("closed source was reusable: %v", err)
	}
	if _, err := os.Lstat(path + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("settled source retained a WAL: %v", err)
	}
	reopened, err := OpenSQLiteEncrypted(ctx, path, id, false, root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.ReadSecret(ctx, value.Ref); err != nil || !reflect.DeepEqual(got, value) {
		t.Fatal("checkpoint lost a committed WAL record", err)
	}
}

func identity() Identity {
	return Identity{uuid.NewString(), uuid.NewString(), KeyRef{uuid.NewString(), 1}}
}

func database(t *testing.T) (*SQLite, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault space #?.db")
	// '?' is not a Windows filename character; '#' and spaces exercise URI escaping.
	path = strings.ReplaceAll(path, "?", "")
	s, err := OpenSQLite(context.Background(), path, identity(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, path
}

func record(s *SQLite) Secret {
	key := KeyRef{uuid.NewString(), 1}
	envelope := func(k KeyRef, n int) vault.Envelope {
		return vault.Envelope{FormatVersion: 1, SuiteID: 1, KeyID: k.ID, KeyVersion: k.Version, Nonce: make([]byte, 12), Ciphertext: make([]byte, n)}
	}
	return Secret{Ref: SecretRef{"credential", uuid.NewString(), "password"}, DEK: key, Envelope: envelope(key, 32), RowVersion: 1, Copy: KeyCopy{Key: key, Holder: s.identity.Root, Issuer: s.identity.Root, Envelope: envelope(s.identity.Root, 48), Signature: make([]byte, 32)}}
}

func next(value Secret) Secret {
	value.RowVersion++
	value.DEK.Version++
	value.Envelope.KeyVersion++
	value.Copy.Key = value.DEK
	return value
}

func exec(t *testing.T, s *SQLite, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *SQLite, query string, want int) {
	t.Helper()
	var got int
	if err := s.db.QueryRowContext(context.Background(), query).Scan(&got); err != nil || got != want {
		t.Fatalf("count=%d want=%d err=%v", got, want, err)
	}
}

func TestSQLiteChecksImportForeignKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	if err := s.CheckForeignKeys(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.CheckForeignKeys(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("a cancelled integrity check was not interrupted", err)
	}
	exec(t, s, `PRAGMA foreign_keys=OFF;`)
	exec(t, s, `UPDATE Keys SET CertSignerKeyId=?, CertSignerKeyVersion=1 WHERE KeyId=?;`, uuid.NewString(), s.identity.Root.ID)
	exec(t, s, `PRAGMA foreign_keys=ON;`)
	if err := s.CheckForeignKeys(ctx); err != ErrFormat {
		t.Fatal("a legacy foreign-key violation was accepted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckForeignKeys(ctx); err != ErrClosed {
		t.Fatal("a closed store accepted an integrity check", err)
	}
}

func TestSQLiteRoundTripVersioningAndOwnership(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	value := record(s)
	if s.Identity() != s.identity {
		t.Fatal("identity changed")
	}
	if _, err := s.ReadSecret(ctx, value.Ref); err != ErrMissing {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, value, 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadSecret(ctx, value.Ref)
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatalf("round trip mismatch: %v", err)
	}
	if err := s.WriteSecret(ctx, value, 0); err != ErrConflict {
		t.Fatal(err)
	}
	updated := next(value)
	if err := s.WriteSecret(ctx, updated, 1); err != nil {
		t.Fatal(err)
	}
	count(t, s, "SELECT count(*) FROM Keys WHERE Kind='dek' AND Status='retired'", 1)
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 2)
	other := record(s)
	other.Ref = value.Ref
	other.Ref.Field = "privateKey"
	if err := s.WriteSecret(ctx, other, 0); err != nil {
		t.Fatal(err)
	}
	count(t, s, "SELECT count(*) FROM Keys WHERE Kind='dek' AND Status='active'", 2)
	count(t, s, "PRAGMA foreign_keys", 1)
	count(t, s, "PRAGMA synchronous", 2)
	count(t, s, "PRAGMA temp_store", 2)
	if competing, err := OpenSQLite(ctx, path, s.identity, false); err != ErrBusy {
		if competing != nil {
			competing.Close()
		}
		t.Fatalf("second owner: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadSecret(ctx, value.Ref); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, value, 0); err != ErrClosed {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, path, s.identity, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err = reopened.ReadSecret(ctx, value.Ref)
	if err != nil || !reflect.DeepEqual(got, updated) {
		t.Fatalf("reopen mismatch: %v", err)
	}
}

func TestSQLiteOpenFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	id := s.Identity()
	if _, err := OpenSQLite(ctx, path, id, true); err != ErrConflict {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, "", id, true); err != ErrStorage {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, path, Identity{}, false); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "absent"), id, false); err != ErrMissing {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, t.TempDir(), id, false); err != ErrStorage {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "absent", "db"), id, true); err != ErrStorage {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := OpenSQLite(cancelled, path, id, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s.Close()
	wrong := id
	wrong.FileID = uuid.NewString()
	if _, err := OpenSQLite(ctx, path, wrong, false); err != ErrIdentity {
		t.Fatal(err)
	}
	s, err := OpenSQLite(ctx, path, id, false)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET SchemaVersion=999")
	s.Close()
	if _, err := OpenSQLite(ctx, path, id, false); err != ErrVersion {
		t.Fatal(err)
	}
	broken := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(broken, []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, broken, id, false); err != ErrStorage {
		t.Fatal(err)
	}
}

func TestSQLiteCASAndAtomicFailures(t *testing.T) {
	ctx := context.Background()
	for _, trigger := range []string{
		"BEFORE INSERT ON Keys", "BEFORE INSERT ON KeyCopies", "BEFORE INSERT ON SecretValues", "BEFORE UPDATE ON WorkspaceMeta", "BEFORE UPDATE ON Keys",
	} {
		t.Run(trigger, func(t *testing.T) {
			s, _ := database(t)
			value := record(s)
			if err := s.WriteSecret(ctx, value, 0); err != nil {
				t.Fatal(err)
			}
			exec(t, s, "CREATE TRIGGER fail_write "+trigger+" BEGIN SELECT RAISE(ABORT, 'private database diagnostic'); END")
			if err := s.WriteSecret(ctx, next(value), 1); err != ErrStorage {
				t.Fatal(err)
			}
			got, err := s.ReadSecret(ctx, value.Ref)
			if err != nil || !reflect.DeepEqual(got, value) {
				t.Fatalf("partial mutation: %v", err)
			}
			count(t, s, "SELECT count(*) FROM Keys", 2)
			count(t, s, "SELECT count(*) FROM KeyCopies", 1)
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
		})
	}
	s, _ := database(t)
	value := record(s)
	if err := s.WriteSecret(ctx, next(value), 1); err != ErrConflict {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, value, 0); err != nil {
		t.Fatal(err)
	}
	wrong := next(value)
	wrong.DEK.ID = uuid.NewString()
	wrong.Envelope.KeyID = wrong.DEK.ID
	wrong.Copy.Key = wrong.DEK
	if err := s.WriteSecret(ctx, wrong, 1); err != ErrConflict {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.WriteSecret(ctx, next(value), 1) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if err != ErrConflict {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners: %d", wins)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=?", int64(math.MaxInt64))
	if err := s.WriteSecret(ctx, next(next(value)), 2); err != ErrConflict {
		t.Fatal(err)
	}
	count(t, s, "SELECT RowVersion FROM SecretValues", 2)
}

func TestSQLiteRejectsCorruptOrOversizedRecords(t *testing.T) {
	for _, query := range []string{
		"UPDATE SecretValues SET Envelope=x'7b'",
		"UPDATE SecretValues SET Envelope=zeroblob(6291457)",
		"UPDATE SecretValues SET Envelope='{}'",
		"UPDATE KeyCopies SET Enc=zeroblob(10000000)",
		"UPDATE KeyCopies SET Ciphertext=zeroblob(10000000)",
		"UPDATE KeyCopies SET Signature=zeroblob(10000000)",
		"UPDATE KeyCopies SET Suite=2",
	} {
		t.Run(query, func(t *testing.T) {
			s, _ := database(t)
			value := record(s)
			if err := s.WriteSecret(context.Background(), value, 0); err != nil {
				t.Fatal(err)
			}
			exec(t, s, query)
			if _, err := s.ReadSecret(context.Background(), value.Ref); err != ErrFormat {
				t.Fatal(err)
			}
		})
	}
	s, _ := database(t)
	value := record(s)
	if _, err := s.ReadSecret(context.Background(), SecretRef{}); err != ErrFormat {
		t.Fatal(err)
	}
	if err := s.WriteSecret(context.Background(), Secret{}, 0); err != ErrFormat {
		t.Fatal(err)
	}
	if err := s.WriteSecret(context.Background(), value, math.MaxInt64); err != ErrFormat {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ReadSecret(ctx, value.Ref); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, value, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Foreign keys must reject an orphan even through the owner's connection.
	if _, err := s.db.ExecContext(context.Background(), "INSERT INTO SecretValues VALUES('credential',?,'password',?,1,x'00',1)", uuid.NewString(), uuid.NewString()); err == nil {
		t.Fatal("orphan accepted")
	}
	exec(t, s, "DROP TABLE SecretValues")
	if _, err := s.ReadSecret(context.Background(), value.Ref); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.WriteSecret(context.Background(), value, 0); err != ErrStorage {
		t.Fatal(err)
	}
}

func TestRecordValidation(t *testing.T) {
	s, _ := database(t)
	value := record(s)
	for _, kind := range []string{"credential", "node", "tunnel", "slot-value"} {
		ref := value.Ref
		ref.OwnerKind = kind
		if !ref.Valid() {
			t.Fatal(kind)
		}
	}
	for _, ref := range []SecretRef{{"unknown", uuid.NewString(), "password"}, {"credential", "not uuid", "x"}, {"node", uuid.NewString(), ""}, {"node", uuid.NewString(), strings.Repeat("x", 129)}, {"node", uuid.NewString(), "\xff"}, {"node", uuid.NewString(), "a\x00b"}} {
		if ref.Valid() {
			t.Fatal("invalid reference accepted")
		}
	}
	if (KeyRef{uuid.Nil.String(), 1}).Valid() || (KeyRef{uuid.NewString(), 0}).Valid() {
		t.Fatal("invalid key accepted")
	}
	value.DEK = s.identity.Root
	value.DEK.Version++
	value.Copy.Key = value.DEK
	value.Envelope.KeyID = value.DEK.ID
	value.Envelope.KeyVersion = value.DEK.Version
	if value.valid(s.identity) {
		t.Fatal("root reused as DEK")
	}
	if storeError(context.DeadlineExceeded) != context.DeadlineExceeded {
		t.Fatal("deadline lost")
	}
}

func TestSQLiteRetirementRejectsCorruptKeyState(t *testing.T) {
	for _, update := range []string{
		"UPDATE Keys SET RowVersion=9223372036854775807 WHERE Kind='dek'",
		"UPDATE Keys SET Status='retired' WHERE Kind='dek'",
		"UPDATE Keys SET Kind='device' WHERE Kind='dek'",
	} {
		t.Run(update, func(t *testing.T) {
			s, _ := database(t)
			value := record(s)
			ctx := context.Background()
			if err := s.WriteSecret(ctx, value, 0); err != nil {
				t.Fatal(err)
			}
			exec(t, s, update)
			if err := s.WriteSecret(ctx, next(value), 1); err != ErrConflict {
				t.Fatal(err)
			}
			count(t, s, "SELECT count(*) FROM Keys", 2)
			count(t, s, "SELECT RowVersion FROM SecretValues", 1)
			count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
		})
	}
}

func TestSQLiteLostConnectionCannotReopenImplicitly(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	id := identity()
	s, err := OpenSQLite(ctx, path, id, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	value := record(s)
	if err := s.WriteSecret(ctx, value, 0); err != nil {
		t.Fatal(err)
	}
	// Simulate a driver invalidating the pinned connection. A pooled DB handle
	// would acquire a fresh connection here and silently regain storage access.
	if err := s.db.Raw(func(any) error { return driver.ErrBadConn }); !errors.Is(err, driver.ErrBadConn) {
		t.Fatal(err)
	}
	if _, err := s.ReadSecret(ctx, value.Ref); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, next(value), 1); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.Close(); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, path, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ReadSecret(ctx, value.Ref)
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatalf("state changed after lost connection: %v", err)
	}
}

func TestSQLiteInitializationRequiresPristineKeyGraph(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	if err := s.ValidateInitialization(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.ValidateInitialization(cancelled); err != context.Canceled {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, record(s), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal(err)
	}
	s.Close()
	if err := s.ValidateInitialization(ctx); err != ErrClosed {
		t.Fatal(err)
	}
}
