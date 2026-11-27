//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

func reserveDB(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func registerTestDB(t *testing.T, path string, key []byte) *Database {
	t.Helper()
	registration, err := Register(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := registration.Close(); err != nil {
			t.Error(err)
		}
	})
	return registration
}

func openTestDB(t *testing.T, registration *Database) *sql.DB {
	t.Helper()
	uri := registration.URI()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	return db
}

func execSQL(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func requireSQL(t *testing.T, db *sql.DB, statement, want string) {
	t.Helper()
	var got string
	if err := db.QueryRow(statement).Scan(&got); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	if got != want {
		t.Fatalf("%s: got %q, want %q", statement, got, want)
	}
}

func scanCiphertext(t *testing.T, path string, forbidden ...string) []byte {
	t.Helper()
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%PageSize != 0 {
		t.Fatalf("%s: unexpected on-disk length %d", filepath.Base(path), len(ciphertext))
	}
	for _, text := range forbidden {
		if bytes.Contains(ciphertext, []byte(text)) {
			t.Fatalf("%s contains plaintext", filepath.Base(path))
		}
	}
	return ciphertext
}

func TestSQLiteEncryptedJournals(t *testing.T) {
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			const firstMarker = "queryable-sensitive-original-2d230"
			const nextMarker = "queryable-sensitive-update-c9dd3"
			first := strings.Repeat(firstMarker, 800)
			next := strings.Repeat(nextMarker, 1200)
			path := reserveDB(t, "vault #%.sqlite")
			key := bytes.Repeat([]byte{0x42}, 32)
			registration := registerTestDB(t, path, key)
			db := openTestDB(t, registration)
			requireSQL(t, db, "PRAGMA page_size", "4096")
			requireSQL(t, db, "PRAGMA locking_mode", "exclusive")
			requireSQL(t, db, "PRAGMA synchronous", "2")
			requireSQL(t, db, "PRAGMA temp_store", "2")
			requireSQL(t, db, "PRAGMA mmap_size=65536", "0")
			requireSQL(t, db, "PRAGMA journal_mode="+mode, mode)
			execSQL(t, db, "PRAGMA cache_size=4")
			execSQL(t, db, "CREATE TABLE metadata (id INTEGER PRIMARY KEY, value TEXT)")
			execSQL(t, db, "INSERT INTO metadata VALUES (1, ?)", first)

			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.Exec("UPDATE metadata SET value=? WHERE id=1", next); err != nil {
				t.Fatal(err)
			}
			if mode == "delete" {
				scanCiphertext(t, path+"-journal", firstMarker, nextMarker)
			} else {
				scanCiphertext(t, path+"-wal", firstMarker, nextMarker, "SQLite format 3")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			requireSQL(t, db, "SELECT value FROM metadata", first)
			execSQL(t, db, "UPDATE metadata SET value=?", next)
			if mode == "wal" {
				scanCiphertext(t, path+"-wal", firstMarker, nextMarker)
				if _, err := os.Stat(path + "-shm"); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected WAL shared memory file: %v", err)
				}
			}
			if err := registration.Close(); !errors.Is(err, ErrBusy) {
				t.Fatalf("close active registration: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			scanCiphertext(t, path, firstMarker, nextMarker, "SQLite format 3", "CREATE TABLE")
			db = openTestDB(t, registration)
			requireSQL(t, db, "PRAGMA integrity_check", "ok")
			requireSQL(t, db, "SELECT value FROM metadata", next)
		})
	}
}

func TestSQLiteRequiresExactFileRegistration(t *testing.T) {
	path := reserveDB(t, "vault.sqlite")
	other := reserveDB(t, "other.sqlite")
	key := make([]byte, 32)
	for _, invalid := range []struct {
		path string
		key  []byte
	}{{"relative.sqlite", key}, {path, key[:31]}, {filepath.Dir(path) + "/../" + filepath.Base(path), key}} {
		if _, err := Register(invalid.path, invalid.key); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid registration: %v", err)
		}
	}
	registration := registerTestDB(t, path, key)
	if _, err := Register(path, key); !errors.Is(err, ErrBusy) {
		t.Fatalf("duplicate registration: %v", err)
	}
	alias := filepath.Join(filepath.Dir(path), "hardlink.sqlite")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(alias, key); !errors.Is(err, ErrBusy) {
		t.Fatalf("duplicate registration through hard link: %v", err)
	}
	uri := registration.URI()
	q := uri.Query()
	if len(q.Get("whk")) != 32 || q.Get("vfs") != Name || strings.Contains(uri.String(), strings.Repeat("00", 32)) {
		t.Fatal("URI lacks the expected opaque key reference")
	}
	probe := func(connectionURI string) {
		t.Helper()
		db, err := sql.Open("sqlite", connectionURI)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec("CREATE TABLE probe (value TEXT)"); err == nil {
			t.Fatal("unexpected ability to write to the file")
		}
	}
	otherRegistration := registerTestDB(t, other, bytes.Repeat([]byte{1}, 32))
	otherURI := otherRegistration.URI()
	otherURI.RawQuery = uri.RawQuery
	probe(otherURI.String())

	db := openTestDB(t, registration)
	execSQL(t, db, "CREATE TABLE protected (value TEXT)")
	execSQL(t, db, "INSERT INTO protected VALUES ('unavailable-without-correct-page-key')")
	probe(uri.String())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registration.Close(); err != nil {
		t.Fatal(err)
	}
	probe(uri.String())
	q.Del("whk")
	uri.RawQuery = q.Encode()
	probe(uri.String())
	q.Del("vfs")
	uri.RawQuery = q.Encode()
	probe(uri.String())
	wrong := registerTestDB(t, path, bytes.Repeat([]byte{2}, 32))
	wrongURI := wrong.URI()
	probe(wrongURI.String())
	if err := wrong.Close(); err != nil {
		t.Fatal(err)
	}
	correct := registerTestDB(t, path, key)
	requireSQL(t, openTestDB(t, correct), "SELECT value FROM protected", "unavailable-without-correct-page-key")
}

func TestSQLiteUsesCanonicalDirectory(t *testing.T) {
	path := reserveDB(t, "vault.sqlite")
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(path), alias); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	registration := registerTestDB(t, filepath.Join(alias, filepath.Base(path)), make([]byte, 32))
	db := openTestDB(t, registration)
	execSQL(t, db, "CREATE TABLE protected (value TEXT)")

	link := filepath.Join(alias, "link.sqlite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(link, make([]byte, 32)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("database registration accepted a symlink: %v", err)
	}
}

func TestSQLiteIgnoresTornTrailingCiphertext(t *testing.T) {
	path := reserveDB(t, "tail.sqlite")
	registration := registerTestDB(t, path, bytes.Repeat([]byte{7}, 32))
	db := openTestDB(t, registration)
	execSQL(t, db, "CREATE TABLE item (value TEXT)")
	execSQL(t, db, "INSERT INTO item VALUES ('durable')")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte{5, 19, 87, 2, 120, 248, 7})
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	db = openTestDB(t, registration)
	requireSQL(t, db, "SELECT value FROM item", "durable")
	requireSQL(t, db, "PRAGMA integrity_check", "ok")
}

func TestSQLiteRejectsReducedDurabilitySettings(t *testing.T) {
	path := reserveDB(t, "protected.sqlite")
	db := openTestDB(t, registerTestDB(t, path, make([]byte, 32)))
	for _, setting := range []string{
		"journal_mode=OFF", "journal_mode=MEMORY", "journal_mode=TRUNCATE",
		"locking_mode=NORMAL", "synchronous=NORMAL", "page_size=8192",
	} {
		if _, err := db.Exec("PRAGMA " + setting); err == nil {
			t.Fatalf("unsafe SQLite setting was accepted: %s", setting)
		}
	}
	execSQL(t, db, "CREATE TABLE item (value TEXT)")
	requireSQL(t, db, "PRAGMA journal_mode", "delete")
	requireSQL(t, db, "PRAGMA locking_mode", "exclusive")
	requireSQL(t, db, "PRAGMA synchronous", "2")
	requireSQL(t, db, "PRAGMA page_size", "4096")
}

func TestSQLiteReadsReferenceAdiantumDatabase(t *testing.T) {
	// Published two-page fixture from ncruces/go-sqlite3 v0.32.0,
	// vfs/adiantum/testdata/test.db (MIT, see testdata/LICENSE.ncruces).
	// The Argon2id settings here are for that fixture's public passphrase.
	ciphertext, err := os.ReadFile("testdata/adiantum-reference.bin")
	if err != nil {
		t.Fatal(err)
	}
	path := reserveDB(t, "reference.sqlite")
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte("correct+horse+battery+staple"),
		[]byte("github.com/ncruces/go-sqlite3/vfs/adiantum"), 3, 64*1024, 4, 32)
	db := openTestDB(t, registerTestDB(t, path, key))
	requireSQL(t, db, "PRAGMA user_version", strconv.Itoa(0xBADDB))
	requireSQL(t, db, "PRAGMA page_count", "2")
	requireSQL(t, db, "PRAGMA integrity_check", "ok")
}

func TestSQLiteVacuumIntoEncryptedDestination(t *testing.T) {
	for _, source := range []string{"plain", "encrypted"} {
		t.Run(source, func(t *testing.T) {
			const record = "vault-metadata-for-conversion"
			src := reserveDB(t, "source.sqlite")
			var db *sql.DB
			switch source {
			case "plain":
				var err error
				db, err = sql.Open("sqlite", src)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
			case "encrypted":
				db = openTestDB(t, registerTestDB(t, src, bytes.Repeat([]byte{1}, 32)))
			}
			execSQL(t, db, "PRAGMA page_size=4096")
			execSQL(t, db, "CREATE TABLE item (value TEXT)")
			execSQL(t, db, "INSERT INTO item VALUES (?)", record)
			dest := reserveDB(t, "destination #%.sqlite")
			registration := registerTestDB(t, dest, bytes.Repeat([]byte{2}, 32))
			uri := registration.URI()
			execSQL(t, db, "VACUUM INTO ?", uri.String())
			scanCiphertext(t, dest, record, "SQLite format 3")
			target := openTestDB(t, registration)
			requireSQL(t, target, "PRAGMA integrity_check", "ok")
			requireSQL(t, target, "SELECT value FROM item", record)
			requireSQL(t, db, "SELECT value FROM item", record)
		})
	}
}

func TestSQLiteConcurrentRegistrationsSurviveGC(t *testing.T) {
	for worker := range 4 {
		t.Run(strconv.Itoa(worker), func(t *testing.T) {
			t.Parallel()
			path := reserveDB(t, "vault.sqlite")
			key := bytes.Repeat([]byte{byte(worker + 1)}, 32)
			db := openTestDB(t, registerTestDB(t, path, key))
			requireSQL(t, db, "PRAGMA journal_mode=wal", "wal")
			execSQL(t, db, "CREATE TABLE item (value TEXT)")
			for round := range 8 {
				if worker == 0 {
					runtime.GC()
				}
				value := strings.Repeat(t.Name()+"/"+strconv.Itoa(round), 500)
				execSQL(t, db, "INSERT INTO item VALUES (?)", value)
				requireSQL(t, db, "SELECT value FROM item ORDER BY rowid DESC LIMIT 1", value)
			}
			requireSQL(t, db, "PRAGMA integrity_check", "ok")
		})
	}
}
