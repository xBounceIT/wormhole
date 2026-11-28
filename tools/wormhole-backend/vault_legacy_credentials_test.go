package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"golang.org/x/crypto/ssh"
)

func legacyVaultSQL(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatal(err)
	}
}

func legacyVaultProfile(t *testing.T, db *sql.DB, id string, kind int) {
	t.Helper()
	legacyVaultSQL(t, db, `INSERT INTO CredentialProfiles(Id,Name,Kind,Protocol,CreatedAt,Username) VALUES(?,?,?,0,'2026-10-30T12:00:00Z','alice')`, id, "profile-"+id, kind)
}

func legacyVaultSecrets(t *testing.T, db *sql.DB) {
	t.Helper()
	legacyVaultSQL(t, db, `CREATE TABLE IF NOT EXISTS CredentialSecrets(Id TEXT PRIMARY KEY,Secret TEXT,Encoding TEXT,UpdatedAt TEXT)`)
}

func TestVaultLegacyCredentialTransferAndWipe(t *testing.T) {
	db, path := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for i, id := range ids {
		kind := 0
		if i == 3 {
			kind = 1
		}
		legacyVaultProfile(t, db, id, kind)
	}
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=1,BitwardenItemId='remote-item' WHERE Id=?`, ids[4])
	key := testSshPrivateKey(t, "")
	signer, err := parseSSHSigner(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	certificate := ssh.MarshalAuthorizedKey(cert)
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SshCertificate=?,PrivateKeyFileName='key',SshCertificateFileName='key-cert.pub' WHERE Id=?`, string(certificate), ids[3])
	expected := map[string]map[string][]byte{
		ids[0]: {"password": []byte("migration-fixture-secret-only")}, ids[1]: {"password": {}}, ids[2]: {},
		ids[3]: {"passphrase": []byte("migration-fixture-passphrase"), "privateKey": key, "certificate": certificate}, ids[4]: {},
	}
	for _, i := range []int{0, 1, 3} {
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,'fixture','now')`, ids[i], fmt.Sprint(i))
	}
	var borrowed [][]byte
	readers := legacyVaultCredentialReaders{
		secret: func(id, encoded, encoding string, userData ...string) ([]byte, error) {
			if encoding != "fixture" || len(userData) != 1 || userData[0] != "source-user-data" {
				t.Fatal("source context lost")
			}
			field := "password"
			if id == ids[3] {
				field = "passphrase"
			}
			value := bytes.Clone(expected[id][field])
			borrowed = append(borrowed, value)
			return value, nil
		},
		privateKey: func(p string) ([]byte, error) {
			if p != credentialPrivateKeyPath(path, ids[3]) {
				t.Fatal("wrong key path")
			}
			value := bytes.Clone(key)
			borrowed = append(borrowed, value)
			return value, nil
		},
	}
	seen := map[string]bool{}
	err = readLegacyVaultCredentials(resolverCaptureReader{ctx, db}, path, "source-user-data", readers, func(record legacyVaultCredential, changes []localvault.SecretChange) error {
		if record.CreatedAt != "2026-10-30T12:00:00Z" {
			t.Fatal("source provenance lost")
		}
		actual := map[string][]byte{}
		for _, c := range changes {
			actual[c.Field] = c.Value
			borrowed = append(borrowed, c.Value)
		}
		if !reflect.DeepEqual(actual, expected[record.Metadata.ID]) {
			t.Fatal("field values or presence changed")
		}
		seen[record.Metadata.ID] = true
		_, err := h.owner.ImportCredential(ctx, record.Metadata, record.CreatedAt, changes)
		return err
	})
	if err != nil || len(seen) != 5 {
		t.Fatalf("transfer failed: %v, %d", err, len(seen))
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("borrowed plaintext retained")
		}
	}
	for id, fields := range expected {
		stored, err := h.owner.ReadCredential(ctx, id, 1)
		if err != nil || stored.CreatedAt != "2026-10-30T12:00:00Z" {
			t.Fatal("source provenance was not persisted", err)
		}
		for field, want := range fields {
			if err := h.owner.WithCredentialSecret(ctx, id, field, 1, func(value []byte) error {
				if !bytes.Equal(value, want) {
					t.Fatal("sealed value changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(h.databasePath + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, expected[ids[0]]["password"]) || bytes.Contains(data, key) {
			t.Fatal("plaintext persisted")
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM CredentialSecrets`).Scan(&n); err != nil || n != 3 {
		t.Fatal("source modified", err, n)
	}
}

func TestVaultLegacyCredentialFailuresWipe(t *testing.T) {
	for _, mode := range []string{"secret-error", "secret-oversize", "key-error", "key-empty", "key-oversize", "sink-error", "cancel-decrypt", "cancel-sink"} {
		t.Run(mode, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := uuid.NewString()
			legacyVaultProfile(t, db, id, 1)
			legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, id)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secret := []byte("temporary-passphrase")
			key := []byte("temporary-key")
			if mode == "secret-oversize" {
				secret = bytes.Repeat([]byte{'x'}, maxStoredCredentialBytes+1)
			}
			if mode == "key-oversize" {
				key = bytes.Repeat([]byte{'x'}, maxSshPrivateKeyBytes+1)
			}
			if mode == "key-empty" {
				key = nil
			}
			sentinel := errors.New("sensitive source detail")
			keyCalled, sinkCalled := false, false
			readers := legacyVaultCredentialReaders{
				secret: func(string, string, string, ...string) ([]byte, error) {
					if mode == "cancel-decrypt" {
						cancel()
					}
					if mode == "secret-error" {
						return secret, sentinel
					}
					return secret, nil
				},
				privateKey: func(string) ([]byte, error) {
					keyCalled = true
					if mode == "key-error" {
						return key, sentinel
					}
					return key, nil
				},
			}
			err := readLegacyVaultCredentials(resolverCaptureReader{ctx, db}, path, "", readers, func(legacyVaultCredential, []localvault.SecretChange) error {
				sinkCalled = true
				if mode == "cancel-sink" {
					cancel()
					return nil
				}
				return sentinel
			})
			want := errVaultMigrationSource
			if mode == "sink-error" {
				want = sentinel
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v", err)
			}
			if sinkCalled != (mode == "sink-error" || mode == "cancel-sink") {
				t.Fatal("invalid record reached sink")
			}
			if mode == "cancel-decrypt" && keyCalled {
				t.Fatal("cancelled import decrypted the private key")
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) || (keyCalled && !bytes.Equal(key, make([]byte, len(key)))) {
				t.Fatal("error path retained plaintext")
			}
		})
	}
}

func TestVaultLegacyCredentialPagingAndMalformedSource(t *testing.T) {
	for _, mode := range []string{"valid", "boundary-case-duplicate", "empty-id", "invalid-id", "oversize-name", "nul-name", "bad-protocol", "bad-kind", "bad-provider", "provider-secret", "invalid-certificate", "password-certificate", "created-at-nul", "local-provider-data", "pending-keys", "pending-secrets", "missing-profiles"} {
		t.Run(mode, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			for i := 0; i < 130; i++ {
				legacyVaultProfile(t, db, fmt.Sprintf("00000000-0000-4000-8000-%012x", i), 0)
			}
			id := "00000000-0000-4000-8000-00000000003f"
			switch mode {
			case "boundary-case-duplicate":
				legacyVaultProfile(t, db, strings.ToUpper(id), 0)
			case "empty-id":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Id='' WHERE Id=?`, id)
			case "invalid-id":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Id='invalid' WHERE Id=?`, id)
			case "oversize-name":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Name=? WHERE Id=?`, strings.Repeat("a", 1025), id)
			case "nul-name":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Name=? WHERE Id=?`, "a\x00b", id)
			case "bad-protocol":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Protocol=42 WHERE Id=?`, id)
			case "bad-kind":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Kind=42 WHERE Id=?`, id)
			case "bad-provider":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=42 WHERE Id=?`, id)
			case "provider-secret":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=1,BitwardenItemId='remote' WHERE Id=?`, id)
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, id)
			case "invalid-certificate":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Kind=1,SshCertificate='invalid' WHERE Id=?`, id)
			case "password-certificate":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SshCertificate='invalid' WHERE Id=?`, id)
			case "created-at-nul":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET CreatedAt=? WHERE Id=?`, "a\x00b", id)
			case "local-provider-data":
				legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET BitwardenItemId='unexpected' WHERE Id=?`, id)
			case "pending-keys", "pending-secrets":
				table := "CredentialPrivateKeyOperations"
				if mode == "pending-secrets" {
					table = "CredentialSecretOperations"
				}
				legacyVaultSQL(t, db, "DROP TABLE IF EXISTS "+table)
				legacyVaultSQL(t, db, "CREATE TABLE "+table+"(Id TEXT)")
				legacyVaultSQL(t, db, "INSERT INTO "+table+" VALUES('pending')")
			case "missing-profiles":
				legacyVaultSQL(t, db, "DROP TABLE CredentialProfiles")
			}
			count := 0
			readers := legacyVaultCredentialReaders{secret: func(string, string, string, ...string) ([]byte, error) {
				t.Fatal("unexpected decrypt")
				return nil, nil
			}, privateKey: func(string) ([]byte, error) { t.Fatal("unexpected key read"); return nil, nil }}
			err := readLegacyVaultCredentials(resolverCaptureReader{context.Background(), db}, path, "", readers, func(legacyVaultCredential, []localvault.SecretChange) error { count++; return nil })
			if mode == "valid" || mode == "provider-secret" {
				if err != nil || count != 130 {
					t.Fatal(err, count)
				}
			} else if !errors.Is(err, errVaultMigrationSource) {
				t.Fatalf("malformed source accepted: %v", err)
			}
		})
	}
}

func TestVaultLegacySecretRowBounds(t *testing.T) {
	for _, mode := range []string{"valid", "empty", "absent", "duplicate", "null-secret", "null-encoding", "large-secret", "large-encoding", "nul-secret", "nul-encoding", "empty-encoding", "utf8-secret", "missing-table", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := snapshotDatabase(t)
			legacyVaultSQL(t, db, "DROP TABLE CredentialSecrets")
			legacyVaultSecrets(t, db)
			id := "abcdefab-0000-4000-8000-000000000001"
			var value, encoding any = "ciphertext", "fixture"
			switch mode {
			case "empty":
				value = ""
			case "null-secret":
				value = nil
			case "null-encoding":
				encoding = nil
			case "large-secret":
				value = strings.Repeat("x", 128*1024+1)
			case "large-encoding":
				encoding = strings.Repeat("x", 129)
			case "nul-secret":
				value = "a\x00b"
			case "nul-encoding":
				encoding = "a\x00b"
			case "empty-encoding":
				encoding = ""
			case "utf8-secret":
				value = string([]byte{255})
			}
			if mode != "absent" {
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, id, value, encoding)
			}
			if mode == "duplicate" {
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, strings.ToUpper(id), value, encoding)
			}
			if mode == "missing-table" {
				legacyVaultSQL(t, db, "DROP TABLE CredentialSecrets")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			actual, actualEncoding, present, err := readLegacyVaultSecretRow(resolverCaptureReader{ctx, db}, id)
			switch mode {
			case "valid", "empty":
				if err != nil || !present || actual != value || actualEncoding != encoding {
					t.Fatal("valid row changed")
				}
			case "absent":
				if err != nil || present || actual != "" || actualEncoding != "" {
					t.Fatal("absence lost")
				}
			default:
				if !errors.Is(err, errVaultMigrationSource) || present || actual != "" || actualEncoding != "" {
					t.Fatal("invalid row escaped")
				}
			}
		})
	}
}

func TestVaultLegacyCredentialEmptyAndPreconditions(t *testing.T) {
	db, path := snapshotDatabase(t)
	legacyVaultSQL(t, db, "DROP TABLE CredentialSecrets")
	reader := resolverCaptureReader{context.Background(), db}
	if err := visitLegacyVaultCredentials(reader, path, "", func(legacyVaultCredential, []localvault.SecretChange) error { t.Fatal("unexpected row"); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"relative.db", filepath.Base(path)} {
		if err := visitLegacyVaultCredentials(reader, p, "", func(legacyVaultCredential, []localvault.SecretChange) error { return nil }); !errors.Is(err, errVaultMigrationSource) {
			t.Fatal(err)
		}
	}
	if err := visitLegacyVaultCredentials(reader, path, "", nil); !errors.Is(err, errVaultMigrationSource) {
		t.Fatal(err)
	}
	id := uuid.NewString()
	legacyVaultProfile(t, db, id, 0)
	if err := visitLegacyVaultCredentials(reader, path, "", func(record legacyVaultCredential, changes []localvault.SecretChange) error {
		if record.Metadata.ID != id || len(changes) != 0 {
			t.Fatal("absent secret changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := visitLegacyVaultCredentials(reader, path, "", func(legacyVaultCredential, []localvault.SecretChange) error { return nil }); !errors.Is(err, errVaultMigrationSource) {
		t.Fatal("database error not redacted", err)
	}
}
