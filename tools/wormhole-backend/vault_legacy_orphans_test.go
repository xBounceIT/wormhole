package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultLegacyOrphansPagingClassificationAndArchive(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSQL(t, db, `DROP TABLE CredentialSecrets`)
	legacyVaultSecrets(t, db)
	h := vaultCredentialFixture(t)
	local, keyID, remote, inline, stale, tunnel := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	legacyVaultProfile(t, db, local, 0)
	legacyVaultProfile(t, db, keyID, 1)
	legacyVaultProfile(t, db, remote, 0)
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=1,BitwardenItemId='remote-item' WHERE Id=?`, remote)
	for _, id := range []string{inline, stale} {
		legacyVaultNodeRow(t, db, id, nil, 1)
	}
	legacyVaultSQL(t, db, `UPDATE Nodes SET UseInlinePassword=1 WHERE Id=?`, inline)
	legacyVaultTunnelRow(t, db, tunnel, 0)
	active := []string{local, keyID, inline, tunnelSecretID(tunnel), mcpTokenCredentialID}
	for _, id := range active {
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'active','fixture','now')`, id)
	}
	want := map[string]string{}
	for i := 0; i < 130; i++ {
		id := fmt.Sprintf("abcdefab-0000-4000-8000-%012x", i+1)
		original := id
		if i%2 == 0 {
			original = strings.ToUpper(id)
		}
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'orphan','fixture',NULL)`, original)
		want["legacy-secret/"+id] = original
	}
	for _, id := range []string{remote, stale} {
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'orphan','fixture','original-time')`, id)
		want["legacy-secret/"+id] = id
	}
	orphanTunnel := uuid.NewString()
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'orphan','fixture',NULL)`, tunnelSecretID(orphanTunnel))
	want["legacy-tunnel-row/"+orphanTunnel] = tunnelSecretID(orphanTunnel)
	files := map[string]string{
		credentialPrivateKeyPath(source, local):      "legacy-private-key/" + local,
		credentialPrivateKeyPath(source, remote):     "legacy-private-key/" + remote,
		legacyTunnelSecretPath(source, orphanTunnel): "legacy-tunnel-file/" + orphanTunnel,
	}
	for path, key := range files {
		writeLegacyStateFixture(t, path, []byte("protected orphan"))
		want[key] = path
	}
	// Active files must not be opened by the archive pass.
	writeLegacyStateFixture(t, credentialPrivateKeyPath(source, keyID), []byte("active key"))
	writeLegacyStateFixture(t, legacyTunnelSecretPath(source, tunnel), []byte("active tunnel"))
	var borrowed [][]byte
	readers := legacyOrphanReaders{
		secret: func(id, encoded, encoding string, paths ...string) ([]byte, error) {
			if encoded != "orphan" || encoding != "fixture" || len(paths) != 1 || paths[0] != "user-data" {
				t.Fatal("active row reached decrypt", id)
			}
			value := []byte("payload/" + id)
			borrowed = append(borrowed, value)
			return value, nil
		},
		file: func(path string, protected []byte) ([]byte, error) {
			if files[path] == "" || string(protected) != "protected orphan" {
				t.Fatal("active file reached decrypt", path)
			}
			value := []byte("payload/" + path)
			borrowed = append(borrowed, protected, value)
			return value, nil
		},
	}
	seen := map[string]bool{}
	err := readLegacyVaultOrphans(resolverCaptureReader{context.Background(), db}, source, "user-data", readers, func(kind, scope string, archive []byte) error {
		key := kind + "/" + scope
		var item legacyVaultOrphan
		if json.Unmarshal(archive, &item) != nil || item.Version != 1 || item.Source != want[key] || seen[key] {
			t.Fatal("archive identity changed", key)
		}
		defer vault.Wipe(item.Value)
		expectedSource := item.Source
		if kind == "legacy-secret" || kind == "legacy-tunnel-row" {
			expectedSource = strings.ToLower(expectedSource)
			if item.Encoded != "orphan" || item.Encoding != "fixture" {
				t.Fatal("row provenance lost")
			}
			if scope == remote || scope == stale {
				if item.UpdatedAt == nil || *item.UpdatedAt != "original-time" {
					t.Fatal("time lost")
				}
			} else if item.UpdatedAt != nil {
				t.Fatal("null time changed")
			}
		} else if item.Encoding != "" || item.Encoded != "" || item.UpdatedAt != nil {
			t.Fatal("file got row provenance")
		}
		if string(item.Value) != "payload/"+expectedSource {
			t.Fatal("archive value changed")
		}
		borrowed = append(borrowed, archive)
		seen[key] = true
		_, err := h.owner.PutLocalState(context.Background(), kind, scope, archive, 0)
		return err
	})
	if err != nil || len(seen) != len(want) {
		t.Fatal("incomplete archive", len(seen), len(want), err)
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("plaintext retained")
		}
	}
	for key := range want {
		parts := strings.SplitN(key, "/", 2)
		if err := h.owner.WithLocalState(context.Background(), parts[0], parts[1], 1, func(value []byte) error {
			var item legacyVaultOrphan
			err := json.Unmarshal(value, &item)
			defer vault.Wipe(item.Value)
			if err == nil && item.Source != want[key] {
				t.Fatal("sealed archive changed")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if db.QueryRow(`SELECT COUNT(*) FROM CredentialSecrets`).Scan(&count) != nil || count != 138 {
		t.Fatal("source rows changed", count)
	}
	for path := range files {
		value, err := os.ReadFile(path)
		if err != nil || string(value) != "protected orphan" {
			t.Fatal("source file changed", err)
		}
	}
}

func TestVaultLegacyOrphansDoNotReactivateUnusedValues(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	node, credential := uuid.NewString(), uuid.NewString()
	legacyVaultNodeRow(t, db, node, nil, 1)
	legacyVaultProfile(t, db, credential, 0)
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=1,BitwardenItemId='remote-item'`)
	for _, id := range []string{node, credential} {
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'unused','fixture','now')`, id)
	}
	reader := resolverCaptureReader{context.Background(), db}
	noSecret := func(string, string, string, ...string) ([]byte, error) {
		t.Fatal("unused secret attached to active record")
		return nil, nil
	}
	if err := readLegacyVaultNodes(reader, "", noSecret, func(_ legacyVaultNode, changes []localvault.SecretChange) error {
		for _, change := range changes {
			if change.Field == "inlinePassword" {
				t.Fatal("inline value activated")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := readLegacyVaultCredentials(reader, source, "", legacyVaultCredentialReaders{secret: noSecret, privateKey: func(string) ([]byte, error) { t.Fatal("remote key activated"); return nil, nil }}, func(_ legacyVaultCredential, changes []localvault.SecretChange) error {
		if len(changes) != 0 {
			t.Fatal("provider value activated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	seen := 0
	err := readLegacyVaultOrphans(reader, source, "", legacyOrphanReaders{secret: func(string, string, string, ...string) ([]byte, error) { return []byte("preserved"), nil }, file: unprotectFileContents}, func(kind, scope string, value []byte) error {
		if kind != "legacy-secret" || (scope != node && scope != credential) {
			t.Fatal("wrong archive")
		}
		seen++
		return nil
	})
	if err != nil || seen != 2 {
		t.Fatal("unused values not preserved", seen, err)
	}
}

func TestVaultLegacyOrphansFailuresAndWipe(t *testing.T) {
	for _, mode := range []string{"decrypt-error", "oversize", "cancel-decrypt", "sink-error", "cancel-sink", "file-error", "file-oversize"} {
		t.Run(mode, func(t *testing.T) {
			db, source := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := uuid.NewString()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := []byte("partial private value")
			var archive, protected []byte
			called := false
			if mode == "oversize" {
				value = make([]byte, maxStoredCredentialBytes+1)
			}
			if mode == "file-oversize" {
				value = make([]byte, maxSshPrivateKeyBytes+1)
			}
			if strings.HasPrefix(mode, "file-") {
				writeLegacyStateFixture(t, credentialPrivateKeyPath(source, id), []byte("protected"))
			} else {
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, id)
			}
			sentinel := errors.New("private diagnostic")
			readers := legacyOrphanReaders{secret: func(string, string, string, ...string) ([]byte, error) {
				if mode == "cancel-decrypt" {
					cancel()
				}
				if mode == "decrypt-error" {
					return value, sentinel
				}
				return value, nil
			}, file: func(_ string, input []byte) ([]byte, error) {
				protected = input
				if mode == "file-error" {
					return value, sentinel
				}
				return value, nil
			}}
			err := readLegacyVaultOrphans(resolverCaptureReader{ctx, db}, source, "", readers, func(_, _ string, raw []byte) error {
				called = true
				archive = raw
				if mode == "sink-error" {
					return sentinel
				}
				if mode == "cancel-sink" {
					cancel()
					return nil
				}
				t.Fatal("invalid value reached sink")
				return nil
			})
			want := errVaultMigrationSource
			if mode == "sink-error" {
				want = sentinel
			}
			if err != want || called != (mode == "sink-error" || mode == "cancel-sink") {
				t.Fatal("failure escaped", err, called)
			}
			for _, buf := range [][]byte{value, protected, archive} {
				if !bytes.Equal(buf, make([]byte, len(buf))) {
					t.Fatal("failure retained plaintext")
				}
			}
		})
	}
}

func TestVaultLegacyOrphansRejectMalformedInventory(t *testing.T) {
	for _, mode := range []string{"id", "nil-id", "long-id", "duplicate", "duplicate-page", "bad-time", "huge-time", "invalid-utf8-time", "unknown-encoding", "pending", "schema", "active-id", "corrupt-file", "bad-file", "cancelled", "no-secrets"} {
		t.Run(mode, func(t *testing.T) {
			db, source := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := "abcdefab-0000-4000-8000-000000000001"
			stamp := "now"
			switch mode {
			case "id":
				id = "other:" + id
			case "nil-id":
				id = uuid.Nil.String()
			case "long-id":
				id += strings.Repeat("a", 30)
			case "bad-time":
				stamp = "a\x00b"
			case "huge-time":
				stamp = strings.Repeat("a", 129)
			case "invalid-utf8-time":
				stamp = string([]byte{255})
			}
			legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture',?)`, id, stamp)
			switch mode {
			case "duplicate":
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, strings.ToUpper(id))
			case "duplicate-page":
				for i := 2; i <= 65; i++ {
					legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, fmt.Sprintf("abcdefab-0000-4000-8000-%012x", i))
				}
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES('ABCDEFAB-0000-4000-8000-000000000040','cipher','fixture','now')`)
			case "pending":
				legacyVaultSQL(t, db, `DROP TABLE IF EXISTS CredentialSecretOperations`)
				legacyVaultSQL(t, db, `CREATE TABLE IF NOT EXISTS CredentialSecretOperations(Id TEXT)`)
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecretOperations(Id) VALUES('pending')`)
			case "schema":
				legacyVaultSQL(t, db, `DROP TABLE Nodes`)
			case "active-id":
				legacyVaultProfile(t, db, "bad", 0)
			case "bad-file":
				writeLegacyStateFixture(t, filepath.Join(filepath.Dir(source), "keys", "invalid.dpapi"), []byte("data"))
			case "no-secrets":
				legacyVaultSQL(t, db, `DROP TABLE CredentialSecrets`)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			readers := legacyOrphanReaders{secret: func(string, string, string, ...string) ([]byte, error) {
				if mode == "unknown-encoding" {
					return nil, errors.New("unknown")
				}
				return []byte("value"), nil
			}, file: unprotectFileContents}
			if mode == "corrupt-file" {
				writeLegacyStateFixture(t, credentialPrivateKeyPath(source, id), []byte("data"))
			}
			err := readLegacyVaultOrphans(resolverCaptureReader{ctx, db}, source, "", readers, func(string, string, []byte) error { return nil })
			if mode == "no-secrets" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err != errVaultMigrationSource {
				t.Fatal("invalid inventory admitted", err)
			}
		})
	}
}

func TestVaultMigrationStageOrphanFiles(t *testing.T) {
	_, source, doc, key, plan, _ := migrationStageFixture(t)
	defer vault.Wipe(key)
	id := uuid.NewString()
	paths := map[string]string{credentialPrivateKeyPath(source, id): "legacy-private-key", legacyTunnelSecretPath(source, id): "legacy-tunnel-file"}
	for path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := protectFile(path, []byte("native orphan fixture")); err != nil {
			t.Fatal(err)
		}
	}
	result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err != nil || result.OrphanSecrets != 2 {
		t.Fatal("native orphan files lost", result, err)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	defer owner.Close()
	for path, kind := range paths {
		if err := owner.WithLocalState(context.Background(), kind, id, 1, func(raw []byte) error {
			var archive legacyVaultOrphan
			err := json.Unmarshal(raw, &archive)
			defer vault.Wipe(archive.Value)
			if err == nil && (archive.Source != path || string(archive.Value) != "native orphan fixture") {
				t.Fatal("native archive changed")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultMigrationStageOrphanFailureRemainsUnpublished(t *testing.T) {
	_, source, doc, key, plan, _ := migrationStageFixture(t)
	defer vault.Wipe(key)
	path := credentialPrivateKeyPath(source, uuid.NewString())
	writeLegacyStateFixture(t, path, []byte("torn protected file"))
	if _, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); !errors.Is(err, errVaultMigrationSource) {
		t.Fatal("damaged orphan ignored", err)
	}
	stage := source + ".migrating-" + doc.FileID
	marker, err := readVaultSlotFile(stage)
	if err != nil || marker.Migration == nil || marker.Migration.Phase != vault.MigrationCopying {
		t.Fatal("failed archive advanced stage", marker, err)
	}
	if owner, err := openVaultFiles(context.Background(), stage, marker, key); owner != nil || err != vault.ErrPolicy {
		t.Fatal("incomplete archive admitted unlock", err)
	}
	if err := protectFile(path, []byte("repaired orphan")); err != nil {
		t.Fatal(err)
	}
	result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err != nil || result.OrphanSecrets != 1 {
		t.Fatal("archive retry failed", result, err)
	}
}
