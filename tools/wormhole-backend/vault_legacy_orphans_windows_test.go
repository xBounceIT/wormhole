//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationStageNativeOrphanRows(t *testing.T) {
	db, source, doc, key, plan, ids := migrationStageFixture(t)
	defer vault.Wipe(key)
	legacyVaultSecrets(t, db)
	userData := t.TempDir()
	remote, orphan, tunnel := uuid.NewString(), uuid.NewString(), uuid.NewString()
	legacyVaultProfile(t, db, remote, 0)
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET SecretProvider=1,BitwardenItemId='remote-item' WHERE Id=?`, remote)
	values := map[string]string{ids[2]: "inactive node password", remote: "inactive provider password", orphan: "unreferenced credential", tunnelSecretID(tunnel): strings.Repeat("orphan-tunnel-fixture", 150000)}
	original := map[string]string{}
	for id, value := range values {
		encoded, err := protectSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		encoding := protectedSecretEncoding
		if id == orphan {
			encoded = writeElectronSafeStorageFixture(t, userData, value, []byte("01234567890123456789012345678901"))
			encoding = electronSafeStorageSecretEncoding
		}
		original[id] = encoded
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets(Id,Secret,Encoding,UpdatedAt) VALUES(?,?,?,'original-time')`, id, encoded, encoding)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := stageLegacyVaultDomains(context.Background(), source, userData, doc, key, plan)
		if err != nil || result.OrphanSecrets != 4 {
			t.Fatal("native residual rows omitted", result, err)
		}
		owner := openNativeMigrationStage(t, result.Path, key)
		for id, want := range values {
			kind, scope := legacyOrphanRowIdentity(id)
			if kind == "legacy-tunnel-row" {
				state, err := owner.ReadLocalState(context.Background(), kind, scope, 1)
				if err != nil || state.ActiveChunks() < 2 {
					t.Fatal("large archive did not span chunks", state.Size, err)
				}
			}
			err := owner.WithLocalState(context.Background(), kind, scope, 1, func(raw []byte) error {
				var item legacyVaultOrphan
				if err := json.Unmarshal(raw, &item); err != nil {
					return err
				}
				defer vault.Wipe(item.Value)
				if string(item.Value) != want || item.Source != id || item.Encoded != original[id] || item.UpdatedAt == nil || *item.UpdatedAt != "original-time" {
					t.Fatal("native archive lost source data", kind)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := owner.WithNodeField(context.Background(), ids[2], "inlinePassword", 2, func([]byte) error { t.Fatal("stale inline value reactivated"); return nil }); err == nil {
			t.Fatal("stale inline value present")
		}
		if err := owner.WithCredentialSecret(context.Background(), remote, "password", 1, func([]byte) error { t.Fatal("stale provider value reactivated"); return nil }); err == nil {
			t.Fatal("stale provider value present")
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(result.Path)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("plaintext archive on disk")
			}
		}
	}
	for id, encoded := range original {
		var actual string
		if db.QueryRow(`SELECT Secret FROM CredentialSecrets WHERE Id=?`, id).Scan(&actual) != nil || actual != encoded {
			t.Fatal("original row changed")
		}
	}
}
