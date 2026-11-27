//go:build windows

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestVaultMigrationStageNativeSecretGraph(t *testing.T) {
	db, source, doc, key, plan, ids := migrationStageFixture(t)
	legacyVaultSecrets(t, db)
	ctx := context.Background()
	password, err := protectSecret("coordinated-password-fixture")
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, ids[0], password, protectedSecretEncoding)
	sshID, tunnelID, inlineID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	legacyVaultProfile(t, db, sshID, 1)
	privateKey := testSshPrivateKey(t, "")
	keyPath := credentialPrivateKeyPath(source, sshID)
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(keyPath, privateKey); err != nil {
		t.Fatal(err)
	}
	userData := t.TempDir()
	passphrase := writeElectronSafeStorageFixture(t, userData, "coordinated-passphrase-fixture", []byte("01234567890123456789012345678901"))
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, sshID, passphrase, electronSafeStorageSecretEncoding)
	legacyVaultTunnelRow(t, db, tunnelID, 1)
	configuration := []byte(`{"ProfileOvpn":"coordinated-vpn-fixture"}`)
	tunnelPath := legacyTunnelSecretPath(source, tunnelID)
	if err := os.MkdirAll(filepath.Dir(tunnelPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(tunnelPath, configuration); err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `UPDATE Nodes SET TunnelEnabled=1,TunnelConfigId=? WHERE Kind=1`, tunnelID)
	legacyVaultNodeRow(t, db, inlineID, ids[1], 1)
	legacyVaultSQL(t, db, `UPDATE Nodes SET Protocol=0,Host='ssh.example',Username='inline-user',CredentialMode=1,UseInlinePassword=1 WHERE Id=?`, inlineID)
	inline, err := protectSecret("coordinated-inline-fixture")
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, inlineID, inline, protectedSecretEncoding)
	plan, err = prepareLegacyResolverMigration(ctx, db, doc.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	protectedKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	protectedTunnel, err := os.ReadFile(tunnelPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := stageLegacyVaultDomains(ctx, source, userData, doc, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Credentials != 2 || result.Nodes != 4 || result.Tunnels != 1 || result.Pins != len(plan.Entries) {
		t.Fatal("wrong graph counts", result)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	for _, value := range []struct {
		id, field string
		expected  []byte
	}{
		{ids[0], "password", []byte("coordinated-password-fixture")},
		{sshID, "privateKey", privateKey},
		{sshID, "passphrase", []byte("coordinated-passphrase-fixture")},
	} {
		if err := owner.WithCredentialSecret(ctx, value.id, value.field, 1, equalLegacyVaultValue(value.expected)); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.WithTunnelConfiguration(ctx, tunnelID, 1, equalLegacyVaultValue(configuration)); err != nil {
		t.Fatal(err)
	}
	if err := owner.WithNodeField(ctx, inlineID, "inlinePassword", 1, equalLegacyVaultValue([]byte("coordinated-inline-fixture"))); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string][]byte{keyPath: protectedKey, tunnelPath: protectedTunnel} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("source protected file changed", err)
		}
	}
	var sourcePassword string
	if err := db.QueryRow(`SELECT Secret FROM CredentialSecrets WHERE Id=?`, ids[0]).Scan(&sourcePassword); err != nil || sourcePassword != password {
		t.Fatal("source secret changed", err)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("coordinated-password-fixture"), []byte("coordinated-passphrase-fixture"), []byte("coordinated-inline-fixture"), configuration, privateKey} {
		if bytes.Contains(data, secret) {
			t.Fatal("plaintext secret persisted in stage")
		}
	}
}

func TestVaultMigrationStageFailedTunnelKeepsPartialStageClosed(t *testing.T) {
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	tunnelID := uuid.NewString()
	legacyVaultTunnelRow(t, db, tunnelID, 1)
	if _, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err == nil {
		t.Fatal("missing payload silently dropped")
	}
	path := source + ".migrating-" + doc.FileID
	owner := openNativeMigrationStage(t, path, key)
	owner.Close()
	tunnelPath := legacyTunnelSecretPath(source, tunnelID)
	if err := os.MkdirAll(filepath.Dir(tunnelPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(tunnelPath, []byte(`{"ProfileOvpn":"restored-profile"}`)); err != nil {
		t.Fatal(err)
	}
	if result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err != nil || result.Tunnels != 1 {
		t.Fatal("source repair could not resume", err)
	}
}
