//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

func TestVaultLegacyNativeCredentialTransfer(t *testing.T) {
	db, path := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	ctx := context.Background()
	workspaceID := uuid.NewString()
	ids := []string{uuid.NewString(), uuid.NewString()}
	userData := t.TempDir()
	for i, id := range ids {
		legacyVaultProfile(t, db, id, i)
		encoding := protectedSecretEncoding
		encoded, err := protectSecret("native-password-fixture")
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			encoding = electronSafeStorageSecretEncoding
			encoded = writeElectronSafeStorageFixture(t, userData, "native-passphrase-fixture", []byte("01234567890123456789012345678901"))
		}
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, id, encoded, encoding)
	}
	key := testSshPrivateKey(t, "")
	keyPath := credentialPrivateKeyPath(path, ids[1])
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(keyPath, key); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyResolverMigration(ctx, db, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	release, err := acquireExclusiveFileLockContext(ctx, credentialPrivateKeyLockPath(path))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	h := vaultCredentialFixture(t)
	var borrowed [][]byte
	err = withLegacyResolverMigration(ctx, db, workspaceID, plan, func(reader resolverCaptureReader, _ legacyResolverBaseline) error {
		return visitLegacyVaultCredentials(reader, path, userData, func(record legacyVaultCredential, changes []localvault.SecretChange) error {
			for _, change := range changes {
				borrowed = append(borrowed, change.Value)
			}
			_, err := h.owner.ImportCredential(ctx, record.Metadata, record.CreatedAt, changes)
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("native plaintext retained")
		}
	}
	for _, item := range []struct {
		id, field string
		want      []byte
	}{{ids[0], "password", []byte("native-password-fixture")}, {ids[1], "passphrase", []byte("native-passphrase-fixture")}, {ids[1], "privateKey", key}} {
		if err := h.owner.WithCredentialSecret(ctx, item.id, item.field, 1, func(value []byte) error {
			if !bytes.Equal(value, item.want) {
				t.Fatal("native transfer changed secret")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("protected source key changed", err)
	}
}

func TestVaultLegacyStoredSecretLimits(t *testing.T) {
	for _, encoding := range []string{protectedSecretEncoding, electronSafeStorageSecretEncoding, "unsupported"} {
		t.Run(encoding, func(t *testing.T) {
			userData := t.TempDir()
			for _, size := range []int{0, maxStoredCredentialBytes, maxStoredCredentialBytes + 1} {
				value := strings.Repeat("x", size)
				encoded, err := protectSecret(value)
				if err != nil {
					t.Fatal(err)
				}
				if encoding == electronSafeStorageSecretEncoding {
					encoded = writeElectronSafeStorageFixture(t, userData, value, []byte("01234567890123456789012345678901"))
				}
				actual, err := unprotectStoredSecret(uuid.NewString(), encoded, encoding, userData)
				if encoding == "unsupported" || size > maxStoredCredentialBytes {
					if err == nil || actual != nil {
						t.Fatal("unsupported or oversized secret accepted")
					}
				} else if err != nil || string(actual) != value {
					t.Fatal("valid native secret rejected", err)
				}
				clearBytes(actual)
			}
		})
	}
	if value, err := unprotectStoredSecret(uuid.NewString(), base64.StdEncoding.EncodeToString([]byte("invalid")), protectedSecretEncoding); err == nil || value != nil {
		t.Fatal("corrupt DPAPI accepted")
	}
	if value, err := unprotectStoredSecret(uuid.NewString(), "", "unsupported"); !errors.Is(err, errUnsupportedSecretEncoding) || value != nil {
		t.Fatal("wrong native error")
	}
}

func TestVaultLegacyNativeNodeTransfer(t *testing.T) {
	db, path := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	id := uuid.NewString()
	legacyVaultNodeRow(t, db, id, nil, 1)
	legacyVaultSQL(t, db, `UPDATE Nodes SET Protocol=0,Host='host.example',Username='alice',UseInlinePassword=1,CredentialMode=1,Notes='native note fixture' WHERE Id=?`, id)
	encoded, err := protectSecret("native inline fixture")
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, id, encoded, protectedSecretEncoding)
	ctx := context.Background()
	workspaceID := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(ctx, db, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	release, err := acquireExclusiveFileLockContext(ctx, credentialPrivateKeyLockPath(path))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	h := vaultCredentialFixture(t)
	err = withLegacyResolverMigration(ctx, db, workspaceID, plan, func(reader resolverCaptureReader, _ legacyResolverBaseline) error {
		return visitLegacyVaultNodes(reader, "", func(record legacyVaultNode, changes []localvault.SecretChange) error {
			_, err := h.owner.ImportNode(ctx, record.Metadata, changes, record.Times)
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.owner.WithNodeField(ctx, id, "inlinePassword", 1, func(value []byte) error {
		if string(value) != "native inline fixture" {
			t.Fatal("native password changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.owner.WithNodeField(ctx, id, "notes", 1, func(value []byte) error {
		if string(value) != "native note fixture" {
			t.Fatal("native note changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultLegacyNativeTunnelTransfer(t *testing.T) {
	for _, mode := range []string{"file", "dpapi-row", "safe-storage-row", "both"} {
		t.Run(mode, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := uuid.NewString()
			legacyVaultTunnelRow(t, db, id, 1)
			configuration := `{"ProfileOvpn":"` + strings.Repeat("native-profile-fixture", 1000) + `"}`
			if mode == "dpapi-row" {
				const prefix, suffix = `{"ProfileOvpn":"`, `"}`
				configuration = prefix + strings.Repeat("p", backendMaxTunnelRequestBytes-len(prefix)-len(suffix)) + suffix
			}
			userData := t.TempDir()
			file := legacyTunnelSecretPath(path, id)
			var before []byte
			if mode == "file" || mode == "both" {
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := protectFile(file, []byte(configuration)); err != nil {
					t.Fatal(err)
				}
				var err error
				before, err = os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode != "file" {
				encoded, err := protectSecret(configuration)
				if err != nil {
					t.Fatal(err)
				}
				encoding := protectedSecretEncoding
				if mode == "safe-storage-row" {
					encoding = electronSafeStorageSecretEncoding
					encoded = writeElectronSafeStorageFixture(t, userData, configuration, []byte("01234567890123456789012345678901"))
				}
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, tunnelSecretID(id), encoded, encoding)
			}
			ctx := context.Background()
			workspaceID := uuid.NewString()
			plan, err := prepareLegacyResolverMigration(ctx, db, workspaceID)
			if err != nil {
				t.Fatal(err)
			}
			release, err := acquireTunnelConfigurationLock(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			h := vaultCredentialFixture(t)
			var borrowed []byte
			err = withLegacyResolverMigration(ctx, db, workspaceID, plan, func(reader resolverCaptureReader, _ legacyResolverBaseline) error {
				return visitLegacyVaultTunnels(reader, path, userData, func(record legacyVaultTunnel, value []byte) error {
					if record.ProtectedFile != (mode == "file" || mode == "both") || record.LegacyRow != (mode != "file") {
						t.Fatal("native source provenance lost")
					}
					borrowed = value
					_, err := h.owner.ImportTunnel(ctx, record.Metadata, value, record.Times)
					return err
				})
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("native tunnel plaintext retained")
			}
			if err := h.owner.WithTunnelConfiguration(ctx, id, 1, func(value []byte) error {
				if string(value) != configuration {
					t.Fatal("native configuration changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if before != nil {
				after, err := os.ReadFile(file)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("source file changed", err)
				}
			}
		})
	}
}

func TestVaultLegacyNativeTunnelPayloadLimits(t *testing.T) {
	for _, size := range []int{maxStoredCredentialBytes + 1, backendMaxTunnelRequestBytes, backendMaxTunnelRequestBytes + 1} {
		value := strings.Repeat("x", size)
		encoded, err := protectSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := unprotectStoredValue("tunnel-fixture", encoded, protectedSecretEncoding, backendMaxTunnelRequestBytes)
		if size <= backendMaxTunnelRequestBytes {
			if err != nil || len(actual) != size {
				t.Fatal("valid tunnel size rejected", err)
			}
		} else if err == nil || actual != nil {
			t.Fatal("oversized tunnel accepted")
		}
		clearBytes(actual)
		if actual, err := unprotectStoredSecret("password-fixture", encoded, protectedSecretEncoding); err == nil || actual != nil {
			t.Fatal("password limit was widened")
		}
	}
}

func TestVaultLegacySafeStorageStateBounds(t *testing.T) {
	for _, kind := range []string{"oversize", "directory", "missing"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			state := filepath.Join(path, "Local State")
			if kind == "oversize" {
				if err := os.WriteFile(state, bytes.Repeat([]byte{'x'}, electronLocalStateMaxBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "directory" {
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if value, err := unprotectStoredValue("tunnel-fixture", "cipher", electronSafeStorageSecretEncoding, backendMaxTunnelRequestBytes, path); err == nil || value != nil {
				t.Fatal("invalid safeStorage source accepted")
			}
		})
	}
}
