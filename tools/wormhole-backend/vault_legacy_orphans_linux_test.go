//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultLegacyOrphanLinuxSecretTool(t *testing.T) {
	for _, mode := range []string{"valid", "failure", "oversize", "missing", "invalid-reference"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("PATH", directory)
			payload := "synthetic-legacy-secret"
			exitCode := "0"
			if mode == "oversize" {
				payload = strings.Repeat("x", maxStoredCredentialBytes+2)
			}
			if mode == "failure" {
				exitCode = "1"
			}
			if mode != "missing" {
				script := "#!/bin/sh\nprintf '%s\\n' '" + payload + "'\nexit " + exitCode + "\n"
				if err := os.WriteFile(filepath.Join(directory, "secret-tool"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			id := uuid.NewString()
			if mode == "invalid-reference" {
				id = "bad"
			}
			value, err := unprotectLegacyLinuxCredentialSecret(id, id)
			defer vault.Wipe(value)
			if mode == "valid" {
				if err != nil || string(value) != payload {
					t.Fatal("legacy payload changed", err)
				}
			} else if err == nil || value != nil {
				t.Fatal("legacy error returned secret bytes", mode, err)
			}
		})
	}
}

func TestVaultMigrationStageLinuxOrphanKeyringRow(t *testing.T) {
	stored := installLinuxCredentialStoreMock(t)
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	defer vault.Wipe(key)
	id := uuid.NewString()
	reference, encoding, err := storeCredentialSecret(id, "", "orphan-keyring-fixture")
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets(Id,Secret,Encoding,UpdatedAt) VALUES(?,?,?,'original-time')`, id, reference, encoding)
	result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err != nil || result.OrphanSecrets != 1 {
		t.Fatal("keyring orphan omitted", result, err)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	defer owner.Close()
	if err := owner.WithLocalState(context.Background(), "legacy-secret", id, 1, func(raw []byte) error {
		var item legacyVaultOrphan
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		defer vault.Wipe(item.Value)
		if !bytes.Equal(item.Value, []byte("orphan-keyring-fixture")) || item.Encoded != reference || item.Encoding != encoding {
			return errors.New("archive changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatal("source keyring entry retired")
	}
}
