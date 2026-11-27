package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/secretclipboard"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type migrationCleanupClipboard struct {
	clipboardFixture
	failClose bool
}

func (d *migrationCleanupClipboard) Close() error {
	if d.failClose {
		return secretclipboard.ErrUnavailable
	}
	return d.clipboardFixture.Close()
}

func TestVaultMigrationResumeRetainsWorkspaceAfterUncertainCleanup(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: setup.LogicalSource, userDataPath: setup.UserData, migrationQuiesced: true}
	defer h.Close()
	if _, err := h.Handle(ctx, "migration-resume", migrationResumeInput(t, setup.Initial)); err != nil {
		t.Fatal(err)
	}
	driver := &migrationCleanupClipboard{failClose: true}
	h.clipboard = secretclipboard.New(driver)
	if err := h.Close(); !errors.Is(err, secretclipboard.ErrUnavailable) {
		t.Fatal("native cleanup failure lost", err)
	}
	if release, err := acquireWorkspaceOwnership(h.databasePath, false); err == nil {
		release()
		t.Fatal("uncertain cleanup released migrated workspace")
	}
	if _, err := h.Handle(ctx, "status", nil); err == nil {
		t.Fatal("failed close retained ordinary operations")
	}
	driver.failClose = false
	if err := h.Close(); err != nil {
		t.Fatal("cleanup retry failed", err)
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, false)
	if err != nil {
		t.Fatal("successful cleanup retained workspace", err)
	}
	release()
}

func migrationResumeInput(t *testing.T, document vault.SlotFile) []byte {
	t.Helper()
	return vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
}

func TestVaultMigrationResumeAdoptsPublicationAtEveryBoundary(t *testing.T) {
	for _, phase := range []string{"setup", "copied", "sql-retired", "source-retired", "database-published", "slots-published"} {
		t.Run(phase, func(t *testing.T) {
			setup, key := migrationSetupFixture(t)
			ctx := context.Background()
			if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
				t.Fatal(err)
			}
			stop := errors.New("own process interruption fixture")
			if phase != "setup" {
				_, err := continueLegacyVaultMigrationWith(ctx, setup.LogicalSource, setup.UserData, setup.Initial, key, setup.Plan, func(step string) error {
					if step == phase {
						return stop
					}
					return nil
				})
				if phase == "copied" || phase == "sql-retired" {
					if !errors.Is(err, stop) {
						t.Fatal("coordinator did not interrupt", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					_, err = publishLegacyVaultMigrationWith(ctx, setup.LogicalSource, setup.UserData, setup.Initial, key, setup.Plan, func(step string) error {
						if step == phase {
							return stop
						}
						return nil
					})
					if !errors.Is(err, stop) {
						t.Fatal("publisher did not interrupt", err)
					}
				}
			}
			h := &vaultFoundationHandler{databasePath: setup.LogicalSource, userDataPath: setup.UserData, migrationQuiesced: true}
			defer h.Close()
			if _, err := h.Handle(ctx, "unlock", migrationResumeInput(t, setup.Initial)); err != errVaultOwnerRequired {
				t.Fatal("ordinary unlock bypassed pending setup", err)
			}
			if _, err := h.Handle(ctx, "migration-resume", migrationResumeInput(t, setup.Initial)); err != nil {
				t.Fatal("native restart failed", err)
			}
			if h.owner == nil || h.databasePath != setup.CanonicalSource || h.releaseWorkspace == nil {
				t.Fatal("publication ownership not adopted")
			}
			if _, err := os.Lstat(legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("completed setup authority retained", err)
			}
			if release, err := acquireWorkspaceOwnership(h.databasePath, false); err == nil {
				release()
				t.Fatal("active migrated owner lost workspace lease")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			other := &vaultFoundationHandler{databasePath: setup.CanonicalSource}
			defer other.Close()
			if _, err := other.Handle(ctx, "unlock", migrationResumeInput(t, setup.Initial)); err != nil {
				t.Fatal("completed vault cannot unlock normally", err)
			}
		})
	}
}

func TestVaultMigrationResumeRequiresNativeQuiescenceAndFreshFactors(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: setup.LogicalSource, userDataPath: setup.UserData}
	defer h.Close()
	valid := migrationResumeInput(t, setup.Initial)
	if _, err := h.Handle(ctx, "migration-resume", valid); err != vaultwire.ErrProtocol {
		t.Fatal("renderer gained quiescence", err)
	}
	h.migrationQuiesced = true
	for _, fields := range []map[string]any{
		{"vaultId": setup.Initial.VaultID, "slotId": setup.Initial.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x33}, 32)},
		{"vaultId": setup.Initial.VaultID, "slotId": setup.Initial.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32), "quiesced": true},
	} {
		if _, err := h.Handle(ctx, "migration-resume", vaultInput(t, fields)); err == nil {
			t.Fatal("untrusted restart accepted")
		}
	}
	h.userDataPath = t.TempDir()
	if _, err := h.Handle(ctx, "migration-resume", valid); err != vault.ErrAuthentication {
		t.Fatal("native profile path substitution accepted", err)
	}
	if h.owner != nil || h.closed {
		t.Fatal("rejected factor created or retired owner")
	}
	if requireLegacyWorkspace(h.databasePath) != errVaultOwnerRequired {
		t.Fatal("failed factor removed quarantine")
	}
	h.userDataPath = setup.UserData
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	if err := os.WriteFile(path, []byte(`corrupt setup`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-resume", valid); err == nil {
		t.Fatal("corrupt capsule accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-resume", valid); err != vault.ErrAuthentication {
		t.Fatal("missing setup accepted", err)
	}
}

func TestVaultMigrationResumeFailsClosedAfterAuthenticatedSourceFailure(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: setup.LogicalSource, userDataPath: setup.UserData, migrationQuiesced: true}
	defer h.Close()
	if _, err := h.Handle(ctx, "migration-resume", []byte(`{}`)); err == nil {
		t.Fatal("missing factors accepted")
	}
	if err := os.Mkdir(sharedWorkspaceDirectory(h.databasePath), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-resume", migrationResumeInput(t, setup.Initial)); err != errVaultOwnerRequired {
		t.Fatal("shared selection allowed", err)
	}
	if err := os.Remove(sharedWorkspaceDirectory(h.databasePath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(h.databasePath), []byte(`corrupt source guard`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-resume", migrationResumeInput(t, setup.Initial)); err == nil || h.owner != nil {
		t.Fatal("corrupt source guard accepted")
	}
	if err := os.Remove(vaultSlotPath(h.databasePath)); err != nil {
		t.Fatal(err)
	}
	// A source changed after confirmation cannot be silently copied under the
	// earlier resolver decisions. No ordinary owner may survive this failure.
	if err := os.WriteFile(h.databasePath, []byte(`not the confirmed legacy database`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-resume", migrationResumeInput(t, setup.Initial)); err == nil || !h.closed || h.owner != nil {
		t.Fatal("failed coordinator did not retire native process", err)
	}
	if _, err := os.Stat(legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)); err != nil {
		t.Fatal("failed copy discarded retry authority", err)
	}
}

func TestVaultMigrationSetupCleanupPreservesUnauthenticatedAuthority(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := removeLegacyMigrationSetup(canceled, setup, key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := removeLegacyMigrationSetup(ctx, setup, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("wrong key deleted setup")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed cleanup changed capsule", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyMigrationSetup(ctx, setup, key); err == nil {
		t.Fatal("missing cleanup authority accepted")
	}
}
