package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Deterministically deliver real context cancellation at a scan boundary.
type migrationSnapshotCancelContext struct {
	context.Context
	cancel     context.CancelFunc
	checks, at int
}

func (c *migrationSnapshotCancelContext) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestVaultMigrationSnapshotCancellationDuringScan(t *testing.T) {
	doc, key := localSlotFixture(t)
	doc.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationCopying}
	doc = snapshotMarker(t, key, doc)
	path := filepath.Join(t.TempDir(), "stage.db")
	if err := os.WriteFile(path, make([]byte, 131073), 0600); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{2, 3, 5} {
		ctx, cancel := context.WithCancel(context.Background())
		controlled := &migrationSnapshotCancelContext{Context: ctx, cancel: cancel, at: at}
		if snapshot, err := vaultMigrationDatabaseDigest(controlled, path, doc, key, false); !errors.Is(err, context.Canceled) || snapshot != nil {
			t.Fatal(at, snapshot, err)
		}
		cancel()
	}
}

func snapshotMarker(t *testing.T, key []byte, doc vault.SlotFile) vault.SlotFile {
	t.Helper()
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestVaultMigrationSnapshotAuthenticatedPersistedStage(t *testing.T) {
	_, source, doc, key, plan, _ := migrationStageFixture(t)
	ctx := context.Background()
	stage, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := readVaultSlotFile(stage.Path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Migration.Snapshot == nil || stored.Migration.Snapshot.Bytes < 512 {
		t.Fatal("unsealed checkpoint")
	}
	if err := verifyVaultMigrationSnapshot(ctx, stage.Path, stored, key); err != nil {
		t.Fatal(err)
	}
	// A crash/restart may reuse the verified checkpoint, but never open it as a
	// published vault. Reading domains does not silently change its file digest.
	owner := openNativeMigrationStage(t, stage.Path, key)
	if _, err := owner.VerifyIntegrity(ctx); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyVaultMigrationSnapshot(ctx, stage.Path, stored, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(stage.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []func([]byte) []byte{
		func(v []byte) []byte { v[len(v)/2] ^= 1; return v },
		func(v []byte) []byte { return v[:len(v)-512] },
		func(v []byte) []byte { return append(v, make([]byte, 512)...) },
	} {
		if err := os.WriteFile(stage.Path, corrupt(bytes.Clone(data)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyVaultMigrationSnapshot(ctx, stage.Path, stored, key); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("changed file accepted", err)
		}
	}
	// Rebuilding is still allowed only with the original authenticated source
	// and resolver choices; the source itself was not retired by this checkpoint.
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan); err != nil {
		t.Fatal(err)
	}
	if err := requireLegacyWorkspace(source); err != errVaultOwnerRequired {
		t.Fatal("pending stage restored legacy access", err)
	}
	if err := requireLegacySlotAbsent(source); err != nil {
		t.Fatal("copy checkpoint started retirement", err)
	}
}

func TestVaultMigrationSnapshotRejectsUntrustedMarkersAndSidecars(t *testing.T) {
	doc, key := localSlotFixture(t)
	doc.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationCopying}
	doc = snapshotMarker(t, key, doc)
	path := filepath.Join(t.TempDir(), "stage.db")
	ctx := context.Background()
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x55}, 131073), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := vaultMigrationDatabaseDigest(ctx, path, doc, key, true)
	if err != nil {
		t.Fatal(err)
	}
	doc.Migration.Phase, doc.Migration.Snapshot = vault.MigrationDomainsCopied, snapshot
	doc = snapshotMarker(t, key, doc)
	if err := verifyVaultMigrationSnapshot(ctx, path, doc, key); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyVaultMigrationSnapshot(ctx, path, doc, key); err != errVaultSlotStorage {
			t.Fatal("sidecar ignored", suffix, err)
		}
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"wrong-key", "unsigned-digest", "no-snapshot", "copying", "no-migration", "rebound-source", "wrong-digest"} {
		altered := snapshotMarker(t, key, doc)
		borrowedKey := bytes.Clone(key)
		switch mode {
		case "wrong-key":
			borrowedKey[0] ^= 1
		case "unsigned-digest":
			altered.Migration.Snapshot.Authentication[0] ^= 1
		case "no-snapshot":
			altered.Migration.Snapshot = nil
		case "copying":
			altered.Migration = &vault.LocalMigration{Binding: doc.Migration.Binding, Phase: vault.MigrationCopying}
		case "no-migration":
			altered.Migration = nil
		case "rebound-source":
			altered.Migration.Binding = strings.Repeat("b", 64)
		case "wrong-digest":
			altered.Migration.Snapshot.Authentication[0] ^= 1
		}
		if mode != "wrong-key" && mode != "unsigned-digest" {
			altered = snapshotMarker(t, key, altered)
		}
		if err := verifyVaultMigrationSnapshot(ctx, path, altered, borrowedKey); err == nil {
			t.Fatal(mode)
		}
		vault.Wipe(borrowedKey)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := verifyVaultMigrationSnapshot(canceled, path, doc, key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, p := range []string{path + ".missing", filepath.Dir(path)} {
		if _, err := vaultMigrationDatabaseDigest(ctx, p, doc, key, false); err != errVaultSlotStorage {
			t.Fatal(p, err)
		}
	}
	if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyVaultMigrationSnapshot(ctx, path, doc, key); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	doc.Migration = nil
	doc = snapshotMarker(t, key, doc)
	if _, err := vaultMigrationDatabaseDigest(ctx, path, doc, key, true); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	doc.Authentication[0] ^= 1
	if _, err := vaultMigrationDatabaseDigest(ctx, path, doc, key, true); err == nil {
		t.Fatal("unauthenticated read")
	}
}

func TestVaultMigrationSnapshotIdentityBinding(t *testing.T) {
	doc, key := localSlotFixture(t)
	doc.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationCopying}
	doc = snapshotMarker(t, key, doc)
	path := filepath.Join(t.TempDir(), "stage.db")
	if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := vaultMigrationDatabaseDigest(context.Background(), path, doc, key, false)
	if err != nil {
		t.Fatal(err)
	}
	doc.Migration.Phase, doc.Migration.Snapshot = vault.MigrationDomainsCopied, snapshot
	for _, change := range []func(*vault.SlotFile){
		func(d *vault.SlotFile) { d.FileID = "11111111-1111-4111-8111-111111111111" },
		func(d *vault.SlotFile) { d.RootKeyID = "11111111-1111-4111-8111-111111111111" },
		func(d *vault.SlotFile) { d.RootKeyVersion++ },
	} {
		altered := doc
		change(&altered)
		altered = snapshotMarker(t, key, altered)
		if err := verifyVaultMigrationSnapshot(context.Background(), path, altered, key); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
	}
}
