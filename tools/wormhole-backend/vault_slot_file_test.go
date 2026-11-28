package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func localSlotFixture(t *testing.T) (vault.SlotFile, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x91}, 32)
	document := vault.SlotFile{FormatVersion: 1, VaultID: "11111111-1111-4111-8111-111111111111", FileID: "22222222-2222-4222-8222-222222222222", Sequence: 1, FileEpoch: 1, ProfileSequence: 3, Nodes: []vault.NodeHighWater{{NodeID: "33333333-3333-4333-8333-333333333333", Revision: 5}}}
	document.RootKeyID, document.RootKeyVersion = "55555555-5555-4555-8555-555555555555", 1
	slot, err := vault.CreateRecoverySlot(document.VaultID, "44444444-4444-4444-8444-444444444444", 1, key, bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	document.Slots = []vault.Slot{slot}
	return document, key
}

func TestVaultSlotFileAtomicPersistenceAndDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	document, key := localSlotFixture(t)
	if descriptor, err := describeVaultSlots(path); descriptor != nil || err != nil {
		t.Fatal("missing descriptor should be empty")
	}
	if err := writeVaultSlotFile(path, key, document, 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.VerifySlotFile(key, loaded, document.VaultID, document.FileID, 1); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(vaultSlotPath(path))
	if err != nil || bytes.Contains(raw, key) {
		t.Fatal("key stored in plaintext")
	}
	descriptor, err := describeVaultSlots(path)
	if err != nil || descriptor.VaultID != document.VaultID || len(descriptor.Slots) != 1 {
		t.Fatal("descriptor unavailable")
	}
	handler := &vaultFoundationHandler{databasePath: path}
	response, err := handler.Handle(context.Background(), "describe", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ciphertext", "keyCheck", "authentication", "salt", "nodes", "fileId"} {
		if bytes.Contains(response, []byte(forbidden)) {
			t.Fatalf("descriptor exposes %s", forbidden)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("slot operation opened SQLite")
	}
	if err := writeVaultSlotFile(path, key, document, 0); err != errVaultSlotConflict {
		t.Fatal("existing file overwritten")
	}
	document.Sequence = 2
	if err := writeVaultSlotFile(path, key, document, 1); err != nil {
		t.Fatal(err)
	}
	loaded, err = readVaultSlotFile(path)
	if err != nil || loaded.Sequence != 2 {
		t.Fatal("update not committed")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp"))
	if len(files) != 0 {
		t.Fatal("temporary slot files leaked")
	}
}

func TestVaultSlotUpdatesCannotLoseAuthenticatedState(t *testing.T) {
	for _, change := range []func(*vault.SlotFile){
		func(f *vault.SlotFile) { f.ProfileSequence-- },
		func(f *vault.SlotFile) { f.FileEpoch = 0 },
		func(f *vault.SlotFile) { f.Nodes = nil },
		func(f *vault.SlotFile) { f.Nodes = []vault.NodeHighWater{{NodeID: f.Nodes[0].NodeID, Revision: 4}} },
	} {
		path := filepath.Join(t.TempDir(), "workspace.db")
		document, key := localSlotFixture(t)
		if err := writeVaultSlotFile(path, key, document, 0); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(vaultSlotPath(path))
		document.Sequence = 2
		change(&document)
		if err := writeVaultSlotFile(path, key, document, 1); err != vault.ErrRollback {
			t.Fatalf("rollback allowed: %v", err)
		}
		after, _ := os.ReadFile(vaultSlotPath(path))
		if !bytes.Equal(before, after) {
			t.Fatal("failed update changed disk")
		}
	}
	path := filepath.Join(t.TempDir(), "workspace.db")
	document, key := localSlotFixture(t)
	if err := writeVaultSlotFile(path, key, document, 0); err != nil {
		t.Fatal(err)
	}
	document.Sequence = 2
	if err := writeVaultSlotFile(path, bytes.Repeat([]byte{1}, 32), document, 1); err != vault.ErrKeyCheck {
		t.Fatal(err)
	}
	document.FileID = "55555555-5555-4555-8555-555555555555"
	if err := writeVaultSlotFile(path, key, document, 1); err != vault.ErrKeyCheck {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(vaultSlotPath(path))
	raw = bytes.Replace(raw, []byte(`"profileSequence":3`), []byte(`"profileSequence":2`), 1)
	os.WriteFile(vaultSlotPath(path), raw, 0o600)
	document.FileID = "22222222-2222-4222-8222-222222222222"
	if err := writeVaultSlotFile(path, key, document, 1); err != vault.ErrAuthentication {
		t.Fatal("tampered old file repaired without authentication")
	}
}

func TestVaultSlotUpdatesRetainSSOAndTunnelHighWaterMarks(t *testing.T) {
	for _, change := range []func(*vault.SlotFile){
		func(f *vault.SlotFile) { f.FormatVersion = 1 },
		func(f *vault.SlotFile) { f.VPNSSO = nil },
		func(f *vault.SlotFile) { f.VPNSSO[0].RowVersion-- },
		func(f *vault.SlotFile) { f.VPNSSO[0].Revision-- },
		func(f *vault.SlotFile) { f.VPNSSO[0].Deleted = true },
		func(f *vault.SlotFile) { f.VPNSSO[0].Digest[0]++ },
		func(f *vault.SlotFile) { f.Tunnels = nil },
		func(f *vault.SlotFile) { f.Tunnels[0].Revision-- },
	} {
		path := filepath.Join(t.TempDir(), "vault.db")
		document, key := localSlotFixture(t)
		document.FormatVersion = vault.SlotFileFormatVersion
		document.VPNSSO = []vault.VPNSSOHighWater{{ScopeID: document.FileID, RowVersion: 4, Revision: 3, Digest: bytes.Repeat([]byte{1}, 32)}}
		document.Tunnels = []vault.TunnelHighWater{{TunnelID: document.FileID, Revision: 6}}
		if err := writeVaultSlotFile(path, key, document, 0); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(vaultSlotPath(path))
		document.Sequence++
		change(&document)
		if err := writeVaultSlotFile(path, key, document, 1); err != vault.ErrRollback {
			t.Fatal("native checkpoint loss allowed", err)
		}
		after, _ := os.ReadFile(vaultSlotPath(path))
		if !bytes.Equal(before, after) {
			t.Fatal("failed checkpoint write changed native file")
		}
	}
}

func TestVaultSlotFileFailurePaths(t *testing.T) {
	document, key := localSlotFixture(t)
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := writeVaultSlotFile(path, key, document, math.MaxUint64); err != errVaultSlotConflict {
		t.Fatal(err)
	}
	document.Sequence = 2
	if err := writeVaultSlotFile(path, key, document, 1); err != errVaultSlotConflict {
		t.Fatal(err)
	}
	document.Sequence = 1
	if err := writeVaultSlotFile(path, nil, document, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(vaultSlotPath(path) + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVaultSlotFile(path, key, document, 0); err != errVaultSlotConflict {
		t.Fatal(err)
	}
	release()
	os.Mkdir(vaultSlotPath(path), 0o700)
	if _, err := readVaultSlotFile(path); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	if _, err := describeVaultSlots(path); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	if err := writeVaultSlotFile(path, key, document, 0); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	if _, err := (&vaultFoundationHandler{databasePath: path}).Handle(context.Background(), "describe", nil); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	if err := writeVaultSlotFile(filepath.Join(vaultSlotPath(path), "child.db", "nested.db"), key, document, 0); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(t.TempDir(), "parent")
	os.WriteFile(blocked, []byte("file"), 0o600)
	if err := writeVaultSlotFile(filepath.Join(blocked, "child.db"), key, document, 0); err != errVaultSlotStorage {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "corrupt.db")
	os.WriteFile(vaultSlotPath(path), []byte("{broken"), 0o600)
	if _, err := readVaultSlotFile(path); err != vault.ErrFormat {
		t.Fatal(err)
	}
	os.WriteFile(vaultSlotPath(path), bytes.Repeat([]byte{'x'}, vault.MaxSlotFileBytes+1), 0o600)
	if _, err := readVaultSlotFile(path); err != vault.ErrFormat {
		t.Fatal("unbounded read")
	}
	if _, err := (&vaultFoundationHandler{}).Handle(context.Background(), "describe", nil); err == nil {
		t.Fatal("empty descriptor path allowed")
	}
}

func TestVaultSlotFileCannotRestoreInitializationOrOlderRootIdentity(t *testing.T) {
	for _, change := range []func(*vault.SlotFile){
		func(doc *vault.SlotFile) { doc.Initializing = true },
		func(doc *vault.SlotFile) { doc.RootKeyVersion = 0 },
		func(doc *vault.SlotFile) { doc.RootKeyID = "66666666-6666-4666-8666-666666666666" },
	} {
		path := filepath.Join(t.TempDir(), "db")
		doc, key := localSlotFixture(t)
		if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
			t.Fatal(err)
		}
		doc.Sequence = 2
		change(&doc)
		if err := writeVaultSlotFile(path, key, doc, 1); err != vault.ErrRollback {
			t.Fatal(err)
		}
	}
}

func TestVaultSlotConcurrentUpdatesHaveOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	document, key := localSlotFixture(t)
	if err := writeVaultSlotFile(path, key, document, 0); err != nil {
		t.Fatal(err)
	}
	document.Sequence = 2
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() { results <- writeVaultSlotFile(path, key, document, 1) })
	}
	workers.Wait()
	winners := 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if err != errVaultSlotConflict {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners: %d", winners)
	}
}

func TestVaultSlotDurabilityFailureRequiresReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	document, key := localSlotFixture(t)
	original := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return errors.New("private filesystem details") }
	t.Cleanup(func() { privateFileDirectorySync = original })
	err := writeVaultSlotFile(path, key, document, 0)
	if err != errVaultSlotCommitUncertain || strings.Contains(err.Error(), "private") {
		t.Fatalf("ambiguous commit not classified: %v", err)
	}
	loaded, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.VerifySlotFile(key, loaded, document.VaultID, document.FileID, 1); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(loaded.Descriptor())
	if len(encoded) == 0 {
		t.Fatal("readback failed")
	}
}
