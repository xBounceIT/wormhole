package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func migrationSetupFixture(t *testing.T) (legacyMigrationSetup, []byte) {
	t.Helper()
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	raw, err := vault.EncodeSlotFile(key, document)
	if err != nil {
		t.Fatal(err)
	}
	document, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := legacyVaultSourceIdentity(source)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := browserInventoryFixture(t)
	return legacyMigrationSetup{Version: 1, LogicalSource: source, CanonicalSource: canonical, UserData: root, Initial: document, Plan: plan}, key
}

func TestVaultMigrationSetupSurvivesBeforeStageAndAfterPublication(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	if requireLegacyWorkspace(setup.LogicalSource) != errVaultOwnerRequired {
		t.Fatal("capsule-only interruption restored legacy access")
	}
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{setup.LogicalSource, setup.UserData, "logicalSource", "canonicalSource", "candidate"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private migration setup leaked to disk")
		}
	}
	read, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, setup.Initial, key)
	if err != nil || read.Plan.Fingerprint != setup.Plan.Fingerprint || read.UserData != setup.UserData {
		t.Fatal("capsule-only restart failed", err)
	}
	if err := saveLegacyMigrationSetup(ctx, setup, key); err == nil {
		t.Fatal("confirmed setup was replaced")
	}
	stage, err := continueLegacyVaultMigration(ctx, read.LogicalSource, read.UserData, read.Initial, key, read.Plan)
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := readVaultSlotFile(stage)
	if _, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, staged, key); err != nil {
		t.Fatal("advanced stage could not resume original setup", err)
	}
	publication, err := publishLegacyVaultMigration(ctx, read.LogicalSource, read.UserData, read.Initial, key, read.Plan)
	if err != nil {
		t.Fatal(err)
	}
	publication.close()
	completed, _ := readVaultSlotFile(setup.CanonicalSource)
	if _, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, completed, key); err != nil {
		t.Fatal("lost final acknowledgement could not resume setup", err)
	}
}

func TestVaultMigrationSetupChunkedPrivatePlanRejectsReordering(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	base := setup.Plan.Entries[0]
	setup.Plan.Entries = make([]resolver.MigrationEntry, 1200)
	for i := range setup.Plan.Entries {
		entry := base
		id := fmt.Sprintf("%08x-0000-4000-8000-000000000001", i+1)
		entry.Legacy.NodeID, entry.Candidate.NodeID = id, id
		entry.Legacy.ProtocolPath, entry.Candidate.ProtocolPath = "ssh", "ssh"
		entry.Legacy.Username, entry.Candidate.Username = string(bytes.Repeat([]byte{'a'}, 2048)), string(bytes.Repeat([]byte{'b'}, 2048))
		setup.Plan.Entries[i] = entry
	}
	if err := saveLegacyMigrationSetup(context.Background(), setup, key); err != nil {
		t.Fatal(err)
	}
	read, err := readLegacyMigrationSetup(context.Background(), setup.CanonicalSource, setup.Initial, key)
	if err != nil || len(read.Plan.Entries) != 1200 {
		t.Fatal(err)
	}
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var capsule legacyMigrationCapsule
	if json.Unmarshal(raw, &capsule) != nil || len(capsule.Chunks) < 2 {
		t.Fatal("fixture did not exercise chunking")
	}
	capsule.Chunks[0], capsule.Chunks[1] = capsule.Chunks[1], capsule.Chunks[0]
	raw, err = json.Marshal(capsule)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyMigrationSetup(context.Background(), setup.CanonicalSource, setup.Initial, key); err == nil {
		t.Fatal("reordered private plan chunks accepted")
	}
}

func TestVaultMigrationSetupRejectsTamperingAndAuthorityDrift(t *testing.T) {
	for _, mutation := range []string{"ciphertext", "size", "count", "header", "slot-authority", "noncanonical", "wrong-key", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			setup, key := migrationSetupFixture(t)
			ctx := context.Background()
			if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
				t.Fatal(err)
			}
			path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var capsule legacyMigrationCapsule
			if json.Unmarshal(raw, &capsule) != nil {
				t.Fatal("fixture decode failed")
			}
			expected := setup.Initial
			switch mutation {
			case "ciphertext":
				capsule.Chunks[0].Ciphertext[0] ^= 1
			case "size":
				capsule.Bytes++
			case "count":
				capsule.Chunks = nil
			case "header":
				capsule.Document.FileEpoch++
			case "slot-authority":
				expected.FileEpoch++
				signed, err := vault.EncodeSlotFile(key, expected)
				if err != nil {
					t.Fatal(err)
				}
				expected, _ = vault.DecodeSlotFile(signed)
			case "wrong-key":
				key = bytes.Repeat([]byte{9}, 32)
			case "cancel":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			raw, err = json.Marshal(capsule)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "noncanonical" {
				raw = append(raw, '\n')
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, expected, key); err == nil {
				t.Fatal("changed setup accepted")
			}
		})
	}
}

func TestVaultMigrationSetupRefusesInvalidOrCancelledSave(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := saveLegacyMigrationSetup(ctx, setup, key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	setup.UserData = "relative"
	if err := saveLegacyMigrationSetup(context.Background(), setup, key); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
}
