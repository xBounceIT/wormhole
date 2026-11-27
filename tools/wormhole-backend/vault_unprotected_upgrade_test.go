package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestUnprotectedUpgradePreparesAndResumesWithoutOrdinarySourceOwner(t *testing.T) {
	f, path := nativeOSRotation(t)
	ctx := context.Background()
	policy, err := f.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err := f.owner.PutLocalPolicy(ctx, policy.Policy, vault.Standard, policy.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.ReadSecurityProfile(ctx); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("OS source still satisfies new floor", err)
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := localvault.Open(ctx, f.source, localVaultOptions(doc), bytes.Clone(f.old)); owner != nil || !errors.Is(err, vault.ErrPolicy) {
		if owner != nil {
			owner.Close()
		}
		t.Fatal("ordinary source opened under Standard", err)
	}
	scope := localvault.NewUnprotectedRootUpgrade()
	defer scope.Close()
	input := bytes.Clone(f.key)
	if err := beginUnprotectedRootUpgrade(ctx, f.source, scope, f.slots, input, noRotationStop); err != nil {
		t.Fatal("forward upgrade", err)
	}
	if !bytes.Equal(input, make([]byte, 32)) {
		t.Fatal("upgrade input retained")
	}
	j, _ := loadRotationJournal(t, f)
	if j.Version != 2 || j.Custody == nil || j.Target.ProfileSequence < 2 {
		t.Fatal("missing upgrade floor/retirement commitments")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	f.release()
	h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
	defer h.Close()
	startup, err := h.Handle(ctx, "startup", nil)
	if err != nil || !bytes.Contains(startup, []byte(`"rotation":{"pending":true}`)) {
		t.Fatal("upgrade startup continuation", err)
	}
	payload := rootRotationUnlockInput(t, j.Target, false)
	defer vault.Wipe(payload)
	if _, err := h.Handle(ctx, "rotation-resume", payload); err != nil {
		t.Fatal("forward resume", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old OS factor retained", err)
	}
	profile, err := h.owner.ReadSecurityProfile(ctx)
	if err != nil || profile.Effective != vault.Standard {
		t.Fatal("forward admission weakened policy", err)
	}
	if err := h.owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
		if string(value) != "native root transition private value" {
			return vault.ErrAuthentication
		}
		return nil
	}); err != nil {
		t.Fatal("upgrade lost secret", err)
	}
}

func TestUnprotectedUpgradeNativeAdmissionRejectsOtherSourcesAndWipesFailures(t *testing.T) {
	for _, mode := range []string{"nil-scope", "nil-step", "cancelled", "protected-source", "corrupt-custody", "shared-source", "legacy-pending"} {
		t.Run(mode, func(t *testing.T) {
			var f nativeRotationFixture
			if mode == "protected-source" {
				f = nativeRootRotation(t)
			} else {
				var path string
				f, path = nativeOSRotation(t)
				if mode == "corrupt-custody" {
					if err := os.WriteFile(path, []byte("foreign ciphertext"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			scope := localvault.NewUnprotectedRootUpgrade()
			if mode == "shared-source" {
				if err := os.Mkdir(sharedWorkspaceDirectory(f.source), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "legacy-pending" {
				if err := os.WriteFile(legacyMigrationSetupPath(f.source, f.slots[1].ID), []byte("untrusted pending migration"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			defer scope.Close()
			selected := scope
			step := noRotationStop
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "nil-scope" {
				selected = nil
			}
			if mode == "nil-step" {
				step = nil
			}
			if mode == "cancelled" {
				cancel()
			}
			input := bytes.Clone(f.key)
			if err := beginUnprotectedRootUpgrade(ctx, f.source, selected, f.slots, input, step); err == nil {
				t.Fatal("invalid forward admission accepted")
			}
			if !bytes.Equal(input, make([]byte, 32)) {
				t.Fatal("denied input retained")
			}
			if _, err := os.Lstat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("denied admission published journal", err)
			}
		})
	}
}
