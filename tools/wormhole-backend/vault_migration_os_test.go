package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func osMigrationSetupFixture(t *testing.T) (legacyMigrationSetup, []byte, string) {
	t.Helper()
	setup, key := migrationSetupFixture(t)
	slotID := uuid.NewString()
	factor, err := createVaultUnprotectedKey(context.Background(), setup.CanonicalSource, setup.Initial.VaultID, slotID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(factor)
	slot, err := vault.CreateUnprotectedSlot(setup.Initial.VaultID, slotID, setup.Initial.RootKeyVersion, key, factor)
	if err != nil {
		t.Fatal(err)
	}
	setup.Initial.FormatVersion, setup.Initial.Slots = vault.SlotFileFormatVersion, []vault.Slot{slot}
	raw, err := vault.EncodeSlotFile(key, setup.Initial)
	if err != nil {
		t.Fatal(err)
	}
	setup.Initial, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := vaultUnprotectedKeyIdentity(setup.CanonicalSource, setup.Initial.VaultID, slotID)
	if err != nil {
		t.Fatal(err)
	}
	return setup, key, path
}

type osMigrationCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks atomic.Int32
	at     int32
}

func (c *osMigrationCancelContext) Err() error {
	if c.checks.Add(1) == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestLegacyOSPrepareCancellationConsumesFactorsAndJoinsMaterialAtEveryBoundary(t *testing.T) {
	finished := false
	cancelled := 0
	for at := int32(1); at <= 128; at++ {
		setup, key := migrationSetupFixture(t)
		vault.Wipe(key)
		h := legacyOSHandler(t, setup, false)
		base, cancel := context.WithCancel(context.Background())
		ctx := &osMigrationCancelContext{Context: base, cancel: cancel, at: at}
		input := vaultInput(t, map[string]any{"legacyMethod": "none", "legacyFactor": []byte{}})
		before, err := os.ReadFile(setup.LogicalSource)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.prepareOSMigration(ctx, input)
		wasCancelled := base.Err() != nil
		cancel()
		if !bytes.Equal(input, make([]byte, len(input))) || h.owner != nil || h.rotationMaterial != nil {
			t.Fatal("cancelled preparation retained inputs or native material")
		}
		after, readErr := os.ReadFile(setup.LogicalSource)
		if readErr != nil || !bytes.Equal(before, after) {
			t.Fatal("cancelled preparation changed legacy data", readErr)
		}
		if !h.closed && h.releaseWorkspace != nil {
			t.Fatal("pre-publication cancellation retained an acknowledged lease")
		}
		if closeErr := h.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if release, lockErr := acquireWorkspaceOwnership(setup.LogicalSource, true); lockErr != nil {
			t.Fatal("native close did not release exclusion", lockErr)
		} else {
			release()
		}
		if err == nil {
			finished = true
			break
		}
		if !wasCancelled {
			t.Fatal("unexpected failure without cancellation", err)
		}
		cancelled++
	}
	if !finished || cancelled == 0 {
		t.Fatal("cancellation scan failed to reach a completed preparation")
	}
}

func legacyOSHandler(t *testing.T, setup legacyMigrationSetup, isolated bool) *vaultFoundationHandler {
	t.Helper()
	h := &vaultFoundationHandler{databasePath: setup.LogicalSource, userDataPath: setup.UserData, migrationQuiesced: isolated}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func TestLegacyOSNativePrepareAndIsolatedResumeRequireRealLegacyProof(t *testing.T) {
	ctx := context.Background()
	for _, method := range []string{"none", "pin", "password"} {
		t.Run(method, func(t *testing.T) {
			setup, key := migrationSetupFixture(t)
			defer vault.Wipe(key)
			factor := []byte{}
			if method != "none" {
				factor = []byte("legacy OS proof fixture")
				salt := bytes.Repeat([]byte{0x23}, authSaltLength)
				verifier := &authVerifier{Salt: salt, Hash: deriveAuthSecret(string(factor), salt, 4096), Iterations: 4096}
				doc := authDocument{Version: authStoreVersion}
				if method == "pin" {
					doc.Pin = verifier
				} else {
					doc.Password = verifier
				}
				path, _ := authPaths(setup.LogicalSource)
				if err := writeAuthDocument(path, doc); err != nil {
					t.Fatal(err)
				}
			}
			h := legacyOSHandler(t, setup, false)
			if _, err := h.Handle(ctx, "migration-os-context", nil); err != nil {
				t.Fatal(err)
			}
			if method != "none" {
				if _, err := h.Handle(ctx, "migration-os-prepare", vaultInput(t, map[string]any{"legacyMethod": "none", "legacyFactor": []byte{}})); !errors.Is(err, vault.ErrAuthentication) {
					t.Fatal("legacy proof bypassed", err)
				}
			}
			before, err := os.ReadFile(setup.LogicalSource)
			if err != nil {
				t.Fatal(err)
			}
			input := vaultInput(t, map[string]any{"legacyMethod": method, "legacyFactor": factor})
			raw, err := h.Handle(ctx, "migration-os-prepare", input)
			if err != nil {
				t.Fatal("native preparation", err)
			}
			if !bytes.Equal(input, make([]byte, len(input))) || !h.closed || h.owner != nil || h.rotationMaterial != nil || h.releaseWorkspace == nil {
				t.Fatal("preparation retained secret, owner or lost exclusion")
			}
			var prepared struct {
				Prepared        bool
				RestartRequired bool
				VaultID         string
			}
			if json.Unmarshal(raw, &prepared) != nil || !prepared.Prepared || !prepared.RestartRequired || prepared.VaultID == "" {
				t.Fatal("bad preparation reply", string(raw))
			}
			if after, _ := os.ReadFile(setup.LogicalSource); !bytes.Equal(before, after) {
				t.Fatal("prepare modified legacy SQLite")
			}
			if release, err := acquireWorkspaceOwnership(setup.LogicalSource, true); err == nil {
				release()
				t.Fatal("preparation lost lease before native close")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			ordinary := legacyOSHandler(t, setup, false)
			startup, err := ordinary.Handle(ctx, "startup", nil)
			if err != nil {
				t.Fatal(err)
			}
			var hints vaultStartupMetadata
			if json.Unmarshal(startup, &hints) != nil || hints.OSMigration == nil || hints.OSMigration.VaultID != prepared.VaultID || hints.Slots != nil || hints.Migration != nil || ordinary.owner != nil {
				t.Fatal("bad OS-only startup hint", string(startup))
			}
			if _, err := ordinary.Handle(ctx, "migration-os-resume", nil); err != vaultwire.ErrProtocol {
				t.Fatal("ordinary launch resumed migration", err)
			}
			if _, err := ordinary.Handle(ctx, "unprotected-open", nil); err == nil {
				t.Fatal("ordinary open accepted pending capsule")
			}
			if err := ordinary.Close(); err != nil {
				t.Fatal(err)
			}
			resume := legacyOSHandler(t, setup, true)
			result, err := resume.Handle(ctx, "migration-os-resume", nil)
			if err != nil {
				t.Fatal("isolated OS resume", err)
			}
			var opened struct {
				Unlocked     bool
				LockedMemory bool
				VaultID      string
			}
			if json.Unmarshal(result, &opened) != nil || !opened.Unlocked || !opened.LockedMemory || opened.VaultID != prepared.VaultID || resume.owner == nil {
				t.Fatal("owner proof not authenticated", string(result))
			}
			if raw, err := resume.Handle(ctx, "protection", nil); err != nil || string(raw) != `{"protected":false}` {
				t.Fatal(string(raw), err)
			}
		})
	}
}

func TestLegacyOSNativeDeniesBrokenCustodyAndAuthorityWithoutSourceChanges(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"missing", "corrupt", "mac", "user-data", "ordinary", "payload", "protected-capsule"} {
		t.Run(change, func(t *testing.T) {
			setup, key, custody := osMigrationSetupFixture(t)
			defer vault.Wipe(key)
			if change == "protected-capsule" {
				setup, key = migrationSetupFixture(t)
				defer vault.Wipe(key)
			}
			if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
				t.Fatal(err)
			}
			path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
			switch change {
			case "missing":
				if err := os.Remove(custody); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(custody, []byte("invalid OS custody"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mac":
				raw, _ := os.ReadFile(path)
				var capsule legacyMigrationCapsule
				if json.Unmarshal(raw, &capsule) != nil {
					t.Fatal("fixture")
				}
				capsule.Document.Authentication[0] ^= 1
				raw, _ = json.Marshal(capsule)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(setup.LogicalSource)
			beforeCapsule, _ := os.ReadFile(path)
			h := legacyOSHandler(t, setup, change != "ordinary")
			if change == "user-data" {
				h.userDataPath = t.TempDir()
			}
			var payload []byte
			if change == "payload" {
				payload = []byte(`{"mode":"default"}`)
			}
			if _, err := h.Handle(ctx, "migration-os-resume", payload); err == nil {
				t.Fatal("invalid authority resumed")
			}
			if h.owner != nil {
				t.Fatal("failed migration adopted owner")
			}
			after, _ := os.ReadFile(setup.LogicalSource)
			afterCapsule, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) || !bytes.Equal(beforeCapsule, afterCapsule) {
				t.Fatal("failed admission changed legacy source")
			}
			if _, err := os.Stat(setup.CanonicalSource + ".migrating-" + setup.Initial.FileID); !os.IsNotExist(err) {
				t.Fatal("failed admission created database stage", err)
			}
		})
	}
}

func TestLegacyOSNativePreparationInputAndPendingGuards(t *testing.T) {
	ctx := context.Background()
	setup, key := migrationSetupFixture(t)
	defer vault.Wipe(key)
	for _, payload := range [][]byte{nil, []byte(`{}`), []byte(`{"legacyMethod":"none","legacyFactor":"","mode":"default"}`), []byte(`{"legacyMethod":"none","legacyFactor":"","legacyMethod":"none"}`), bytes.Repeat([]byte{1}, 4097)} {
		h := legacyOSHandler(t, setup, false)
		if _, err := h.Handle(ctx, "migration-os-prepare", payload); err == nil {
			t.Fatal("invalid input accepted")
		}
		if h.rotationMaterial != nil || h.releaseWorkspace != nil || h.owner != nil {
			t.Fatal("invalid input retained resources")
		}
	}
	for _, change := range []string{"user-data", "enrollment", "material", "lease", "held", "shared-marker", "root-marker"} {
		t.Run(change, func(t *testing.T) {
			s, k := migrationSetupFixture(t)
			defer vault.Wipe(k)
			h := legacyOSHandler(t, s, false)
			switch change {
			case "user-data":
				h.userDataPath = "relative"
			case "enrollment":
				h.enrollment = &vaultEnrollment{}
			case "material":
				h.rotationMaterial = &uncertainRotationRelease{}
			case "lease":
				h.releaseWorkspace = func() {}
			case "held":
				release, err := acquireWorkspaceOwnership(s.LogicalSource, true)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "shared-marker":
				if err := os.Mkdir(sharedWorkspaceDirectory(s.LogicalSource), 0700); err != nil {
					t.Fatal(err)
				}
			case "root-marker":
				if err := os.WriteFile(rootRotationJournalPath(s.LogicalSource), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.Handle(ctx, "migration-os-prepare", vaultInput(t, map[string]any{"legacyMethod": "none", "legacyFactor": []byte{}})); err == nil {
				t.Fatal("pending state accepted")
			}
			h.enrollment, h.rotationMaterial = nil, nil
		})
	}
	for _, operation := range []string{"migration-os-prepare", "migration-os-resume"} {
		if !(&vaultFoundationHandler{}).ExitOnCancel(operation) {
			t.Fatal("cancellation did not retire", operation)
		}
	}
}

func TestOSCustodyUsesOneCanonicalNamespaceAcrossDirectoryAliases(t *testing.T) {
	directory := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Skip("directory aliases unavailable: ", err)
	}
	vid, sid := uuid.NewString(), uuid.NewString()
	logical := filepath.Join(alias, "workspace.db")
	canonical := filepath.Join(directory, "workspace.db")
	a, err := createVaultUnprotectedKey(context.Background(), logical, vid, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(a)
	b, err := openVaultUnprotectedKey(context.Background(), canonical, vid, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(b)
	if !bytes.Equal(a, b) {
		t.Fatal("alias changed sole root custody")
	}
	left, _, err := vaultUnprotectedKeyIdentity(logical, vid, sid)
	if err != nil {
		t.Fatal(err)
	}
	right, _, err := vaultUnprotectedKeyIdentity(canonical, vid, sid)
	if err != nil || left != right {
		t.Fatal("aliases use different keychain scopes", err)
	}
}

func TestLegacyOSPrepareFailsBeforeCreatingCustodyForUnreadableSource(t *testing.T) {
	for _, change := range []string{"database", "schema", "auth"} {
		t.Run(change, func(t *testing.T) {
			setup, key := migrationSetupFixture(t)
			defer vault.Wipe(key)
			switch change {
			case "database":
				if err := os.WriteFile(setup.LogicalSource, []byte("not SQLite"), 0600); err != nil {
					t.Fatal(err)
				}
			case "schema":
				database, err := openLegacyMigrationSource(setup.LogicalSource)
				if err != nil {
					t.Fatal(err)
				}
				_, execErr := database.ExecContext(context.Background(), "DROP TABLE Nodes")
				if err := errors.Join(execErr, database.Close()); err != nil {
					t.Fatal(err)
				}
			case "auth":
				path, _ := authPaths(setup.LogicalSource)
				if err := os.WriteFile(path, []byte("not a protected verifier"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			h := legacyOSHandler(t, setup, false)
			if _, err := h.Handle(context.Background(), "migration-os-prepare", vaultInput(t, map[string]any{"legacyMethod": "none", "legacyFactor": []byte{}})); err == nil {
				t.Fatal("unreadable source accepted")
			}
			if h.owner != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil {
				t.Fatal("failed source retained resources")
			}
			entries, err := os.ReadDir(filepath.Dir(setup.CanonicalSource))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".wormhole-unprotected-") || strings.HasSuffix(entry.Name(), ".setup") {
					t.Fatal("failed source created root custody or capsule")
				}
			}
		})
	}
}

func TestLegacyOSMigrationReusesAuthenticatedPublicationAndPreservesTargetCustody(t *testing.T) {
	ctx := context.Background()
	setup, key, custody := osMigrationSetupFixture(t)
	defer vault.Wipe(key)
	before, err := os.ReadFile(custody)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	hint, err := discoverLegacyMigrationSetup(ctx, setup.LogicalSource)
	if err != nil || hint == nil || hint.Document.FormatVersion != 4 {
		t.Fatal("OS capsule not discoverable", err)
	}
	read, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, hint.Document, key)
	if err != nil {
		t.Fatal("transient authority not matched", err)
	}
	stage, err := continueLegacyVaultMigration(ctx, read.LogicalSource, read.UserData, read.Initial, key, read.Plan)
	if err != nil {
		t.Fatal("OS copy/retirement failed", err)
	}
	staged, err := readVaultSlotFile(stage)
	if err != nil || staged.FormatVersion != 4 {
		t.Fatal("stage lost transient version", err)
	}
	publication, err := publishLegacyVaultMigration(ctx, read.LogicalSource, read.UserData, read.Initial, key, read.Plan)
	if err != nil {
		t.Fatal("OS publication failed", err)
	}
	if err := publication.close(); err != nil {
		t.Fatal(err)
	}
	final, err := readVaultSlotFile(setup.CanonicalSource)
	if err != nil || final.FormatVersion != 3 || final.Migration != nil {
		t.Fatal("ordinary version not published", err)
	}
	if _, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, final, key); err != nil {
		t.Fatal("lost final acknowledgement cannot resume", err)
	}
	if err := removeLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(custody)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("new target custody retired as legacy", err)
	}
	h := unprotectedHandler(t, setup.CanonicalSource)
	if _, err := h.Handle(ctx, "unprotected-open", nil); err != nil {
		t.Fatal("completed OS migration not openable", err)
	}
	if raw, err := h.Handle(ctx, "protection", nil); err != nil || string(raw) != `{"protected":false}` {
		t.Fatal("false protection assurance", string(raw), err)
	}
	contents, err := os.ReadFile(setup.CanonicalSource)
	if err != nil || bytes.Contains(contents, []byte("private stage note")) {
		t.Fatal("legacy secret remained plaintext", err)
	}
}
