package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type uncertainRotationRelease struct{ failed bool }

func (r *uncertainRotationRelease) Close() error {
	if r.failed {
		return securemem.ErrUnavailable
	}
	return nil
}

func TestVaultRootRotationRetainsUncertainNativeCleanupAndCancelsService(t *testing.T) {
	source := filepath.Join(t.TempDir(), "workspace.db")
	release, err := acquireWorkspaceOwnership(source, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup := &uncertainRotationRelease{failed: true}
	h := &vaultFoundationHandler{databasePath: source, rotationMaterial: cleanup, releaseWorkspace: release, migrationQuiesced: true}
	if !h.ExitOnCancel("rotation-resume") {
		t.Fatal("cancelled rotation can leave a live service")
	}
	if _, err := h.resumeRootRotation(context.Background(), []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal("pending native release admitted new resume", err)
	}
	if err := h.Close(); !errors.Is(err, securemem.ErrUnavailable) || h.rotationMaterial == nil {
		t.Fatal("uncertain allocation discarded", err)
	}
	if release, err := acquireWorkspaceOwnership(source, true); err == nil {
		release()
		t.Fatal("uncertain cleanup released workspace")
	}
	cleanup.failed = false
	if err := h.Close(); err != nil || h.rotationMaterial != nil {
		t.Fatal("cleanup retry", err)
	}
	last, err := acquireWorkspaceOwnership(source, true)
	if err != nil {
		t.Fatal(err)
	}
	last()
}

// Native browser tests keep this fixture process alive until the real backend
// and protected Electron window finish. Stdout carries public paths/IDs only;
// random roots remain inside Go and encrypted native files.
func TestVaultRootRotationBrowserFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_ROOT_ROTATION_BROWSER_FIXTURE")
	if mode != "1" && mode != "2" && mode != "3" && mode != "4" {
		return
	}
	var f nativeRotationFixture
	if mode == "4" {
		f.source = filepath.Join(t.TempDir(), "workspace.db")
		f.release = func() {}
		h := unprotectedHandler(t, f.source)
		if _, err := h.Handle(context.Background(), "unprotected-create", nil); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	} else if mode == "3" {
		f, _, _ = upgradeEnrollmentSource(t)
	} else if mode == "2" {
		f, _ = nativeOSRotation(t)
	} else {
		f = nativeRootRotation(t)
	}
	if mode != "3" && mode != "4" {
		if err := beginLocalRootRotation(context.Background(), f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
			t.Fatal(err)
		}
	}
	f.release()
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Database string `json:"database"`
		VaultID  string `json:"vaultId"`
	}{f.source, doc.VaultID}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func rootRotationUnlockInput(t *testing.T, document vault.SlotFile, recovery bool) []byte {
	t.Helper()
	if !recovery {
		return vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[0].ID, "password": []byte("new native transition password")})
	}
	key := bytes.Repeat([]byte{0x7a}, 32)
	defer vault.Wipe(key)
	code, err := vault.FormatRecoveryKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	return vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[1].ID, "recoveryCode": code})
}

func TestVaultRootRotationResumeOpensOnlyPublishedNewEpoch(t *testing.T) {
	for _, cut := range []string{"journal-prepared", "barrier-prepared", "journal-retiring", "barrier-publishing", "source-retired", "database-published", "old-copies-removed", "slots-published"} {
		t.Run(cut, func(t *testing.T) {
			f := nativeRootRotation(t)
			ctx := context.Background()
			stop := errors.New("durable cut")
			checkpoint := func(s string) error {
				if s == cut {
					return stop
				}
				return nil
			}
			err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), checkpoint)
			if cut == "journal-prepared" || cut == "barrier-prepared" {
				if !errors.Is(err, stop) {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := resumeLocalRootRotation(ctx, f.source, f.key, checkpoint); !errors.Is(err, stop) {
					t.Fatal(err)
				}
			}
			f.release()
			h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
			defer h.Close()
			metadata, err := h.Handle(ctx, "startup", nil)
			if err != nil {
				t.Fatal(err)
			}
			var startup vaultStartupMetadata
			if err := json.Unmarshal(metadata, &startup); err != nil || startup.Rotation == nil || startup.NewWorkspace || startup.Shared != nil || startup.Migration != nil || startup.Slots == nil {
				t.Fatal("bad resume startup", err)
			}
			if h.owner != nil {
				t.Fatal("startup opened database")
			}
			j, _ := loadRotationJournal(t, f)
			payload := rootRotationUnlockInput(t, j.Target, cut == "source-retired")
			result, err := h.Handle(ctx, "rotation-resume", payload)
			vault.Wipe(payload)
			if err != nil || string(result) != `{"unlocked":true,"lockedMemory":true}` || h.owner == nil || h.closed {
				t.Fatal("native resumption", err)
			}
			if release, err := acquireWorkspaceOwnership(f.source, true); err == nil {
				release()
				t.Fatal("published owner lost workspace ownership")
			}
			if err := h.owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
				if string(value) != "native root transition private value" {
					return vault.ErrAuthentication
				}
				return nil
			}); err != nil {
				t.Fatal("published data", err)
			}
			if _, err := h.Handle(ctx, "rotation-resume", rootRotationUnlockInput(t, j.Target, false)); err != vaultwire.ErrProtocol {
				t.Fatal("unlocked service resumed again", err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			release, err := acquireWorkspaceOwnership(f.source, true)
			if err != nil {
				t.Fatal("shutdown retained owner", err)
			}
			release()
		})
	}
}

func TestVaultRootRotationResumeRejectsWithoutTouchingDatabases(t *testing.T) {
	for _, attack := range []string{"ordinary-launch", "wire-authority", "wrong-password", "wrong-workspace", "owner-present", "enrollment-present", "corrupt-journal", "corrupt-database", "owner-busy", "cancelled"} {
		t.Run(attack, func(t *testing.T) {
			f := nativeRootRotation(t)
			ctx := context.Background()
			if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
				t.Fatal(err)
			}
			j, _ := loadRotationJournal(t, f)
			if attack != "owner-busy" {
				f.release()
			}
			h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
			defer func() { h.enrollment = nil; h.owner = nil; h.Close() }()
			payload := rootRotationUnlockInput(t, j.Target, false)
			defer vault.Wipe(payload)
			switch attack {
			case "ordinary-launch":
				h.migrationQuiesced = false
			case "wire-authority":
				payload = vaultInput(t, map[string]any{"quiesced": true, "vaultId": j.Target.VaultID, "slotId": j.Target.Slots[0].ID, "password": []byte("new native transition password")})
			case "wrong-password":
				payload = vaultInput(t, map[string]any{"vaultId": j.Target.VaultID, "slotId": j.Target.Slots[0].ID, "password": []byte("wrong")})
			case "wrong-workspace":
				payload = vaultInput(t, map[string]any{"vaultId": j.Source.FileID, "slotId": j.Target.Slots[0].ID, "password": []byte("new native transition password")})
			case "owner-present":
				h.owner = f.owner
			case "enrollment-present":
				h.enrollment = &vaultEnrollment{}
			case "corrupt-journal":
				if err := os.WriteFile(rootRotationJournalPath(f.source), []byte("malformed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-database":
				if err := os.WriteFile(j.stagePath(), bytes.Repeat([]byte{0x42}, 1024), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before, err := os.ReadFile(f.source)
			if err != nil {
				t.Fatal(err)
			}
			slotsBefore, err := os.ReadFile(vaultSlotPath(f.source))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Handle(ctx, "rotation-resume", payload); err == nil {
				t.Fatal("attack accepted")
			}
			after, err := os.ReadFile(f.source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("denial changed source", err)
			}
			slotsAfter, err := os.ReadFile(vaultSlotPath(f.source))
			if err != nil || !bytes.Equal(slotsBefore, slotsAfter) {
				t.Fatal("denial changed slots", err)
			}
			if h.owner != nil && h.owner != f.owner {
				t.Fatal("failed resume adopted owner")
			}
			if attack != "owner-busy" {
				release, err := acquireWorkspaceOwnership(f.source, true)
				if err != nil {
					t.Fatal("denial retained ownership", err)
				}
				release()
			}
		})
	}
}

func TestVaultRootRotationDiscoveryIsBoundedAndNeverFallsBackToOldSlots(t *testing.T) {
	ctx := context.Background()
	if hint, err := discoverRootRotation(ctx, filepath.Join(t.TempDir(), "missing-parent", "new.db")); hint != nil || err != nil {
		t.Fatal(hint, err)
	}
	if _, err := discoverRootRotation(ctx, "relative.db"); err != vault.ErrFormat {
		t.Fatal(err)
	}
	f := nativeRootRotation(t)
	if hint, err := discoverRootRotation(ctx, f.source); hint != nil || err != nil {
		t.Fatal(hint, err)
	}
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rootRotationJournalPath(f.source)); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
	defer h.Close()
	if _, err := h.startup(ctx, nil); err != vault.ErrPolicy {
		t.Fatal("missing journal offered old slots", err)
	}
	if _, err := h.Handle(ctx, "rotation-resume", []byte(`{}`)); err != vault.ErrAuthentication {
		t.Fatal("missing authority", err)
	}
	if err := os.Mkdir(rootRotationJournalPath(f.source), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.startup(ctx, nil); err == nil {
		t.Fatal("directory journal")
	}
}
