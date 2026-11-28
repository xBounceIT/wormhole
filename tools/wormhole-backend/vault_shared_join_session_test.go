package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func vaultJoiningFixture(t *testing.T, pending bool) (*vaultFoundationHandler, *recoveryFixture, *preparedDeviceProbe, *invitationJoinProbe, []byte, *int) {
	t.Helper()
	j, f, p, source := sharedJoinPasswordPreparationFixture(t)
	database := filepath.Join(t.TempDir(), "workspace.db")
	f.o.TrustPath = sharedWorkspaceTrustPath(database)
	protection := startupTestProtection()
	if pending {
		j.newRecovery = func() sharedJoinRecovery {
			return &joinRecoveryProbe{run: func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
				return nil, errors.New("interrupted after dispatch")
			}}
		}
	}
	result, err := j.joinPreparedWithStartup(context.Background(), f.o, p, &protection)
	if result == nil || !result.Submitted || source.calls != 1 || pending && err == nil || !pending && (err != nil || !result.Confirmed) {
		t.Fatal("initial setup", result, err)
	}
	factories := 0
	h := &vaultFoundationHandler{databasePath: database, sharedProtection: &protection, sharedFactory: func() *sharedAdmissionController {
		factories++
		if pending && factories == 1 {
			return f.c
		}
		c, _ := selectedDeviceController(t, f)
		return c
	}}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	payload := vaultInput(t, map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": p.slots.VaultID, "slotId": p.slots.Slots[0].ID, "password": []byte("recovery-test-password")}})
	return h, f, p, source, payload, &factories
}

func TestVaultSharedEnrollmentResumeAuthenticatesBeforeAdmissionAndNeverReplaysInvite(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active-before-anchor", true: "pending-confirmation"}[pending], func(t *testing.T) {
			h, f, p, source, payload, factories := vaultJoiningFixture(t, pending)
			if _, err := h.Handle(context.Background(), "shared-unlock", payload); err == nil {
				t.Fatal("ordinary unlock accepted initial selection")
			}
			raw, err := h.Handle(context.Background(), "shared-recover-enrollment", payload)
			var result map[string]bool
			if err != nil || json.Unmarshal(raw, &result) != nil || len(result) != 3 || !result["admitted"] || !result["orgEscrow"] {
				t.Fatal("resume did not admit", string(raw), err)
			}
			if source.calls != 1 || *factories != 2 {
				t.Fatal("replayed invitation or reused recovery session", source.calls, *factories)
			}
			if h.owner != nil || h.shared == nil || h.shared.vaultID != p.slots.VaultID || !h.shared.controller.Unlocked() {
				t.Fatal("wrong native owner")
			}
			if err := h.shared.selected.account.Borrow(func(*sharedpg.AccountMaster, *sharedpg.DeviceTrustRoot) error {
				t.Fatal("account derivation roots retained")
				return nil
			}); err == nil {
				t.Fatal("account roots still exposed")
			}
			if err := requireNoSharedJoinStartup(f.o.TrustPath); err != nil {
				t.Fatal("initial record not retired", err)
			}
			anchor, err := readSharedStartupAnchor(f.o.TrustPath, h.startupProtection())
			if err != nil || anchor.Binding != f.o.Binding || anchor.VaultID != p.slots.VaultID {
				t.Fatal("verified selection missing", err)
			}
			runtime := verifySharedRuntimeAfterAdmission(t, h)
			if runtime.WorkspaceID != f.o.Binding.WorkspaceID.String() || runtime.VaultID != p.slots.VaultID {
				t.Fatal("application received wrong admitted identity")
			}
			if _, err := acquireWorkspaceOwnership(h.databasePath, false); !errors.Is(err, errWorkspaceInUse) {
				t.Fatal("native owner lost exclusion", err)
			}
			if !h.ExitOnCancel("shared-recover-enrollment") {
				t.Fatal("recovery cancellation did not retire")
			}
			if _, err := h.Handle(context.Background(), "shared-recover-enrollment", payload); err == nil {
				t.Fatal("already admitted session resumed twice")
			}
		})
	}
}

func TestVaultSharedLegacyJoinSelectionRecoveryCompatibility(t *testing.T) {
	for _, pending := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			name := map[bool]string{false: "active", true: "pending"}[pending] + map[bool]string{false: "-complete", true: "-missing"}[missing]
			t.Run(name, func(t *testing.T) {
				h, f, _, source, payload, _ := vaultJoiningFixture(t, pending)
				p, err := readSharedJoinStartup(f.o.TrustPath, h.startupProtection())
				if err != nil {
					t.Fatal(err)
				}
				p.FormatVersion, p.Purpose, p.Pending, p.Transport = 1, "wormhole/shared-join-startup/v1", nil, nil
				if err := persistSharedJoinStartupValue(context.Background(), f.o.TrustPath, p, h.startupProtection()); err != nil {
					t.Fatal(err)
				}
				devicePath := sharedDeviceEnrollmentPath(f.o.TrustPath)
				if missing {
					if err := os.Remove(devicePath); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := h.Handle(context.Background(), "shared-recover-enrollment", payload)
				if missing {
					if err == nil || len(raw) != 0 {
						t.Fatal("v1 snapshot authorized missing-file reconstruction")
					}
					if _, err := os.Lstat(devicePath); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("v1 recovery recreated missing device", err)
					}
				} else {
					var admission map[string]bool
					if err != nil || json.Unmarshal(raw, &admission) != nil || len(admission) != 3 || !admission["admitted"] {
						t.Fatal("complete legacy selection lost recovery", err)
					}
				}
				if source.calls != 1 {
					t.Fatal("legacy recovery replayed enrollment")
				}
			})
		}
	}
}

func TestVaultSharedEnrollmentResumeFailsClosedAndPreservesRetrySelection(t *testing.T) {
	for _, mode := range []string{"password", "vault", "slot", "missing-device", "foreign-device", "corrupt-initial", "missing-initial", "corrupt-pending", "missing-active", "proof", "factory", "second-factory", "protect", "local-source"} {
		t.Run(mode, func(t *testing.T) {
			pending := mode == "corrupt-pending" || mode == "proof"
			h, f, p, source, payload, _ := vaultJoiningFixture(t, pending)
			switch mode {
			case "password", "vault", "slot":
				factor := map[string]any{"vaultId": p.slots.VaultID, "slotId": p.slots.Slots[0].ID, "password": []byte("recovery-test-password")}
				if mode == "password" {
					factor["password"] = []byte("wrong")
				}
				if mode == "vault" {
					factor["vaultId"] = p.slots.FileID
				}
				if mode == "slot" {
					factor["slotId"] = p.slots.FileID
				}
				payload = vaultInput(t, map[string]any{"appVersion": "1.0.0", "factors": factor})
			case "missing-device":
				if err := os.Remove(sharedDeviceEnrollmentPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "foreign-device":
				if err := os.WriteFile(sharedDeviceEnrollmentPath(f.o.TrustPath), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-initial":
				if err := os.WriteFile(sharedJoinStartupPath(f.o.TrustPath), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-initial":
				if err := os.Remove(sharedJoinStartupPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-pending":
				if err := os.WriteFile(sharedPendingEnrollmentPath(f.o.TrustPath), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-active":
				if err := os.Remove(f.o.TrustPath); err != nil {
					t.Fatal(err)
				}
			case "proof":
				f.c.verifyEnrollment = func(context.Context, sharedAdmissionSession, sharedpg.TrustBinding, sharedpg.PendingEnrollment, *sharedpg.AccountMaster, *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
					return nil, errors.New("unverified remote result")
				}
			case "factory":
				h.sharedFactory = func() *sharedAdmissionController { return nil }
			case "second-factory":
				calls := 0
				h.sharedFactory = func() *sharedAdmissionController {
					calls++
					if calls > 1 {
						return nil
					}
					c, _ := selectedDeviceController(t, f)
					return c
				}
			case "protect":
				protection := *h.sharedProtection
				protection.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("OS store unavailable") }
				h.sharedProtection = &protection
			case "local-source":
				if err := os.WriteFile(h.databasePath, []byte("legacy sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if raw, err := h.Handle(context.Background(), "shared-recover-enrollment", payload); err == nil || len(raw) != 0 {
				t.Fatal("invalid resume granted admission", mode)
			}
			if h.shared != nil || h.owner != nil || source.calls != 1 {
				t.Fatal("failed recovery retained authority or replayed invitation")
			}
			if mode != "missing-initial" {
				if _, err := os.Lstat(sharedJoinStartupPath(f.o.TrustPath)); err != nil {
					t.Fatal("failed recovery erased initial selection", err)
				}
			}
		})
	}
}

func TestSharedJoiningSelectionGuards(t *testing.T) {
	ctx := context.Background()
	for _, runtime := range []sharedAdmissionOptions{{}, {TrustPath: "relative"}} {
		if _, err := unlockSharedJoiningDevice(ctx, runtime, "", nil, nil, startupTestProtection()); err == nil {
			t.Fatal("invalid runtime")
		}
	}
	h, f, p, _, _, _ := vaultJoiningFixture(t, false)
	if _, err := unlockSharedJoiningDevice(nil, f.o, "", nil, nil, h.startupProtection()); err == nil {
		t.Fatal("nil context")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := unlockSharedJoiningDevice(canceled, f.o, "", nil, nil, h.startupProtection()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	selection, err := unlockSharedJoiningDevice(ctx, f.o, p.slots.Slots[0].ID, []byte("recovery-test-password"), nil, h.startupProtection())
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	if err := selection.reconcileInitialEnrollment(nil, f.c); err == nil {
		t.Fatal("nil reconciliation")
	}
	if err := (&sharedSelectedDevice{}).reconcileInitialEnrollment(ctx, f.c); err == nil {
		t.Fatal("missing initial selection")
	}
	if err := selection.reconcileInitialEnrollment(ctx, nil); err == nil {
		t.Fatal("missing recovery controller")
	}
	if selection.options.Binding != f.o.Binding || selection.options.Settings.Database != "" {
		t.Fatal("caller supplied connection settings trusted")
	}
}
