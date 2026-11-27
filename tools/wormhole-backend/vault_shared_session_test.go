package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultSharedFixture(t *testing.T) (*vaultFoundationHandler, *recoveryFixture, []byte, **sharedAdmissionProbe) {
	t.Helper()
	f, owner := sharedStartupFixture(t)
	database := filepath.Join(t.TempDir(), "workspace.db")
	path := sharedWorkspaceTrustPath(database)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".connection", ".device"} {
		raw, err := os.ReadFile(f.o.TrustPath + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+suffix, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.o.TrustPath = path
	p := startupTestProtection()
	a, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Workspace", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	err = owner.BorrowDeviceStorage(func(_ []byte, raw []byte) error {
		slots, _, e := sharedpg.DecodeDeviceEnrollmentFile(raw)
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				id = slot.ID
			}
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	var probe *sharedAdmissionProbe
	h := &vaultFoundationHandler{databasePath: database, sharedProtection: &p, sharedFactory: func() *sharedAdmissionController {
		c, p := selectedDeviceController(t, f)
		probe = p
		return c
	}}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	payload, err := json.Marshal(map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": a.VaultID, "slotId": id, "password": []byte("recovery-test-password")}})
	if err != nil {
		t.Fatal(err)
	}
	return h, f, payload, &probe
}

func TestVaultSharedSessionLifecycle(t *testing.T) {
	h, f, payload, probe := vaultSharedFixture(t)
	raw, err := h.Handle(context.Background(), "shared-unlock", payload)
	if err != nil || h.shared == nil || !h.shared.controller.Unlocked() || h.owner != nil {
		t.Fatal("service shared admission", string(raw), err)
	}
	if err := h.shared.selected.account.Borrow(func(*sharedpg.AccountMaster, *sharedpg.DeviceTrustRoot) error { return nil }); err == nil {
		t.Fatal("account roots retained after admission")
	}
	var result map[string]bool
	if json.Unmarshal(raw, &result) != nil || len(result) != 3 || !result["admitted"] || !result["orgEscrow"] {
		t.Fatal("response", string(raw))
	}
	if _, err := acquireWorkspaceOwnership(h.databasePath, false); !errors.Is(err, errWorkspaceInUse) {
		t.Fatal("workspace lease missing", err)
	}
	for _, operation := range []string{"unlock", "initialize", "enrollment-begin", "credential-list", "shared-unlock", "shared-recover-password"} {
		if _, err := h.Handle(context.Background(), operation, payload); err == nil {
			t.Fatal("mixed mode", operation)
		}
	}
	a, err := readSharedStartupAnchor(f.o.TrustPath, h.startupProtection())
	if err == nil && (h.shared.vaultID != a.VaultID || h.shared.vaultID == a.Binding.WorkspaceID.String()) {
		t.Fatal("device slot and workspace identities were conflated")
	}
	if err != nil || a.Revision != 2 {
		t.Fatal("anchor not refreshed", err)
	}
	if !h.ExitOnCancel("shared-unlock") || !h.ExitOnCancel("shared-recover-password") {
		t.Fatal("unsafe cancel")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if (*probe).closes.Load() == 0 {
		t.Fatal("network owner leaked")
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, false)
	if err != nil {
		t.Fatal("lease retained", err)
	}
	release()
	if _, err := h.Handle(context.Background(), "shared-unlock", payload); err == nil {
		t.Fatal("closed handler reused")
	}
}

func TestVaultSharedSessionFailureCleanup(t *testing.T) {
	for _, mode := range []string{"payload", "nil-context", "canceled", "wrong-vault", "wrong-password", "missing-anchor", "local-slots", "local-database", "missing-directory", "locked", "nil-controller", "anchor-write", "retired-during-write", "network", "cleanup", "recovery-without-journal"} {
		t.Run(mode, func(t *testing.T) {
			h, f, payload, probe := vaultSharedFixture(t)
			ctx := context.Background()
			op := "shared-unlock"
			var held func()
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			input, err := decodeVaultUnlock(fields["factors"])
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "payload":
				payload = []byte(`{"password":"unexpected"}`)
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-vault", "wrong-password":
				if mode == "wrong-vault" {
					input.VaultID = uuid.NewString()
				} else {
					input.Password = []byte("wrong")
				}
				payload, err = json.Marshal(map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": input.VaultID, "slotId": input.SlotID, "password": input.Password}})
				if err != nil {
					t.Fatal(err)
				}
			case "missing-anchor":
				if err := os.Remove(sharedStartupAnchorPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "local-slots":
				if err := os.WriteFile(vaultSlotPath(h.databasePath), []byte("broken local vault"), 0600); err != nil {
					t.Fatal(err)
				}
			case "local-database":
				if err := os.WriteFile(h.databasePath, []byte("legacy database"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-directory":
				h.databasePath = filepath.Join(t.TempDir(), "missing.db")
			case "locked":
				held, err = acquireWorkspaceOwnership(h.databasePath, true)
				if err != nil {
					t.Fatal(err)
				}
				defer held()
			case "nil-controller":
				h.sharedFactory = func() *sharedAdmissionController { return nil }
			case "anchor-write":
				h.sharedProtection.protect = func(string, []byte) ([]byte, error) { return nil, os.ErrPermission }
			case "retired-during-write":
				protect := h.sharedProtection.protect
				h.sharedProtection.protect = func(path string, raw []byte) ([]byte, error) {
					if err := h.shared.controller.Close(context.Background()); err != nil {
						return nil, err
					}
					return protect(path, raw)
				}
			case "network", "cleanup":
				factory := h.sharedFactory
				h.sharedFactory = func() *sharedAdmissionController {
					c := factory()
					(*probe).open = func(context.Context, sharedpg.Settings) error { return sharedpg.ErrConfiguration }
					if mode == "cleanup" {
						(*probe).closeFailure.Store(true)
					}
					return c
				}
			case "recovery-without-journal":
				op = "shared-recover-password"
			}
			_, err = h.openShared(ctx, op, payload)
			input.wipe()
			if err == nil {
				t.Fatal("failed open succeeded")
			}
			if mode == "cleanup" {
				(*probe).closeFailure.Store(false)
				if !h.closed || h.shared == nil || !errors.Is(err, vaultwire.ErrRetired) {
					t.Fatal("cleanup uncertainty lost", err)
				}
				if _, e := acquireWorkspaceOwnership(h.databasePath, false); e == nil {
					t.Fatal("lease released during uncertain cleanup")
				}
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			} else if h.shared != nil {
				t.Fatal("failed session retained")
			}
			if held != nil {
				held()
				held = nil
			}
			release, err := acquireWorkspaceOwnership(h.databasePath, false)
			if err != nil {
				t.Fatal("failed operation leaked lease", err)
			}
			release()
		})
	}
}

func TestVaultSharedMarkerBlocksLegacyAndLocal(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{true: "directory", false: "corrupt-file"}[directory], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			if err := requireNoSharedWorkspace(path); err != nil {
				t.Fatal(err)
			}
			var err error
			if directory {
				err = os.Mkdir(sharedWorkspaceDirectory(path), 0700)
			} else {
				err = os.WriteFile(sharedWorkspaceDirectory(path), []byte("broken"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if requireLegacyWorkspace(path) != errVaultOwnerRequired || requireLegacySlotAbsent(path) != errVaultOwnerRequired || requireNewVaultWorkspace(path) != errVaultOwnerRequired {
				t.Fatal("marker ignored")
			}
			h := &vaultFoundationHandler{databasePath: path}
			if _, err := h.Handle(context.Background(), "unlock", nil); err != errVaultOwnerRequired {
				t.Fatal("local unlock fallback", err)
			}
			for _, op := range []string{"startup", "describe"} {
				if raw, err := h.Handle(context.Background(), op, nil); err == nil || len(raw) != 0 {
					t.Fatal("shared profile advertised as local", op, err)
				}
			}
		})
	}
}

func TestVaultSharedServiceRecoversPassword(t *testing.T) {
	h, f, payload, _ := vaultSharedFixture(t)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	input, err := decodeVaultUnlock(fields["factors"])
	if err != nil {
		t.Fatal(err)
	}
	defer input.wipe()
	current, err := unlockSharedSelectedDevice(context.Background(), f.o, input.SlotID, input.Password, nil, sharedDeviceOrdinary, h.startupProtection())
	if current != nil {
		defer current.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := current.account.PreparePasswordChange(context.Background(), []byte("new-service-password"), nil, vault.Default, vault.Default)
	if prepared != nil {
		defer prepared.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	actual := *f.account
	var login []byte
	var slotID string
	err = prepared.BorrowPasswordChange(current.account, func(old, next *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, key, raw []byte, selection sharedpg.DeviceUnlockSelection) error {
		slots, _, e := sharedpg.DecodeDeviceEnrollmentFile(raw)
		if e != nil {
			return e
		}
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				slotID = slot.ID
			}
		}
		if e := root.Use(func(newRoot []byte) error {
			state, e := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, 1)
			if e != nil {
				return e
			}
			_, e = stageSharedTrustRootTransitionWithDevice(f.o.TrustPath, f.root, newRoot, f.o.Binding, state.Revision, &sharedDevicePasswordCandidate{key, raw, selection.VaultID, selection.FileID, selection.MinimumSequence})
			return e
		}); e != nil {
			return e
		}
		return old.Use(func(oldKey []byte, _ vault.KDFPreset, _ bool) error {
			return next.Use(func(nextKey []byte, _ vault.KDFPreset, _ bool) error {
				var e error
				actual.Binding, actual.Envelope, e = vault.RewrapUserKeys(oldKey, nextKey, actual.Binding, actual.Envelope, actual.EnrollmentCertificate.Rekey.Public)
				if e != nil {
					return e
				}
				login, e = vault.DeriveKey(nextKey, nil, vault.PurposeLogin)
				return e
			})
		})
	})
	defer vault.Wipe(login)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	h.sharedFactory = func() *sharedAdmissionController {
		c, p := selectedDeviceController(t, f)
		p.loginMaterial = login
		p.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return &actual, nil }
		return c
	}
	payload, err = json.Marshal(map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": input.VaultID, "slotId": slotID, "password": []byte("new-service-password")}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Handle(context.Background(), "shared-recover-password", payload)
	if err != nil || string(raw) != `{"recovered":true}` || h.shared != nil || h.closed {
		t.Fatal("service recovery", string(raw), err)
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(sharedTrustTransitionPath(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal retained", err)
	}
}

func TestVaultSharedNativeProtectionDefault(t *testing.T) {
	p := (&vaultFoundationHandler{}).startupProtection()
	if p.protect == nil || p.unprotect == nil {
		t.Fatal("OS protection unavailable")
	}
}
