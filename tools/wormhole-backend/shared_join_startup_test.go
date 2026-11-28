package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedJoinPasswordPreparationFixture(t *testing.T) (*sharedInvitationJoin, *recoveryFixture, *preparedDeviceProbe, *invitationJoinProbe) {
	t.Helper()
	j, f, p, source := preparedDeviceJoinFixture(t)
	slot, err := vault.CreatePasswordSlot(context.Background(), p.slots.VaultID, uuid.NewString(), p.slots.RootKeyVersion, p.key, []byte("recovery-test-password"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	p.slots.Slots = []vault.Slot{slot}
	raw, err := vault.EncodeSlotFile(p.key, p.slots)
	if err != nil {
		t.Fatal(err)
	}
	p.slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return j, f, p, source
}

func sharedJoinStartupFixture(t *testing.T) (*sharedInvitationJoin, *recoveryFixture, *preparedDeviceProbe, sharedJoinStartup, sharedStartupProtection) {
	t.Helper()
	j, f, p, _ := sharedJoinPasswordPreparationFixture(t)
	initial, err := makeSharedJoinStartup(f.o, &sharedJoinDeviceStorage{root: p.key, slots: p.slots, envelope: p.envelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.o.TrustPath), 0700); err != nil {
		t.Fatal(err)
	}
	return j, f, p, initial, startupTestProtection()
}

func TestSharedJoinStartupStageAndExactDurabilityConfirmation(t *testing.T) {
	ctx := context.Background()
	_, f, p, initial, protection := sharedJoinStartupFixture(t)
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, true); err == nil {
		t.Fatal("confirmation created missing selection")
	}
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); err != nil {
		t.Fatal(err)
	}
	if err := requireNoSharedJoinStartup(f.o.TrustPath); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("missing selection gate", err)
	}
	actual, err := readSharedJoinStartup(f.o.TrustPath, protection)
	if err != nil || !reflect.DeepEqual(actual, initial) {
		t.Fatal("selection not independently protected", err)
	}
	if !bytes.Equal(actual.DeviceFile, initial.DeviceFile) {
		t.Fatal("encrypted retry snapshot lost")
	}
	sealed, err := os.ReadFile(sharedJoinStartupPath(f.o.TrustPath))
	if err != nil || bytes.Contains(sealed, p.key) || bytes.Contains(sealed, f.root) || bytes.Contains(sealed, []byte(initial.LoginName)) {
		t.Fatal("plaintext material persisted", err)
	}
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("creation replaced selection", err)
	}
	old := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = old })
	count := 0
	privateFileDirectorySync = func(string) error { count++; return errors.New("sync uncertain") }
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, true); !errors.Is(err, errSharedTrustCommitUncertain) || count == 0 {
		t.Fatal("readback mistaken for durability", err)
	}
	privateFileDirectorySync = old
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, true); err != nil {
		t.Fatal("exact retry", err)
	}
	foreign := initial
	foreign.Binding.DeviceID = uuid.New()
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, foreign, protection, true); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("adopted another selection", err)
	}
	if err := removeSharedJoinStartupLocked(f.o.TrustPath, foreign, protection); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("erased competing selection", err)
	}
	if err := removeSharedJoinStartupLocked(f.o.TrustPath, initial, protection); err != nil {
		t.Fatal(err)
	}
	if err := requireNoSharedJoinStartup(f.o.TrustPath); err != nil {
		t.Fatal(err)
	}
	if err := removeSharedJoinStartupLocked(f.o.TrustPath, initial, protection); !errors.Is(err, errSharedTrustMissing) {
		t.Fatal("missing record mistaken for exact removal", err)
	}
	if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); err != nil {
		t.Fatal(err)
	}
	privateFileDirectorySync = func(string) error { return errors.New("uncertain removal") }
	if err := removeSharedJoinStartupLocked(f.o.TrustPath, initial, protection); !errors.Is(err, errSharedTrustCommitUncertain) {
		t.Fatal("unconfirmed removal accepted", err)
	}
	privateFileDirectorySync = old
}

func TestSharedJoinStartupRejectsMalformedUntrustedAndForeignState(t *testing.T) {
	for _, mode := range []string{"version", "purpose", "path", "workspace", "user", "device", "key", "key-version", "login", "login-control", "device-file", "duplicate", "unknown", "noncanonical", "oversize", "unprotect", "empty", "directory"} {
		t.Run(mode, func(t *testing.T) {
			_, f, _, initial, protection := sharedJoinStartupFixture(t)
			path := f.o.TrustPath
			switch mode {
			case "version":
				initial.FormatVersion++
			case "purpose":
				initial.Purpose = "wormhole/shared-startup/v1"
			case "path":
				path = filepath.Join(t.TempDir(), "foreign.trust")
			case "workspace":
				initial.Binding.WorkspaceID = uuid.Nil
			case "user":
				initial.Binding.UserID = uuid.Nil
			case "device":
				initial.Binding.DeviceID = uuid.Nil
			case "key":
				initial.Binding.KeyID = uuid.Nil
			case "key-version":
				initial.Binding.KeyVersion = 0
			case "login":
				initial.LoginName = "bad\x00login"
			case "login-control":
				initial.LoginName = "bad\nlogin"
			case "device-file":
				initial.DeviceFile = []byte("invalid")
			}
			raw, err := json.Marshal(initial)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "duplicate":
				raw = append([]byte(`{"formatVersion":1,`), raw[1:]...)
			case "unknown":
				raw = append([]byte(`{"trusted":true,`), raw[1:]...)
			case "noncanonical":
				raw = append([]byte(" "), raw...)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), maxSharedJoinStartupBytes+1)
			case "empty":
				raw = nil
			}
			sealed, err := protection.protect(sharedJoinStartupPath(path), raw)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unprotect" {
				sealed[0] ^= 1
			}
			if mode == "directory" {
				if err := os.Mkdir(sharedJoinStartupPath(path), 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(sharedJoinStartupPath(path), sealed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSharedJoinStartup(path, protection); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}

func TestSharedJoinStartupNativeAdmissionAndStorageFailures(t *testing.T) {
	ctx := context.Background()
	_, f, p, initial, protection := sharedJoinStartupFixture(t)
	if _, err := makeSharedJoinStartup(f.o, nil); err == nil {
		t.Fatal("nil native storage")
	}
	for _, mode := range []string{"binding", "key", "floor", "path"} {
		o := f.o
		d := &sharedJoinDeviceStorage{root: p.key, slots: p.slots, envelope: p.envelope}
		switch mode {
		case "binding":
			o.Binding.DeviceID = uuid.New()
		case "key":
			d.root = make([]byte, 32)
		case "floor":
			o.OSFloor = "unknown"
		case "path":
			o.TrustPath = "relative"
		}
		if _, err := makeSharedJoinStartup(o, d); err == nil {
			t.Fatal("bad admission accepted", mode)
		}
	}
	if _, err := readSharedJoinStartup("relative", protection); err == nil {
		t.Fatal("relative read")
	}
	if _, err := readSharedJoinStartup(f.o.TrustPath, sharedStartupProtection{}); err == nil {
		t.Fatal("missing OS authentication")
	}
	if err := writeSharedJoinStartup(nil, f.o.TrustPath, initial, protection, false); err == nil {
		t.Fatal("nil context")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := writeSharedJoinStartup(canceled, f.o.TrustPath, initial, protection, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, mode := range []string{"nil-protect", "protect", "empty-protect", "oversize-protect", "held", "trust", "transition", "anchor", "device", "connection", "pending"} {
		t.Run(mode, func(t *testing.T) {
			_, f, _, initial, protection := sharedJoinStartupFixture(t)
			switch mode {
			case "nil-protect":
				protection.protect = nil
			case "protect":
				protection.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("store failure") }
			case "empty-protect":
				protection.protect = func(string, []byte) ([]byte, error) { return nil, nil }
			case "oversize-protect":
				protection.protect = func(string, []byte) ([]byte, error) { return make([]byte, 2*maxSharedJoinStartupBytes+1), nil }
			case "held":
				release, err := tryAcquireExclusiveFileLock(f.o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			default:
				path := map[string]string{"trust": f.o.TrustPath, "transition": sharedTrustTransitionPath(f.o.TrustPath), "anchor": sharedStartupAnchorPath(f.o.TrustPath), "device": sharedDeviceEnrollmentPath(f.o.TrustPath), "connection": sharedTransportSetupPath(f.o.TrustPath), "pending": sharedPendingEnrollmentPath(f.o.TrustPath)}[mode]
				if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); err == nil {
				t.Fatal("unsafe creation", mode)
			}
		})
	}
}

func TestSharedPreparedJoinPublishesInitialSelectionBeforeItsSingleDispatch(t *testing.T) {
	for _, mode := range []string{"receipt", "uncertain", "unknown-outcome", "sync-retry", "sync-failure", "protect-failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			j, f, p, source := sharedJoinPasswordPreparationFixture(t)
			protection := startupTestProtection()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oldSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = oldSync })
			if mode == "sync-retry" || mode == "sync-failure" {
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					if mode == "sync-failure" || calls == 1 {
						return errors.New("uncertain sync")
					}
					return oldSync(path)
				}
			}
			if mode == "protect-failure" {
				protection.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("store failure") }
			}
			if mode == "cancel" {
				protect := protection.protect
				protection.protect = func(path string, raw []byte) ([]byte, error) {
					sealed, err := protect(path, raw)
					cancel()
					return sealed, err
				}
			}
			source.commit = func(context.Context, *sharedpg.PreparedInvitationCommit) error {
				initial, err := readSharedJoinStartup(f.o.TrustPath, protection)
				if err != nil || initial.Binding != f.o.Binding {
					t.Fatal("SQL before protected selection", err)
				}
				raw, err := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
				if err != nil || !bytes.Equal(initial.DeviceFile, raw) {
					t.Fatal("SQL before exact recoverable device", err)
				}
				if mode == "uncertain" || mode == "unknown-outcome" {
					return sharedpg.ErrInvitationCommitUncertain
				}
				return nil
			}
			if mode == "unknown-outcome" {
				j.newRecovery = func() sharedJoinRecovery {
					return &joinRecoveryProbe{run: func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
						return nil, errors.New("remote evidence unavailable")
					}}
				}
			}
			result, err := j.joinPreparedWithStartup(ctx, f.o, p, &protection)
			if mode == "sync-failure" || mode == "protect-failure" || mode == "cancel" {
				if err == nil || source.calls != 0 {
					t.Fatal("failed staging dispatched SQL", result, err)
				}
				privateFileDirectorySync = oldSync
				if err := j.DiscardDevicePreparation(context.Background(), f.root, p.key); err != nil {
					t.Fatal("retained cleanup retry", err)
				}
				if err := requireNoSharedJoinStartup(f.o.TrustPath); err != nil {
					t.Fatal("unsubmitted selection left behind", err)
				}
			} else {
				if source.calls != 1 || result == nil || !result.Submitted {
					t.Fatal("not one dispatch", result, err)
				}
				if mode == "unknown-outcome" {
					if err == nil || result.Confirmed {
						t.Fatal("unknown commit claimed complete")
					}
				} else if err != nil || !result.Confirmed {
					t.Fatal("join", result, err)
				}
				if _, err := readSharedJoinStartup(f.o.TrustPath, protection); err != nil {
					t.Fatal("submitted retry selection lost", err)
				}
				if err := j.DiscardDevicePreparation(context.Background(), f.root, p.key); !errors.Is(err, errSharedTrustConflict) {
					t.Fatal("submitted selection erased", err)
				}
			}
		})
	}
}

func TestSharedJoinStartupRequiresUsablePasswordSlots(t *testing.T) {
	for _, mode := range []string{"recovery-only", "os", "low-kdf", "encrypted", "initializing"} {
		t.Run(mode, func(t *testing.T) {
			_, f, p, initial, _ := sharedJoinStartupFixture(t)
			slots := p.slots
			var slot vault.Slot
			var err error
			switch mode {
			case "recovery-only":
				slot, err = vault.CreateRecoverySlot(slots.VaultID, uuid.NewString(), slots.RootKeyVersion, p.key, bytes.Repeat([]byte{18}, 32))
				slots.Slots = []vault.Slot{slot}
			case "os":
				slots.FormatVersion = 3
				slot, err = vault.CreateUnprotectedSlot(slots.VaultID, uuid.NewString(), slots.RootKeyVersion, p.key, bytes.Repeat([]byte{19}, 32))
				slots.Slots = []vault.Slot{slot}
			case "low-kdf":
				slot, err = vault.CreatePasswordSlot(context.Background(), slots.VaultID, uuid.NewString(), slots.RootKeyVersion, p.key, []byte("synthetic password"), nil, vault.KDFLow)
				slots.Slots = []vault.Slot{slot}
			case "encrypted":
				slots.Encrypted = true
				slot, err = vault.CreateRecoverySlot(slots.VaultID, uuid.NewString(), slots.RootKeyVersion, p.key, bytes.Repeat([]byte{18}, 32))
				slots.Slots = append(slots.Slots, slot)
			case "initializing":
				slots.Initializing = true
				slots.FormatVersion = 3
			}
			if err != nil {
				t.Fatal(err)
			}
			rawSlots, err := vault.EncodeSlotFile(p.key, slots)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeviceFile, err = json.Marshal(struct {
				FormatVersion uint16          `json:"formatVersion"`
				Slots         json.RawMessage `json:"slots"`
				Enrollment    json.RawMessage `json:"enrollment"`
			}{1, rawSlots, p.envelope})
			if err != nil {
				t.Fatal(err)
			}
			if initial.valid(f.o.TrustPath) {
				t.Fatal("unsupported initial device selected")
			}
		})
	}
}

func TestSharedJoinStartupDescribesRetryWithoutKeysSQLOrFallback(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"snapshot-only", "pending", "corrupt", "local", "local-slots", "transition", "held", "canceled", "directory"} {
		t.Run(mode, func(t *testing.T) {
			_, f, p, _, protection := sharedJoinStartupFixture(t)
			database := filepath.Join(t.TempDir(), "workspace.db")
			f.o.TrustPath = sharedWorkspaceTrustPath(database)
			initial, err := makeSharedJoinStartup(f.o, &sharedJoinDeviceStorage{root: p.key, slots: p.slots, envelope: p.envelope})
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); err != nil {
				t.Fatal(err)
			}
			h := &vaultFoundationHandler{databasePath: database, sharedProtection: &protection}
			var payload []byte
			probe := ctx
			switch mode {
			case "pending":
				if err := os.WriteFile(sharedPendingEnrollmentPath(f.o.TrustPath), []byte("pending, not an ordinary unlock"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(sharedJoinStartupPath(f.o.TrustPath), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "local", "local-slots":
				path := database
				if mode == "local-slots" {
					path = vaultSlotPath(database)
				}
				if err := os.WriteFile(path, []byte("untouched legacy sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			case "transition":
				if err := os.WriteFile(sharedTrustTransitionPath(f.o.TrustPath), []byte("conflicting transition"), 0600); err != nil {
					t.Fatal(err)
				}
			case "held":
				release, err := tryAcquireExclusiveFileLock(f.o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				probe = canceled
			case "directory":
				if err := os.Remove(sharedJoinStartupPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(sharedJoinStartupPath(f.o.TrustPath), 0700); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := h.startup(probe, payload)
			if mode == "snapshot-only" || mode == "pending" {
				var metadata vaultStartupMetadata
				if err != nil || json.Unmarshal(raw, &metadata) != nil || metadata.SharedJoin == nil || metadata.Shared != nil || metadata.NewWorkspace || metadata.Legacy != nil || metadata.Slots == nil || !metadata.Slots.Encrypted || metadata.Slots.VaultID != p.slots.VaultID {
					t.Fatal("wrong retry hint", err, string(raw))
				}
				if metadata.SharedJoin.LastLoginName != initial.LoginName {
					t.Fatal("lost public login")
				}
				for _, path := range []string{database, vaultSlotPath(database), sharedDeviceEnrollmentPath(f.o.TrustPath)} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("probe recreated source/device", err)
					}
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatal("unsafe retry became a fallback")
			}
			if h.owner != nil || h.shared != nil || h.releaseWorkspace != nil || h.rotationMaterial != nil {
				t.Fatal("metadata acquired authority")
			}
		})
	}
	for _, h := range []*vaultFoundationHandler{{}, {databasePath: "relative"}} {
		if _, _, err := h.describeSharedJoinStartup(ctx); err == nil {
			t.Fatal("invalid native source")
		}
	}
	h := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db")}
	if _, _, err := h.describeSharedJoinStartup(nil); err == nil {
		t.Fatal("nil context")
	}
}

func TestSharedJoinStartupDiscardAuthenticatesAllOwnedFilesBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"owned", "foreign", "missing", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			j, f, _, initial, protection := sharedJoinStartupFixture(t)
			if err := writeSharedJoinStartup(ctx, f.o.TrustPath, initial, protection, false); err != nil {
				t.Fatal(err)
			}
			j.preparation = &sharedJoinPreparation{options: f.o, startup: &initial, startupProtection: &protection}
			if mode == "foreign" {
				foreign := initial
				foreign.Binding.DeviceID = uuid.New()
				raw, _ := json.Marshal(foreign)
				sealed, _ := protection.protect(sharedJoinStartupPath(f.o.TrustPath), raw)
				if err := os.WriteFile(sharedJoinStartupPath(f.o.TrustPath), sealed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing" {
				if err := os.Remove(sharedJoinStartupPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			}
			old := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = old })
			if mode == "uncertain" {
				privateFileDirectorySync = func(string) error { return errors.New("uncertain deletion") }
			}
			err := j.DiscardPreparation(ctx, f.root)
			if mode == "foreign" {
				if !errors.Is(err, errSharedTrustConflict) {
					t.Fatal("foreign selection erased", err)
				}
				j.preparation = nil
				return
			}
			if mode == "uncertain" {
				if err == nil || j.preparation == nil {
					t.Fatal("cleanup obligation dropped")
				}
				privateFileDirectorySync = old
				if err := j.DiscardPreparation(ctx, f.root); err != nil {
					t.Fatal("cleanup retry", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err := requireNoSharedJoinStartup(f.o.TrustPath); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedJoinStartupRetiresOnlyAfterDurableActiveSelection(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"success", "uncertain-anchor", "foreign-selection", "corrupt-selection", "missing-active-trust"} {
		t.Run(mode, func(t *testing.T) {
			j, f, p, _ := sharedJoinPasswordPreparationFixture(t)
			protection := startupTestProtection()
			result, err := j.joinPreparedWithStartup(ctx, f.o, p, &protection)
			if err != nil || result == nil || !result.Confirmed {
				t.Fatal("join did not confirm", err)
			}
			initial, err := readSharedJoinStartup(f.o.TrustPath, protection)
			if err != nil {
				t.Fatal(err)
			}
			selection := sharedpg.DeviceUnlockSelection{VaultID: p.slots.VaultID, FileID: p.slots.FileID, SlotID: p.slots.Slots[0].ID, MinimumSequence: p.slots.Sequence}
			owner, err := sharedpg.OpenDeviceAccount(ctx, initial.DeviceFile, selection, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
			if err != nil {
				t.Fatal("native account", err)
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			if _, err := unlockSharedSelectedDevice(ctx, f.o, selection.SlotID, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, protection); !errors.Is(err, errSharedTrustConflict) {
				t.Fatal("ordinary unlock bypassed pending initial selection", err)
			}
			if mode == "foreign-selection" {
				initial.Binding.DeviceID = uuid.New()
				raw, _ := json.Marshal(initial)
				sealed, _ := protection.protect(sharedJoinStartupPath(f.o.TrustPath), raw)
				if err := os.WriteFile(sharedJoinStartupPath(f.o.TrustPath), sealed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "corrupt-selection" {
				if err := os.WriteFile(sharedJoinStartupPath(f.o.TrustPath), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing-active-trust" {
				if err := os.Remove(f.o.TrustPath); err != nil {
					t.Fatal(err)
				}
			}
			oldSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = oldSync })
			if mode == "uncertain-anchor" {
				privateFileDirectorySync = func(string) error { return errors.New("anchor durability uncertain") }
			}
			anchor, err := writeSharedStartupAnchor(ctx, f.o, owner, "Confirmed shared workspace", 0, protection)
			if mode == "foreign-selection" || mode == "corrupt-selection" || mode == "missing-active-trust" {
				if err == nil {
					t.Fatal("invalid selection retired")
				}
				if _, err := os.Lstat(sharedJoinStartupPath(f.o.TrustPath)); err != nil {
					t.Fatal("retry record erased", err)
				}
				if _, err := os.Lstat(sharedStartupAnchorPath(f.o.TrustPath)); !os.IsNotExist(err) {
					t.Fatal("unverified selection published", err)
				}
				return
			}
			if mode == "uncertain-anchor" {
				if !errors.Is(err, errSharedTrustCommitUncertain) {
					t.Fatal("uncertain anchor accepted", err)
				}
				if _, err := readSharedJoinStartup(f.o.TrustPath, protection); err != nil {
					t.Fatal("uncertain anchor lost retry authority", err)
				}
				privateFileDirectorySync = oldSync
				anchor, err = writeSharedStartupAnchor(ctx, f.o, owner, "Confirmed shared workspace", 0, protection)
			}
			if err != nil || anchor.VaultID != selection.VaultID || anchor.Binding != f.o.Binding {
				t.Fatal("active selection", err)
			}
			if err := requireNoSharedJoinStartup(f.o.TrustPath); err != nil {
				t.Fatal("confirmed initial selection retained", err)
			}
			if _, err := readSharedStartupAnchor(f.o.TrustPath, protection); err != nil {
				t.Fatal("active anchor not recoverable", err)
			}
		})
	}
}
