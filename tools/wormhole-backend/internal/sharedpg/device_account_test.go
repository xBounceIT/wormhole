package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func deviceAccountSelection(t *testing.T, raw []byte) DeviceUnlockSelection {
	t.Helper()
	slots, _, err := DecodeDeviceEnrollmentFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotPassword {
			return DeviceUnlockSelection{slots.VaultID, slots.FileID, slot.ID, slots.Sequence}
		}
	}
	t.Fatal("password slot missing")
	return DeviceUnlockSelection{}
}

func TestDeviceAccountOwners(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	_, journal, err := f.prepare(f.setup)
	if err != nil {
		t.Fatal(err)
	}
	selection := deviceAccountSelection(t, f.target)
	for _, pending := range []bool{false, true} {
		var owner *UnlockedDeviceAccount
		if pending {
			owner, err = OpenDeviceTransitionAccount(context.Background(), journal, selection, []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
		} else {
			owner, err = OpenDeviceAccount(context.Background(), f.target, selection, []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = owner.Locked()
		if raw, e := json.Marshal(owner); e != nil || string(raw) != "{}" {
			t.Fatal("owner serialized", e)
		}
		if err := owner.BorrowDeviceStorage(func(key, raw []byte) error {
			if !bytes.Equal(key, f.storage) || !bytes.Equal(raw, f.target) {
				t.Fatal("wrong storage")
			}
			raw[0] ^= 1
			return owner.Borrow(func(master *AccountMaster, root *DeviceTrustRoot) error {
				if root.Binding() != f.b {
					t.Fatal("wrong binding")
				}
				return root.Use(func(key []byte) error {
					if !bytes.Equal(key, f.next) {
						t.Fatal("wrong root")
					}
					return master.Use(func([]byte, vault.KDFPreset, bool) error { return nil })
				})
			})
		}); err != nil {
			t.Fatal(err)
		}
		if err := owner.BorrowDeviceStorage(func([]byte, []byte) error { return nil }); err != nil {
			t.Fatal("file alias", err)
		}
		called := false
		err = owner.BorrowTransition(func(master *AccountMaster, root *DeviceTrustRoot, record TrustRootTransition) error {
			called = true
			if record.Device == nil {
				t.Fatal("lost journal")
			}
			return root.Use(func([]byte) error { return master.Use(func([]byte, vault.KDFPreset, bool) error { return nil }) })
		})
		if pending != (err == nil) || pending != called {
			t.Fatal("transition access", err)
		}
		if owner.Borrow(nil) == nil || owner.BorrowDeviceStorage(nil) == nil || owner.BorrowTransition(nil) == nil {
			t.Fatal("nil callback")
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		if owner.Locked() || owner.Borrow(func(*AccountMaster, *DeviceTrustRoot) error { t.Fatal("closed borrow"); return nil }) == nil {
			t.Fatal("closed owner")
		}
		if owner.BorrowDeviceStorage(func([]byte, []byte) error { return nil }) == nil || owner.BorrowTransition(func(*AccountMaster, *DeviceTrustRoot, TrustRootTransition) error { return nil }) == nil {
			t.Fatal("closed secrets")
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeviceAccountInvalidInputsAndCleanup(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	selection := deviceAccountSelection(t, f.target)
	for _, mode := range []string{"nil-context", "canceled", "zero-floor", "empty-slot", "wrong-slot", "recovery-slot", "wrong-vault", "wrong-file", "rollback", "empty-password", "large-password", "wrong-password", "bad-ask", "unknown-floor", "unsupported-floor", "malformed", "bad-mac", "bad-envelope", "low-slot", "allocate", "copy", "cancel-copy", "cleanup", "wrong-journal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw := f.target
			selected := selection
			password, ask := []byte("transition-new-password"), f.ask
			floor := vault.Default
			var pending []byte
			memory := &masterMemoryProbe{data: make([]byte, 32)}
			allocate := func(bool) (accountMasterMemory, error) { return memory, nil }
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "zero-floor":
				selected.MinimumSequence = 0
			case "empty-slot":
				selected.SlotID = ""
			case "wrong-slot":
				selected.SlotID = uuid.NewString()
			case "recovery-slot":
				slots, _, _ := DecodeDeviceEnrollmentFile(raw)
				selected.SlotID = slots.Slots[0].ID
			case "wrong-vault":
				selected.VaultID = uuid.NewString()
			case "wrong-file":
				selected.FileID = uuid.NewString()
			case "rollback":
				selected.MinimumSequence++
			case "empty-password":
				password = nil
			case "large-password":
				password = bytes.Repeat([]byte{'x'}, 1025)
			case "wrong-password":
				password = []byte("wrong")
			case "bad-ask":
				ask = []byte{1}
			case "unknown-floor":
				floor = "unknown"
			case "unsupported-floor":
				floor = vault.Hardened
			case "malformed":
				raw = []byte("{}")
			case "bad-mac", "bad-envelope", "low-slot":
				var file deviceEnrollmentFile
				if err := json.Unmarshal(raw, &file); err != nil {
					t.Fatal(err)
				}
				if mode == "bad-mac" || mode == "low-slot" {
					slots, _, _ := DecodeDeviceEnrollmentFile(raw)
					if mode == "bad-mac" {
						slots.Authentication[0] ^= 1
					} else {
						for i := range slots.Slots {
							if slots.Slots[i].ID == selected.SlotID {
								slots.Slots[i].Preset = vault.KDFLow
							}
						}
					}
					file.Slots, _ = json.Marshal(slots)
				} else {
					var envelope vault.Envelope
					json.Unmarshal(file.Enrollment, &envelope)
					envelope.Ciphertext[0] ^= 1
					file.Enrollment, _ = json.Marshal(envelope)
				}
				raw, _ = json.Marshal(file)
			case "allocate":
				allocate = func(bool) (accountMasterMemory, error) { return nil, securemem.ErrUnavailable }
			case "copy":
				memory.useError = securemem.ErrUnavailable
			case "cancel-copy":
				memory.afterUse = cancel
			case "cleanup":
				memory.useError = securemem.ErrUnavailable
				memory.failClose = true
			case "wrong-journal":
				pending = []byte("{}")
			}
			owner, err := openDeviceAccount(ctx, raw, pending, selected, password, ask, vault.Default, floor, allocate)
			if mode == "low-slot" && !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("low slot reached password authentication", err)
			}
			if err == nil {
				if owner != nil {
					owner.Close()
				}
				t.Fatal("invalid input accepted")
			}
			if mode == "cleanup" {
				if owner == nil || !errors.Is(err, ErrDeviceStorageCleanup) || !memory.retired {
					t.Fatal("cleanup owner lost", err)
				}
				memory.failClose = false
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			} else if owner != nil {
				owner.Close()
				t.Fatal("failed owner retained without cleanup failure")
			}
		})
	}
	if owner, err := OpenDeviceTransitionAccount(context.Background(), []byte("{}"), selection, []byte("password"), nil, vault.Default, vault.Default); err == nil || owner != nil {
		t.Fatal("invalid wrapper")
	}
}

func TestDeviceAccountRequiresASK(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	source := devicePasswordSource(t, p, key, slots)
	ask := bytes.Repeat([]byte{29}, 32)
	password := []byte("protected-password")
	raw, err := PrepareDevicePasswordFile(context.Background(), key, source, slots.VaultID, slots.FileID, 1, password, ask, vault.Default, vault.Standard)
	if err != nil {
		t.Fatal(err)
	}
	selection := deviceAccountSelection(t, raw)
	for _, factor := range [][]byte{nil, bytes.Repeat([]byte{30}, 32)} {
		if owner, err := OpenDeviceAccount(context.Background(), raw, selection, password, factor, vault.Default, vault.Standard); err == nil || owner != nil {
			if owner != nil {
				owner.Close()
			}
			t.Fatal("ASK bypassed", err)
		}
	}
	owner, err := OpenDeviceAccount(context.Background(), raw, selection, password, ask, vault.Default, vault.Standard)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := owner.Borrow(func(master *AccountMaster, _ *DeviceTrustRoot) error {
		return master.Use(func(_ []byte, _ vault.KDFPreset, used bool) error {
			if !used {
				t.Fatal("ASK fact lost")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceAccountCloseRetryAndBorrowIntegrity(t *testing.T) {
	storage := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	root := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	master := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	owner := &UnlockedDeviceAccount{storage: storage, root: &DeviceTrustRoot{memory: root}, master: &AccountMaster{memory: master}, file: []byte("ciphertext"), journal: []byte("ciphertext")}
	if !owner.Locked() {
		t.Fatal("lock status")
	}
	err := owner.Close()
	if !errors.Is(err, ErrDeviceStorageCleanup) || !errors.Is(err, ErrDeviceTrustRootCleanup) || !errors.Is(err, ErrAccountMasterCleanup) || !storage.retired || !root.retired || !master.retired {
		t.Fatal("partial close", err)
	}
	storage.failClose, root.failClose, master.failClose = false, false, false
	if err := owner.Close(); err != nil || owner.storage != nil || owner.root != nil || owner.master != nil || owner.file != nil || owner.journal != nil {
		t.Fatal("retry", err)
	}
	var missing *UnlockedDeviceAccount
	if missing.Locked() || missing.Close() != nil || missing.Borrow(nil) == nil || missing.BorrowDeviceStorage(nil) == nil || missing.BorrowTransition(nil) == nil {
		t.Fatal("nil owner")
	}
	f := newDeviceTransitionFixture(t)
	_, journal, err := f.prepare(f.setup)
	if err != nil {
		t.Fatal(err)
	}
	owner, err = OpenDeviceTransitionAccount(context.Background(), journal, deviceAccountSelection(t, f.target), []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.journal = []byte("{}")
	if owner.BorrowTransition(func(*AccountMaster, *DeviceTrustRoot, TrustRootTransition) error {
		t.Fatal("bad journal exposed")
		return nil
	}) == nil {
		t.Fatal("journal not checked")
	}
	owner.file = []byte("{}")
	if owner.BorrowDeviceStorage(func([]byte, []byte) error { t.Fatal("bad file exposed"); return nil }) == nil {
		t.Fatal("file not checked")
	}
	owner.file = bytes.Clone(f.target)
	if err := owner.storage.With(func(key []byte) error { key[0] ^= 1; return nil }); err != nil {
		t.Fatal(err)
	}
	if owner.BorrowDeviceStorage(func([]byte, []byte) error { t.Fatal("bad key exposed"); return nil }) == nil {
		t.Fatal("key not checked")
	}
}
