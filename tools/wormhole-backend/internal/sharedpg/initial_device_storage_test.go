package sharedpg

import (
	"bytes"
	"context"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func verifyInitialDeviceStorage(t *testing.T, p *PreparedInitialEnrollment, password, ask []byte, floor vault.Profile) {
	t.Helper()
	var expectedRoot, raw []byte
	var binding TrustBinding
	if err := p.Borrow(func(_ *AccountMaster, root *DeviceTrustRoot, _ *PreparedInvitationCommit) error {
		binding = root.Binding()
		return root.Use(func(key []byte) error { expectedRoot = bytes.Clone(key); return nil })
	}); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(expectedRoot)
	var selectedVault, selectedFile string
	if err := p.BorrowDeviceStorage(func(key []byte, slots vault.SlotFile, envelope []byte) error {
		if bytes.Equal(key, expectedRoot) {
			t.Fatal("device/account roots reused")
		}
		if len(slots.Slots) != 1 || slots.Slots[0].Kind != vault.SlotPassword || slots.Slots[0].Preset != vault.KDFV1 || slots.Slots[0].ASKRequired != (len(ask) != 0) {
			t.Fatal("wrong bootstrap slot")
		}
		selectedVault, selectedFile = slots.VaultID, slots.FileID
		var err error
		raw, err = EncodeDeviceEnrollmentFile(key, slots, envelope)
		// A consumer cannot mutate the owner's persistent file through these
		// independently decoded buffers.
		slots.Slots[0].WrappedKey.Ciphertext[0] ^= 1
		envelope[0] ^= 1
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.BorrowDeviceStorage(func([]byte, vault.SlotFile, []byte) error { return nil }); err != nil {
		t.Fatal("borrow aliases storage", err)
	}
	_ = p.DeviceStorageLocked()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.DeviceStorageLocked() || p.BorrowDeviceStorage(func([]byte, vault.SlotFile, []byte) error { t.Fatal("closed storage exposed"); return nil }) == nil {
		t.Fatal("closed storage")
	}
	slots, envelope, err := DecodeDeviceEnrollmentFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.OpenPasswordSlot(context.Background(), selectedVault, slots.Slots[0], password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(key)
	e, err := OpenDeviceEnrollment(key, slots, selectedVault, selectedFile, 1, envelope)
	if err != nil {
		t.Fatal(err)
	}
	d, policy, err := e.Derivation(vault.Default, floor)
	if err != nil {
		t.Fatal(err)
	}
	master, err := DeriveAccountMaster(context.Background(), d, policy, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	root, err := master.DeriveTrustRoot(context.Background(), e.Binding())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if root.Binding() != binding {
		t.Fatal("enrolled identity changed")
	}
	if err := root.Use(func(actual []byte) error {
		if !bytes.Equal(actual, expectedRoot) {
			t.Fatal("root not recoverable after retirement")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if leaked, err := vault.OpenPasswordSlot(context.Background(), selectedVault, slots.Slots[0], []byte("wrong password"), ask); err == nil {
		vault.Wipe(leaked)
		t.Fatal("wrong password opened storage")
	}
	if len(ask) != 0 {
		if leaked, err := vault.OpenPasswordSlot(context.Background(), selectedVault, slots.Slots[0], password, nil); err == nil {
			vault.Wipe(leaked)
			t.Fatal("ASK bypassed")
		}
	}
}

func TestInitialDeviceStorageFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "closed", "already-owned", "wiped-request", "allocate", "required-pages", "copy", "cancel-allocation", "cancel-after-copy", "bad-password", "bad-ask", "seal"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _ := deviceEnrollmentFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			password := []byte("native password")
			var ask []byte
			memory := &masterMemoryProbe{data: make([]byte, 32)}
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "closed":
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
			case "already-owned":
				p.storage = memory
			case "wiped-request":
				p.commit.Wipe()
			case "required-pages":
				p.master.requireLocked = true
			case "copy":
				memory.useError = securemem.ErrUnavailable
			case "cancel-after-copy":
				memory.afterUse = cancel
			case "bad-password":
				password = nil
			case "bad-ask":
				ask = []byte{1}
			}
			calls := 0
			err := p.prepareDeviceStorage(ctx, password, ask, func(required bool) (accountMasterMemory, error) {
				calls++
				if required != (mode == "required-pages") {
					t.Fatal("storage memory policy changed")
				}
				if mode == "allocate" || mode == "required-pages" {
					return nil, securemem.ErrUnavailable
				}
				if mode == "cancel-allocation" {
					cancel()
				}
				if mode == "seal" {
					p.commit.Wipe()
				}
				return memory, nil
			})
			if err == nil {
				t.Fatal("invalid preparation accepted")
			}
			if (mode == "nil-context" || mode == "canceled" || mode == "closed" || mode == "already-owned" || mode == "wiped-request") && calls != 0 {
				t.Fatal("invalid input allocated")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(memory.data, make([]byte, 32)) || p.deviceFile != nil {
				t.Fatal("failed storage retained material")
			}
		})
	}
	var absent *PreparedInitialEnrollment
	if absent.prepareDeviceStorage(context.Background(), nil, nil, allocateDeviceStorage) == nil || absent.BorrowDeviceStorage(nil) == nil || absent.DeviceStorageLocked() {
		t.Fatal("nil owner")
	}
}

func TestInitialDeviceStorageBorrowFailures(t *testing.T) {
	p, _, _ := deviceEnrollmentFixture(t)
	if err := p.BorrowDeviceStorage(nil); err == nil {
		t.Fatal("missing storage")
	}
	if err := p.prepareDeviceStorage(context.Background(), []byte("native password"), nil, allocateDeviceStorage); err != nil {
		t.Fatal(err)
	}
	if err := p.BorrowDeviceStorage(nil); err == nil {
		t.Fatal("nil callback")
	}
	saved := bytes.Clone(p.deviceFile)
	p.deviceFile = []byte("bad")
	if err := p.BorrowDeviceStorage(func([]byte, vault.SlotFile, []byte) error { t.Fatal("malformed file exposed"); return nil }); err == nil {
		t.Fatal("malformed file")
	}
	p.deviceFile = saved
	if err := p.storage.With(func(key []byte) error { key[0] ^= 1; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.BorrowDeviceStorage(func([]byte, vault.SlotFile, []byte) error { t.Fatal("wrong storage key exposed"); return nil }); err == nil {
		t.Fatal("wrong root")
	}
}
