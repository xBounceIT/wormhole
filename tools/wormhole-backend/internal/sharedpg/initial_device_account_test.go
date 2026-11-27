package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func initialAccountTransferFixture(t *testing.T) *PreparedInitialEnrollment {
	t.Helper()
	p, _, _ := deviceEnrollmentFixture(t)
	if err := p.prepareDeviceStorage(context.Background(), []byte("native preparation factor"), nil, allocateDeviceStorage); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPreparedInitialAccountTransferPreservesIndependentOwnersAndWipesCommit(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared-is-not-commit-proof", true: "consumed-commit"}[dispatched], func(t *testing.T) {
			p := initialAccountTransferFixture(t)
			master, root, storage, request := p.master, p.root, p.storage, p.commit
			file := bytes.Clone(p.deviceFile)
			payload := append([][]byte{p.commit.pending}, p.commit.params...)
			if dispatched {
				p.commit.Wipe() // The coordinator consumes the request after dispatch.
			}
			owner, err := p.TakeDeviceAccount(context.Background())
			if err != nil || owner == nil {
				t.Fatal("transfer", err)
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			if owner.master != master || owner.root != root || owner.storage != storage || !bytes.Equal(owner.file, file) {
				t.Fatal("native owners copied or replaced")
			}
			for _, raw := range payload {
				if !bytes.Equal(raw, make([]byte, len(raw))) {
					t.Fatal("commit material retained")
				}
			}
			if request.master != nil || request.params != nil || request.pending != nil || !p.closed || p.master != nil || p.root != nil || p.storage != nil || p.deviceFile != nil || p.commit != nil {
				t.Fatal("source retained transferred ownership")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if err := owner.Borrow(func(gotMaster *AccountMaster, gotRoot *DeviceTrustRoot) error {
				if gotMaster != master || gotRoot != root {
					t.Fatal("ownership changed")
				}
				return gotMaster.Use(func([]byte, vault.KDFPreset, bool) error { return nil })
			}); err != nil {
				t.Fatal("preparation Close destroyed transferred material", err)
			}
			if err := owner.BorrowDeviceStorage(func([]byte, []byte) error { return nil }); err != nil {
				t.Fatal("lost encrypted device binding", err)
			}
			if _, err := p.TakeDeviceAccount(context.Background()); err == nil {
				t.Fatal("double transfer")
			}
			if p.Borrow(func(*AccountMaster, *DeviceTrustRoot, *PreparedInvitationCommit) error {
				t.Fatal("closed source borrowed")
				return nil
			}) == nil {
				t.Fatal("source still available")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if err := master.Use(func([]byte, vault.KDFPreset, bool) error { t.Fatal("closed master exposed"); return nil }); !errors.Is(err, securemem.ErrClosed) {
				t.Fatal("master not retired", err)
			}
		})
	}
}

func TestPreparedInitialAccountTransferRefusesDriftWithoutLosingCleanup(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "closed", "no-master", "no-root", "no-storage", "no-request", "no-file", "bad-file", "wrong-storage-key", "binding", "workspace", "login", "kdf", "ask", "closed-master", "closed-root", "storage-fault", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := initialAccountTransferFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			master, root, storage, request, file := p.master, p.root, p.storage, p.commit, p.deviceFile
			savedBinding, savedWorkspace, savedLogin, savedKDF, savedASK := root.binding, master.workspaceID, master.loginName, master.preset, master.askUsed
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "closed":
				p.closed = true
			case "no-master":
				p.master = nil
			case "no-root":
				p.root = nil
			case "no-storage":
				p.storage = nil
			case "no-request":
				p.commit = nil
			case "no-file":
				p.deviceFile = nil
			case "bad-file":
				p.deviceFile = []byte("malformed")
			case "wrong-storage-key":
				if err := storage.With(func(key []byte) error { key[0] ^= 1; return nil }); err != nil {
					t.Fatal(err)
				}
			case "binding":
				root.binding.DeviceID = uuid.New()
			case "workspace":
				master.workspaceID = uuid.New()
			case "login":
				master.loginName = "different"
			case "kdf":
				master.preset = vault.KDFV2
			case "ask":
				master.askUsed = !master.askUsed
			case "closed-master":
				if err := master.Close(); err != nil {
					t.Fatal(err)
				}
			case "closed-root":
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			case "storage-fault":
				p.storage = &masterMemoryProbe{useError: securemem.ErrUnavailable}
			case "late-cancel":
				var raw []byte
				if err := storage.With(func(key []byte) error { raw = bytes.Clone(key); return nil }); err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				p.storage = &masterMemoryProbe{data: raw, afterUse: cancel}
			}
			owner, err := p.TakeDeviceAccount(ctx)
			if err == nil || owner != nil {
				t.Fatal("invalid transfer accepted")
			}
			// Restore only test substitutions so the original owner can release all
			// real allocations; a failed transfer itself must not consume anything.
			if p.commit != request && mode != "no-request" {
				t.Fatal("failed transfer consumed request")
			}
			p.closed = false
			p.master, p.root, p.storage, p.commit, p.deviceFile = master, root, storage, request, file
			root.binding, master.workspaceID, master.loginName, master.preset, master.askUsed = savedBinding, savedWorkspace, savedLogin, savedKDF, savedASK
			if err := p.Close(); err != nil {
				t.Fatal("cleanup obligation lost", err)
			}
		})
	}
	var absent *PreparedInitialEnrollment
	if owner, err := absent.TakeDeviceAccount(context.Background()); err == nil || owner != nil {
		t.Fatal("nil preparation")
	}
}

func TestPreparedInitialAccountTransferKeepsFailedReleaseWithNewOwner(t *testing.T) {
	for _, kind := range []string{"storage", "master", "root"} {
		t.Run(kind, func(t *testing.T) {
			p := initialAccountTransferFixture(t)
			owner, err := p.TakeDeviceAccount(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			memory := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
			var expected error
			switch kind {
			case "storage":
				if err := owner.storage.Close(); err != nil {
					t.Fatal(err)
				}
				owner.storage, expected = memory, ErrDeviceStorageCleanup
			case "master":
				if err := owner.master.memory.Close(); err != nil {
					t.Fatal(err)
				}
				owner.master.memory, expected = memory, ErrAccountMasterCleanup
			case "root":
				if err := owner.root.memory.Close(); err != nil {
					t.Fatal(err)
				}
				owner.root.memory, expected = memory, ErrDeviceTrustRootCleanup
			}
			if err := owner.Close(); !errors.Is(err, expected) {
				t.Fatal("uncertain release not retained", err)
			}
			if kind == "storage" && owner.storage == nil || kind == "master" && owner.master == nil || kind == "root" && owner.root == nil {
				t.Fatal("new owner dropped failed cleanup")
			}
			if err := p.Close(); err != nil {
				t.Fatal("source reclaimed transferred cleanup", err)
			}
			memory.failClose = false
			if err := owner.Close(); err != nil {
				t.Fatal("cleanup retry", err)
			}
			if owner.storage != nil || owner.master != nil || owner.root != nil {
				t.Fatal("successful release retained owners")
			}
		})
	}
}
