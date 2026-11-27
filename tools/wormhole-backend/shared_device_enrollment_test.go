package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedDeviceFileFixture(t *testing.T) (string, []byte, vault.SlotFile, []byte, sharedpg.TrustBinding) {
	t.Helper()
	f, p := preparedJoinFixture(t)
	slots, key := localSlotFixture(t)
	slots.Nodes = nil
	raw, err := vault.EncodeSlotFile(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := p.SealDeviceEnrollment(key, slots, f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(key) })
	return f.o.TrustPath, key, slots, envelope, f.o.Binding
}

func TestSharedDeviceEnrollmentDurability(t *testing.T) {
	path, key, slots, envelope, b := sharedDeviceFileFixture(t)
	if _, _, err := readSharedDeviceEnrollment(path); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	syncDir := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = syncDir })
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	raw, err := stageSharedDeviceEnrollment(path, key, slots, envelope)
	if err != errSharedTrustCommitUncertain || len(raw) == 0 {
		t.Fatal("uncertain publication", err)
	}
	loaded, cipher, err := readSharedDeviceEnrollment(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := sharedpg.OpenDeviceEnrollment(key, loaded, slots.VaultID, slots.FileID, 1, cipher)
	if err != nil || metadata.Binding() != b {
		t.Fatal("stored pair", err)
	}
	if bytes.Contains(raw, key) || bytes.Contains(raw, []byte(b.UserID.String())) {
		t.Fatal("plaintext secret or account metadata")
	}
	if err := confirmSharedDeviceEnrollment(path, key, slots.VaultID, slots.FileID, 1, raw); err != errSharedTrustCommitUncertain {
		t.Fatal("readback hid failed sync", err)
	}
	privateFileDirectorySync = syncDir
	if err := confirmSharedDeviceEnrollment(path, key, slots.VaultID, slots.FileID, 1, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := stageSharedDeviceEnrollment(path, key, slots, envelope); err != errSharedTrustConflict {
		t.Fatal("existing pair replaced", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("device setup activated trust")
	}
}

func TestSharedDeviceEnrollmentGuards(t *testing.T) {
	for _, mode := range []string{"relative", "root", "malformed", "locked", "trust", "pending", "password-transition", "connection", "parent-file", "changed", "missing", "confirmation-root", "confirmation-identity", "confirmation-floor", "confirmation-malformed"} {
		t.Run(mode, func(t *testing.T) {
			path, key, slots, envelope, _ := sharedDeviceFileFixture(t)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			var expected []byte
			confirm := mode == "changed" || mode == "missing" || len(mode) > 12 && mode[:12] == "confirmation"
			if confirm {
				var err error
				expected, err = stageSharedDeviceEnrollment(path, key, slots, envelope)
				if err != nil {
					t.Fatal(err)
				}
			}
			vaultID, minimum := slots.VaultID, uint64(1)
			write := func(p string) {
				t.Helper()
				if err := os.WriteFile(p, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "relative":
				path = "relative"
			case "root", "confirmation-root":
				key = bytes.Repeat([]byte{88}, 32)
			case "malformed":
				envelope = []byte("bad")
			case "locked":
				release, err := tryAcquireExclusiveFileLock(path + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "trust":
				write(path)
			case "pending":
				write(sharedPendingEnrollmentPath(path))
			case "password-transition":
				write(sharedTrustTransitionPath(path))
			case "connection":
				write(sharedTransportSetupPath(path))
			case "parent-file":
				file := filepath.Join(t.TempDir(), "file")
				write(file)
				path = filepath.Join(file, "device")
			case "changed":
				write(sharedDeviceEnrollmentPath(path))
			case "missing":
				if err := os.Remove(sharedDeviceEnrollmentPath(path)); err != nil {
					t.Fatal(err)
				}
			case "confirmation-identity":
				vaultID = "foreign"
			case "confirmation-floor":
				minimum = 2
			case "confirmation-malformed":
				expected = []byte("bad")
			}
			var err error
			if confirm {
				err = confirmSharedDeviceEnrollment(path, key, vaultID, slots.FileID, minimum, expected)
			} else {
				_, err = stageSharedDeviceEnrollment(path, key, slots, envelope)
			}
			if err == nil {
				t.Fatal("guard bypassed")
			}
			if mode == "relative" {
				if _, _, err := readSharedDeviceEnrollment(path); err == nil {
					t.Fatal("relative read")
				}
				if err := confirmSharedDeviceEnrollment(path, key, vaultID, slots.FileID, 1, nil); err == nil {
					t.Fatal("relative confirm")
				}
			}
		})
	}
}

func TestSharedDeviceEnrollmentConfirmationState(t *testing.T) {
	for _, mode := range []string{"locked", "trust", "pending", "password-transition"} {
		t.Run(mode, func(t *testing.T) {
			path, key, slots, envelope, _ := sharedDeviceFileFixture(t)
			raw, err := stageSharedDeviceEnrollment(path, key, slots, envelope)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "locked" {
				release, err := tryAcquireExclusiveFileLock(path + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			} else {
				marker := path
				if mode == "pending" {
					marker = sharedPendingEnrollmentPath(path)
				}
				if mode == "password-transition" {
					marker = sharedTrustTransitionPath(path)
				}
				if err := os.WriteFile(marker, []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := confirmSharedDeviceEnrollment(path, key, slots.VaultID, slots.FileID, 1, raw); err == nil {
				t.Fatal("conflicting state confirmed")
			}
		})
	}
}
