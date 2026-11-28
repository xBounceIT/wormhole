//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"golang.org/x/sys/unix"
)

func TestVaultUnlockWhenMemoryLockIsDenied(t *testing.T) {
	const child = "WORMHOLE_TEST_VAULT_ZERO_MEMLOCK"
	if os.Getenv(child) != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestVaultUnlockWhenMemoryLockIsDenied$", "-test.v")
		command.Env = append(os.Environ(), child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("vault memory-lock subprocess: %v\n%s", err, output)
		} else {
			t.Logf("%s", output)
		}
		return
	}
	// Only change the limit in this dedicated process. Linux permits a process
	// with CAP_IPC_LOCK to bypass this limit, so check the effective result.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{}); err != nil {
		t.Fatal(err)
	}
	if buffer, err := securemem.New(32, true); err == nil {
		_ = buffer.Close()
		t.Skip("test process can lock pages despite a zero memory-lock limit")
	} else if !errors.Is(err, securemem.ErrUnavailable) {
		t.Fatal(err)
	}
	for _, mode := range []string{"plain", "encrypted"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			doc, key := localSlotFixture(t)
			defer vault.Wipe(key)
			doc.Initializing, doc.Encrypted = true, mode == "encrypted"
			if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
				t.Fatal(err)
			}
			h := &vaultFoundationHandler{databasePath: path}
			t.Cleanup(func() {
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			})
			input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
			reply, err := h.Handle(t.Context(), "unlock", input)
			if doc.Encrypted {
				if h.owner != nil || reply != nil || !errors.Is(err, vaultwire.ErrRetired) {
					t.Fatalf("encrypted vault did not require locked memory: %s %v", reply, err)
				}
				return
			}
			if err != nil || h.owner == nil || vaultTestUnlockReceipt(t, reply) {
				t.Fatalf("plain vault did not report the denied memory lock: %s %v", reply, err)
			}
			status, err := h.Handle(t.Context(), "status", nil)
			var result struct {
				Unlocked     bool  `json:"unlocked"`
				LockedMemory *bool `json:"lockedMemory"`
			}
			if err != nil || json.Unmarshal(status, &result) != nil || !result.Unlocked || result.LockedMemory == nil || *result.LockedMemory {
				t.Fatalf("status did not preserve the native result: %s %v", status, err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := &vaultFoundationHandler{databasePath: path}
			t.Cleanup(func() { _ = reopened.Close() })
			reply, err = reopened.Handle(t.Context(), "unlock", vaultInput(t, map[string]any{
				"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32),
			}))
			if err != nil || reopened.owner == nil || vaultTestUnlockReceipt(t, reply) {
				t.Fatalf("plain vault did not reopen without locked memory: %s %v", reply, err)
			}
		})
	}
}
