//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

// The interactive launcher supplies a window owned by this process's parent.
// Ordinary CI never prompts and cannot produce a physical-device result.
func TestWindowsHelloPhysicalDevice(t *testing.T) {
	handle := os.Getenv("WORMHOLE_TEST_HELLO_OWNER_WINDOW")
	if handle == "" {
		t.Skip("requires scripts/test-windows-hello-device.ps1 and a local operator")
	}
	hwnd, err := strconv.ParseUint(handle, 10, strconv.IntSize)
	if err != nil || hwnd == 0 {
		t.Fatal("invalid test owner window")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	if err := platformVaultHelloAvailable(ctx); err != nil {
		t.Fatal("Windows Hello availability:", err)
	}
	vaultID, fileID, slotID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	name := vaultHelloKeyName(vaultID, slotID)
	root := make([]byte, 32)
	defer vault.Wipe(root)
	if _, err := rand.Read(root); err != nil {
		t.Fatal("could not prepare the temporary vault root")
	}
	var slot vault.Slot
	err = withPlatformVaultHello(ctx, name, uintptr(hwnd), true, func(credential vault.HelloCredential) error {
		// The platform created this key with FailIfExists. Never remove a
		// pre-existing credential when creation itself fails.
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			if !platformRemoveVaultHello(cleanup, name) {
				t.Error("Windows did not confirm temporary credential removal")
			}
		})
		var err error
		slot, err = vault.CreateHelloSlot(ctx, vaultID, fileID, slotID, 1, root, credential)
		return err
	})
	if err != nil {
		t.Fatal("enrollment:", err)
	}
	err = withPlatformVaultHello(ctx, name, uintptr(hwnd), false, func(credential vault.HelloCredential) error {
		opened, err := vault.OpenHelloSlot(ctx, vaultID, fileID, slot, credential)
		defer vault.Wipe(opened)
		if err == nil && subtle.ConstantTimeCompare(root, opened) != 1 {
			return vault.ErrAuthentication
		}
		return err
	})
	if err != nil {
		t.Fatal("reopen:", err)
	}
	t.Logf("Windows build %d, %s, repeatable signatures and reopened slot, attestation %s",
		windows.RtlGetVersion().BuildNumber, runtime.GOARCH, slot.Hello.Attestation)
}
