//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWindowsVaultHelloRefusesUnconfirmedConsoleBeforeWinRT(t *testing.T) {
	previous := windowsHelloSession
	t.Cleanup(func() { windowsHelloSession = previous })
	for _, want := range []error{errVaultHelloRemote, errVaultHelloUnavailable} {
		windowsHelloSession = func() error { return want }
		if err := inVaultHelloApartment(t.Context(), func() error {
			t.Fatal("ineligible session entered WinRT")
			return nil
		}); err != want {
			t.Fatalf("wrong session disposition: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	windowsHelloSession = func() error { t.Fatal("cancelled request queried WTS"); return nil }
	if err := platformVaultHelloAvailable(ctx); err != context.Canceled {
		t.Fatal("cancellation did not stop the capability query", err)
	}
}

func TestWindowsVaultHelloRejectsInvalidWindow(t *testing.T) {
	if window, err := vaultHelloOwnerWindow(0); window != 0 || err != vault.ErrPolicy {
		t.Fatal("an invalid owner reached WinRT", err)
	}
}

func TestWindowsVaultHelloCapabilityWithoutPrompt(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_VAULT_HELLO_PROBE") != "1" {
		t.Skip("set WORMHOLE_TEST_VAULT_HELLO_PROBE=1 for a local Windows capability query")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := vaultHelloAvailability(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(result))
	cancel()
	if err := platformVaultHelloAvailable(ctx); !errors.Is(err, context.Canceled) && !errors.Is(err, errVaultHelloRemote) {
		t.Fatal("cancellation still entered WinRT", err)
	}
}
