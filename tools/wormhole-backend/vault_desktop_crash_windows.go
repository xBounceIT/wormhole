//go:build windows

package main

import (
	"os"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The parent process ID is fixed for the lifetime of the native vault owner.
// Cache its discovery so profile polling does not take a process snapshot
// every time. The registry policy itself is read on every strict check.
var vaultDesktopParentPID = sync.OnceValue(os.Getppid)

func validateDesktopCrashPolicy(profile vault.Profile) error {
	return validateWindowsDesktopCrashPolicy(profile, securemem.CheckWindowsDesktopCrashPolicy)
}

func validateWindowsDesktopCrashPolicy(profile vault.Profile, checkProcess func(int) error) error {
	if profile == vault.Hardened || profile == vault.Paranoid {
		// The native vault owner is a direct child of Electron main. The
		// kernel resolves the parent image without a renderer-provided path.
		if err := checkProcess(vaultDesktopParentPID()); err != nil {
			return vault.ErrPolicy
		}
	}
	return nil
}

func validateNativeRdpCrashPolicy(pid int) error {
	return securemem.CheckWindowsProcessLocalDumps(pid)
}
