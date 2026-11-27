//go:build windows

package main

import (
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWindowsDesktopCrashPolicyChecksTheParentOnlyForStrictProfiles(t *testing.T) {
	for _, profile := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
		t.Run(string(profile), func(t *testing.T) {
			var calls int
			check := func(pid int) error {
				calls++
				if pid != os.Getppid() || pid <= 0 {
					t.Fatalf("checked process %d instead of the parent", pid)
				}
				return errors.New("private crash policy failure")
			}
			err := validateWindowsDesktopCrashPolicy(profile, check)
			if profile == vault.Hardened || profile == vault.Paranoid {
				if err != vault.ErrPolicy || calls != 1 {
					t.Fatalf("strict profile = %v after %d checks", err, calls)
				}
				if err := validateWindowsDesktopCrashPolicy(profile, func(int) error { return nil }); err != nil {
					t.Fatal(err)
				}
			} else if err != nil || calls != 0 {
				t.Fatalf("lower profile = %v after %d checks", err, calls)
			}
		})
	}
}
