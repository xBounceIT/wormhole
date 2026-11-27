//go:build linux || darwin

package securemem

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestVaultProcessDisablesCoreDumps(t *testing.T) {
	// This test executable contains only securemem tests. The irreversible
	// process-wide limit cannot affect the parent go command or the user's app.
	if err := DisableProcessDumps(); err != nil {
		t.Fatal(err)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatal("core dumps remain enabled")
	}
}
