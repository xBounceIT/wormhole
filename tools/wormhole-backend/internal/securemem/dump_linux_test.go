//go:build linux

package securemem

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestVaultProcessIsNotDumpable(t *testing.T) {
	if err := DisableProcessDumps(); err != nil {
		t.Fatal(err)
	}
	value, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if value != 0 {
		t.Fatal("process remains dumpable")
	}
}
