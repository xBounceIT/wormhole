//go:build linux

package ospolicy

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxInstallationRejectsUIDRemapping(t *testing.T) {
	for _, raw := range []string{"", "0 1000 1\n", "0 0 1\n", "0 0 4294967294\n", "0 0 4294967295\n1 1 1\n", strings.Repeat(" ", 128) + "0 0 4294967295"} {
		if isInitialLinuxUIDMap([]byte(raw)) {
			t.Fatalf("invalid UID map accepted: %q", raw)
		}
	}
	if !isInitialLinuxUIDMap([]byte("         0          0 4294967295\n")) {
		t.Fatal("initial namespace rejected")
	}
}

func TestLinuxInstallationUsesKernelExecutableIdentity(t *testing.T) {
	proc, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(proc)
	mapBytes, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || initialLinuxUserNamespace(proc) != isInitialLinuxUIDMap(mapBytes) {
		t.Fatal("protected proc lookup did not identify the current user namespace", err)
	}
	directory, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)
	if initialLinuxUserNamespace(directory) {
		t.Fatal("a non-proc mount became a user namespace authority")
	}
	path, err := readLinuxProcessImage(proc, "self/exe")
	if err != nil || !sameLinuxProcessImage(proc, "self/exe", path) {
		t.Fatal("self image was not bound to its inode", err)
	}
	if sameLinuxProcessImage(proc, "self/exe", "/proc/self/status") {
		t.Fatal("another inode matched the executable")
	}
	if _, err := readLinuxProcessImage(proc, strconv.Itoa(os.Getpid())+"/nonexistent"); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("invalid executable entry accepted", err)
	}
	if _, err := checkNativeInstallation(context.Background()); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("unbundled test executable was admitted", err)
	}
}
