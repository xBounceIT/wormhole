//go:build linux || darwin

package ospolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/unix"
)

func TestProtectedManagedManifestPolicy(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("ab", 32)
	name := "managed-update.sha256"
	readDigest := func() (string, error) {
		t.Helper()
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		return readProtectedPolicyAt(context.Background(), fd, []string{name}, uint32(unix.Geteuid()), "", parseManagedUpdateDigest)
	}
	if got, err := readDigest(); got != "" || err != nil {
		t.Fatal(got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(digest+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readDigest(); got != digest || err != nil {
		t.Fatal(got, err)
	}
}

func TestProtectedPackageOpenSupportsArtifactsLargerThanPolicy(t *testing.T) {
	dir := t.TempDir()
	const name = "wormhole.deb"
	if err := os.WriteFile(filepath.Join(dir, name), make([]byte, maxPolicyBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := openProtectedFileAt(context.Background(), fd, []string{name}, uint32(unix.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != maxPolicyBytes+1 {
		t.Fatal(info, err)
	}
}

func TestProtectedMachinePolicyFiles(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "missing-parent", "directory", "symlink", "parent-link", "writable", "parent-writable", "wrong-owner", "oversize", "empty", "malformed", "fifo", "cancel", "invalid-component", "bad-fd"} {
		t.Run(mode, func(t *testing.T) {
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "managed"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "managed", "policy.json")
			if err := os.WriteFile(path, []byte(`{"profile":"standard"}`), 0600); err != nil {
				t.Fatal(err)
			}
			components := []string{"managed", "policy.json"}
			uid := uint32(unix.Geteuid())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing":
				must(os.Remove(path))
			case "missing-parent":
				components[0] = "absent"
			case "directory":
				must(os.Remove(path))
				must(os.Mkdir(path, 0700))
			case "symlink":
				must(os.Remove(path))
				must(os.Symlink("../outside", path))
			case "parent-link":
				must(os.Symlink("managed", filepath.Join(dir, "link")))
				components[0] = "link"
			case "writable":
				must(os.Chmod(path, 0666))
			case "parent-writable":
				must(os.Chmod(filepath.Dir(path), 0777))
			case "wrong-owner":
				uid++
			case "oversize":
				must(os.WriteFile(path, make([]byte, maxPolicyBytes+1), 0600))
			case "empty":
				must(os.WriteFile(path, nil, 0600))
			case "malformed":
				must(os.WriteFile(path, []byte(`{}`), 0600))
			case "fifo":
				must(os.Remove(path))
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "invalid-component":
				components[1] = "../policy.json"
			}
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "bad-fd" {
				unix.Close(fd)
			}
			p, err := readProtectedPolicyAt(ctx, fd, components, uid, vault.Default, parseJSON)
			switch mode {
			case "valid":
				if p != vault.Standard || err != nil {
					t.Fatal(p, err)
				}
			case "missing", "missing-parent":
				if p != vault.Default || err != nil {
					t.Fatal(p, err)
				}
			case "cancel":
				if p != "" || err != context.Canceled {
					t.Fatal(p, err)
				}
			default:
				if p != "" || err != vault.ErrPolicy {
					t.Fatal(p, err)
				}
			}
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); !errors.Is(err, unix.EBADF) {
				t.Fatal("descriptor retained", err)
			}
		})
	}
}
