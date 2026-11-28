//go:build linux || darwin

package ospolicy

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixInstallationWalkConfinesFrameworkLinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "Wormhole.app")
	frontend, backend := filepath.Join(root, "Wormhole"), filepath.Join(root, "native")
	framework := filepath.Join(root, "Framework.framework")
	target := filepath.Join(framework, "Versions", "A")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{frontend, backend, filepath.Join(target, "Framework"), filepath.Join(base, "external")} {
		if err := os.WriteFile(file, []byte("fixture"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(framework, "Versions", "Current")
	if err := os.Symlink("A", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Versions/Current/Framework", filepath.Join(framework, "Framework")); err != nil {
		t.Fatal(err)
	}
	inspect := func(path string, _ fs.FileMode) (uint32, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return 0, err
		}
		return uint32(info.Mode().Perm()), nil
	}
	ctx := context.Background()
	if err := checkUnixInstallationTree(ctx, root, frontend, backend, inspect); err != nil {
		t.Fatal("confined framework links rejected", err)
	}
	if err := os.Chmod(backend, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkUnixInstallationTree(ctx, root, frontend, backend, inspect); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("missing executable bit was accepted", err)
	}
	if err := os.Chmod(backend, 0755); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"../../../external", "/etc", "Current", "missing"} {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(replacement, link); err != nil {
			t.Fatal(err)
		}
		if err := checkUnixInstallationTree(ctx, root, frontend, backend, inspect); !errors.Is(err, ErrInstallationLocation) {
			t.Fatal("unsafe framework link was accepted", err)
		}
	}
}
