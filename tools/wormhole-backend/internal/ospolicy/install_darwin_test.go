//go:build darwin

package ospolicy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinInstallationQueriesTextVnode(t *testing.T) {
	running, err := darwinProcessImage(os.Getpid())
	if err != nil {
		t.Fatal("cannot read the running process image", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, err := os.Stat(running)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(self)
	if err != nil || !os.SameFile(a, b) {
		t.Fatal("kernel path did not identify the running image", err)
	}
	if _, err := checkNativeInstallation(context.Background()); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("unbundled test executable was admitted", err)
	}
}

func TestDarwinInstallationReadsNativeACLs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "framework")
	if err := os.WriteFile(file, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "Current")
	if err := os.Symlink("framework", link); err != nil {
		t.Fatal(err)
	}
	if !checkDarwinACL(file) || !checkDarwinACL(link) {
		t.Fatal("a file or link without ACL grants was rejected")
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow write", file).CombinedOutput(); err != nil {
		t.Fatalf("cannot set ACL on test fixture: %v %s", err, output)
	}
	if checkDarwinACL(file) || !checkDarwinACL(link) {
		t.Fatal("the file's ACL was not distinguished from the link's ACL")
	}
}
