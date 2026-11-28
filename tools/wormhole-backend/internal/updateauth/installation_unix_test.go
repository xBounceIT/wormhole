//go:build darwin || linux

package updateauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledTreeBindsFrameworkLinks(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "Wormhole.app")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"version-A", "version-B"} {
		writeInstallationFile(t, root, name, "same bytes")
	}
	writeInstallationFile(t, base, "external", "same bytes")
	link := filepath.Join(root, "Current")
	var previous string
	for _, target := range []string{"version-A", "version-B", "../external"} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		inventory, err := InventoryInstallation(ctx, root, "v2.4.3", "darwin/universal")
		if target == "../external" {
			if !errors.Is(err, ErrArtifact) {
				t.Fatal("escaping link admitted", err)
			}
		} else if err != nil || inventory.Entries != 3 || inventory.TreeSHA256 == previous {
			t.Fatal("different link targets must change the signed tree", err)
		}
		previous = inventory.TreeSHA256
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
}
