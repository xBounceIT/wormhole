//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func TestLinuxMachinePackageHandoff(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_MANAGED_PACKAGE_STAGE") != "1" {
		t.Skip("requires a root-provisioned CI staging directory")
	}
	const directory = "/var/lib/wormhole/updates"
	const contents = "managed package fixture"
	digest := sha256.Sum256([]byte(contents))
	request := updateDownloadRequest{InstallerSize: int64(len(contents)), InstallerSha256: hex.EncodeToString(digest[:])}
	for _, name := range []string{"ci-protected.deb", "ci-writable.deb", "ci-linked.deb"} {
		request.InstallerFileName = name
		got, err := managedSystemPackagePath(request, directory)
		if name == "ci-protected.deb" {
			if err != nil || got != filepath.Join(directory, name) {
				t.Fatal(got, err)
			}
		} else if !errors.Is(err, updateauth.ErrArtifact) || got != "" {
			t.Fatalf("accepted unsafe %s: %s, %v", name, got, err)
		}
	}
	request.InstallerFileName = "ci-protected.deb"
	if _, err := managedSystemPackagePath(request, t.TempDir()); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("accepted a path outside the machine staging directory", err)
	}
}
