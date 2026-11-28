package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestManagedUpdateNeverFallsBackWithoutPolicyPermission(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(githubRelease{TagName: "v1.2.3"})
	}))
	defer server.Close()
	setUpdateTestOrigin(t, server.URL)
	oldReader := readManagedUpdatePolicy
	t.Cleanup(func() { readManagedUpdatePolicy = oldReader })
	for _, tc := range []struct {
		name, mode              string
		policy                  ospolicy.ManagedUpdate
		policyErr               error
		public, managed, failed bool
	}{
		{name: "required without approval", mode: "required", managed: true},
		{name: "required with invalid policy", mode: "required", policyErr: vault.ErrPolicy, managed: true, failed: true},
		{name: "preferred without approval", mode: "preferred", public: true},
		{name: "preferred with invalid policy", mode: "preferred", policyErr: vault.ErrPolicy, managed: true, failed: true},
		{name: "preferred with missing staging", mode: "preferred", policy: ospolicy.ManagedUpdate{Digest: strings.Repeat("1", 64)}, managed: true, failed: true},
		{name: "public", public: true},
		{name: "invalid mode", mode: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests.Store(0)
			readManagedUpdatePolicy = func(context.Context) (ospolicy.ManagedUpdate, error) { return tc.policy, tc.policyErr }
			result, err := checkVaultUpdateRelease(filepath.Join(t.TempDir(), "workspace.db"), updateCheckRequest{CurrentVersion: "1.2.3", ManagedMode: tc.mode})
			if (err != nil) != (tc.mode == "unknown") || (requests.Load() != 0) != tc.public || result.Managed != tc.managed || result.CheckFailed != tc.failed || result.IsUpdateAvailable {
				t.Fatalf("unexpected path: %+v, calls %d, error %v", result, requests.Load(), err)
			}
		})
	}
}

func TestManagedUpdateApprovalBindsCheckCopyAndVerification(t *testing.T) {
	const version = "9.8.6"
	contents := []byte("unsigned test installer")
	var fixture, identity string
	switch runtime.GOOS {
	case "windows":
		old := updateWindowsPublisherSPKI
		t.Cleanup(func() { updateWindowsPublisherSPKI = old })
		updateWindowsPublisherSPKI = strings.Repeat("a1", 32)
		fixture, identity = os.Getenv("WORMHOLE_TEST_AUTHENTICODE_INSTALLER"), os.Getenv("WORMHOLE_TEST_AUTHENTICODE_SPKI")
		if fixture != "" {
			updateWindowsPublisherSPKI = identity
		}
	case "darwin":
		old := updateDarwinPublisherTeamID
		t.Cleanup(func() { updateDarwinPublisherTeamID = old })
		updateDarwinPublisherTeamID = "AB7CDEFGH9"
		fixture, identity = os.Getenv("WORMHOLE_TEST_NOTARIZED_DMG"), os.Getenv("WORMHOLE_TEST_NOTARIZED_TEAM_ID")
		if fixture != "" {
			updateDarwinPublisherTeamID = identity
		}
	}
	if fixture != "" {
		var err error
		contents, err = os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
	}
	manifestName := updateauth.ManifestName
	asset, raw := signedUpdateFixture(t, "v9.8.7", contents)
	if runtime.GOOS == "linux" {
		m, err := updateauth.NewSystemManifest("v9.8.7")
		if err != nil {
			t.Fatal(err)
		}
		deb, ok := m.LinuxPackage(updateTargetArchitecture(), "deb")
		if !ok {
			t.Fatal("missing native system package")
		}
		asset, raw = signFixtureManifest(t, m, deb, contents)
		manifestName = updateauth.SystemManifestName
	}
	_, other := signedUpdateFixture(t, "v9.8.8", contents)
	stage := t.TempDir()
	if runtime.GOOS == "linux" {
		// Exercise the handoff with a private temporary staging directory. The
		// native root-ownership and no-follow walk has its own Unix fixtures.
		original := openManagedSystemPackage
		t.Cleanup(func() { openManagedSystemPackage = original })
		openManagedSystemPackage = func(path string) (*os.File, error) {
			if filepath.Dir(path) != stage {
				return nil, os.ErrPermission
			}
			return os.Open(path)
		}
	}
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	digest := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(stage, manifestName)
	installerPath := filepath.Join(stage, asset.Name)
	write(installerPath, contents)
	approval := ospolicy.ManagedUpdate{Directory: stage, Digest: digest(raw)}
	oldReader := readManagedUpdatePolicy
	t.Cleanup(func() { readManagedUpdatePolicy = oldReader })
	readManagedUpdatePolicy = func(context.Context) (ospolicy.ManagedUpdate, error) { return approval, nil }
	check := func(current string) updateCheckResponse {
		t.Helper()
		result, err := checkVaultUpdateRelease(databasePath, updateCheckRequest{CurrentVersion: current, ManagedMode: "required"})
		if err != nil || !result.Managed || result.ReleaseUrl != "" || result.ReleaseNotes != "" {
			t.Fatalf("unexpected managed response: %+v %v", result, err)
		}
		return result
	}
	for _, payload := range [][]byte{nil, other, bytes.Repeat([]byte{'a'}, updateauth.MaxManifestBytes+1), []byte(`{"signature":"forged"}`)} {
		if payload != nil {
			write(manifestPath, payload)
		}
		if result := check(version); !result.CheckFailed || result.IsUpdateAvailable {
			t.Fatalf("unapproved release offered: %+v", result)
		}
	}
	// The administrator's digest cannot replace the embedded signing key.
	approval.Digest = digest([]byte(`{"signature":"forged"}`))
	if !check(version).CheckFailed {
		t.Fatal("accepted administrator-approved bytes without a valid signature")
	}
	approval.Digest = digest(raw)
	write(manifestPath, raw)
	oldKey := updateManifestPublicKeyHex
	updateManifestPublicKeyHex = ""
	if !check(version).CheckFailed {
		t.Fatal("managed approval bypassed the pinned release key")
	}
	updateManifestPublicKeyHex = oldKey
	write(installerPath, contents[:1])
	if !check(version).CheckFailed {
		t.Fatal("accepted incomplete package")
	}
	write(installerPath, contents)
	if result := check("9.8.7"); result.IsUpdateAvailable || result.CheckFailed {
		t.Fatalf("current release was offered: %+v", result)
	}
	if !check("invalid version").CheckFailed {
		t.Fatal("invalid version accepted")
	}
	result := check(version)
	if !result.IsUpdateAvailable || result.CheckFailed || result.InstallerUrl != managedUpdateURLPrefix+asset.Name ||
		result.LatestVersion != "9.8.7" || result.LastUpdateCheck == "" || result.PublisherVerification != managedPublisherRequired() || !bytes.Equal(result.SignedManifest, raw) {
		t.Fatalf("approved update missing: %+v", result)
	}
	request := updateDownloadRequest{InstallerUrl: result.InstallerUrl, InstallerFileName: asset.Name,
		InstallerSha256: asset.SHA256, InstallerSize: asset.Size, SignedManifest: raw, CurrentVersion: version}
	encode := func(r updateDownloadRequest) *bytes.Reader {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(data)
	}
	bad := request
	bad.InstallerUrl += "/extra"
	if err := serveUpdateDownload(databasePath, encode(bad), io.Discard); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("noncanonical managed locator accepted", err)
	}
	bad = request
	bad.SignedManifest = nil
	if err := serveUpdateDownload(databasePath, encode(bad), io.Discard); err == nil {
		t.Fatal("unsigned managed request accepted")
	}
	approval.Digest = digest(other)
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); !errors.Is(err, updateauth.ErrManifest) {
		t.Fatal("superseded approval permitted download", err)
	}
	approval.Digest = digest(raw)
	if err := os.Remove(installerPath); err != nil {
		t.Fatal(err)
	}
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("missing staged package was accepted", err)
	}
	write(installerPath, contents[:1])
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("incomplete staged package was accepted", err)
	}
	write(installerPath, bytes.Repeat([]byte{'b'}, len(contents)))
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); err == nil {
		t.Fatal("tampered staged package was copied to the cache")
	}
	write(installerPath, contents)
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); err != nil {
		t.Fatal(err)
	}
	approval.Digest = ""
	if _, err := verifyCachedUpdate(databasePath, encode(request)); !errors.Is(err, updateauth.ErrManifest) {
		t.Fatal("withdrawn approval permitted install", err)
	}
	approval.Digest = digest(raw)
	verified, err := verifyCachedUpdate(databasePath, encode(request))
	if managedPublisherRequired() && fixture == "" {
		if verified.Verified || !errors.Is(err, updateauth.ErrPublisherUntrusted) {
			t.Fatal("managed mode accepted unsigned native installer", verified, err)
		}
		return
	}
	if err != nil || !verified.Verified || verified.PublisherVerified != managedPublisherRequired() {
		t.Fatal("cannot install an approved, verified package", verified, err)
	}
	if runtime.GOOS == "windows" {
		// Verify the real publisher fixture, then close the pipe without a launch decision.
		var receipt bytes.Buffer
		err := serveWindowsUpdateHandoff(databasePath, io.MultiReader(encode(request), strings.NewReader("\n")), &receipt)
		if !errors.Is(err, updateauth.ErrArtifact) || receipt.String() != "P\n" {
			t.Fatalf("cancelled publisher-verified handoff: %q, %v", receipt.String(), err)
		}
	}
	if runtime.GOOS == "linux" {
		if verified.ManagedPackagePath != installerPath {
			t.Fatal("expected administrator-staged file", verified)
		}
		write(installerPath, bytes.Repeat([]byte{'z'}, len(contents)))
		if result, err := verifyCachedUpdate(databasePath, encode(request)); result.Verified || result.ManagedPackagePath != "" || !errors.Is(err, updateauth.ErrArtifact) {
			t.Fatal("cached valid bytes hid a changed system package", result, err)
		}
		if err := os.Remove(installerPath); err != nil {
			t.Fatal(err)
		}
		if verified, err := verifyCachedUpdate(databasePath, encode(request)); verified.Verified || !errors.Is(err, updateauth.ErrArtifact) {
			t.Fatal("withdrawn system package permitted install", verified, err)
		}
		write(installerPath, contents)
	}
	checks := 0
	readManagedUpdatePolicy = func(context.Context) (ospolicy.ManagedUpdate, error) {
		checks++
		if checks == 1 {
			return approval, nil
		}
		return ospolicy.ManagedUpdate{}, nil
	}
	if verified, err := verifyCachedUpdate(databasePath, encode(request)); verified.Verified || !errors.Is(err, updateauth.ErrManifest) {
		t.Fatal("approval was withdrawn during verification", verified, err)
	}
}

func TestManagedSystemPackageHandoffRequiresProtectedSignedBytes(t *testing.T) {
	dir := t.TempDir()
	const name = "Wormhole-2.4.3-linux-amd64.deb"
	content := []byte("approved package")
	sum := sha256.Sum256(content)
	request := updateDownloadRequest{InstallerFileName: name, InstallerSize: int64(len(content)), InstallerSha256: hex.EncodeToString(sum[:])}
	original := openManagedSystemPackage
	t.Cleanup(func() { openManagedSystemPackage = original })
	path := filepath.Join(dir, name)
	check := func(want string) {
		t.Helper()
		got, err := managedSystemPackagePath(request, dir)
		if want == "" && !errors.Is(err, updateauth.ErrArtifact) || want != "" && err != nil || got != want {
			t.Fatal(got, err)
		}
	}
	openManagedSystemPackage = func(string) (*os.File, error) { return nil, os.ErrPermission }
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	check("")
	openManagedSystemPackage = os.Open
	check(path)
	previous := filepath.Join(dir, "previous-package")
	if err := os.WriteFile(previous, content, 0600); err != nil {
		t.Fatal(err)
	}
	openManagedSystemPackage = func(string) (*os.File, error) { return os.Open(previous) }
	check("") // A valid handle cannot attest a different object currently at the staging path.
	openManagedSystemPackage = os.Open
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(content)), 0600); err != nil {
		t.Fatal(err)
	}
	check("")
}

func TestManagedLinuxPackageSelection(t *testing.T) {
	m, err := updateauth.NewSystemManifest("v2.4.3")
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Artifacts {
		m.Artifacts[i].Size = 4
	}
	for _, arch := range []string{"x64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			directory := t.TempDir()
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			selectPackage := func(want string) {
				t.Helper()
				asset, err := stagedManagedInstaller(root, m, "linux", arch)
				if want == "" && !errors.Is(err, updateauth.ErrArtifact) || want != "" && (err != nil || asset.Name != want) {
					t.Fatalf("selected %q, %v; want %q", asset.Name, err, want)
				}
			}
			appImage, _ := m.ArtifactFor("linux", arch)
			deb, _ := m.LinuxPackage(arch, "deb")
			rpm, _ := m.LinuxPackage(arch, "rpm")
			write := func(name, value string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(appImage.Name, "data")
			selectPackage("")
			write(rpm.Name, "bad")
			selectPackage("")
			write(rpm.Name, "data")
			selectPackage(rpm.Name)
			write(deb.Name, "data")
			selectPackage("")
			if err := root.Remove(rpm.Name); err != nil {
				t.Fatal(err)
			}
			selectPackage(deb.Name)
			if err := root.Mkdir(rpm.Name, 0700); err != nil {
				t.Fatal(err)
			}
			selectPackage("")
			legacy, _ := updateauth.NewManifest("v2.4.3")
			if _, err := stagedManagedInstaller(root, legacy, "linux", arch); !errors.Is(err, updateauth.ErrArtifact) {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedLinuxPackageApprovalTracksStagedFormat(t *testing.T) {
	m, err := updateauth.NewSystemManifest("v2.4.3")
	if err != nil {
		t.Fatal(err)
	}
	deb, _ := m.LinuxPackage("x64", "deb")
	rpm, _ := m.LinuxPackage("x64", "rpm")
	contents := []byte("release bytes")
	_, raw := signFixtureManifest(t, m, deb, contents)
	sum := sha256.Sum256(raw)
	dir := t.TempDir()
	approval := ospolicy.ManagedUpdate{Directory: dir, Digest: hex.EncodeToString(sum[:])}
	request := updateDownloadRequest{InstallerFileName: deb.Name, SignedManifest: raw}
	verify := func() error { return verifyManagedApproval(request, approval, "linux", "x64") }
	debPath := filepath.Join(dir, deb.Name)
	if err := os.WriteFile(debPath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(debPath, filepath.Join(dir, rpm.Name)); err != nil {
		t.Fatal(err)
	}
	if err := verify(); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("withdrawn DEB still approved", err)
	}
	request.InstallerFileName = rpm.Name
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	approval.Directory = filepath.Join(dir, "missing")
	if err := verify(); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("missing stage approved", err)
	}
	approval.Directory = dir
	pin := updateManifestPublicKeyHex
	updateManifestPublicKeyHex = ""
	if err := verify(); err == nil {
		t.Fatal("missing release key accepted")
	}
	updateManifestPublicKeyHex = pin
	request.SignedManifest = []byte("invalid")
	if err := verify(); !errors.Is(err, updateauth.ErrManifest) {
		t.Fatal("withdrawn digest accepted", err)
	}
	sum = sha256.Sum256(request.SignedManifest)
	approval.Digest = hex.EncodeToString(sum[:])
	if err := verify(); !errors.Is(err, updateauth.ErrManifest) {
		t.Fatal("unsigned approval accepted", err)
	}
}
