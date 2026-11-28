package main

import (
	"bytes"
	"crypto/ed25519"
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
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func signedUpdateFixture(t *testing.T, tag string, contents []byte) (updateauth.Artifact, []byte) {
	t.Helper()
	m, err := updateauth.NewManifest(tag)
	if err != nil {
		t.Fatal(err)
	}
	asset, ok := m.ArtifactFor(runtime.GOOS, updateTargetArchitecture())
	if !ok {
		t.Skip("no installer for this platform")
	}
	return signFixtureManifest(t, m, asset, contents)
}

func signFixtureManifest(t *testing.T, m updateauth.Manifest, asset updateauth.Artifact, contents []byte) (updateauth.Artifact, []byte) {
	t.Helper()
	hash := sha256.Sum256(contents)
	for i := range m.Artifacts {
		m.Artifacts[i].Size = int64(len(contents))
		m.Artifacts[i].SHA256 = hex.EncodeToString(hash[:])
		if m.Artifacts[i].Name == asset.Name {
			asset = m.Artifacts[i]
		}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, ed25519.SeedSize))
	oldPin := updateManifestPublicKeyHex
	updateManifestPublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	t.Cleanup(func() { updateManifestPublicKeyHex = oldPin })
	raw, err := updateauth.Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	return asset, raw
}

func setUpdateTestOrigin(t *testing.T, origin string) {
	t.Helper()
	oldAPI, oldOrigin := updateApiBaseURL, updateReleaseOrigin
	updateApiBaseURL, updateReleaseOrigin = origin, origin
	t.Cleanup(func() { updateApiBaseURL, updateReleaseOrigin = oldAPI, oldOrigin })
}

func TestSignedUpdateDownloadAndCachedVerification(t *testing.T) {
	const tag = "v9.8.7"
	contents := []byte("installer with signed release metadata")
	asset, raw := signedUpdateFixture(t, tag, contents)
	assetPrefix := "/" + updateauth.Repository + "/releases/download/" + tag + "/"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/xBounceIT/wormhole/releases/latest":
			_ = json.NewEncoder(w).Encode(githubRelease{TagName: tag, Assets: []githubReleaseAsset{
				{Name: asset.Name, BrowserDownloadUrl: "https://untrusted.invalid/mismatch", Size: 8},
				{Name: updateauth.ManifestName, BrowserDownloadUrl: "https://untrusted.invalid/manifest"},
			}})
		case assetPrefix + updateauth.ManifestName:
			_, _ = w.Write(raw)
		case assetPrefix + asset.Name:
			_, _ = w.Write(contents)
		default:
			t.Errorf("unexpected updater request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setUpdateTestOrigin(t, server.URL)

	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	result, err := checkForUpdate(databasePath, updateCheckRequest{CurrentVersion: "9.8.6"})
	if err != nil || !result.IsUpdateAvailable || !result.IsNewerRelease || result.InstallerUrl != server.URL+assetPrefix+asset.Name ||
		result.InstallerSha256 != asset.SHA256 || result.InstallerSize == nil || *result.InstallerSize != asset.Size ||
		!bytes.Equal(result.SignedManifest, raw) {
		t.Fatalf("signed update missing: %+v, %v", result, err)
	}
	request := updateDownloadRequest{
		InstallerUrl: result.InstallerUrl, InstallerFileName: result.InstallerFileName,
		InstallerSize: *result.InstallerSize, InstallerSha256: result.InstallerSha256,
		CurrentVersion: "9.8.6", SignedManifest: result.SignedManifest,
	}
	encode := func(v updateDownloadRequest) *bytes.Reader {
		input, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(input)
	}
	for name, mutate := range map[string]func(*updateDownloadRequest){
		"missing proof": func(r *updateDownloadRequest) { r.SignedManifest = nil },
		"unknown URL":   func(r *updateDownloadRequest) { r.InstallerUrl = server.URL + "/wrong" },
		"other file":    func(r *updateDownloadRequest) { r.InstallerFileName = "different.exe" },
		"subdirectory":  func(r *updateDownloadRequest) { r.InstallerFileName = "folder/different.exe" },
		"other digest":  func(r *updateDownloadRequest) { r.InstallerSha256 = strings.Repeat("bc", 32) },
		"non-hex":       func(r *updateDownloadRequest) { r.InstallerSha256 = strings.Repeat("zz", 32) },
		"short hash":    func(r *updateDownloadRequest) { r.InstallerSha256 = "abc" },
		"zero bytes":    func(r *updateDownloadRequest) { r.InstallerSize = 0 },
		"other size":    func(r *updateDownloadRequest) { r.InstallerSize++ },
		"current":       func(r *updateDownloadRequest) { r.CurrentVersion = "9.8.7" },
		"downgrade":     func(r *updateDownloadRequest) { r.CurrentVersion = "10.0.0" },
		"bad version":   func(r *updateDownloadRequest) { r.CurrentVersion = "invalid" },
		"empty URL":     func(r *updateDownloadRequest) { r.InstallerUrl = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			mutate(&bad)
			if err := serveUpdateDownload(databasePath, encode(bad), io.Discard); err == nil {
				t.Fatal("downloader accepted invalid metadata")
			}
		})
	}
	if _, err := os.Stat(updateCacheDirectory(databasePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected requests created a cache directory: %v", err)
	}
	if _, err := verifyCachedUpdate(databasePath, encode(request)); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatalf("unexpected verification without the cache: %v", err)
	}
	if err := serveUpdateDownload(databasePath, encode(request), io.Discard); err != nil {
		t.Fatal(err)
	}
	args := []string{"--operation", "update-verify-installer", "--database", databasePath}
	var output, errorsOut bytes.Buffer
	if code := runBackendCLI(args, encode(request), &output, &errorsOut); code != 0 || strings.TrimSpace(output.String()) != `{"verified":true}` {
		t.Fatalf("cache verification failed: %d %s %s", code, output.String(), errorsOut.String())
	}
	file := filepath.Join(updateCacheDirectory(databasePath), asset.Name)
	if err := os.WriteFile(file, bytes.Repeat([]byte{'x'}, len(contents)), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code := runBackendCLI(args, encode(request), &output, &errorsOut); code == 0 || output.Len() != 0 || !strings.Contains(errorsOut.String(), updateauth.ErrArtifact.Error()) {
		t.Fatalf("tampered cache was accepted: %d %s %s", code, output.String(), errorsOut.String())
	}
	if _, err := verifyCachedUpdate(databasePath, strings.NewReader("{")); err == nil {
		t.Fatal("cache verification accepted invalid JSON")
	}
}

func TestSignedUpdateWorkerDoesNotJoinWorkspaceOwnership(t *testing.T) {
	const tag = "v9.8.7"
	data := []byte("an installer")
	asset, raw := signedUpdateFixture(t, tag, data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			_ = json.NewEncoder(w).Encode(githubRelease{TagName: tag})
		case strings.HasSuffix(r.URL.Path, "/"+updateauth.ManifestName):
			_, _ = w.Write(raw)
		case strings.HasSuffix(r.URL.Path, "/"+asset.Name):
			_, _ = w.Write(data)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setUpdateTestOrigin(t, server.URL)
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	lease, err := acquireWorkspaceOwnership(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer lease()
	var out, errorsOut bytes.Buffer
	run := func(operation, input string) {
		t.Helper()
		out.Reset()
		errorsOut.Reset()
		if code := runBackendCLI([]string{"--operation", operation, "--database", databasePath}, strings.NewReader(input), &out, &errorsOut); code != 0 {
			t.Fatalf("%s returned %d: %s", operation, code, errorsOut.String())
		}
	}
	run("update-check-release", `{"currentVersion":"1.2.3"}`)
	var checked updateCheckResponse
	if err := json.Unmarshal(out.Bytes(), &checked); err != nil || !checked.IsUpdateAvailable || checked.LastUpdateCheck == "" || !bytes.Equal(checked.SignedManifest, raw) {
		t.Fatalf("unexpected signed result %s (%v)", out.String(), err)
	}
	request, err := json.Marshal(updateDownloadRequest{
		CurrentVersion: "1.2.3", SignedManifest: checked.SignedManifest, InstallerUrl: checked.InstallerUrl,
		InstallerSha256: asset.SHA256, InstallerFileName: asset.Name, InstallerSize: asset.Size,
	})
	if err != nil {
		t.Fatal(err)
	}
	run("update-download", string(request))
	run("update-verify-installer", string(request))
	_, settings := authPaths(databasePath)
	for _, path := range []string{databasePath, settings} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("release operation touched %s (%v)", path, err)
		}
	}
	updateManifestPublicKeyHex = ""
	run("update-check-release", `{"currentVersion":"1.2.3"}`)
	if err := json.Unmarshal(out.Bytes(), &checked); err != nil || checked.IsUpdateAvailable {
		t.Fatalf("unsigned metadata enabled installation: %s (%v)", out.String(), err)
	}
}

func TestSignedUpdateNativePublisherEnforced(t *testing.T) {
	var pin *string
	var fixture, fixturePublisher, samplePublisher string
	switch runtime.GOOS {
	case "windows":
		pin = &updateWindowsPublisherSPKI
		fixture = os.Getenv("WORMHOLE_TEST_AUTHENTICODE_INSTALLER")
		fixturePublisher = os.Getenv("WORMHOLE_TEST_AUTHENTICODE_SPKI")
		samplePublisher = strings.Repeat("ef", 32)
	case "darwin":
		pin = &updateDarwinPublisherTeamID
		fixture = os.Getenv("WORMHOLE_TEST_NOTARIZED_DMG")
		fixturePublisher = os.Getenv("WORMHOLE_TEST_NOTARIZED_TEAM_ID")
		samplePublisher = "AB7CDEFGH9"
	default:
		t.Skip("platform lacks a native publisher verifier")
	}
	const tag = "v9.8.7"
	oldPublisher := *pin
	t.Cleanup(func() { *pin = oldPublisher })

	for _, c := range []struct {
		name      string
		data      []byte
		publisher string
		want      error
	}{
		{"missing", []byte("unsigned installer"), "", updateauth.ErrPublisherUnavailable},
		{"invalid", []byte("unsigned installer"), "not a pin", updateauth.ErrPublisherUnavailable},
		{"unsigned", []byte("unsigned installer"), samplePublisher, updateauth.ErrPublisherUntrusted},
		{"signed fixture", nil, fixturePublisher, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := c.data
			if data == nil {
				if fixture == "" {
					t.Skip("requires a signed installer and publisher pin")
				}
				var err error
				data, err = os.ReadFile(fixture)
				if err != nil {
					t.Fatal(err)
				}
			}
			asset, raw := signedUpdateFixture(t, tag, data)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/"+updateauth.ManifestName) {
					t.Errorf("unexpected request %s", r.URL.Path)
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			setUpdateTestOrigin(t, server.URL)
			*pin = c.publisher
			checked := checkSignedUpdate(updateCheckResponse{ReleaseTag: tag, IsNewerRelease: true}, updateTargetArchitecture())
			wantCapability := c.publisher != "" && c.name != "invalid"
			if checked.PublisherVerification != wantCapability || checked.IsUpdateAvailable != (c.name != "invalid") {
				t.Fatalf("unexpected updater metadata: %+v", checked)
			}
			db := filepath.Join(t.TempDir(), "workspace.db")
			cache := updateCacheDirectory(db)
			if err := os.MkdirAll(cache, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cache, asset.Name), data, 0o600); err != nil {
				t.Fatal(err)
			}
			request := updateVerifyRequest{updateDownloadRequest: updateDownloadRequest{
				InstallerUrl: signedAssetURL(tag, asset.Name), InstallerFileName: asset.Name,
				InstallerSize: asset.Size, InstallerSha256: asset.SHA256, SignedManifest: raw, CurrentVersion: "9.8.6",
			}}
			// Configured builds check the publisher even when the caller omits the policy flag.
			request.RequirePublisher = c.publisher == ""
			input, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			out, err := verifyCachedUpdate(db, bytes.NewReader(input))
			if !errors.Is(err, c.want) || out.Verified != (c.want == nil) || out.PublisherVerified != (c.want == nil) {
				t.Fatalf("unexpected installer verification: %+v, %v (expected %v)", out, err, c.want)
			}
		})
	}
}

func TestSignedUpdateRefusesFallback(t *testing.T) {
	const tag = "v9.8.7"
	asset, raw := signedUpdateFixture(t, tag, []byte("installer"))
	_, older := signedUpdateFixture(t, "v9.8.6", []byte("installer"))
	for _, tc := range []struct {
		name string
		tag  string
		raw  []byte
		pin  string
	}{
		{"missing", tag, nil, updateManifestPublicKeyHex},
		{"replayed", tag, older, updateManifestPublicKeyHex},
		{"tampered", tag, bytes.Replace(raw, []byte(asset.SHA256), []byte(strings.Repeat("f", 64)), 1), updateManifestPublicKeyHex},
		{"bad pin", tag, raw, "bad pin"},
		{"bad tag", "9.8.7", raw, updateManifestPublicKeyHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/releases/latest"):
					_ = json.NewEncoder(w).Encode(githubRelease{TagName: tc.tag, Assets: []githubReleaseAsset{
						{Name: asset.Name, BrowserDownloadUrl: "https://untrusted.invalid", Size: asset.Size},
						{Name: asset.Name + ".sha256", BrowserDownloadUrl: "record-if-accessed"},
					}})
				case strings.HasSuffix(r.URL.Path, "/"+updateauth.ManifestName):
					if tc.name == "bad tag" || tc.name == "bad pin" {
						t.Error("manifest requested before validating the tag and pin")
					}
					if tc.raw == nil {
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write(tc.raw)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			setUpdateTestOrigin(t, server.URL)
			oldPin := updateManifestPublicKeyHex
			updateManifestPublicKeyHex = tc.pin
			t.Cleanup(func() { updateManifestPublicKeyHex = oldPin })
			result, err := checkForUpdate(filepath.Join(t.TempDir(), "workspace.db"), updateCheckRequest{CurrentVersion: "9.8.5"})
			if err != nil || result.IsUpdateAvailable || !result.IsNewerRelease || len(result.SignedManifest) != 0 || result.InstallerUrl != "" {
				t.Fatalf("accepted unsigned fallback: %+v, %v", result, err)
			}
		})
	}
}

func TestSignedUpdateRestrictsRedirects(t *testing.T) {
	client := signedUpdateClient(updateCheckTimeout)
	for _, c := range []struct {
		address string
		depth   int
		allowed bool
	}{
		{"https://release-assets.githubusercontent.com/asset", 1, true},
		{"https://objects.githubusercontent.com/asset", 1, true},
		{"https://github-releases.githubusercontent.com/asset", 4, true},
		{"https://release-assets.githubusercontent.com/asset", 5, false},
		{"http://release-assets.githubusercontent.com/asset", 1, false},
		{"https://release-assets.githubusercontent.com:8443/asset", 1, false},
		{"https://user@release-assets.githubusercontent.com/asset", 1, false},
		{"https://release-assets.githubusercontent.com.invalid/asset", 1, false},
	} {
		req, err := http.NewRequest(http.MethodGet, c.address, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckRedirect(req, make([]*http.Request, c.depth)); (err == nil) != c.allowed {
			t.Errorf("wrong redirect policy for %s at depth %d: %v", c.address, c.depth, err)
		}
	}
}
