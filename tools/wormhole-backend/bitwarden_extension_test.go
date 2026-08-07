package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validBitwardenManifest = `{
  "manifest_version": 3,
  "name": "Bitwarden Password Manager",
  "version": "2026.6.1",
  "action": {
    "default_popup": "popup.html"
  }
}`

func TestBitwardenInstallLatestPrefersEdgeAssetVerifiesDigestAndPersists(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipBytes := bitwardenTestZip(t, map[string]string{
		"manifest.json": validBitwardenManifest,
		"popup.html":    "<html></html>",
	})
	sha256hex := bitwardenTestSha256(zipBytes)
	server := bitwardenTestReleaseServer(t, "browser-v2026.6.1", sha256hex, zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	install, err := installBitwardenLatestRelease(databasePath, &settings)
	if err != nil {
		t.Fatal(err)
	}
	if install.Version != "2026.6.1" {
		t.Fatalf("version = %q", install.Version)
	}
	if install.AssetName != "dist-edge-2026.6.1.zip" {
		t.Fatalf("asset = %q", install.AssetName)
	}
	if install.Sha256 != sha256hex {
		t.Fatalf("sha256 = %q", install.Sha256)
	}
	if _, err := os.Stat(filepath.Join(install.Path, "manifest.json")); err != nil {
		t.Fatalf("installed manifest missing: %v", err)
	}

	persisted, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != install.Path || persisted.Version != "2026.6.1" {
		t.Fatalf("persisted install = %q / %q", persisted.Path, persisted.Version)
	}
	if persisted.Source != bitwardenSourceOfficialGitHub {
		t.Fatalf("source = %d", persisted.Source)
	}
	if persisted.LastUpdateCheckUtc == nil {
		t.Fatal("last update check was not stamped")
	}
	if !strings.HasPrefix(persisted.LastUpdateStatus, "Installed official release") {
		t.Fatalf("status = %q", persisted.LastUpdateStatus)
	}
}

func TestBitwardenReinstallPreservesConfiguredPath(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.5.1")
	oldOnly := filepath.Join(currentPath, "old-only.txt")
	if err := os.WriteFile(oldOnly, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipBytes := bitwardenTestZip(t, map[string]string{
		"manifest.json": validBitwardenManifest,
		"popup.html":    "<html></html>",
	})
	sha256hex := bitwardenTestSha256(zipBytes)
	server := bitwardenTestReleaseServer(t, "browser-v2026.6.1", sha256hex, zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeySource:  bitwardenSourceOfficialGitHub,
		bwExtKeyVersion: "2026.5.1",
		bwExtKeyPath:    currentPath,
		bwExtKeyEnabled: true,
	})
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	install, err := installBitwardenLatestRelease(databasePath, &settings)
	if err != nil {
		t.Fatal(err)
	}
	if install.Path != currentPath {
		t.Fatalf("path changed: %q", install.Path)
	}
	if _, err := os.Stat(filepath.Join(currentPath, "popup.html")); err != nil {
		t.Fatalf("new files missing: %v", err)
	}
	if _, err := os.Stat(oldOnly); !os.IsNotExist(err) {
		t.Fatalf("old files survived: %v", err)
	}
	bitwardenTestAssertNoBackups(t, installRoot)
}

func TestEnsureBitwardenExtensionInstalledReusesConfiguredInstall(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.6.1")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeyEnabled: true,
		bwExtKeySource:  bitwardenSourceOfficialGitHub,
		bwExtKeyVersion: "2026.6.1",
		bwExtKeyPath:    currentPath,
	})

	state, err := ensureBitwardenExtensionInstalled(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Installed == nil || state.Installed.Path != currentPath ||
		state.Installed.Version != "2026.6.1" {
		t.Fatalf("ensure result = %+v", state)
	}
}

func TestBitwardenInstallRejectsDigestMismatch(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipBytes := bitwardenTestZip(t, map[string]string{
		"manifest.json": validBitwardenManifest,
	})
	server := bitwardenTestReleaseServer(t, "browser-v2026.6.1", strings.Repeat("0", 64), zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installBitwardenLatestRelease(databasePath, &settings); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("expected checksum error, got %v", err)
	}
	persisted, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != "" {
		t.Fatalf("path persisted despite failure: %q", persisted.Path)
	}
}

func TestBitwardenImportZipBlocksZipSlipEntries(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipPath := filepath.Join(t.TempDir(), "unsafe.zip")
	bitwardenTestWriteZip(t, zipPath, map[string]string{
		"manifest.json":  validBitwardenManifest,
		"../outside.txt": "nope",
	})

	if _, err := importBitwardenExtensionZip(databasePath, zipPath); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "unsafe path") {
		t.Fatalf("expected unsafe path error, got %v", err)
	}
	outside := filepath.Join(filepath.Dir(zipPath), "outside.txt")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("zip slip wrote outside the archive: %v", err)
	}
	persisted, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Enabled {
		t.Fatal("manual import did not preserve the WinUI enable action after failure")
	}
}

func TestBitwardenImportFolderCopiesAndPersistsManualSource(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	source := filepath.Join(t.TempDir(), "source-extension")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "manifest.json"), []byte(validBitwardenManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "popup.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeySource:             bitwardenSourceOfficialGitHub,
		bwExtKeyLastUpdateCheckUtc: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
	})

	state, err := importBitwardenExtensionFolder(databasePath, source)
	if err != nil {
		t.Fatal(err)
	}
	if state.Installed == nil || state.Installed.Path == source {
		t.Fatalf("installed = %+v", state.Installed)
	}
	if state.Installed.DefaultPopup != "popup.html" {
		t.Fatalf("popup = %q", state.Installed.DefaultPopup)
	}
	persisted, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Source != bitwardenSourceManualFolder {
		t.Fatalf("source = %d", persisted.Source)
	}
	if persisted.LastUpdateCheckUtc != nil {
		t.Fatal("manual install kept the auto-update stamp")
	}
	if !strings.HasPrefix(persisted.LastUpdateStatus, "Manual folder install is pinned") {
		t.Fatalf("status = %q", persisted.LastUpdateStatus)
	}
	if !persisted.Enabled {
		t.Fatal("import did not enable the extension")
	}
	if !state.Enabled {
		t.Fatal("state did not report the extension as enabled")
	}
}

func TestBitwardenImportFolderReimportPreservesConfiguredPath(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.5.1")
	oldOnly := filepath.Join(currentPath, "old-only.txt")
	if err := os.WriteFile(oldOnly, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source-extension")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "manifest.json"), []byte(validBitwardenManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "popup.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeySource:  bitwardenSourceManualFolder,
		bwExtKeyVersion: "2026.5.1",
		bwExtKeyPath:    currentPath,
	})

	state, err := importBitwardenExtensionFolder(databasePath, source)
	if err != nil {
		t.Fatal(err)
	}
	if state.Installed == nil || state.Installed.Path != currentPath {
		t.Fatalf("installed = %+v", state.Installed)
	}
	if _, err := os.Stat(filepath.Join(currentPath, "popup.html")); err != nil {
		t.Fatalf("new files missing: %v", err)
	}
	if _, err := os.Stat(oldOnly); !os.IsNotExist(err) {
		t.Fatalf("old files survived: %v", err)
	}
	bitwardenTestAssertNoBackups(t, installRoot)
}

func TestBitwardenReleaseHelpers(t *testing.T) {
	release := bitwardenRelease{
		TagName: "browser-v2026.6.1",
		Assets: []bitwardenReleaseAsset{
			{Name: "dist-chrome-2026.6.1.zip", BrowserDownloadURL: "https://example/chrome.zip"},
			{Name: "dist-edge-2026.6.1.zip", BrowserDownloadURL: "https://example/edge.zip"},
		},
	}
	if !isBitwardenBrowserRelease(release) {
		t.Fatal("release was not recognized as a browser release")
	}
	if asset := findPreferredBitwardenAsset(release); asset == nil || asset.Name != "dist-edge-2026.6.1.zip" {
		t.Fatalf("preferred asset = %+v", asset)
	}
	if version := parseBitwardenBrowserVersion("browser-v2026.6.1"); version != "2026.6.1" {
		t.Fatalf("version = %q", version)
	}
	if digest := parseBitwardenGitHubSha256("sha256:" + strings.Repeat("A", 64)); digest != strings.Repeat("a", 64) {
		t.Fatalf("digest = %q", digest)
	}
}

func TestBitwardenUpdateInstallsNewerOfficialRelease(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.6.1")
	oldOnly := filepath.Join(currentPath, "old-only.txt")
	if err := os.WriteFile(oldOnly, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipBytes := bitwardenTestZip(t, map[string]string{
		"manifest.json": validBitwardenManifest,
		"popup.html":    "<html></html>",
	})
	sha256hex := bitwardenTestSha256(zipBytes)
	server := bitwardenTestReleaseServer(t, "browser-v2026.6.2", sha256hex, zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeySource:  bitwardenSourceOfficialGitHub,
		bwExtKeyVersion: "2026.6.1",
		bwExtKeyPath:    currentPath,
		bwExtKeyEnabled: true,
	})

	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	check, install, wasUpdated, err := updateBitwardenIfAvailable(databasePath, &settings)
	if err != nil {
		t.Fatal(err)
	}
	if !wasUpdated || !check.IsUpdateAvailable || install == nil || install.Version != "2026.6.2" {
		t.Fatalf("update = %+v / %+v / %v", check, install, wasUpdated)
	}
	if install.Path != currentPath {
		t.Fatalf("path changed: %q", install.Path)
	}
	if _, err := os.Stat(filepath.Join(currentPath, "popup.html")); err != nil {
		t.Fatalf("new files missing: %v", err)
	}
	if _, err := os.Stat(oldOnly); !os.IsNotExist(err) {
		t.Fatalf("old files survived: %v", err)
	}
	bitwardenTestAssertNoBackups(t, installRoot)
}

func TestBitwardenUpdateSkipsWhenLatestIsNotNewer(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.6.2")
	server := bitwardenTestReleaseServer(t, "browser-v2026.6.2", "", nil)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeySource:  bitwardenSourceOfficialGitHub,
		bwExtKeyVersion: "2026.6.2",
		bwExtKeyPath:    currentPath,
	})

	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	check, install, wasUpdated, err := updateBitwardenIfAvailable(databasePath, &settings)
	if err != nil {
		t.Fatal(err)
	}
	if wasUpdated || check.IsUpdateAvailable || install != nil {
		t.Fatalf("update = %+v / %+v / %v", check, install, wasUpdated)
	}
	persisted, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != currentPath || persisted.Version != "2026.6.2" {
		t.Fatalf("persisted = %q / %q", persisted.Path, persisted.Version)
	}
}

func TestBitwardenCompareVersionsUsesNumericSegments(t *testing.T) {
	if compareBitwardenVersions("2026.6.10", "2026.6.2") <= 0 {
		t.Fatal("2026.6.10 should be newer than 2026.6.2")
	}
	if compareBitwardenVersions("browser-v2026.6.0", "2026.6") != 0 {
		t.Fatal("browser-v2026.6.0 should equal 2026.6")
	}
	if compareBitwardenVersions("2026.7", "2026.6.99") <= 0 {
		t.Fatal("2026.7 should be newer than 2026.6.99")
	}
}

func TestBitwardenUpdateIfStaleSkipsFreshCheck(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.6.1")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		t.Fatal("release feed was queried despite a fresh last check")
	}))
	defer server.Close()
	restore := bitwardenTestBaseURL(t, server)
	defer restore()
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeyEnabled:            true,
		bwExtKeySource:             bitwardenSourceOfficialGitHub,
		bwExtKeyVersion:            "2026.6.1",
		bwExtKeyPath:               currentPath,
		bwExtKeyLastUpdateCheckUtc: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
	})

	state, err := updateBitwardenExtensionIfStale(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastUpdateStatus != nil {
		t.Fatalf("status changed despite fresh check: %q", *state.LastUpdateStatus)
	}
}

func TestBitwardenUpdateIfStaleRecordsFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	currentPath := bitwardenTestInstallTree(t, installRoot, "2026.6.1")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	restore := bitwardenTestBaseURL(t, server)
	defer restore()
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwExtKeyEnabled:          true,
		bwExtKeySource:           bitwardenSourceOfficialGitHub,
		bwExtKeyVersion:          "2026.6.1",
		bwExtKeyPath:             currentPath,
		bwExtKeyAvailableVersion: "2026.7.0",
	})

	state, err := updateBitwardenExtensionIfStale(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastUpdateStatus == nil || *state.LastUpdateStatus != "Auto-update check failed." {
		t.Fatalf("status = %+v", state.LastUpdateStatus)
	}
	if state.LastUpdateError == nil || *state.LastUpdateError == "" {
		t.Fatalf("error was not recorded: %+v", state.LastUpdateError)
	}
	if state.LastUpdateCheckUtc == nil {
		t.Fatal("failed check did not stamp LastUpdateCheckUtc")
	}
	if state.AvailableVersion == nil || *state.AvailableVersion != "2026.7.0" {
		t.Fatalf("failed check discarded the last known available version: %+v", state.AvailableVersion)
	}
}

func TestBitwardenManifestReadRequiresName(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(`{"version": "1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBitwardenManifest(root); err == nil ||
		!strings.Contains(err.Error(), "does not define a name") {
		t.Fatalf("expected name error, got %v", err)
	}
}

func TestBitwardenManifestReadRejectsOversizedDocument(t *testing.T) {
	root := t.TempDir()
	contents := append([]byte(`{"name":"Bitwarden","padding":"`), bytes.Repeat([]byte("x"), bitwardenMaxManifestBytes)...)
	contents = append(contents, []byte(`"}`)...)
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBitwardenManifest(root); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected manifest size error, got %v", err)
	}
}

func TestBitwardenZipRejectsSymbolicLinkEntries(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "symlink.zip")
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "linked-manifest.json", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	writer, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("manifest.json")); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractBitwardenZipSafely(zipPath, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("expected unsupported file error, got %v", err)
	}
}

func TestBitwardenFolderCopyRejectsNestedDestination(t *testing.T) {
	source := t.TempDir()
	if err := copyBitwardenDirectory(source, filepath.Join(source, "nested")); err == nil {
		t.Fatal("nested staging directory was accepted")
	}
}

func TestBitwardenFolderCopyCountsDirectoriesAgainstEntryLimit(t *testing.T) {
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "one", "two", "three"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyBitwardenDirectoryWithLimits(source, filepath.Join(t.TempDir(), "copy"), 2, 1024); err == nil ||
		!strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("expected entry count error, got %v", err)
	}
}

func TestBitwardenFolderCopyRejectsFilesOverExtractedSizeLimit(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "large.bin"), []byte("too-large"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyBitwardenDirectoryWithLimits(source, filepath.Join(t.TempDir(), "copy"), 10, 4); err == nil ||
		!strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected extracted size error, got %v", err)
	}
}

func TestBitwardenExtensionInstallRestoresFilesAndSettingsWhenCommitFails(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	finalPath := filepath.Join(installRoot, "2026.6.0")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "manifest.json"), []byte(`{"name":"Bitwarden old","version":"2026.6.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "extension")
	if err := os.MkdirAll(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "manifest.json"), []byte(`{"name":"Bitwarden new","version":"2026.6.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := bitwardenExtensionSettings{
		Enabled: true,
		Source:  bitwardenSourceOfficialGitHub,
		Version: "2026.6.0",
		Path:    finalPath,
		Sha256:  "old-digest",
	}
	original := settings
	previousWriter := bitwardenExtensionSettingsWriter
	bitwardenExtensionSettingsWriter = func(string, bitwardenExtensionSettings) error {
		return errors.New("settings commit failed")
	}
	t.Cleanup(func() { bitwardenExtensionSettingsWriter = previousWriter })

	if _, err := activateBitwardenInstall(
		databasePath,
		&settings,
		staged,
		"Bitwarden new",
		"popup/index.html",
		"2026.6.1",
		"new-digest",
		"dist-edge.zip",
		"https://example/new.zip",
		bitwardenSourceOfficialGitHub,
	); err == nil {
		t.Fatal("expected settings commit failure")
	}
	if settings != original {
		t.Fatalf("settings mutated after rollback: %+v", settings)
	}
	manifest, err := os.ReadFile(filepath.Join(finalPath, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "Bitwarden old") {
		t.Fatalf("previous install was not restored: %s", manifest)
	}
	bitwardenTestAssertNoBackups(t, installRoot)
}

func TestBitwardenExtensionRollbackReportsMissingBackup(t *testing.T) {
	root := t.TempDir()
	finalPath := filepath.Join(root, "current")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rollbackBitwardenInstall(finalPath, filepath.Join(root, "missing-backup")); err == nil {
		t.Fatal("rollback unexpectedly succeeded without the previous installation")
	}
	if directoryExists(finalPath) {
		t.Fatal("failed rollback left the replacement installation active")
	}
}

func bitwardenTestReleaseServer(t *testing.T, tagName, digest string, zipBytes []byte) *httptest.Server {
	t.Helper()
	assetName := "dist-edge-" + strings.TrimPrefix(tagName, "browser-v") + ".zip"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/repos/") {
			asset := map[string]any{
				"name":                 assetName,
				"browser_download_url": fmt.Sprintf("http://%s/download.zip", request.Host),
			}
			if digest != "" {
				asset["digest"] = "sha256:" + digest
			}
			_ = json.NewEncoder(writer).Encode([]map[string]any{{
				"tag_name":   tagName,
				"draft":      false,
				"prerelease": false,
				"assets":     []map[string]any{asset},
			}})
			return
		}
		if zipBytes == nil {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(zipBytes)
	}))
	t.Cleanup(server.Close)
	return server
}

func bitwardenTestBaseURL(t *testing.T, server *httptest.Server) func() {
	t.Helper()
	previous := bitwardenGithubBaseURL
	bitwardenGithubBaseURL = server.URL + "/"
	return func() { bitwardenGithubBaseURL = previous }
}

func bitwardenTestZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, contents := range entries {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func bitwardenTestWriteZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, contents := range entries {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bitwardenTestSha256(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func bitwardenTestInstallTree(t *testing.T, installRoot, version string) string {
	t.Helper()
	if err := os.MkdirAll(installRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(installRoot, version)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), []byte(validBitwardenManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func bitwardenTestWriteSettings(t *testing.T, databasePath string, values map[string]any) {
	t.Helper()
	document := map[string]json.RawMessage{
		settingsSchemaVersionKey: json.RawMessage("8"),
	}
	for key, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		document[key] = encoded
	}
	contents, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(databasePath), authSettingsFilename), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bitwardenTestAssertNoBackups(t *testing.T, installRoot string) {
	t.Helper()
	entries, err := os.ReadDir(installRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".backup-") || strings.HasPrefix(entry.Name(), ".staging-") {
			t.Fatalf("leftover staging/backup directory: %s", entry.Name())
		}
	}
}
