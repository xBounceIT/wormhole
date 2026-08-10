package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseAppVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		wantOK bool
		want   string
	}{
		{raw: "v1.2.3", wantOK: true, want: "1.2.3"},
		{raw: "V1.2", wantOK: true, want: "1.2"},
		{raw: "1.2.3.4", wantOK: true, want: "1.2.3.4"},
		{raw: "0.9.0", wantOK: true, want: "0.9.0"},
		{raw: "01.2", wantOK: true, want: "1.2"},
		{raw: "1", wantOK: false},
		{raw: "v", wantOK: false},
		{raw: "1.2.x", wantOK: false},
		{raw: "1..3", wantOK: false},
		{raw: "1.2.3.4.5", wantOK: false},
		{raw: "-1.2", wantOK: false},
		{raw: "", wantOK: false},
	}
	for _, tc := range cases {
		version, ok := parseAppVersion(tc.raw)
		if ok != tc.wantOK {
			t.Errorf("parseAppVersion(%q) ok = %v, want %v", tc.raw, ok, tc.wantOK)
			continue
		}
		if ok && version.String() != tc.want {
			t.Errorf("parseAppVersion(%q) = %q, want %q", tc.raw, version.String(), tc.want)
		}
	}
}

func TestAppVersionComparison(t *testing.T) {
	t.Parallel()
	cases := []struct {
		left     string
		right    string
		wantLess bool
	}{
		{left: "0.9.0", right: "0.10.0", wantLess: true},
		{left: "1.2.3", right: "1.2.4", wantLess: true},
		{left: "1.2", right: "1.2.0", wantLess: false},
		{left: "1.2.3", right: "1.2.3", wantLess: false},
		{left: "1.2.3.4", right: "1.2.3.5", wantLess: true},
		{left: "2.0.0", right: "1.9.9", wantLess: false},
	}
	for _, tc := range cases {
		left, _ := parseAppVersion(tc.left)
		right, _ := parseAppVersion(tc.right)
		if got := left.lessThan(right); got != tc.wantLess {
			t.Errorf("%q < %q = %v, want %v", tc.left, tc.right, got, tc.wantLess)
		}
	}
}

func TestFindInstallerAsset(t *testing.T) {
	t.Parallel()
	release := githubRelease{Assets: []githubReleaseAsset{
		{Name: "Wormhole-0.9.1-win-x64-setup.exe", BrowserDownloadUrl: "https://example/x64.exe", Size: 10},
		{Name: "Wormhole-0.9.1-win-arm64-setup.exe", BrowserDownloadUrl: "https://example/arm64.exe"},
		{Name: "Wormhole-0.9.1-linux-x86_64-setup.AppImage", BrowserDownloadUrl: "https://example/linux-x64"},
		{Name: "Wormhole-0.9.1-linux-arm64-setup.AppImage", BrowserDownloadUrl: "https://example/linux-arm64"},
		{Name: "Wormhole-0.9.1-mac-universal-setup.dmg", BrowserDownloadUrl: "https://example/mac"},
		{Name: "Wormhole-0.9.1-win-x64-setup.exe.sha256", BrowserDownloadUrl: "https://example/x64.sha256"},
		{Name: "README.txt"},
		{Name: "wormhole-0.9.1-win-x64-setup.exe", BrowserDownloadUrl: "https://example/lower.exe"},
	}}
	for _, test := range []struct {
		goos string
		arch string
		name string
	}{
		{goos: "windows", arch: "x64", name: "Wormhole-0.9.1-win-x64-setup.exe"},
		{goos: "windows", arch: "arm64", name: "Wormhole-0.9.1-win-arm64-setup.exe"},
		{goos: "linux", arch: "x64", name: "Wormhole-0.9.1-linux-x86_64-setup.AppImage"},
		{goos: "linux", arch: "arm64", name: "Wormhole-0.9.1-linux-arm64-setup.AppImage"},
		{goos: "darwin", arch: "x64", name: "Wormhole-0.9.1-mac-universal-setup.dmg"},
		{goos: "darwin", arch: "arm64", name: "Wormhole-0.9.1-mac-universal-setup.dmg"},
	} {
		asset := findInstallerAsset(release, test.goos, test.arch)
		if asset == nil || asset.Name != test.name {
			t.Fatalf("%s/%s asset = %+v, want %q", test.goos, test.arch, asset, test.name)
		}
	}
	if asset := findInstallerAsset(release, "linux", "x86"); asset != nil {
		t.Fatalf("x86 asset should not match: %+v", asset)
	}
}

func TestParseShaSidecar(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", 32)
	upper := strings.ToUpper(hash)
	cases := []struct {
		raw  string
		want string
	}{
		{raw: hash + "  Wormhole-1.2.3-win-x64-setup.exe\n", want: hash},
		{raw: upper + " *Wormhole.exe\r\n", want: hash},
		{raw: "\r\n\n" + hash + "\n", want: hash},
		// The first token-bearing line decides the result, even when it is invalid — matching
		// WinUI's ParseShaSidecar, which never falls back to a later line.
		{raw: "not-a-hash  file.exe\n" + hash + "  file2.exe\n", want: ""},
		{raw: "", want: ""},
		{raw: strings.Repeat("ab", 31) + "  file.exe", want: ""},
		{raw: "zz" + strings.Repeat("ab", 31) + "  file.exe", want: ""},
		{raw: hash + "x  file.exe", want: ""},
	}
	for _, tc := range cases {
		if got := parseShaSidecar(tc.raw); got != tc.want {
			t.Errorf("parseShaSidecar(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCheckForUpdate(t *testing.T) {
	hash := strings.Repeat("cd", 32)
	installerName := "Wormhole-9.9.9" + updateInstallerAssetSuffix(runtime.GOOS, updateTargetArchitecture())
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/releases/latest"):
			if request.Header.Get("User-Agent") == "" {
				t.Error("GitHub API request is missing the User-Agent header")
			}
			_ = json.NewEncoder(writer).Encode(githubRelease{
				TagName: "v9.9.9",
				Name:    "Wormhole 9.9.9",
				Body:    "Release notes",
				HtmlUrl: "https://github.com/xBounceIT/wormhole/releases/tag/v9.9.9",
				Assets: []githubReleaseAsset{
					{Name: installerName, BrowserDownloadUrl: server.URL + "/installer", Size: 123},
					{Name: installerName + ".sha256", BrowserDownloadUrl: server.URL + "/installer.sha256"},
				},
			})
		case strings.HasSuffix(request.URL.Path, "/installer.sha256"):
			_, _ = writer.Write([]byte(hash + "  " + installerName + "\n"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	oldBaseURL := updateApiBaseURL
	updateApiBaseURL = server.URL
	defer func() { updateApiBaseURL = oldBaseURL }()

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	result, err := checkForUpdate(databasePath, updateCheckRequest{CurrentVersion: "0.9.0"})
	if err != nil {
		t.Fatalf("checkForUpdate failed: %v", err)
	}
	if !result.IsUpdateAvailable || result.CheckFailed {
		t.Fatalf("expected an available update, got %+v", result)
	}
	if result.LatestVersion != "9.9.9" || result.CurrentVersion != "0.9.0" {
		t.Fatalf("unexpected versions: %+v", result)
	}
	if result.InstallerFileName != installerName ||
		result.InstallerUrl == "" || result.InstallerSize == nil || *result.InstallerSize != 123 {
		t.Fatalf("installer fields missing: %+v", result)
	}
	if result.InstallerSha256 != hash {
		t.Fatalf("sidecar hash = %q, want %q", result.InstallerSha256, hash)
	}
	if result.ReleaseNotes != "Release notes" || result.ReleaseUrl == "" {
		t.Fatalf("release fields missing: %+v", result)
	}

	_, _, lastCheck, _ := mustReadAppSettings(t, databasePath)
	if lastCheck == nil || *lastCheck == "" {
		t.Fatal("LastUpdateCheck was not persisted after a successful check")
	}
}

func TestCheckForUpdateRejectsInstallerWithoutDigest(t *testing.T) {
	installerName := "Wormhole-9.9.9" + updateInstallerAssetSuffix(runtime.GOOS, updateTargetArchitecture())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(githubRelease{
			TagName: "v9.9.9",
			HtmlUrl: "https://github.com/xBounceIT/wormhole/releases/tag/v9.9.9",
			Assets: []githubReleaseAsset{{
				Name: installerName, BrowserDownloadUrl: "https://example.invalid/installer", Size: 123,
			}},
		})
	}))
	defer server.Close()
	oldBaseURL := updateApiBaseURL
	updateApiBaseURL = server.URL
	defer func() { updateApiBaseURL = oldBaseURL }()

	result, err := checkForUpdate(filepath.Join(t.TempDir(), "wormhole.db"), updateCheckRequest{CurrentVersion: "0.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsUpdateAvailable || result.InstallerUrl != "" || result.InstallerFileName != "" || result.InstallerSha256 != "" {
		t.Fatalf("unverified installer was exposed: %+v", result)
	}
	if result.LatestVersion != "9.9.9" || result.ReleaseUrl == "" {
		t.Fatalf("release metadata was lost with the rejected installer: %+v", result)
	}
}

func TestCheckForUpdatePreservesMetadataWithoutCompatibleAsset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(githubRelease{
			TagName: "v9.9.9",
			Name:    "Wormhole 9.9.9",
			Body:    "Release notes",
			HtmlUrl: "https://github.com/xBounceIT/wormhole/releases/tag/v9.9.9",
		})
	}))
	defer server.Close()
	oldBaseURL := updateApiBaseURL
	updateApiBaseURL = server.URL
	defer func() { updateApiBaseURL = oldBaseURL }()

	result, err := checkForUpdate(filepath.Join(t.TempDir(), "wormhole.db"), updateCheckRequest{CurrentVersion: "0.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsUpdateAvailable || result.LatestVersion != "9.9.9" || result.ReleaseUrl == "" ||
		result.ReleaseNotes != "Release notes" {
		t.Fatalf("newer release metadata was not preserved: %+v", result)
	}
}

func TestCheckForUpdateFailureDoesNotPersistMarker(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	oldBaseURL := updateApiBaseURL
	updateApiBaseURL = server.URL
	defer func() { updateApiBaseURL = oldBaseURL }()

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	result, err := checkForUpdate(databasePath, updateCheckRequest{CurrentVersion: "0.9.0"})
	if err == nil {
		t.Fatal("expected an error for a non-2xx GitHub response")
	}
	if !result.CheckFailed || result.IsUpdateAvailable {
		t.Fatalf("expected a failed check, got %+v", result)
	}
	_, _, lastCheck, _ := mustReadAppSettings(t, databasePath)
	if lastCheck != nil {
		t.Fatalf("LastUpdateCheck must not be persisted on failure, got %q", *lastCheck)
	}
}

func TestCheckForUpdateSkipsDraftAndMissingAsset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		release githubRelease
	}{
		{name: "draft", release: githubRelease{TagName: "v9.9.9", Draft: true}},
		{name: "prerelease", release: githubRelease{TagName: "v9.9.9", Prerelease: true}},
		{name: "no asset", release: githubRelease{TagName: "v9.9.9"}},
		{name: "older tag", release: githubRelease{TagName: "v0.8.0"}},
		{name: "bad tag", release: githubRelease{TagName: "not-a-version"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(writer).Encode(tc.release)
			}))
			defer server.Close()
			oldBaseURL := updateApiBaseURL
			updateApiBaseURL = server.URL
			defer func() { updateApiBaseURL = oldBaseURL }()

			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			result, err := checkForUpdate(databasePath, updateCheckRequest{CurrentVersion: "0.9.0"})
			if err != nil {
				t.Fatalf("checkForUpdate failed: %v", err)
			}
			if result.IsUpdateAvailable || result.CheckFailed {
				t.Fatalf("expected no update, got %+v", result)
			}
		})
	}
}

func TestServeUpdateDownload(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("wormhole-installer"), 20000)
	hashBytes := sha256.Sum256(payload)
	hash := hex.EncodeToString(hashBytes[:])
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	output := &bytes.Buffer{}
	installerName := "Wormhole-9.9.9" + updateInstallerAssetSuffix(runtime.GOOS, updateTargetArchitecture())
	request := updateDownloadRequest{
		InstallerUrl:      server.URL + "/" + installerName,
		InstallerFileName: installerName,
		InstallerSha256:   hash,
		InstallerSize:     int64(len(payload)),
	}
	encoded, _ := json.Marshal(request)
	if err := serveUpdateDownload(databasePath, bytes.NewReader(encoded), output); err != nil {
		t.Fatalf("serveUpdateDownload failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected progress + complete lines, got %d lines", len(lines))
	}
	var progress updateDownloadProgress
	if err := json.Unmarshal([]byte(lines[0]), &progress); err != nil ||
		progress.Type != "progress" ||
		progress.Total != int64(len(payload)) ||
		progress.Downloaded <= 0 ||
		progress.Downloaded > progress.Total {
		t.Fatalf("unexpected progress line %q", lines[0])
	}
	var lastProgress updateDownloadProgress
	if err := json.Unmarshal([]byte(lines[len(lines)-2]), &lastProgress); err != nil ||
		lastProgress.Downloaded != int64(len(payload)) {
		t.Fatalf("final progress line should report the full download, got %q", lines[len(lines)-2])
	}
	var complete updateDownloadComplete
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &complete); err != nil || complete.Type != "complete" {
		t.Fatalf("unexpected complete line %q", lines[len(lines)-1])
	}
	installed, err := os.ReadFile(complete.Path)
	if err != nil {
		t.Fatalf("installer not found at %s: %v", complete.Path, err)
	}
	if !bytes.Equal(installed, payload) {
		t.Fatal("installed payload does not match the served bytes")
	}
	if runtime.GOOS == "linux" && filepath.Ext(complete.Path) == ".AppImage" {
		info, statErr := os.Stat(complete.Path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm()&0o100 == 0 {
			t.Fatalf("downloaded AppImage is not executable: mode=%v", info.Mode())
		}
	}
	if _, err := os.Stat(complete.Path + ".part"); !os.IsNotExist(err) {
		t.Fatal("partial file was not removed")
	}
}

func TestServeUpdateDownloadShaMismatch(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("payload"))
	}))
	defer server.Close()

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	output := &bytes.Buffer{}
	request := updateDownloadRequest{
		InstallerUrl:      server.URL + "/Wormhole-9.9.9-win-x64-setup.exe",
		InstallerFileName: "Wormhole-9.9.9-win-x64-setup.exe",
		InstallerSha256:   strings.Repeat("00", 32),
		InstallerSize:     int64(len("payload")),
	}
	encoded, _ := json.Marshal(request)
	err := serveUpdateDownload(databasePath, bytes.NewReader(encoded), output)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected a SHA-256 mismatch error, got %v", err)
	}
	cache := updateCacheDirectory(databasePath)
	entries, _ := os.ReadDir(cache)
	if len(entries) != 0 {
		t.Fatalf("mismatched download left files behind: %v", entries)
	}
}

func TestServeUpdateDownloadRequiresDigest(t *testing.T) {
	t.Parallel()
	request, _ := json.Marshal(updateDownloadRequest{
		InstallerUrl:      "https://example.invalid/Wormhole-9.9.9-linux-x86_64-setup.AppImage",
		InstallerFileName: "Wormhole-9.9.9-linux-x86_64-setup.AppImage",
	})
	err := serveUpdateDownload(filepath.Join(t.TempDir(), "wormhole.db"), bytes.NewReader(request), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "requires a valid SHA-256") {
		t.Fatalf("missing update digest was accepted: %v", err)
	}
}

func TestServeUpdateDownloadRejectsUnexpectedSize(t *testing.T) {
	t.Parallel()
	payload := []byte("payload")
	hashBytes := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	request, _ := json.Marshal(updateDownloadRequest{
		InstallerUrl:      server.URL + "/Wormhole-9.9.9-win-x64-setup.exe",
		InstallerFileName: "Wormhole-9.9.9-win-x64-setup.exe",
		InstallerSha256:   hex.EncodeToString(hashBytes[:]),
		InstallerSize:     int64(len(payload) + 1),
	})
	err := serveUpdateDownload(filepath.Join(t.TempDir(), "wormhole.db"), bytes.NewReader(request), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "size is invalid") {
		t.Fatalf("unexpected update size was accepted: %v", err)
	}
}

func mustReadAppSettings(t *testing.T, databasePath string) (bool, bool, *string, *string) {
	t.Helper()
	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatalf("readAppSettings failed: %v", err)
	}
	return settings.PromptBeforeTunnelConnect, settings.AutoCheckForUpdates,
		settings.LastUpdateCheck, settings.SkippedUpdateVersion
}

func TestUpdateSettingsMergePreservesKeys(t *testing.T) {
	t.Parallel()
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")

	if err := writePromptBeforeTunnelConnect(databasePath, false); err != nil {
		t.Fatalf("writePromptBeforeTunnelConnect failed: %v", err)
	}
	if err := writeSettingsValues(databasePath, map[string]any{
		autoCheckForUpdatesKey:  false,
		skippedUpdateVersionKey: "9.9.9",
	}); err != nil {
		t.Fatalf("writeSettingsValues failed: %v", err)
	}

	prompt, autoCheck, lastCheck, skipped := mustReadAppSettings(t, databasePath)
	if prompt || autoCheck {
		t.Fatalf("settings not written: prompt=%v autoCheck=%v", prompt, autoCheck)
	}
	if lastCheck != nil {
		t.Fatalf("lastCheck should be nil, got %q", *lastCheck)
	}
	if skipped == nil || *skipped != "9.9.9" {
		t.Fatalf("skipped = %v, want 9.9.9", skipped)
	}

	if err := writeSettingsValues(databasePath, map[string]any{skippedUpdateVersionKey: nil}); err != nil {
		t.Fatalf("clearing skipped version failed: %v", err)
	}
	_, autoCheck, _, skipped = mustReadAppSettings(t, databasePath)
	if autoCheck {
		t.Fatal("autoCheckForUpdates must survive a skipped-version write")
	}
	if skipped != nil {
		t.Fatalf("skipped should be cleared, got %q", *skipped)
	}
}

func TestUpdateCacheMaintenanceRemovesOnlyStaleAndSupersededFiles(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	cache := updateCacheDirectory(databasePath)
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	oldPart := filepath.Join(cache, "old.part")
	recentPart := filepath.Join(cache, "recent.part")
	ordinary := filepath.Join(cache, "ordinary.txt")
	directoryPart := filepath.Join(cache, "directory.part")
	for _, path := range []string{oldPart, recentPart, ordinary} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(directoryPart, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-updateStalePartialPartAge - time.Hour)
	if err := os.Chtimes(oldPart, old, old); err != nil {
		t.Fatal(err)
	}
	cleanupStalePartialDownloads(databasePath)
	if fileExists(oldPart) || !fileExists(recentPart) || !fileExists(ordinary) || !directoryExists(directoryPart) {
		t.Fatal("partial-download cleanup removed the wrong cache entries")
	}
	cleanupStalePartialDownloads(filepath.Join(t.TempDir(), "missing.db"))

	keepName := "Wormhole-2.0.0-linux-x86_64-setup.AppImage"
	removeNames := []string{
		"Wormhole-1.0.0-win-x64-setup.exe",
		"Wormhole-1.0.0-linux-x86_64-setup.AppImage",
		"Wormhole-1.0.0-mac-universal-setup.dmg",
	}
	for _, name := range append([]string{keepName}, removeNames...) {
		if err := os.WriteFile(filepath.Join(cache, name), []byte("installer"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rotateInstallerCache(databasePath, keepName)
	if !fileExists(filepath.Join(cache, keepName)) {
		t.Fatal("installer cache rotation removed the selected installer")
	}
	for _, removeName := range removeNames {
		if fileExists(filepath.Join(cache, removeName)) {
			t.Fatalf("installer cache rotation kept superseded %q", removeName)
		}
	}
	if architecture := updateTargetArchitecture(); architecture != "x64" && architecture != "arm64" && architecture != "" {
		t.Fatalf("unexpected update architecture %q", architecture)
	}
}
