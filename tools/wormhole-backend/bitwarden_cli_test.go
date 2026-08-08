package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func bitwardenCliTestZip(t *testing.T, executableContents []byte) []byte {
	t.Helper()
	name := bitwardenCliExecutableName()
	return bitwardenTestZip(t, map[string]string{
		name:                string(executableContents),
		"README.txt":        "Bitwarden CLI fixture",
		"LICENSE.txt":       "MIT",
		"sub/dir/extra.txt": "extra",
	})
}

func bitwardenCliTestReleaseServer(t *testing.T, tagName, digest string, zipBytes []byte) *httptest.Server {
	t.Helper()
	assetName := "bw-windows-" + strings.TrimPrefix(strings.TrimPrefix(tagName, "cli-v"), "cli-v") + ".zip"
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

func TestBitwardenCliInstallLatestPrefersNonOSSAssetVerifiesDigestAndPersists(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipBytes := bitwardenCliTestZip(t, []byte("#!/usr/bin/env false\n"))
	sha256hex := bitwardenTestSha256(zipBytes)
	server := bitwardenCliTestReleaseServer(t, "cli-v2026.6.1", sha256hex, zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	install, err := installBitwardenCliLatest(databasePath, &settings)
	if err != nil {
		t.Fatal(err)
	}
	if install.Version != "2026.6.1" {
		t.Fatalf("version = %q", install.Version)
	}
	if install.Path == "" {
		t.Fatal("install path is empty")
	}
	if _, err := os.Stat(install.Path); err != nil {
		t.Fatalf("installed executable missing: %v", err)
	}
	if install.Sha256 != sha256hex {
		t.Fatalf("sha256 = %q", install.Sha256)
	}

	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != install.Path || persisted.Version != "2026.6.1" {
		t.Fatalf("persisted install = %q / %q", persisted.Path, persisted.Version)
	}
	if !strings.HasPrefix(persisted.InstallStatus, "Installed official Bitwarden CLI") {
		t.Fatalf("install status = %q", persisted.InstallStatus)
	}
}

func TestBitwardenCliFindWindowsAssetPrefersNonOSS(t *testing.T) {
	release := bitwardenRelease{
		TagName: "cli-v2026.6.1",
		Assets: []bitwardenReleaseAsset{
			{Name: "bw-oss-windows-2026.6.1.zip", BrowserDownloadURL: "https://example/oss.zip"},
			{Name: "bw-windows-2026.6.1.zip", BrowserDownloadURL: "https://example/main.zip"},
		},
	}
	asset := findBitwardenCliWindowsAsset(release)
	if asset == nil || asset.Name != "bw-windows-2026.6.1.zip" {
		t.Fatalf("asset = %+v", asset)
	}
}

func TestBitwardenCliFindWindowsAssetRejectsOSSOnlyRelease(t *testing.T) {
	release := bitwardenRelease{
		TagName: "cli-v2026.6.1",
		Assets: []bitwardenReleaseAsset{
			{Name: "bw-oss-windows-2026.6.1.zip", BrowserDownloadURL: "https://example/oss.zip"},
		},
	}
	if asset := findBitwardenCliWindowsAsset(release); asset != nil {
		t.Fatalf("asset = %+v", asset)
	}
}

func TestBitwardenCliParseVersion(t *testing.T) {
	if version := parseBitwardenCliVersion("cli-v2026.6.1"); version != "2026.6.1" {
		t.Fatalf("version = %q", version)
	}
	if version := parseBitwardenCliVersion("bw-windows-2026.6.1.zip"); version != "2026.6.1" {
		t.Fatalf("version = %q", version)
	}
}

func TestBitwardenCliInstallRejectsDigestMismatch(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipBytes := bitwardenCliTestZip(t, []byte("#!/usr/bin/env false\n"))
	server := bitwardenCliTestReleaseServer(t, "cli-v2026.6.1", strings.Repeat("0", 64), zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installBitwardenCliLatest(databasePath, &settings); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("expected checksum error, got %v", err)
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Version != "" || persisted.DownloadURL != "" {
		t.Fatalf("install persisted despite failure: %+v", persisted)
	}
}

func TestBitwardenCliInstallActionEnablesVaultBeforeFailedDownload(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipBytes := bitwardenCliTestZip(t, []byte("test executable"))
	server := bitwardenCliTestReleaseServer(t, "cli-v2026.6.1", strings.Repeat("0", 64), zipBytes)
	restore := bitwardenTestBaseURL(t, server)
	defer restore()

	if _, err := installBitwardenCliLatestWrapped(databasePath); err == nil {
		t.Fatal("expected install failure")
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Enabled {
		t.Fatal("explicit install did not preserve the WinUI enable action")
	}
}

func TestEnsureBitwardenCliInstalledReusesConfiguredExecutableWithoutEnablingVault(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	executable := filepath.Join(t.TempDir(), bitwardenCliExecutableName())
	if err := os.WriteFile(executable, []byte("existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	settings.Path = executable
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}

	result, err := ensureBitwardenCliInstalled(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	state, ok := result.(bitwardenCliState)
	if !ok || state.Installed == nil || state.Installed.Path != executable {
		t.Fatalf("ensure result = %#v", result)
	}
	if state.Enabled {
		t.Fatal("ensure-installed unexpectedly enabled the vault")
	}
}

func TestBitwardenCliInstallRestoresSettingsWhenCommitFails(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipPath := filepath.Join(t.TempDir(), "bw.zip")
	if err := os.WriteFile(zipPath, bitwardenCliTestZip(t, []byte("test executable")), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := bitwardenCliSettings{
		Enabled: true,
		Path:    "existing-bw",
		Version: "existing",
		Sha256:  "old-digest",
	}
	original := settings
	previousWriter := bitwardenCliSettingsWriter
	bitwardenCliSettingsWriter = func(string, bitwardenCliSettings) error {
		return errors.New("settings commit failed")
	}
	t.Cleanup(func() { bitwardenCliSettingsWriter = previousWriter })

	if _, err := installBitwardenCliZipFile(
		databasePath,
		&settings,
		zipPath,
		"2026.6.1",
		"new-digest",
		"bw-windows.zip",
		"https://example/bw.zip",
	); err == nil {
		t.Fatal("expected settings commit failure")
	}
	if settings != original {
		t.Fatalf("settings mutated after rollback: %+v", settings)
	}
	entries, err := os.ReadDir(bitwardenCliInstallRoot(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".staging-") {
			t.Fatalf("failed install left committed path %q", entry.Name())
		}
	}
}

func TestBitwardenCliInstallRejectsZipSlip(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	zipPath := filepath.Join(t.TempDir(), "unsafe.zip")
	bitwardenTestWriteZip(t, zipPath, map[string]string{
		"../outside.txt": "nope",
	})
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installBitwardenCliZipFile(databasePath, &settings, zipPath, "2026.6.1", "abc", "unsafe.zip", "https://example/unsafe.zip"); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "unsafe path") {
		t.Fatalf("expected unsafe path error, got %v", err)
	}
	outside := filepath.Join(filepath.Dir(zipPath), "outside.txt")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("zip slip wrote outside the archive: %v", err)
	}
}

func TestBitwardenCliZipRejectsSymbolicLinkEntries(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "symlink.zip")
	var archiveBuffer bytes.Buffer
	archive := zip.NewWriter(&archiveBuffer)
	header := &zip.FileHeader{Name: bitwardenCliExecutableName(), Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	writer, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("outside")); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, archiveBuffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractBitwardenCliZipSafely(zipPath, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("expected unsupported file error, got %v", err)
	}
}

func TestBitwardenCliResolveExecutable(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "bw.exe")
	if err := os.WriteFile(executable, []byte("#!/usr/bin/env false\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := bitwardenCliSettings{Path: executable}
	if resolved := resolveBitwardenCliExecutable(settings); resolved == "" {
		t.Fatal("absolute path was not resolved")
	}
	if install := resolveBitwardenCliInstall(settings); install == nil || install.Path != resolvedPath(executable) {
		t.Fatalf("install = %+v", install)
	}
}

func resolvedPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

func TestBitwardenCliVaultStatusAndList(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("bitwarden CLI fixture is a Windows-style executable")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	dir := t.TempDir()
	helper := filepath.Join(dir, "bw.exe")
	source := filepath.Join(dir, "main.go")
	sourceCode := `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	switch os.Args[1] {
	case "status":
		fmt.Print("{\"status\":\"unlocked\",\"userEmail\":\"a@b.c\",\"serverUrl\":\"https://vault.bitwarden.com\",\"lastSync\":\"2026-01-01T00:00:00Z\"}")
	case "list":
		fmt.Print("[{\"id\":\"abc\",\"name\":\"Site\",\"login\":{\"username\":\"u\",\"password\":\"p\"},\"revisionDate\":\"2026-01-01T00:00:00Z\"}]")
	case "get":
		if len(os.Args) < 3 || os.Args[2] != "item" {
			os.Exit(1)
		}
		if len(os.Args) < 4 || os.Args[3] == "missing" {
			fmt.Fprint(os.Stderr, "Could not find the item: not found")
			os.Exit(1)
		}
		fmt.Print("{\"id\":\"abc\",\"name\":\"Site\",\"type\":1,\"login\":{\"username\":\"u\",\"password\":\"pw\"},\"revisionDate\":\"2026-01-01T00:00:00Z\"}")
	case "logout":
		fmt.Fprint(os.Stdout, "You are not logged in")
		os.Exit(1)
	default:
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(source, []byte(sourceCode), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", helper, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("could not build fixture: %v\n%s", err, output)
	}
	settings := bitwardenCliSettings{Path: helper}

	status, err := bitwardenCliStatusState(databasePath, settings)
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "Unlocked" {
		t.Fatalf("status = %v", status["status"])
	}
	items, err := bitwardenCliListItems(databasePath, settings, "session", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "abc" || items[0].Username != "u" || items[0].Password != "" {
		t.Fatalf("items = %+v", items)
	}

	item, err := bitwardenCliGetItem(databasePath, settings, "session", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if item == nil || item.ID != "abc" || item.Password != "pw" {
		t.Fatalf("item = %+v", item)
	}
	missing, err := bitwardenCliGetItem(databasePath, settings, "session", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Fatalf("expected nil for missing item, got %+v", missing)
	}

	// Logout already-logged-out output on stdout must be treated as a successful logout.
	if err := bitwardenCliLogout(databasePath, settings); err != nil {
		t.Fatalf("logout with stdout already-logged-out failed: %v", err)
	}
}

func TestBitwardenCliSyncOperationListsAfterSync(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("bitwarden CLI fixture is a Windows-style executable")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	dir := t.TempDir()
	helper := filepath.Join(dir, "bw.exe")
	source := filepath.Join(dir, "main.go")
	sourceCode := `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	switch os.Args[1] {
	case "sync":
		fmt.Print("{}")
	case "list":
		if len(os.Args) < 3 || os.Args[2] != "items" {
			os.Exit(1)
		}
		fmt.Print("[{\"id\":\"after\",\"name\":\"After sync\",\"login\":{\"username\":\"u\"}}]")
	default:
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(source, []byte(sourceCode), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", helper, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("could not build fixture: %v\n%s", err, output)
	}
	settings := bitwardenCliSettings{Path: helper}
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}

	result, err := bitwardenCliSyncOperation(databasePath, "session")
	if err != nil {
		t.Fatal(err)
	}
	document := result.(map[string]any)
	if document["availableCount"] != 1 {
		t.Fatalf("availableCount = %v", document["availableCount"])
	}
	status, ok := document["lastSyncStatus"].(string)
	if !ok || !strings.Contains(status, "Synced 1") {
		t.Fatalf("lastSyncStatus = %v", document["lastSyncStatus"])
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.AvailableCount == nil || *persisted.AvailableCount != 1 {
		t.Fatalf("persisted count = %+v", persisted.AvailableCount)
	}
}

func TestBitwardenCliSanitizeErrorRedactsSecrets(t *testing.T) {
	sanitized := bitwardenCliSanitizeError("login failed --session secret --code 123456 BW_SESSION=abc WORMHOLE_BW_PASSWORD=hunter2")
	if strings.Contains(sanitized, "hunter2") ||
		strings.Contains(sanitized, "secret") ||
		strings.Contains(sanitized, "123456") ||
		strings.Contains(sanitized, "abc WORMHOLE_BW_PASSWORD") {
		t.Fatalf("sanitized output leaked a secret: %q", sanitized)
	}
	if !strings.Contains(sanitized, "[redacted]") {
		t.Fatalf("expected redaction, got %q", sanitized)
	}
}

func TestBitwardenCliErrorSummaryStripsAnsiAndExplainsInteractivePrompt(t *testing.T) {
	errorText := "\x1b[32m\x1b[39m\n\x1b[1mMaster password:\x1b[22m\n\x1b[2m[input is hidden]\x1b[22m"
	summary := summarizeBitwardenCliError(errors.New(errorText))
	if summary != "Bitwarden authentication is required. Unlock the vault and try again." {
		t.Fatalf("summary = %q", summary)
	}
	if strings.Contains(summary, "\x1b") || strings.Contains(summary, "[32m") {
		t.Fatalf("ANSI sequence leaked into summary: %q", summary)
	}
}

func TestBitwardenCliSanitizeErrorRedactsBareRuntimeSecrets(t *testing.T) {
	sanitized := bitwardenCliSanitizeError(
		"helper leaked master-password, session-value, and 654321",
		"master-password",
		"session-value",
		"654321",
	)
	for _, secret := range []string{"master-password", "session-value", "654321"} {
		if strings.Contains(sanitized, secret) {
			t.Fatalf("sanitized output leaked %q: %q", secret, sanitized)
		}
	}
}

func TestBitwardenCliSensitiveValuesFindsEnvironmentAndFlagSecrets(t *testing.T) {
	values := bitwardenCliSensitiveValues(
		[]string{"login", "--code", "123456", "--session=arg-session"},
		map[string]string{
			bitwardenCliPasswordEnvVar: "master-password",
			bitwardenCliSessionEnvVar:  "env-session",
			"UNRELATED":                "public",
		},
	)
	joined := strings.Join(values, "|")
	for _, expected := range []string{"123456", "arg-session", "master-password", "env-session"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing sensitive value %q from %q", expected, joined)
		}
	}
	if strings.Contains(joined, "public") {
		t.Fatalf("unrelated environment value was treated as a secret: %q", joined)
	}
}

func TestBitwardenCliIsAuthenticationError(t *testing.T) {
	if !bitwardenCliIsAuthenticationError("Vault is locked.") {
		t.Fatal("expected auth error for locked")
	}
	if bitwardenCliIsAuthenticationError("Generic failure.") {
		t.Fatal("unexpected auth error")
	}
}

func TestBitwardenCliOutputBufferCapsRunawayOutput(t *testing.T) {
	buffer := bitwardenCliOutputBuffer{maxBytes: 8}
	written, err := buffer.Write([]byte("abcdefghijklmnop"))
	if err != nil {
		t.Fatal(err)
	}
	if written != 16 {
		t.Fatalf("written = %d", written)
	}
	if !buffer.overflowed {
		t.Fatal("expected overflow flag")
	}
	if got := buffer.String(); got != "abcdefgh" {
		t.Fatalf("buffer = %q", got)
	}
	if _, err := buffer.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if got := buffer.String(); got != "abcdefgh" {
		t.Fatalf("buffer grew past the cap: %q", got)
	}
}

func TestBitwardenCliMergeEnvOverridesDuplicateKeys(t *testing.T) {
	base := []string{"PATH=/usr/bin", "BW_SESSION=stale", "KEEP=yes", "WORMHOLE_BW_PASSWORD=old"}
	merged := bitwardenCliMergeEnv(base, map[string]string{
		"BW_SESSION":           "fresh",
		"WORMHOLE_BW_PASSWORD": "newpass",
	})
	got := make(map[string]string)
	for _, entry := range merged {
		if index := strings.IndexByte(entry, '='); index > 0 {
			got[entry[:index]] = entry[index+1:]
		}
	}
	if got["BW_SESSION"] != "fresh" {
		t.Fatalf("BW_SESSION = %q", got["BW_SESSION"])
	}
	if got["WORMHOLE_BW_PASSWORD"] != "newpass" {
		t.Fatalf("WORMHOLE_BW_PASSWORD = %q", got["WORMHOLE_BW_PASSWORD"])
	}
	if got["KEEP"] != "yes" || got["PATH"] != "/usr/bin" {
		t.Fatalf("unexpected base env: %+v", got)
	}
	count := 0
	for _, entry := range merged {
		if strings.HasPrefix(entry, "BW_SESSION=") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("BW_SESSION appears %d times: %v", count, merged)
	}
}

func TestBitwardenCliMergeEnvScrubsInheritedSecretsWithoutOverrides(t *testing.T) {
	merged := bitwardenCliMergeEnv(
		[]string{"PATH=/usr/bin", "bw_session=stale", "WORMHOLE_BW_PASSWORD=old", "KEEP=yes"},
		nil,
	)
	joined := strings.Join(merged, "\n")
	if strings.Contains(strings.ToLower(joined), "bw_session=") ||
		strings.Contains(strings.ToLower(joined), "wormhole_bw_password=") {
		t.Fatalf("sensitive parent environment leaked: %v", merged)
	}
	if !strings.Contains(joined, "KEEP=yes") {
		t.Fatalf("non-sensitive environment was removed: %v", merged)
	}
}

func TestBitwardenCliMergeEnvReplacesSensitiveKeysCaseInsensitively(t *testing.T) {
	merged := bitwardenCliMergeEnv(
		[]string{"Path=C:\\Windows", "bw_session=stale", "wormhole_bw_password=stale"},
		map[string]string{bitwardenCliSessionEnvVar: "fresh", bitwardenCliPasswordEnvVar: "new"},
	)
	for _, stale := range []string{"bw_session=stale", "wormhole_bw_password=stale"} {
		for _, entry := range merged {
			if entry == stale {
				t.Fatalf("sensitive environment override left stale entry %q: %v", stale, merged)
			}
		}
	}
}

func TestBitwardenCliRejectsOversizedSessionKey(t *testing.T) {
	if _, err := bitwardenCliReadSessionKey(strings.Repeat("s", bitwardenCliMaxSessionKey+1)); err == nil {
		t.Fatal("oversized session key was accepted")
	}
}

func TestBitwardenCliStoreAndReadSettings(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settings := defaultBitwardenCliSettings()
	settings.Enabled = true
	settings.Path = "C:\\tools\\bw.exe"
	settings.ServerRegion = bitwardenCliServerEurope
	settings.Version = "2026.6.1"
	count := 42
	settings.AvailableCount = &count
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	read, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !read.Enabled || read.Path != "C:\\tools\\bw.exe" || read.ServerRegion != bitwardenCliServerEurope ||
		read.Version != "2026.6.1" || read.AvailableCount == nil || *read.AvailableCount != 42 {
		t.Fatalf("read = %+v", read)
	}
}

func TestBitwardenCliDisablePreservesIntegrationState(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	count := 7
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		bwCliKeyEnabled:        true,
		bwCliKeyPath:           "bw",
		bwCliKeyVersion:        "2026.6.1",
		bwCliKeySha256:         strings.Repeat("a", 64),
		bwCliKeyInstallStatus:  "Installed official Bitwarden CLI 2026.6.1.",
		bwCliKeyAvailableCount: count,
		bwCliKeyLastSyncStatus: "Synced 7 items.",
		bwCliKeyLastSyncUtc:    "2026-01-01T00:00:00Z",
	})
	state, err := setBitwardenCliEnabled(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if state.Enabled {
		t.Fatal("state still enabled")
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Version != "2026.6.1" || persisted.InstallStatus == "" || persisted.AvailableCount == nil ||
		*persisted.AvailableCount != count || persisted.LastSyncStatus != "Synced 7 items." ||
		persisted.LastSyncUtc == nil || persisted.LastSyncUtc.UTC().Format(time.RFC3339) != "2026-01-01T00:00:00Z" {
		t.Fatalf("disable did not preserve state: %+v", persisted)
	}
	if persisted.Path != "bw" {
		t.Fatalf("path was cleared on disable: %q", persisted.Path)
	}
}

func TestBitwardenCliSetConfigPersistsPathAndRegion(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	state, changed, err := setBitwardenCliConfig(databasePath, "C:\\tools\\bw.exe", bitwardenCliServerEurope)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("config change was not reported")
	}
	if state.Path != "C:\\tools\\bw.exe" || state.ServerRegion != "Europe" {
		t.Fatalf("state = %+v", state)
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != "C:\\tools\\bw.exe" || persisted.ServerRegion != bitwardenCliServerEurope {
		t.Fatalf("persisted = %+v", persisted)
	}
}

func TestBitwardenCliSetConfigReportsUnchangedValues(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if _, changed, err := setBitwardenCliConfig(databasePath, "bw", bitwardenCliServerUnitedStates); err != nil {
		t.Fatal(err)
	} else if changed {
		t.Fatal("default config was reported as changed")
	}
}

func TestBitwardenCliProcessFailureReportsAuthenticationFromStdout(t *testing.T) {
	err := bitwardenCliThrowProcessFailure(bitwardenCliProcessResult{
		StandardOut: "Vault is locked.",
	})
	if !bitwardenCliIsAuthenticationError(err.Error()) {
		t.Fatalf("authentication failure was hidden by generic error: %v", err)
	}
	if strings.Contains(err.Error(), "Vault is locked.") {
		t.Fatalf("untrusted stdout was exposed: %v", err)
	}
}

func TestBitwardenCliSetConfigRejectsInvalidRegion(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if _, _, err := setBitwardenCliConfig(databasePath, "bw", 99); err == nil {
		t.Fatal("invalid region was accepted")
	}
}

func TestBitwardenCliSetConfigNormalizesPathAndClearsInstallMetadata(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settings := defaultBitwardenCliSettings()
	settings.Path = "C:\\old\\bw.exe"
	settings.Version = "2026.1.0"
	settings.Sha256 = strings.Repeat("a", 64)
	settings.AssetName = "bw-windows.zip"
	settings.DownloadURL = "https://example.invalid/bw.zip"
	settings.InstallStatus = "Installed."
	settings.InstallError = "old error"
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	if _, _, err := setBitwardenCliConfig(databasePath, "  ", bitwardenCliServerCurrent); err != nil {
		t.Fatal(err)
	}
	persisted, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Path != "bw" || persisted.Version != "" || persisted.Sha256 != "" ||
		persisted.AssetName != "" || persisted.DownloadURL != "" ||
		persisted.InstallStatus != "" || persisted.InstallError != "" {
		t.Fatalf("path change left stale install metadata: %+v", persisted)
	}
}

func TestBitwardenCliPathComparisonMatchesPlatformFilesystem(t *testing.T) {
	if runtime.GOOS == "windows" {
		if !bitwardenCliPathsEqual(`C:\\Tools\\BW.EXE`, `c:\\tools\\bw.exe`) {
			t.Fatal("Windows CLI paths should compare case-insensitively")
		}
		return
	}
	if bitwardenCliPathsEqual("/opt/BW", "/opt/bw") {
		t.Fatal("non-Windows CLI paths should preserve case")
	}
}
