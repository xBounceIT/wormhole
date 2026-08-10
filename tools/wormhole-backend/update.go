package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	updateRepositoryOwner      = "xBounceIT"
	updateRepositoryName       = "wormhole"
	updateCheckTimeout         = 30 * time.Second
	updateDownloadTimeout      = 30 * time.Minute
	updateDownloadBufferSize   = 81920
	updateMaxInstallerBytes    = 2 * 1024 * 1024 * 1024
	updateProgressReportStep   = 0.01
	updateProgressReportWindow = 100 * time.Millisecond
	updateStalePartialPartAge  = 24 * time.Hour
)

var updateInstallerCachePatterns = []string{
	"Wormhole-*-win-*-setup.exe",
	"Wormhole-*-linux-*-setup.AppImage",
	"Wormhole-*-mac-*-setup.dmg",
}

// updateApiBaseURL is overridden by tests with a local server. The GitHub REST endpoint is the
// same one the WinUI 3 app queries (base address api.github.com + repos/{owner}/{repo}/releases/latest).
var updateApiBaseURL = "https://api.github.com"

type updateCheckRequest struct {
	CurrentVersion string `json:"currentVersion"`
}

// updateCheckResponse is shared by every Electron host. latestVersion is empty when the check
// found nothing newer; installer fields are populated only for a verified asset matching the
// running operating system and architecture.
type updateCheckResponse struct {
	CurrentVersion    string `json:"currentVersion"`
	LatestVersion     string `json:"latestVersion,omitempty"`
	IsUpdateAvailable bool   `json:"isUpdateAvailable"`
	CheckFailed       bool   `json:"checkFailed"`
	ReleaseTag        string `json:"releaseTag,omitempty"`
	ReleaseName       string `json:"releaseName,omitempty"`
	ReleaseUrl        string `json:"releaseUrl,omitempty"`
	ReleaseNotes      string `json:"releaseNotes,omitempty"`
	InstallerUrl      string `json:"installerUrl,omitempty"`
	InstallerFileName string `json:"installerFileName,omitempty"`
	InstallerSize     *int64 `json:"installerSize,omitempty"`
	InstallerSha256   string `json:"installerSha256,omitempty"`
}

type githubRelease struct {
	TagName    string               `json:"tag_name"`
	Name       string               `json:"name"`
	Body       string               `json:"body"`
	HtmlUrl    string               `json:"html_url"`
	Draft      bool                 `json:"draft"`
	Prerelease bool                 `json:"prerelease"`
	Assets     []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadUrl string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type updateDownloadRequest struct {
	InstallerUrl      string `json:"installerUrl"`
	InstallerFileName string `json:"installerFileName"`
	InstallerSha256   string `json:"installerSha256"`
	InstallerSize     int64  `json:"installerSize"`
}

type updateDownloadProgress struct {
	Type       string `json:"type"`
	Downloaded int64  `json:"downloaded"`
	Total      int64  `json:"total"`
}

type updateDownloadComplete struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// appVersion mirrors the component-wise comparison of System.Version: up to four numeric
// components with missing trailing components treated as zero.
type appVersion struct {
	components [4]int
	length     int
}

func parseAppVersion(raw string) (appVersion, bool) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 1 && (trimmed[0] == 'v' || trimmed[0] == 'V') {
		trimmed = trimmed[1:]
	}
	if trimmed == "" {
		return appVersion{}, false
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return appVersion{}, false
	}
	var version appVersion
	for index, part := range parts {
		if part == "" {
			return appVersion{}, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return appVersion{}, false
		}
		version.components[index] = value
	}
	version.length = len(parts)
	return version, true
}

func (version appVersion) lessThan(other appVersion) bool {
	for index := 0; index < len(version.components); index++ {
		if version.components[index] != other.components[index] {
			return version.components[index] < other.components[index]
		}
	}
	return false
}

func (version appVersion) String() string {
	values := make([]string, 0, version.length)
	for index := 0; index < version.length; index++ {
		component := version.components[index]
		values = append(values, strconv.Itoa(component))
	}
	return strings.Join(values, ".")
}

func updateTargetArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func updateInstallerAssetSuffix(operatingSystem, arch string) string {
	switch operatingSystem {
	case "windows":
		if arch == "x64" || arch == "arm64" {
			return "-win-" + arch + "-setup.exe"
		}
	case "linux":
		if arch == "x64" {
			arch = "x86_64"
		}
		if arch == "x86_64" || arch == "arm64" {
			return "-linux-" + arch + "-setup.AppImage"
		}
	case "darwin":
		if arch == "x64" || arch == "arm64" {
			return "-mac-universal-setup.dmg"
		}
	}
	return ""
}

func findInstallerAsset(release githubRelease, operatingSystem, arch string) *githubReleaseAsset {
	suffix := updateInstallerAssetSuffix(operatingSystem, arch)
	if suffix == "" {
		return nil
	}
	for index := range release.Assets {
		asset := &release.Assets[index]
		name := strings.TrimSpace(asset.Name)
		if len(name) >= len("Wormhole-") &&
			strings.EqualFold(name[:len("Wormhole-")], "Wormhole-") &&
			strings.HasSuffix(name, suffix) {
			return asset
		}
	}
	return nil
}

// parseShaSidecar mirrors UpdateService.ParseShaSidecar: the first non-empty line's
// whitespace-delimited token must be a 64-character hex SHA-256. A token-bearing line that is
// not a valid SHA-256 ends the parse (no fallback to later lines), matching WinUI.
func parseShaSidecar(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		token := line
		if separator := strings.IndexAny(line, " \t"); separator >= 0 {
			token = line[:separator]
		}
		if len(token) != 64 {
			return ""
		}
		if _, err := hex.DecodeString(token); err != nil {
			return ""
		}
		return strings.ToLower(token)
	}
	return ""
}

func updateCacheDirectory(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "cache", "updates")
}

func cleanupStalePartialDownloads(databasePath string) {
	cacheDirectory := updateCacheDirectory(databasePath)
	entries, err := os.ReadDir(cacheDirectory)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-updateStalePartialPartAge)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".part") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(cacheDirectory, entry.Name()))
	}
}

func rotateInstallerCache(databasePath string, keepFileName string) {
	cacheDirectory := updateCacheDirectory(databasePath)
	for _, pattern := range updateInstallerCachePatterns {
		entries, err := filepath.Glob(filepath.Join(cacheDirectory, pattern))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.EqualFold(filepath.Base(entry), keepFileName) {
				continue
			}
			_ = os.Remove(entry)
		}
	}
}

func stripMarkOfTheWeb(path string) {
	if runtime.GOOS != "windows" {
		return
	}
	// Deleting the alternate data stream is exactly what the WinUI app does (File.Delete on
	// "path:Zone.Identifier") so a downloaded installer never triggers SmartScreen blocks.
	_ = os.Remove(path + ":Zone.Identifier")
}

// checkForUpdate queries the GitHub latest release, mirrors UpdateService.CheckAsync, and
// persists the LastUpdateCheck marker only after a parseable GitHub answer.
func checkForUpdate(databasePath string, request updateCheckRequest) (updateCheckResponse, error) {
	cleanupStalePartialDownloads(databasePath)

	currentText := strings.TrimSpace(request.CurrentVersion)
	if currentText == "" {
		currentText = "0.0.0"
	}
	currentVersion, _ := parseAppVersion(currentText)
	failed := func() updateCheckResponse {
		return updateCheckResponse{
			CurrentVersion: currentVersion.String(),
			CheckFailed:    true,
		}
	}

	arch := updateTargetArchitecture()
	if arch == "" {
		return updateCheckResponse{CurrentVersion: currentVersion.String()}, nil
	}

	client := &http.Client{Timeout: updateCheckTimeout}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", updateApiBaseURL, updateRepositoryOwner, updateRepositoryName)
	httpRequest, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return failed(), fmt.Errorf("cannot build the update request: %w", err)
	}
	httpRequest.Header.Set("User-Agent", "Wormhole-Electron")
	response, err := client.Do(httpRequest)
	if err != nil {
		return failed(), fmt.Errorf("update check failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return failed(), fmt.Errorf("GitHub releases/latest returned %s", response.Status)
	}

	var release githubRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 8*1024*1024)).Decode(&release); err != nil {
		return failed(), fmt.Errorf("cannot parse the GitHub release: %w", err)
	}

	// Only a parseable GitHub answer counts as a check for throttling purposes.
	now := time.Now().UTC().Format(time.RFC3339)
	if err := writeSettingsValues(databasePath, map[string]any{"LastUpdateCheck": now}); err != nil {
		return failed(), err
	}

	if release.Draft || release.Prerelease {
		return updateCheckResponse{CurrentVersion: currentVersion.String()}, nil
	}
	latestVersion, ok := parseAppVersion(release.TagName)
	if !ok {
		return updateCheckResponse{CurrentVersion: currentVersion.String()}, nil
	}
	if !currentVersion.lessThan(latestVersion) {
		return updateCheckResponse{
			CurrentVersion: currentVersion.String(),
			LatestVersion:  latestVersion.String(),
		}, nil
	}
	newerRelease := updateCheckResponse{
		CurrentVersion: currentVersion.String(),
		LatestVersion:  latestVersion.String(),
		ReleaseTag:     release.TagName,
		ReleaseName:    release.Name,
		ReleaseUrl:     release.HtmlUrl,
		ReleaseNotes:   release.Body,
	}

	asset := findInstallerAsset(release, runtime.GOOS, arch)
	if asset == nil || strings.TrimSpace(asset.BrowserDownloadUrl) == "" ||
		asset.Size <= 0 || asset.Size > updateMaxInstallerBytes {
		return newerRelease, nil
	}

	assetSize := asset.Size
	sha256Sidecar := fetchSha256Sidecar(client, release, asset)
	if sha256Sidecar == "" {
		return newerRelease, nil
	}

	newerRelease.IsUpdateAvailable = true
	newerRelease.InstallerUrl = asset.BrowserDownloadUrl
	newerRelease.InstallerFileName = asset.Name
	newerRelease.InstallerSize = &assetSize
	newerRelease.InstallerSha256 = sha256Sidecar
	return newerRelease, nil
}

// fetchSha256Sidecar looks for "{installerName}.sha256" among the release assets and parses the
// hash out of it. Missing or unreadable integrity metadata makes the asset unavailable for an
// in-app update; release metadata remains visible so users can still inspect the release page.
func fetchSha256Sidecar(client *http.Client, release githubRelease, installerAsset *githubReleaseAsset) string {
	wanted := installerAsset.Name + ".sha256"
	var sidecar *githubReleaseAsset
	for index := range release.Assets {
		asset := &release.Assets[index]
		if strings.EqualFold(asset.Name, wanted) {
			sidecar = asset
			break
		}
	}
	if sidecar == nil || strings.TrimSpace(sidecar.BrowserDownloadUrl) == "" {
		return ""
	}
	httpRequest, err := http.NewRequest(http.MethodGet, sidecar.BrowserDownloadUrl, nil)
	if err != nil {
		return ""
	}
	httpRequest.Header.Set("User-Agent", "Wormhole-Electron")
	response, err := client.Do(httpRequest)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ""
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return ""
	}
	return parseShaSidecar(string(contents))
}

// serveUpdateDownload streams the installer to the update cache, writes JSON progress lines to
// stdout, and finishes with {"type":"complete","path":...}. Errors are reported on stderr with a
// non-zero exit, which the Electron main process surfaces to the renderer.
func serveUpdateDownload(databasePath string, input io.Reader, output io.Writer) error {
	var request updateDownloadRequest
	if err := decodeInputReader(input, &request); err != nil {
		return err
	}
	installerURL := strings.TrimSpace(request.InstallerUrl)
	installerFileName := strings.TrimSpace(request.InstallerFileName)
	if installerURL == "" || installerFileName == "" {
		return errors.New("update download request is invalid")
	}
	if filepath.Base(installerFileName) != installerFileName ||
		installerFileName == "." || installerFileName == ".." {
		return errors.New("update download file name is invalid")
	}
	expectedSha := strings.ToLower(strings.TrimSpace(request.InstallerSha256))
	if len(expectedSha) != sha256.Size*2 {
		return errors.New("update download requires a valid SHA-256 digest")
	}
	if _, err := hex.DecodeString(expectedSha); err != nil {
		return errors.New("update download requires a valid SHA-256 digest")
	}
	if request.InstallerSize <= 0 || request.InstallerSize > updateMaxInstallerBytes {
		return errors.New("update download size is invalid")
	}

	cleanupStalePartialDownloads(databasePath)
	cacheDirectory := updateCacheDirectory(databasePath)
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return fmt.Errorf("cannot create the update cache directory: %w", err)
	}
	finalPath := filepath.Join(cacheDirectory, installerFileName)
	partPath := finalPath + ".part"
	_ = os.Remove(partPath)
	_ = os.Remove(finalPath)

	httpRequest, err := http.NewRequest(http.MethodGet, installerURL, nil)
	if err != nil {
		return fmt.Errorf("cannot build the installer download request: %w", err)
	}
	httpRequest.Header.Set("User-Agent", "Wormhole-Electron")
	response, err := (&http.Client{Timeout: updateDownloadTimeout}).Do(httpRequest)
	if err != nil {
		return fmt.Errorf("cannot download the installer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("installer download returned %s", response.Status)
	}

	if response.ContentLength > 0 && response.ContentLength != request.InstallerSize {
		return fmt.Errorf(
			"installer download size is invalid: expected %d bytes, got %d",
			request.InstallerSize, response.ContentLength,
		)
	}
	total := request.InstallerSize

	file, err := os.OpenFile(partPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create the installer download file: %w", err)
	}
	hash := sha256.New()
	buffer := make([]byte, updateDownloadBufferSize)
	downloaded := int64(0)
	lastReportedProgress := 0.0
	lastReportedAt := time.Now()
	encoder := json.NewEncoder(output)
	removePartial := func() {
		_ = file.Close()
		_ = os.Remove(partPath)
	}
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			if downloaded+int64(read) > request.InstallerSize {
				removePartial()
				return fmt.Errorf("installer download exceeded the expected size of %d bytes", request.InstallerSize)
			}
			if _, writeErr := file.Write(buffer[:read]); writeErr != nil {
				removePartial()
				return fmt.Errorf("cannot write the installer download: %w", writeErr)
			}
			_, _ = hash.Write(buffer[:read])
			downloaded += int64(read)
			if total > 0 && shouldReportDownloadProgress(downloaded, total, lastReportedProgress, lastReportedAt) {
				lastReportedProgress = float64(downloaded) / float64(total)
				lastReportedAt = time.Now()
				_ = encoder.Encode(updateDownloadProgress{
					Type:       "progress",
					Downloaded: downloaded,
					Total:      total,
				})
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				removePartial()
				return fmt.Errorf("cannot download the installer: %w", readErr)
			}
			break
		}
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(partPath)
		return fmt.Errorf("cannot finish the installer download: %w", err)
	}
	if downloaded != request.InstallerSize {
		_ = os.Remove(partPath)
		return fmt.Errorf(
			"installer download size is invalid: expected %d bytes, got %d",
			request.InstallerSize, downloaded,
		)
	}

	computedSha := hex.EncodeToString(hash.Sum(nil))
	if computedSha != expectedSha {
		_ = os.Remove(partPath)
		return fmt.Errorf(
			"SHA-256 mismatch for %s. Expected %s, got %s.",
			installerFileName, expectedSha, computedSha,
		)
	}
	if err := os.Rename(partPath, finalPath); err != nil {
		_ = os.Remove(partPath)
		return fmt.Errorf("cannot finalize the installer download: %w", err)
	}
	if runtime.GOOS == "linux" && strings.EqualFold(filepath.Ext(finalPath), ".AppImage") {
		if err := os.Chmod(finalPath, 0o700); err != nil {
			_ = os.Remove(finalPath)
			return fmt.Errorf("cannot make the downloaded AppImage executable: %w", err)
		}
	}
	stripMarkOfTheWeb(finalPath)
	rotateInstallerCache(databasePath, installerFileName)
	return encoder.Encode(updateDownloadComplete{Type: "complete", Path: finalPath})
}

func shouldReportDownloadProgress(downloaded, total int64, lastReportedProgress float64, lastReportedAt time.Time) bool {
	current := float64(downloaded) / float64(total)
	if current < 0 {
		current = 0
	}
	if current > 1 {
		current = 1
	}
	return current >= 1 ||
		current-lastReportedProgress >= updateProgressReportStep ||
		time.Since(lastReportedAt) >= updateProgressReportWindow
}
