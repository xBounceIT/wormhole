package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	bitwardenReleaseRequestTimeout = 30 * time.Second
	bitwardenDownloadTimeout       = 5 * time.Minute
	bitwardenDownloadBufferSize    = 128 * 1024
	bitwardenMaxReleaseBytes       = 8 << 20
	bitwardenMaxZipBytes           = 512 << 20
	bitwardenMaxExtractedBytes     = 512 << 20
	bitwardenMaxManifestBytes      = 1 << 20
	bitwardenMaxExtractedFiles     = 100_000
	bitwardenGithubUserAgent       = "Wormhole/electron"
)

// bitwardenGithubBaseURL is a variable so tests can point the release feed at an httptest server.
var bitwardenGithubBaseURL = bitwardenExtensionReleasesBaseURL
var bitwardenExtensionSettingsWriter = writeBitwardenExtensionSettings

type bitwardenReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

type bitwardenRelease struct {
	TagName    string                  `json:"tag_name"`
	Draft      bool                    `json:"draft"`
	Prerelease bool                    `json:"prerelease"`
	Assets     []bitwardenReleaseAsset `json:"assets"`
}

type resolvedBitwardenRelease struct {
	Version        string
	Asset          bitwardenReleaseAsset
	ExpectedSha256 string
}

type bitwardenUpdateCheck struct {
	CurrentVersion    string `json:"currentVersion,omitempty"`
	LatestVersion     string `json:"latestVersion"`
	IsUpdateAvailable bool   `json:"isUpdateAvailable"`
	AssetName         string `json:"assetName"`
	DownloadURL       string `json:"downloadUrl"`
	ExpectedSha256    string `json:"expectedSha256,omitempty"`
}

type bitwardenExtensionInstall struct {
	ManifestName string `json:"-"`
	DefaultPopup string `json:"-"`
	Version      string `json:"version"`
	Path         string `json:"path"`
	Sha256       string `json:"sha256,omitempty"`
	AssetName    string `json:"assetName,omitempty"`
	DownloadURL  string `json:"downloadUrl,omitempty"`
}

type bitwardenExtensionManifest struct {
	ManifestVersion int
	Name            string
	Version         string
	DefaultPopup    string
}

func getBitwardenExtensionInstall(settings bitwardenExtensionSettings) *bitwardenExtensionInstall {
	path := strings.TrimSpace(settings.Path)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil
	}
	manifest, err := readBitwardenManifest(path)
	if err != nil || validateBitwardenElectronManifest(manifest) != nil {
		return nil
	}
	version := settings.Version
	if version == "" {
		version = manifest.Version
	}
	if version == "" {
		version = "manual"
	}
	return &bitwardenExtensionInstall{
		ManifestName: manifest.Name,
		DefaultPopup: manifest.DefaultPopup,
		Version:      version,
		Path:         path,
		Sha256:       settings.Sha256,
		AssetName:    settings.AssetName,
		DownloadURL:  settings.DownloadURL,
	}
}

func readBitwardenManifest(extensionRoot string) (bitwardenExtensionManifest, error) {
	manifestPath := filepath.Join(extensionRoot, "manifest.json")
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return bitwardenExtensionManifest{}, errors.New("The selected Bitwarden extension folder does not contain manifest.json.")
	}
	defer manifestFile.Close()
	contents, err := io.ReadAll(io.LimitReader(manifestFile, bitwardenMaxManifestBytes+1))
	if err != nil || len(contents) > bitwardenMaxManifestBytes {
		return bitwardenExtensionManifest{}, errors.New("The extension manifest is too large.")
	}
	var document struct {
		ManifestVersion int    `json:"manifest_version"`
		Name            string `json:"name"`
		Version         string `json:"version"`
		Action          *struct {
			DefaultPopup string `json:"default_popup"`
		} `json:"action"`
		BrowserAction *struct {
			DefaultPopup string `json:"default_popup"`
		} `json:"browser_action"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		return bitwardenExtensionManifest{}, errors.New("The extension manifest is not valid JSON.")
	}
	if strings.TrimSpace(document.Name) == "" {
		return bitwardenExtensionManifest{}, errors.New("The extension manifest does not define a name.")
	}
	manifest := bitwardenExtensionManifest{
		ManifestVersion: document.ManifestVersion,
		Name:            document.Name,
		Version:         strings.TrimSpace(document.Version),
	}
	if document.Action != nil {
		manifest.DefaultPopup = strings.TrimSpace(document.Action.DefaultPopup)
	}
	if manifest.DefaultPopup == "" && document.BrowserAction != nil {
		manifest.DefaultPopup = strings.TrimSpace(document.BrowserAction.DefaultPopup)
	}
	return manifest, nil
}

func validateBitwardenElectronManifest(manifest bitwardenExtensionManifest) error {
	if manifest.ManifestVersion != 2 {
		return errors.New("This Bitwarden browser package is not supported. Install a compatible Bitwarden browser package instead.")
	}
	if strings.TrimSpace(manifest.DefaultPopup) == "" {
		return errors.New("The Bitwarden browser package does not define a popup.")
	}
	return nil
}

func isBitwardenBrowserRelease(release bitwardenRelease) bool {
	return !release.Draft &&
		!release.Prerelease &&
		strings.HasPrefix(strings.ToLower(release.TagName), "browser-v")
}

func findPreferredBitwardenAsset(release bitwardenRelease) *bitwardenReleaseAsset {
	// Electron officially supports MV2 background pages, while Bitwarden's Chromium bundles use
	// an MV3 service worker and currently fail during chrome.* API initialization. The Firefox
	// bundle is Bitwarden's supported MV2 build and runs as a persistent background page.
	if asset := findBitwardenAsset(release, "dist-firefox-"); asset != nil {
		return asset
	}
	return nil
}

func findBitwardenAsset(release bitwardenRelease, prefix string) *bitwardenReleaseAsset {
	for index := range release.Assets {
		asset := &release.Assets[index]
		if strings.TrimSpace(asset.Name) == "" ||
			strings.TrimSpace(asset.BrowserDownloadURL) == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(asset.Name), prefix) &&
			strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
			return asset
		}
	}
	return nil
}

func parseBitwardenGitHubSha256(digest string) string {
	value := strings.TrimSpace(digest)
	if value == "" {
		return ""
	}
	prefix := "sha256:"
	if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
		value = value[len(prefix):]
	}
	value = strings.ToLower(value)
	if len(value) != 64 {
		return ""
	}
	for _, character := range value {
		if !isHexDigit(character) {
			return ""
		}
	}
	return value
}

func isHexDigit(character rune) bool {
	return (character >= '0' && character <= '9') ||
		(character >= 'a' && character <= 'f')
}

func parseBitwardenBrowserVersion(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	marker := strings.Index(strings.ToLower(text), "browser-v")
	if marker >= 0 {
		text = text[marker+len("browser-v"):]
	}
	text = trimBitwardenPrefix(text, "dist-edge-")
	text = trimBitwardenPrefix(text, "dist-chrome-")
	text = trimBitwardenPrefix(text, "dist-firefox-")
	if strings.HasSuffix(strings.ToLower(text), ".zip") {
		text = text[:len(text)-4]
	}
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return sanitizeBitwardenVersion(text)
}

func trimBitwardenPrefix(value, prefix string) string {
	if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
		return value[len(prefix):]
	}
	return value
}

func compareBitwardenVersions(left, right string) int {
	if strings.TrimSpace(left) == "" {
		if strings.TrimSpace(right) == "" {
			return 0
		}
		return -1
	}
	if strings.TrimSpace(right) == "" {
		return 1
	}
	leftParts := splitBitwardenVersion(left)
	rightParts := splitBitwardenVersion(right)
	count := len(leftParts)
	if len(rightParts) > count {
		count = len(rightParts)
	}
	for index := 0; index < count; index++ {
		leftPart := "0"
		rightPart := "0"
		if index < len(leftParts) {
			leftPart = leftParts[index]
		}
		if index < len(rightParts) {
			rightPart = rightParts[index]
		}
		if comparison := compareBitwardenVersionPart(leftPart, rightPart); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func splitBitwardenVersion(value string) []string {
	text := parseBitwardenBrowserVersion(value)
	if text == "" {
		text = value
	}
	var parts []string
	for _, part := range strings.FieldsFunc(text, func(character rune) bool {
		return character == '.' || character == '-' || character == '_'
	}) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func compareBitwardenVersionPart(left, right string) int {
	var leftNumber, rightNumber int64
	leftIsNumber := parseBitwardenLong(left, &leftNumber)
	rightIsNumber := parseBitwardenLong(right, &rightNumber)
	if leftIsNumber && rightIsNumber {
		switch {
		case leftNumber < rightNumber:
			return -1
		case leftNumber > rightNumber:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(strings.ToLower(left), strings.ToLower(right))
}

func parseBitwardenLong(value string, target *int64) bool {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return false
	}
	*target = parsed
	return true
}

func sanitizeBitwardenVersion(value string) string {
	var builder strings.Builder
	for _, character := range strings.TrimSpace(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteRune('-')
		}
	}
	if builder.Len() == 0 {
		return "manual"
	}
	return builder.String()
}

func resolveBitwardenLatestRelease(settings bitwardenExtensionSettings) (resolvedBitwardenRelease, error) {
	releasesPath := bitwardenExtensionDefaultReleasesURL
	if strings.TrimSpace(settings.ReleasesURL) != "" {
		releasesPath = strings.TrimSpace(settings.ReleasesURL)
	}
	requestURL := bitwardenGithubBaseURL + strings.TrimPrefix(releasesPath, "/")
	if strings.Contains(releasesPath, "://") {
		requestURL = releasesPath
	}

	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not check Bitwarden browser releases.")
	}
	request.Header.Set("User-Agent", bitwardenGithubUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: bitwardenReleaseRequestTimeout}
	response, err := client.Do(request)
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not reach the Bitwarden browser release feed.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden browser release feed returned an error.")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, bitwardenMaxReleaseBytes+1))
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not read the Bitwarden browser release feed.")
	}
	if len(contents) > bitwardenMaxReleaseBytes {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden browser release feed is too large.")
	}

	var releases []bitwardenRelease
	if err := json.Unmarshal(contents, &releases); err != nil {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden browser release feed is not valid JSON.")
	}
	var release *bitwardenRelease
	for index := range releases {
		if isBitwardenBrowserRelease(releases[index]) {
			release = &releases[index]
			break
		}
	}
	if release == nil {
		return resolvedBitwardenRelease{}, errors.New("No Bitwarden browser extension release was found.")
	}
	asset := findPreferredBitwardenAsset(*release)
	if asset == nil {
		return resolvedBitwardenRelease{}, errors.New("The latest Bitwarden browser release has no package compatible with Wormhole.")
	}
	if strings.TrimSpace(asset.BrowserDownloadURL) == "" {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden extension asset has no download URL.")
	}
	version := parseBitwardenBrowserVersion(release.TagName)
	if version == "" {
		version = parseBitwardenBrowserVersion(asset.Name)
	}
	if version == "" {
		version = "latest"
	}
	return resolvedBitwardenRelease{
		Version:        version,
		Asset:          *asset,
		ExpectedSha256: parseBitwardenGitHubSha256(asset.Digest),
	}, nil
}

func installBitwardenLatestRelease(databasePath string, settings *bitwardenExtensionSettings) (bitwardenExtensionInstall, error) {
	latest, err := resolveBitwardenLatestRelease(*settings)
	if err != nil {
		return bitwardenExtensionInstall{}, err
	}
	return installBitwardenReleaseAsset(
		databasePath,
		settings,
		latest.Version,
		latest.Asset.Name,
		latest.Asset.BrowserDownloadURL,
		latest.ExpectedSha256,
	)
}

func updateBitwardenIfAvailable(
	databasePath string,
	settings *bitwardenExtensionSettings,
) (bitwardenUpdateCheck, *bitwardenExtensionInstall, bool, error) {
	if settings.Source != bitwardenSourceOfficialGitHub {
		return bitwardenUpdateCheck{}, nil, false,
			errors.New("Manual Bitwarden browser extension installations are pinned and cannot be auto-updated.")
	}
	check, err := checkBitwardenForUpdate(*settings)
	if err != nil {
		return bitwardenUpdateCheck{}, nil, false, err
	}
	if !check.IsUpdateAvailable {
		return check, nil, false, nil
	}
	install, err := installBitwardenReleaseAsset(
		databasePath,
		settings,
		check.LatestVersion,
		check.AssetName,
		check.DownloadURL,
		check.ExpectedSha256,
	)
	if err != nil {
		return bitwardenUpdateCheck{}, nil, false, err
	}
	return check, &install, true, nil
}

func checkBitwardenForUpdate(settings bitwardenExtensionSettings) (bitwardenUpdateCheck, error) {
	latest, err := resolveBitwardenLatestRelease(settings)
	if err != nil {
		return bitwardenUpdateCheck{}, err
	}
	current := ""
	if install := getBitwardenExtensionInstall(settings); install != nil {
		current = install.Version
	}
	return bitwardenUpdateCheck{
		CurrentVersion:    current,
		LatestVersion:     latest.Version,
		IsUpdateAvailable: compareBitwardenVersions(latest.Version, current) > 0,
		AssetName:         latest.Asset.Name,
		DownloadURL:       latest.Asset.BrowserDownloadURL,
		ExpectedSha256:    latest.ExpectedSha256,
	}, nil
}

func installBitwardenReleaseAsset(
	databasePath string,
	settings *bitwardenExtensionSettings,
	version, assetName, downloadURL, expectedSha256 string,
) (bitwardenExtensionInstall, error) {
	downloadRoot := bitwardenExtensionDownloadRoot(databasePath)
	if err := os.MkdirAll(downloadRoot, 0o700); err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not create the Bitwarden download cache.")
	}
	zipPath := filepath.Join(downloadRoot, fmt.Sprintf("bitwarden-browser-%s-%s.zip", version, bitwardenRandomSuffix()))
	defer func() {
		_ = os.Remove(zipPath)
	}()

	actualSha256, err := downloadBitwardenZip(downloadURL, zipPath)
	if err != nil {
		return bitwardenExtensionInstall{}, err
	}
	if expectedSha256 != "" && !strings.EqualFold(expectedSha256, actualSha256) {
		return bitwardenExtensionInstall{}, errors.New("The downloaded Bitwarden extension checksum does not match the GitHub release metadata.")
	}
	return installBitwardenZipFile(
		databasePath,
		settings,
		zipPath,
		version,
		actualSha256,
		assetName,
		downloadURL,
		bitwardenSourceOfficialGitHub,
	)
}

func downloadBitwardenZip(downloadURL, outputPath string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", errors.New("The Bitwarden extension download URL is invalid.")
	}
	request.Header.Set("User-Agent", bitwardenGithubUserAgent)
	client := &http.Client{Timeout: bitwardenDownloadTimeout}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("Could not download the Bitwarden browser extension.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("Could not download the Bitwarden browser extension.")
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", errors.New("Could not create the Bitwarden download cache file.")
	}
	hasher := sha256.New()
	written := int64(0)
	buffer := make([]byte, bitwardenDownloadBufferSize)
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			written += int64(read)
			if written > bitwardenMaxZipBytes {
				_ = output.Close()
				_ = os.Remove(outputPath)
				return "", errors.New("The Bitwarden browser extension download is too large.")
			}
			if _, writeErr := output.Write(buffer[:read]); writeErr != nil {
				_ = output.Close()
				_ = os.Remove(outputPath)
				return "", errors.New("Could not write the Bitwarden browser extension download.")
			}
			_, _ = hasher.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = output.Close()
			_ = os.Remove(outputPath)
			return "", errors.New("Could not download the Bitwarden browser extension.")
		}
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(outputPath)
		return "", errors.New("Could not finalize the Bitwarden browser extension download.")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func installBitwardenZipFile(
	databasePath string,
	settings *bitwardenExtensionSettings,
	zipPath, forcedVersion, sha256hex, assetName, downloadURL string,
	source int,
) (bitwardenExtensionInstall, error) {
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not create the Bitwarden extension directory.")
	}
	staging := filepath.Join(installRoot, ".staging-"+bitwardenRandomSuffix())
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not stage the Bitwarden browser extension.")
	}
	defer func() {
		_ = os.RemoveAll(staging)
	}()

	if err := extractBitwardenZipSafely(zipPath, staging); err != nil {
		return bitwardenExtensionInstall{}, err
	}
	extensionRoot, err := findBitwardenExtensionRoot(staging)
	if err != nil {
		return bitwardenExtensionInstall{}, err
	}
	manifest, err := readBitwardenManifest(extensionRoot)
	if err != nil {
		return bitwardenExtensionInstall{}, err
	}
	if err := validateBitwardenElectronManifest(manifest); err != nil {
		return bitwardenExtensionInstall{}, err
	}
	version := forcedVersion
	if version == "" {
		version = manifest.Version
	}
	if version == "" {
		version = "manual"
	}
	version = sanitizeBitwardenVersion(version)
	return activateBitwardenInstall(
		databasePath,
		settings,
		extensionRoot,
		manifest.Name,
		manifest.DefaultPopup,
		version,
		sha256hex,
		assetName,
		downloadURL,
		source,
	)
}

func installBitwardenFolder(
	databasePath string,
	settings *bitwardenExtensionSettings,
	folderPath string,
) (bitwardenExtensionInstall, error) {
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not create the Bitwarden extension directory.")
	}
	staging := filepath.Join(installRoot, ".staging-"+bitwardenRandomSuffix())
	stagedExtension := filepath.Join(staging, "extension")
	defer func() {
		_ = os.RemoveAll(staging)
	}()

	if err := copyBitwardenDirectory(folderPath, stagedExtension); err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not copy the selected Bitwarden extension folder.")
	}
	manifest, err := readBitwardenManifest(stagedExtension)
	if err != nil {
		return bitwardenExtensionInstall{}, err
	}
	if err := validateBitwardenElectronManifest(manifest); err != nil {
		return bitwardenExtensionInstall{}, err
	}
	version := manifest.Version
	if version == "" {
		version = "manual"
	}
	version = sanitizeBitwardenVersion(version)
	sha256hex, err := computeBitwardenDirectorySha256(stagedExtension)
	if err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not hash the selected Bitwarden extension folder.")
	}
	return activateBitwardenInstall(
		databasePath,
		settings,
		stagedExtension,
		manifest.Name,
		manifest.DefaultPopup,
		version,
		sha256hex,
		"",
		"",
		bitwardenSourceManualFolder,
	)
}

func activateBitwardenInstall(
	databasePath string,
	settings *bitwardenExtensionSettings,
	extensionRoot, manifestName, defaultPopup, version, sha256hex, assetName, downloadURL string,
	source int,
) (bitwardenExtensionInstall, error) {
	originalSettings := *settings
	installRoot := bitwardenExtensionInstallRoot(databasePath)
	finalPath := bitwardenReplacementPath(settings.Path, installRoot)
	if finalPath == "" {
		finalPath = bitwardenUniqueInstallPath(installRoot, version)
	}
	backupPath, err := replaceOrMoveBitwardenInstall(extensionRoot, finalPath, installRoot)
	if err != nil {
		return bitwardenExtensionInstall{}, errors.New("Could not install the Bitwarden browser extension.")
	}
	settings.Source = source
	settings.Version = version
	settings.Path = finalPath
	settings.Sha256 = sha256hex
	settings.AssetName = assetName
	settings.DownloadURL = downloadURL
	settings.AvailableVersion = ""
	settings.LastUpdateError = ""
	switch source {
	case bitwardenSourceManualZip:
		settings.LastUpdateStatus = "Manual ZIP install is pinned; auto-update disabled."
	case bitwardenSourceManualFolder:
		settings.LastUpdateStatus = "Manual folder install is pinned; auto-update disabled."
	default:
		settings.LastUpdateStatus = fmt.Sprintf("Installed official release %s.", version)
	}
	if source == bitwardenSourceOfficialGitHub {
		now := time.Now().UTC()
		settings.LastUpdateCheckUtc = &now
	} else {
		settings.LastUpdateCheckUtc = nil
	}
	if err := bitwardenExtensionSettingsWriter(databasePath, *settings); err != nil {
		// The settings document is the commit point. Restore the previous extension if it could
		// not be updated, otherwise a metadata-write failure silently replaces a working install.
		*settings = originalSettings
		if rollbackErr := rollbackBitwardenInstall(finalPath, backupPath); rollbackErr != nil {
			return bitwardenExtensionInstall{}, errors.New("Could not save the Bitwarden browser extension settings, and the previous installation could not be restored safely.")
		}
		return bitwardenExtensionInstall{}, err
	}
	if backupPath != "" {
		_ = os.RemoveAll(backupPath)
	}
	return bitwardenExtensionInstall{
		ManifestName: manifestName,
		DefaultPopup: defaultPopup,
		Version:      version,
		Path:         finalPath,
		Sha256:       sha256hex,
		AssetName:    assetName,
		DownloadURL:  downloadURL,
	}, nil
}

func rollbackBitwardenInstall(finalPath, backupPath string) error {
	if err := os.RemoveAll(finalPath); err != nil {
		return err
	}
	if backupPath == "" {
		return nil
	}
	return os.Rename(backupPath, finalPath)
}

func bitwardenReplacementPath(configuredPath, installRoot string) string {
	if strings.TrimSpace(configuredPath) == "" {
		return ""
	}
	info, err := os.Stat(configuredPath)
	if err != nil || !info.IsDir() {
		return ""
	}
	root := filepath.Clean(installRoot)
	candidate := filepath.Clean(configuredPath)
	relative, err := filepath.Rel(root, candidate)
	if err != nil ||
		filepath.IsAbs(relative) ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ""
	}
	return candidate
}

func bitwardenUniqueInstallPath(installRoot, version string) string {
	base := filepath.Join(installRoot, version)
	if !directoryExists(base) {
		return base
	}
	for index := 2; index < 1000; index++ {
		candidate := fmt.Sprintf("%s-%d", base, index)
		if !directoryExists(candidate) {
			return candidate
		}
	}
	return base + "-" + bitwardenRandomSuffix()
}

func replaceOrMoveBitwardenInstall(extensionRoot, finalPath, installRoot string) (string, error) {
	if !directoryExists(finalPath) {
		if err := os.Rename(extensionRoot, finalPath); err != nil {
			return "", err
		}
		return "", nil
	}
	// Keep the absolute install path stable across installs and updates so the Chromium extension
	// id (derived from the unpacked folder path) and its stored login state stay attached.
	backupPath := filepath.Join(installRoot, ".backup-"+bitwardenRandomSuffix())
	if err := os.Rename(finalPath, backupPath); err != nil {
		return "", err
	}
	if err := os.Rename(extensionRoot, finalPath); err != nil {
		if rollbackErr := os.Rename(backupPath, finalPath); rollbackErr != nil {
			return "", errors.New("the new extension could not be activated and the previous installation could not be restored")
		}
		return "", err
	}
	return backupPath, nil
}

func extractBitwardenZipSafely(zipPath, destinationRoot string) error {
	return extractZipSafely(zipPath, destinationRoot, safeZipExtractionOptions{
		maxEntries:           bitwardenMaxExtractedFiles,
		maxExtractedBytes:    bitwardenMaxExtractedBytes,
		unsafePathError:      "The extension ZIP contains an unsafe path.",
		unsupportedTypeError: "The extension ZIP contains an unsupported file type.",
		tooManyEntriesError:  "The Bitwarden browser extension archive contains too many files.",
		tooLargeError:        "The Bitwarden browser extension archive is too large.",
		extractionError:      "Could not extract the Bitwarden browser extension.",
	})
}

func findBitwardenExtensionRoot(stagingRoot string) (string, error) {
	if fileExists(filepath.Join(stagingRoot, "manifest.json")) {
		return stagingRoot, nil
	}
	var manifests []string
	_ = filepath.Walk(stagingRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.EqualFold(info.Name(), "manifest.json") {
			manifests = append(manifests, path)
		}
		return nil
	})
	if len(manifests) == 0 {
		return "", errors.New("The extension ZIP does not contain manifest.json.")
	}
	if len(manifests) == 1 {
		return filepath.Dir(manifests[0]), nil
	}
	for _, manifestPath := range manifests {
		directory := filepath.Dir(manifestPath)
		manifest, err := readBitwardenManifest(directory)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(manifest.Name), "bitwarden") {
			return directory, nil
		}
	}
	return "", errors.New("The extension ZIP contains multiple manifests and none could be identified as Bitwarden.")
}

func copyBitwardenDirectory(source, destination string) error {
	return copyBitwardenDirectoryWithLimits(
		source,
		destination,
		bitwardenMaxExtractedFiles,
		bitwardenMaxExtractedBytes,
	)
}

func copyBitwardenDirectoryWithLimits(
	source, destination string,
	maxEntries int,
	maxBytes int64,
) error {
	sourceRoot, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	destinationRoot, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if relative, relativeErr := filepath.Rel(sourceRoot, destinationRoot); relativeErr == nil &&
		(relative == "." || (!filepath.IsAbs(relative) && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
		return errors.New("the extension staging directory cannot be inside the selected folder")
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	var copied int64
	entryCount := 0
	return filepath.Walk(sourceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative != "." {
			entryCount++
			if entryCount > maxEntries {
				return errors.New("the selected extension folder contains too many entries")
			}
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return errors.New("the selected extension folder contains an unsupported file type")
		}
		if info.Size() < 0 || info.Size() > maxBytes-copied {
			return errors.New("the selected extension folder is too large")
		}
		copied += info.Size()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			_ = input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeInputErr != nil {
			return closeInputErr
		}
		if written != info.Size() {
			return errors.New("the selected extension file changed while it was copied")
		}
		return nil
	})
}

func computeBitwardenFileSha256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func computeBitwardenDirectorySha256(directory string) (string, error) {
	hasher := sha256.New()
	var files []string
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	sort.Slice(files, func(left, right int) bool {
		return strings.ToLower(files[left]) < strings.ToLower(files[right])
	})
	for _, path := range files {
		relative := filepath.ToSlash(relativeBitwardenPath(directory, path))
		_, _ = hasher.Write([]byte(relative))
		_, _ = hasher.Write([]byte{0})
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hasher, file)
		_ = file.Close()
		if copyErr != nil {
			return "", copyErr
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func relativeBitwardenPath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return relative
}

func bitwardenRandomSuffix() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
