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
	"strings"
	"time"
)

const (
	bitwardenCliReleaseRequestTimeout = 30 * time.Second
	bitwardenCliDownloadTimeout       = 10 * time.Minute
	bitwardenCliDownloadBufferSize    = 128 * 1024
	bitwardenCliMaxReleaseBytes       = 8 << 20
	bitwardenCliMaxZipBytes           = 512 << 20
	bitwardenCliMaxExtractedBytes     = 512 << 20
	bitwardenCliMaxExtractedFiles     = 100_000
)

var bitwardenCliSettingsWriter = writeBitwardenCliSettings

// resolveBitwardenCliExecutable resolves the configured bw path to an absolute executable path, or
// nil when it cannot be found. Mirrors BitwardenCliInstaller.GetConfiguredInstall semantics.
func resolveBitwardenCliExecutable(settings bitwardenCliSettings) string {
	path := strings.TrimSpace(settings.Path)
	if path == "" {
		path = "bw"
	}
	if filepath.IsAbs(path) || strings.ContainsRune(path, filepath.Separator) ||
		(filepath.Separator != '/' && strings.ContainsRune(path, '/')) {
		if fileExists(path) {
			absolute, err := filepath.Abs(path)
			if err == nil {
				return absolute
			}
		}
		return ""
	}

	candidates := []string{path}
	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		candidates = append(candidates, path+".exe")
	}
	for _, directory := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		directory = strings.TrimSpace(directory)
		if directory == "" {
			continue
		}
		for _, candidate := range candidates {
			fullPath := filepath.Join(directory, candidate)
			if fileExists(fullPath) {
				absolute, err := filepath.Abs(fullPath)
				if err == nil {
					return absolute
				}
			}
		}
	}
	return ""
}

func resolveBitwardenCliInstall(settings bitwardenCliSettings) *bitwardenCliInstalled {
	path := resolveBitwardenCliExecutable(settings)
	if path == "" {
		return nil
	}
	version := settings.Version
	if version == "" {
		if strings.TrimSpace(settings.DownloadURL) == "" {
			version = "external"
		} else {
			version = "official"
		}
	}
	return &bitwardenCliInstalled{
		Version:     version,
		Path:        path,
		Sha256:      settings.Sha256,
		AssetName:   settings.AssetName,
		DownloadURL: settings.DownloadURL,
	}
}

func isBitwardenCliRelease(release bitwardenRelease) bool {
	return !release.Draft &&
		!release.Prerelease &&
		strings.HasPrefix(strings.ToLower(release.TagName), "cli-v")
}

// findBitwardenCliWindowsAsset accepts only the standard Windows CLI bundle, matching WinUI 3.
func findBitwardenCliWindowsAsset(release bitwardenRelease) *bitwardenReleaseAsset {
	for index := range release.Assets {
		asset := &release.Assets[index]
		name := strings.ToLower(strings.TrimSpace(asset.Name))
		if name == "" || strings.TrimSpace(asset.BrowserDownloadURL) == "" {
			continue
		}
		if !strings.HasPrefix(name, "bw-windows-") || !strings.HasSuffix(name, ".zip") {
			continue
		}
		return asset
	}
	return nil
}

func parseBitwardenCliVersion(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	marker := strings.Index(strings.ToLower(text), "cli-v")
	if marker >= 0 {
		text = text[marker+len("cli-v"):]
	}
	text = trimBitwardenPrefix(text, "bw-windows-")
	if strings.HasSuffix(strings.ToLower(text), ".zip") {
		text = text[:len(text)-4]
	}
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return sanitizeBitwardenVersion(text)
}

func resolveBitwardenCliLatestRelease(settings bitwardenCliSettings) (resolvedBitwardenRelease, error) {
	releasesPath := bitwardenCliDefaultReleasesURL
	if strings.TrimSpace(settings.ReleasesURL) != "" {
		releasesPath = strings.TrimSpace(settings.ReleasesURL)
	}
	requestURL := bitwardenGithubBaseURL + strings.TrimPrefix(releasesPath, "/")
	if strings.Contains(releasesPath, "://") {
		requestURL = releasesPath
	}

	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not check Bitwarden CLI releases.")
	}
	request.Header.Set("User-Agent", bitwardenGithubUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: bitwardenCliReleaseRequestTimeout}
	response, err := client.Do(request)
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not reach the Bitwarden CLI release feed.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden CLI release feed returned an error.")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, bitwardenCliMaxReleaseBytes+1))
	if err != nil {
		return resolvedBitwardenRelease{}, errors.New("Could not read the Bitwarden CLI release feed.")
	}
	if len(contents) > bitwardenCliMaxReleaseBytes {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden CLI release feed is too large.")
	}

	var releases []bitwardenRelease
	if err := json.Unmarshal(contents, &releases); err != nil {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden CLI release feed is not valid JSON.")
	}
	var release *bitwardenRelease
	for index := range releases {
		if isBitwardenCliRelease(releases[index]) {
			release = &releases[index]
			break
		}
	}
	if release == nil {
		return resolvedBitwardenRelease{}, errors.New("No Bitwarden CLI release was found.")
	}
	asset := findBitwardenCliWindowsAsset(*release)
	if asset == nil {
		return resolvedBitwardenRelease{}, errors.New("The latest Bitwarden CLI release has no Windows ZIP asset.")
	}
	if strings.TrimSpace(asset.BrowserDownloadURL) == "" {
		return resolvedBitwardenRelease{}, errors.New("The Bitwarden CLI asset has no download URL.")
	}
	version := parseBitwardenCliVersion(release.TagName)
	if version == "" {
		version = parseBitwardenCliVersion(asset.Name)
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

func installBitwardenCliLatest(databasePath string, settings *bitwardenCliSettings) (bitwardenCliInstalled, error) {
	latest, err := resolveBitwardenCliLatestRelease(*settings)
	if err != nil {
		return bitwardenCliInstalled{}, err
	}
	return installBitwardenCliReleaseAsset(
		databasePath,
		settings,
		latest.Version,
		latest.Asset.Name,
		latest.Asset.BrowserDownloadURL,
		latest.ExpectedSha256,
	)
}

func installBitwardenCliReleaseAsset(
	databasePath string,
	settings *bitwardenCliSettings,
	version, assetName, downloadURL, expectedSha256 string,
) (bitwardenCliInstalled, error) {
	downloadRoot := bitwardenCliDownloadRoot(databasePath)
	if err := os.MkdirAll(downloadRoot, 0o700); err != nil {
		return bitwardenCliInstalled{}, errors.New("Could not create the Bitwarden CLI download cache.")
	}
	zipPath := filepath.Join(downloadRoot, fmt.Sprintf("bitwarden-cli-%s-%s.zip", version, bitwardenRandomSuffix()))
	defer func() {
		_ = os.Remove(zipPath)
	}()

	actualSha256, err := downloadBitwardenCliZip(downloadURL, zipPath)
	if err != nil {
		return bitwardenCliInstalled{}, err
	}
	if expectedSha256 != "" && !strings.EqualFold(expectedSha256, actualSha256) {
		return bitwardenCliInstalled{}, errors.New("The downloaded Bitwarden CLI checksum does not match the GitHub release metadata.")
	}
	return installBitwardenCliZipFile(
		databasePath,
		settings,
		zipPath,
		version,
		actualSha256,
		assetName,
		downloadURL,
	)
}

func downloadBitwardenCliZip(downloadURL, outputPath string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", errors.New("The Bitwarden CLI download URL is invalid.")
	}
	request.Header.Set("User-Agent", bitwardenGithubUserAgent)
	client := &http.Client{Timeout: bitwardenCliDownloadTimeout}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("Could not download the Bitwarden CLI.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("Could not download the Bitwarden CLI.")
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", errors.New("Could not create the Bitwarden CLI download cache file.")
	}
	hasher := sha256.New()
	written := int64(0)
	buffer := make([]byte, bitwardenCliDownloadBufferSize)
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			written += int64(read)
			if written > bitwardenCliMaxZipBytes {
				_ = output.Close()
				_ = os.Remove(outputPath)
				return "", errors.New("The Bitwarden CLI download is too large.")
			}
			if _, writeErr := output.Write(buffer[:read]); writeErr != nil {
				_ = output.Close()
				_ = os.Remove(outputPath)
				return "", errors.New("Could not write the Bitwarden CLI download.")
			}
			_, _ = hasher.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = output.Close()
			_ = os.Remove(outputPath)
			return "", errors.New("Could not download the Bitwarden CLI.")
		}
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(outputPath)
		return "", errors.New("Could not finalize the Bitwarden CLI download.")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func installBitwardenCliZipFile(
	databasePath string,
	settings *bitwardenCliSettings,
	zipPath, forcedVersion, sha256hex, assetName, downloadURL string,
) (bitwardenCliInstalled, error) {
	originalSettings := *settings
	installRoot := bitwardenCliInstallRoot(databasePath)
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		return bitwardenCliInstalled{}, errors.New("Could not create the Bitwarden CLI directory.")
	}
	staging := filepath.Join(installRoot, ".staging-"+bitwardenRandomSuffix())
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return bitwardenCliInstalled{}, errors.New("Could not stage the Bitwarden CLI.")
	}
	defer func() {
		_ = os.RemoveAll(staging)
	}()

	if err := extractBitwardenCliZipSafely(zipPath, staging); err != nil {
		return bitwardenCliInstalled{}, err
	}
	executable, err := findBitwardenCliExecutable(staging)
	if err != nil {
		return bitwardenCliInstalled{}, err
	}
	version := forcedVersion
	if version == "" {
		version = "latest"
	}
	version = sanitizeBitwardenVersion(version)
	finalPath := bitwardenCliUniqueInstallPath(installRoot, version)
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		return bitwardenCliInstalled{}, errors.New("Could not create the Bitwarden CLI install directory.")
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(finalPath)
		}
	}()
	finalExecutable := filepath.Join(finalPath, bitwardenCliExecutableName())
	input, err := os.Open(executable)
	if err != nil {
		return bitwardenCliInstalled{}, errors.New("Could not read the Bitwarden CLI executable.")
	}
	output, err := os.OpenFile(finalExecutable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		_ = input.Close()
		return bitwardenCliInstalled{}, errors.New("Could not install the Bitwarden CLI executable.")
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, bitwardenCliMaxExtractedBytes+1))
	closeOutputErr := output.Close()
	closeInputErr := input.Close()
	if copyErr != nil || closeOutputErr != nil || closeInputErr != nil ||
		written <= 0 || written > bitwardenCliMaxExtractedBytes {
		return bitwardenCliInstalled{}, errors.New("Could not install the Bitwarden CLI executable.")
	}

	settings.Path = finalExecutable
	settings.Version = version
	settings.Sha256 = sha256hex
	settings.AssetName = assetName
	settings.DownloadURL = downloadURL
	settings.InstallStatus = fmt.Sprintf("Installed official Bitwarden CLI %s.", version)
	settings.InstallError = ""
	if err := bitwardenCliSettingsWriter(databasePath, *settings); err != nil {
		*settings = originalSettings
		return bitwardenCliInstalled{}, err
	}
	committed = true
	return bitwardenCliInstalled{
		Version:     version,
		Path:        finalExecutable,
		Sha256:      sha256hex,
		AssetName:   assetName,
		DownloadURL: downloadURL,
	}, nil
}

func bitwardenCliExecutableName() string {
	if runtime.GOOS == "windows" {
		return "bw.exe"
	}
	return "bw"
}

func bitwardenCliUniqueInstallPath(installRoot, version string) string {
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

func extractBitwardenCliZipSafely(zipPath, destinationRoot string) error {
	return extractZipSafely(zipPath, destinationRoot, safeZipExtractionOptions{
		maxEntries:           bitwardenCliMaxExtractedFiles,
		maxExtractedBytes:    bitwardenCliMaxExtractedBytes,
		unsafePathError:      "The Bitwarden CLI ZIP contains an unsafe path.",
		unsupportedTypeError: "The Bitwarden CLI ZIP contains an unsupported file type.",
		tooManyEntriesError:  "The Bitwarden CLI archive contains too many files.",
		tooLargeError:        "The Bitwarden CLI archive is too large.",
		extractionError:      "Could not extract the Bitwarden CLI.",
	})
}

func findBitwardenCliExecutable(stagingRoot string) (string, error) {
	name := bitwardenCliExecutableName()
	matches := []string{}
	_ = filepath.Walk(stagingRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.EqualFold(info.Name(), name) {
			matches = append(matches, path)
		}
		return nil
	})
	if len(matches) == 0 {
		return "", fmt.Errorf("The Bitwarden CLI ZIP does not contain %s.", name)
	}
	return matches[0], nil
}
