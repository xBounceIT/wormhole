package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	bitwardenBrowserProfileMarkerFile   = "wormhole-bitwarden-extension.json"
	bitwardenBrowserProfileMarkerSchema = 1
)

type bitwardenBrowserProfileMarker struct {
	SchemaVersion int    `json:"schemaVersion"`
	ExtensionPath string `json:"extensionPath"`
	ExtensionID   string `json:"extensionId"`
	RouteKey      string `json:"routeKey,omitempty"`
}

type bitwardenBrowserProfileCandidate struct {
	profilePath     string
	marker          bitwardenBrowserProfileMarker
	updatedAt       time.Time
	cookieUpdatedAt time.Time
}

type bitwardenBrowserProfileSeedResult struct {
	Initialized          bool     `json:"initialized"`
	Seeded               bool     `json:"seeded"`
	CookieSourceProfiles []string `json:"cookieSourceProfiles"`
}

func (m *vncManager) seedBitwardenBrowserProfile(
	profilePath,
	extensionPath,
	routeKey string,
) (bitwardenBrowserProfileSeedResult, error) {
	if !validBitwardenBrowserProfileLocation(profilePath, m.electronUserDataPath) ||
		!validBitwardenExtensionPath(extensionPath) || !validBitwardenRouteKey(routeKey) {
		return bitwardenBrowserProfileSeedResult{}, errors.New("Bitwarden browser profile seed request is invalid")
	}
	routeKey = normalizeBitwardenRouteKey(routeKey)
	_, _, initialized := readBitwardenBrowserProfileMarker(
		filepath.Join(profilePath, bitwardenBrowserProfileMarkerFile),
	)
	candidates, err := findBitwardenBrowserProfileCandidates(
		m.electronUserDataPath,
		profilePath,
		extensionPath,
		routeKey,
	)
	if err != nil {
		return bitwardenBrowserProfileSeedResult{}, err
	}
	result := bitwardenBrowserProfileSeedResult{
		Initialized: initialized,
		CookieSourceProfiles: bitwardenCookieSourceProfiles(
			candidates,
			routeKey,
			initialized,
			bitwardenCookieProfileLastWrite(profilePath),
		),
	}
	if initialized {
		return result, nil
	}
	for _, candidate := range candidates {
		seeded, seedErr := seedBitwardenExtensionIndexedDB(
			candidate.profilePath,
			profilePath,
			candidate.marker.ExtensionID,
		)
		if seedErr != nil {
			continue
		}
		if seeded {
			result.Seeded = true
			break
		}
	}
	return result, nil
}

func (m *vncManager) registerBitwardenBrowserProfile(
	profilePath,
	extensionPath,
	extensionID,
	routeKey string,
) (map[string]bool, error) {
	if !validBitwardenBrowserProfileLocation(profilePath, m.electronUserDataPath) ||
		!validBitwardenExtensionPath(extensionPath) || !validBitwardenExtensionID(extensionID) ||
		!validBitwardenRouteKey(routeKey) {
		return nil, errors.New("Bitwarden browser profile registration is invalid")
	}
	marker := bitwardenBrowserProfileMarker{
		SchemaVersion: bitwardenBrowserProfileMarkerSchema,
		ExtensionPath: filepath.Clean(extensionPath),
		ExtensionID:   strings.ToLower(strings.TrimSpace(extensionID)),
		RouteKey:      normalizeBitwardenRouteKey(routeKey),
	}
	encoded, err := json.Marshal(marker)
	if err != nil {
		return nil, errors.New("Bitwarden browser profile registration could not be encoded")
	}
	if err := writePrivateFileAtomic(
		filepath.Join(profilePath, bitwardenBrowserProfileMarkerFile),
		encoded,
	); err != nil {
		return nil, errors.New("Bitwarden browser profile registration could not be saved")
	}
	return map[string]bool{"registered": true}, nil
}

func validBitwardenBrowserProfileLocation(profilePath, userDataRoot string) bool {
	if !validBitwardenBrowserProfilePath(profilePath) || strings.TrimSpace(userDataRoot) == "" {
		return false
	}
	root, err := filepath.Abs(userDataRoot)
	if err != nil {
		return false
	}
	root = filepath.Clean(root)
	profile := filepath.Clean(profilePath)
	relative, err := filepath.Rel(root, profile)
	if err != nil || filepath.IsAbs(relative) || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func validBitwardenExtensionPath(extensionPath string) bool {
	if strings.TrimSpace(extensionPath) == "" || len(extensionPath) > 4096 ||
		!filepath.IsAbs(extensionPath) || filepath.Clean(extensionPath) != extensionPath {
		return false
	}
	info, err := os.Stat(extensionPath)
	return err == nil && info.IsDir()
}

func validBitwardenExtensionID(extensionID string) bool {
	id := strings.ToLower(strings.TrimSpace(extensionID))
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character < 'a' || character > 'p' {
			return false
		}
	}
	return true
}

func validBitwardenRouteKey(routeKey string) bool {
	if routeKey == "" {
		return true
	}
	if routeKey != strings.TrimSpace(routeKey) || len(routeKey) != 64 {
		return false
	}
	for _, character := range routeKey {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func normalizeBitwardenRouteKey(routeKey string) string {
	return strings.ToLower(strings.TrimSpace(routeKey))
}

func findBitwardenBrowserProfileCandidates(
	userDataRoot,
	destinationProfile,
	extensionPath,
	routeKey string,
) ([]bitwardenBrowserProfileCandidate, error) {
	root, err := filepath.Abs(userDataRoot)
	if err != nil {
		return nil, errors.New("Bitwarden browser profile root is invalid")
	}
	profiles := []string{filepath.Clean(root)}
	partitionsRoot := filepath.Join(root, "Partitions")
	entries, readErr := os.ReadDir(partitionsRoot)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, errors.New("Bitwarden browser profiles could not be enumerated")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			profiles = append(profiles, filepath.Join(partitionsRoot, entry.Name()))
		}
	}

	candidates := make([]bitwardenBrowserProfileCandidate, 0)
	for _, profile := range profiles {
		if bitwardenPathsEqual(profile, destinationProfile) {
			continue
		}
		markerPath := filepath.Join(profile, bitwardenBrowserProfileMarkerFile)
		marker, info, ok := readBitwardenBrowserProfileMarker(markerPath)
		if !ok || !bitwardenPathsEqual(marker.ExtensionPath, extensionPath) {
			continue
		}
		candidates = append(candidates, bitwardenBrowserProfileCandidate{
			profilePath:     profile,
			marker:          marker,
			updatedAt:       info.ModTime(),
			cookieUpdatedAt: bitwardenCookieProfileLastWrite(profile),
		})
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		leftMatches := candidates[left].marker.RouteKey == routeKey
		rightMatches := candidates[right].marker.RouteKey == routeKey
		if leftMatches != rightMatches {
			return leftMatches
		}
		if !candidates[left].cookieUpdatedAt.Equal(candidates[right].cookieUpdatedAt) {
			return candidates[left].cookieUpdatedAt.After(candidates[right].cookieUpdatedAt)
		}
		return candidates[left].updatedAt.After(candidates[right].updatedAt)
	})
	return candidates, nil
}

func bitwardenCookieSourceProfiles(
	candidates []bitwardenBrowserProfileCandidate,
	routeKey string,
	initialized bool,
	destinationCookieUpdatedAt time.Time,
) []string {
	if routeKey == "" {
		return []string{}
	}
	desiredRoutes := []string{routeKey, ""}
	if initialized {
		desiredRoutes = desiredRoutes[:1]
	}
	profiles := make([]string, 0, len(candidates))
	for _, desiredRoute := range desiredRoutes {
		for _, candidate := range candidates {
			if candidate.marker.RouteKey == desiredRoute &&
				(!initialized || candidate.cookieUpdatedAt.After(destinationCookieUpdatedAt)) {
				profiles = append(profiles, candidate.profilePath)
			}
		}
	}
	return profiles
}

func bitwardenCookieProfileLastWrite(profilePath string) time.Time {
	newest := time.Time{}
	for _, relativePath := range []string{
		filepath.Join("Network", "Cookies"),
		filepath.Join("Default", "Network", "Cookies"),
		"Cookies",
		filepath.Join("Default", "Cookies"),
	} {
		for _, suffix := range []string{"", "-wal", "-journal"} {
			info, err := os.Stat(filepath.Join(profilePath, relativePath) + suffix)
			if err == nil && info.Mode().IsRegular() && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	return newest
}

func readBitwardenBrowserProfileMarker(
	markerPath string,
) (bitwardenBrowserProfileMarker, os.FileInfo, bool) {
	info, err := os.Stat(markerPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16*1024 {
		return bitwardenBrowserProfileMarker{}, nil, false
	}
	contents, err := os.ReadFile(markerPath)
	if err != nil {
		return bitwardenBrowserProfileMarker{}, nil, false
	}
	var marker bitwardenBrowserProfileMarker
	if json.Unmarshal(contents, &marker) != nil ||
		marker.SchemaVersion != bitwardenBrowserProfileMarkerSchema ||
		!validBitwardenExtensionID(marker.ExtensionID) ||
		strings.TrimSpace(marker.ExtensionPath) == "" || !filepath.IsAbs(marker.ExtensionPath) ||
		!validBitwardenRouteKey(marker.RouteKey) {
		return bitwardenBrowserProfileMarker{}, nil, false
	}
	marker.ExtensionPath = filepath.Clean(marker.ExtensionPath)
	marker.ExtensionID = strings.ToLower(strings.TrimSpace(marker.ExtensionID))
	marker.RouteKey = normalizeBitwardenRouteKey(marker.RouteKey)
	return marker, info, true
}

func seedBitwardenExtensionIndexedDB(sourceProfile, destinationProfile, extensionID string) (bool, error) {
	if !validBitwardenExtensionID(extensionID) {
		return false, errors.New("Bitwarden extension id is invalid")
	}
	directoryName := "chrome-extension_" + strings.ToLower(strings.TrimSpace(extensionID)) +
		"_0.indexeddb.leveldb"
	seeded := false
	var firstErr error
	for _, relativeRoot := range []string{"IndexedDB", filepath.Join("Default", "IndexedDB")} {
		source := filepath.Join(sourceProfile, relativeRoot, directoryName)
		destination := filepath.Join(destinationProfile, relativeRoot, directoryName)
		copied, err := seedBitwardenProfileDirectory(source, destination)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		seeded = seeded || copied
	}
	if seeded {
		return true, nil
	}
	return false, firstErr
}

func seedBitwardenProfileDirectory(source, destination string) (bool, error) {
	if !directoryExists(source) || directoryExists(destination) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return false, err
	}
	staging := destination + ".seed-" + bitwardenRandomSuffix()
	defer func() { _ = os.RemoveAll(staging) }()
	if err := copyBitwardenDirectoryWithLimits(
		source,
		staging,
		bitwardenMaxExtractedFiles,
		bitwardenMaxExtractedBytes,
	); err != nil {
		return false, err
	}
	if err := os.Rename(staging, destination); err != nil {
		if directoryExists(destination) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func bitwardenPathsEqual(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
