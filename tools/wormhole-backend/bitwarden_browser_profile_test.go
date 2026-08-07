package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testBitwardenExtensionID = "abcdefghijklmnopabcdefghijklmnop"
const testBitwardenRouteKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBitwardenBrowserProfileLocationMustStayInsideUserDataRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "Partitions", "persist_wormhole")
	outside := t.TempDir()

	if !validBitwardenBrowserProfileLocation(inside, root) {
		t.Fatal("expected a profile inside Electron user data to be accepted")
	}
	if validBitwardenBrowserProfileLocation(outside, root) {
		t.Fatal("expected a profile outside Electron user data to be rejected")
	}
}

func TestRegisterBitwardenBrowserProfileWritesValidatedMarker(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "Partitions", "persist_wormhole")
	extension := filepath.Join(root, "extensions", "bitwarden")
	mustMakeDirectory(t, profile)
	mustMakeDirectory(t, extension)
	manager := newVncManager(nil, nil, root)

	result, err := manager.registerBitwardenBrowserProfile(
		profile,
		extension,
		testBitwardenExtensionID,
		testBitwardenRouteKey,
	)
	if err != nil {
		t.Fatalf("register profile: %v", err)
	}
	if !result["registered"] {
		t.Fatal("expected profile registration result")
	}
	marker, _, ok := readBitwardenBrowserProfileMarker(
		filepath.Join(profile, bitwardenBrowserProfileMarkerFile),
	)
	if !ok {
		t.Fatal("expected a readable profile marker")
	}
	if marker.ExtensionPath != extension || marker.ExtensionID != testBitwardenExtensionID ||
		marker.RouteKey != testBitwardenRouteKey {
		t.Fatalf("unexpected marker: %+v", marker)
	}

	if _, err := manager.registerBitwardenBrowserProfile(
		profile,
		extension,
		"not-an-extension-id",
		"",
	); err == nil {
		t.Fatal("expected an invalid extension id to be rejected")
	}
	if _, err := manager.registerBitwardenBrowserProfile(
		profile,
		extension,
		testBitwardenExtensionID,
		"not-a-route-key",
	); err == nil {
		t.Fatal("expected an invalid route key to be rejected")
	}
}

func TestSeedBitwardenBrowserProfileCopiesOnlyMatchingExtensionIndexedDB(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	source := filepath.Join(root, "Partitions", "persist_source")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	mustMakeDirectory(t, extension)
	mustMakeDirectory(t, source)
	mustMakeDirectory(t, destination)
	manager := newVncManager(nil, nil, root)
	if _, err := manager.registerBitwardenBrowserProfile(
		source,
		extension,
		testBitwardenExtensionID,
		testBitwardenRouteKey,
	); err != nil {
		t.Fatalf("register source profile: %v", err)
	}

	extensionDatabase := filepath.Join(
		source,
		"Default",
		"IndexedDB",
		"chrome-extension_"+testBitwardenExtensionID+"_0.indexeddb.leveldb",
	)
	siteDatabase := filepath.Join(
		source,
		"Default",
		"IndexedDB",
		"https_router.example_0.indexeddb.leveldb",
	)
	mustWriteFile(t, filepath.Join(extensionDatabase, "CURRENT"), "bitwarden-state")
	mustWriteFile(t, filepath.Join(siteDatabase, "CURRENT"), "site-state")

	result, err := manager.seedBitwardenBrowserProfile(destination, extension, testBitwardenRouteKey)
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if !result.Seeded {
		t.Fatal("expected the extension IndexedDB to be seeded")
	}
	seededFile := filepath.Join(
		destination,
		"Default",
		"IndexedDB",
		"chrome-extension_"+testBitwardenExtensionID+"_0.indexeddb.leveldb",
		"CURRENT",
	)
	contents, err := os.ReadFile(seededFile)
	if err != nil {
		t.Fatalf("read seeded extension database: %v", err)
	}
	if string(contents) != "bitwarden-state" {
		t.Fatalf("unexpected seeded contents %q", contents)
	}
	if directoryExists(filepath.Join(
		destination,
		"Default",
		"IndexedDB",
		"https_router.example_0.indexeddb.leveldb",
	)) {
		t.Fatal("site IndexedDB must not be copied into another browser profile")
	}
}

func TestSeedBitwardenBrowserProfileDoesNotOverwriteExistingIndexedDB(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	source := filepath.Join(root, "Partitions", "persist_source")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	mustMakeDirectory(t, extension)
	mustMakeDirectory(t, source)
	mustMakeDirectory(t, destination)
	manager := newVncManager(nil, nil, root)
	if _, err := manager.registerBitwardenBrowserProfile(
		source,
		extension,
		testBitwardenExtensionID,
		testBitwardenRouteKey,
	); err != nil {
		t.Fatalf("register source profile: %v", err)
	}
	relativeDatabase := filepath.Join(
		"Default",
		"IndexedDB",
		"chrome-extension_"+testBitwardenExtensionID+"_0.indexeddb.leveldb",
	)
	mustWriteFile(t, filepath.Join(source, relativeDatabase, "CURRENT"), "source")
	mustWriteFile(t, filepath.Join(destination, relativeDatabase, "CURRENT"), "destination")

	result, err := manager.seedBitwardenBrowserProfile(destination, extension, testBitwardenRouteKey)
	if err != nil {
		t.Fatalf("seed existing profile: %v", err)
	}
	if result.Seeded {
		t.Fatal("expected an existing extension database not to be replaced")
	}
	contents, err := os.ReadFile(filepath.Join(destination, relativeDatabase, "CURRENT"))
	if err != nil {
		t.Fatalf("read destination database: %v", err)
	}
	if string(contents) != "destination" {
		t.Fatalf("existing database was overwritten with %q", contents)
	}
}

func TestSeedBitwardenBrowserProfileDoesNotRepairRegisteredProfile(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	source := filepath.Join(root, "Partitions", "persist_source")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	mustMakeDirectory(t, extension)
	mustMakeDirectory(t, source)
	mustMakeDirectory(t, destination)
	manager := newVncManager(nil, nil, root)
	for _, profile := range []string{source, destination} {
		if _, err := manager.registerBitwardenBrowserProfile(
			profile,
			extension,
			testBitwardenExtensionID,
			testBitwardenRouteKey,
		); err != nil {
			t.Fatalf("register profile %s: %v", profile, err)
		}
	}
	relativeDatabase := filepath.Join(
		"Default",
		"IndexedDB",
		"chrome-extension_"+testBitwardenExtensionID+"_0.indexeddb.leveldb",
	)
	mustWriteFile(t, filepath.Join(source, relativeDatabase, "CURRENT"), "source")

	result, err := manager.seedBitwardenBrowserProfile(destination, extension, testBitwardenRouteKey)
	if err != nil {
		t.Fatalf("seed registered profile: %v", err)
	}
	if !result.Initialized || result.Seeded {
		t.Fatalf("unexpected registered profile result: %+v", result)
	}
	if directoryExists(filepath.Join(destination, relativeDatabase)) {
		t.Fatal("a registered profile must not receive a replacement extension database")
	}
}

func TestSeedBitwardenBrowserProfileIgnoresMismatchedMarker(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	otherExtension := filepath.Join(root, "extensions", "other")
	source := filepath.Join(root, "Partitions", "persist_source")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	mustMakeDirectory(t, extension)
	mustMakeDirectory(t, otherExtension)
	mustMakeDirectory(t, source)
	mustMakeDirectory(t, destination)
	manager := newVncManager(nil, nil, root)
	if _, err := manager.registerBitwardenBrowserProfile(
		source,
		otherExtension,
		testBitwardenExtensionID,
		testBitwardenRouteKey,
	); err != nil {
		t.Fatalf("register source profile: %v", err)
	}
	mustWriteFile(t, filepath.Join(
		source,
		"Default",
		"IndexedDB",
		"chrome-extension_"+testBitwardenExtensionID+"_0.indexeddb.leveldb",
		"CURRENT",
	), "source")

	result, err := manager.seedBitwardenBrowserProfile(destination, extension, testBitwardenRouteKey)
	if err != nil {
		t.Fatalf("seed profile with mismatched marker: %v", err)
	}
	if result.Seeded {
		t.Fatal("a profile for a different extension install must not be used as a seed")
	}
}

func TestSeedBitwardenBrowserProfilePrefersCookieSourcesForSameRoute(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	direct := filepath.Join(root, "Partitions", "persist_direct")
	matching := filepath.Join(root, "Partitions", "persist_matching")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	for _, directory := range []string{extension, direct, matching, destination} {
		mustMakeDirectory(t, directory)
	}
	manager := newVncManager(nil, nil, root)
	if _, err := manager.registerBitwardenBrowserProfile(
		direct,
		extension,
		testBitwardenExtensionID,
		"",
	); err != nil {
		t.Fatalf("register direct profile: %v", err)
	}
	if _, err := manager.registerBitwardenBrowserProfile(
		matching,
		extension,
		testBitwardenExtensionID,
		testBitwardenRouteKey,
	); err != nil {
		t.Fatalf("register matching profile: %v", err)
	}

	result, err := manager.seedBitwardenBrowserProfile(
		destination,
		extension,
		testBitwardenRouteKey,
	)
	if err != nil {
		t.Fatalf("seed routed profile: %v", err)
	}
	if len(result.CookieSourceProfiles) != 2 ||
		result.CookieSourceProfiles[0] != matching || result.CookieSourceProfiles[1] != direct {
		t.Fatalf("unexpected cookie sources: %#v", result.CookieSourceProfiles)
	}

	directResult, err := manager.seedBitwardenBrowserProfile(
		filepath.Join(root, "Partitions", "persist_other_direct"),
		extension,
		"",
	)
	if err != nil {
		t.Fatalf("seed direct profile: %v", err)
	}
	if len(directResult.CookieSourceProfiles) != 0 {
		t.Fatalf("direct profile requested cookie migration: %#v", directResult.CookieSourceProfiles)
	}
}

func TestSeedBitwardenBrowserProfileRefreshesRegisteredRouteFromNewerCookies(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "extensions", "bitwarden")
	source := filepath.Join(root, "Partitions", "persist_source")
	destination := filepath.Join(root, "Partitions", "persist_destination")
	for _, directory := range []string{extension, source, destination} {
		mustMakeDirectory(t, directory)
	}
	manager := newVncManager(nil, nil, root)
	for _, profile := range []string{source, destination} {
		if _, err := manager.registerBitwardenBrowserProfile(
			profile,
			extension,
			testBitwardenExtensionID,
			testBitwardenRouteKey,
		); err != nil {
			t.Fatalf("register profile %s: %v", profile, err)
		}
	}

	destinationCookies := filepath.Join(destination, "Network", "Cookies")
	sourceCookies := filepath.Join(source, "Network", "Cookies-wal")
	mustWriteFile(t, destinationCookies, "old")
	mustWriteFile(t, sourceCookies, "new")
	oldTime := time.Now().Add(-time.Hour)
	newTime := time.Now()
	if err := os.Chtimes(destinationCookies, oldTime, oldTime); err != nil {
		t.Fatalf("stamp destination cookies: %v", err)
	}
	if err := os.Chtimes(sourceCookies, newTime, newTime); err != nil {
		t.Fatalf("stamp source cookies: %v", err)
	}

	result, err := manager.seedBitwardenBrowserProfile(
		destination,
		extension,
		testBitwardenRouteKey,
	)
	if err != nil {
		t.Fatalf("refresh registered profile: %v", err)
	}
	if !result.Initialized || len(result.CookieSourceProfiles) != 1 ||
		result.CookieSourceProfiles[0] != source {
		t.Fatalf("unexpected cookie refresh sources: %+v", result)
	}

	olderTime := oldTime.Add(-time.Hour)
	if err := os.Chtimes(sourceCookies, olderTime, olderTime); err != nil {
		t.Fatalf("restamp source cookies: %v", err)
	}
	result, err = manager.seedBitwardenBrowserProfile(
		destination,
		extension,
		testBitwardenRouteKey,
	)
	if err != nil {
		t.Fatalf("refresh registered profile with older source: %v", err)
	}
	if len(result.CookieSourceProfiles) != 0 {
		t.Fatalf("older cookie source must not replace the destination: %#v", result.CookieSourceProfiles)
	}
}

func mustMakeDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("create directory %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, contents string) {
	t.Helper()
	mustMakeDirectory(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
