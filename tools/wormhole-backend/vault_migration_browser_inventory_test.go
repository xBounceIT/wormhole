package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func browserInventoryFixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{
		"Local State": []byte("native root state with protected Chromium key"),
		"Partitions/wormhole-tunnel-auth-azure/Cookies":                                             []byte("cookie-private-marker"),
		"Partitions/wormhole-tunnel-auth-azure/IndexedDB/leveldb/000003.log":                        []byte("indexeddb-private-marker"),
		"Partitions/wormhole-tunnel-auth-azure/Session Storage/CURRENT":                             {},
		"Partitions/wormhole-tunnel-auth-watchguard-0123456789abcdef/Local Storage/leveldb/CURRENT": []byte("sso-private-marker"),
		"Partitions/wormhole-web-ext-abcdef0123456789/Local Extension Settings/extension/CURRENT":   {0, 1, 255, 0},
		"Partitions/unrelated-web/Cookies":                                                          []byte("ordinary-web-cookie-outside-scope"),
	}
	for path, value := range files {
		physical := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(physical), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(physical, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure", "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	return root, files
}

func TestVaultMigrationBrowserInventoryExactSourcesAndClearing(t *testing.T) {
	root, files := browserInventoryFixture(t)
	workspace, key := uuid.NewString(), bytes.Repeat([]byte{7}, 32)
	var borrowed [][]byte
	inventory, err := captureLegacyBrowserInventory(context.Background(), root, workspace, key, func(file legacyBrowserFile, value []byte) error {
		path := "Local State"
		if file.Profile != "" {
			path = "Partitions/" + file.Profile + "/" + file.Path
		}
		if !bytes.Equal(value, files[path]) || !matchesLegacyBrowserFile(key, root, file, value) {
			t.Fatal("wrong source or commitment")
		}
		wrong := bytes.Clone(key)
		wrong[0]++
		if matchesLegacyBrowserFile(wrong, root, file, value) || matchesLegacyBrowserFile(key, root+".other", file, value) {
			t.Fatal("unbound browser source")
		}
		borrowed = append(borrowed, value)
		return nil
	})
	if err != nil || inventory.Version != 1 || len(inventory.Profiles) != 3 || inventory.RootState == nil || len(borrowed) != 6 {
		t.Fatal("incomplete native browser inventory", err)
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("retained plaintext after callback")
		}
	}
	raw, err := json.Marshal(inventory)
	if err != nil || bytes.Contains(raw, []byte("private-marker")) || bytes.Contains(raw, []byte("unrelated-web")) {
		t.Fatal("inventory contains raw secrets or unrelated profiles", err)
	}
	again, err := captureLegacyBrowserInventory(context.Background(), root, workspace, key, nil)
	if err != nil || !equalLegacyBrowserInventory(inventory, again) {
		t.Fatal("unstable checkpoint", err)
	}
	path := filepath.Join(root, "Partitions", inventory.Profiles[0].Name, "Cookies")
	if err := os.WriteFile(path, []byte("changed cookie"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err = captureLegacyBrowserInventory(context.Background(), root, workspace, key, nil)
	if err != nil || equalLegacyBrowserInventory(inventory, again) {
		t.Fatal("source edit ignored", err)
	}
}

func TestVaultMigrationBrowserStageArchivesAndQuarantine(t *testing.T) {
	_, source, document, key, plan, _ := migrationStageFixture(t)
	root, files := browserInventoryFixture(t)
	ctx := context.Background()
	stage, err := stageLegacyVaultDomains(ctx, source, root, document, key, plan)
	if err != nil || stage.LocalStates != 6 {
		t.Fatal("browser archive omitted from staging", stage.LocalStates, err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	doc, _ := readVaultSlotFile(stage.Path)
	inventory, _, _, err := readLegacyRetirementInventory(ctx, owner, doc, source)
	if err != nil || inventory.Browser == nil {
		t.Fatal(err)
	}
	entries := []legacyBrowserFile{*inventory.Browser.RootState}
	for _, profile := range inventory.Browser.Profiles {
		entries = append(entries, profile.Files...)
	}
	for _, entry := range entries {
		path := "Local State"
		if entry.Profile != "" {
			path = "Partitions/" + entry.Profile + "/" + entry.Path
		}
		if err := owner.WithLocalState(ctx, migrationBrowserFileKind, entry.ScopeID, 1, equalLegacyVaultValue(files[path])); err != nil {
			t.Fatal("archive lost exact native bytes", err)
		}
	}
	owner.Close()
	raw, err := os.ReadFile(stage.Path)
	if err != nil || bytes.Contains(raw, []byte("private-marker")) {
		t.Fatal("browser plaintext persisted outside encryption", err)
	}
	if _, err := retireLegacyVaultFiles(ctx, source, root, stage.Path, key); err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyVaultSQL(ctx, source, stage.Path, key); err != vault.ErrPolicy {
		t.Fatal("SQL phase skipped live browser sources", err)
	}
	progress, err := retireLegacyVaultSources(ctx, source, root, stage.Path, key)
	if err != nil || progress.BrowserProfiles != 3 {
		t.Fatal("browser retirement failed", progress, err)
	}
	if err := retireLegacyVaultSQL(ctx, source, stage.Path, key); err != nil {
		t.Fatal("SQL did not continue after browser retirement", err)
	}
	if value, err := os.ReadFile(filepath.Join(root, "Partitions", "unrelated-web", "Cookies")); err != nil || !bytes.Equal(value, files["Partitions/unrelated-web/Cookies"]) {
		t.Fatal("ordinary web state changed", err)
	}
	if value, err := os.ReadFile(filepath.Join(root, "Local State")); err != nil || !bytes.Equal(value, files["Local State"]) {
		t.Fatal("shared Chromium root state changed", err)
	}
	if requireLegacyWorkspace(source) != errVaultOwnerRequired {
		t.Fatal("incomplete browser migration enabled ordinary access")
	}
}

func TestVaultMigrationBrowserPathAndProfileBoundaries(t *testing.T) {
	for _, name := range []string{"wormhole-tunnel-auth-azure", "wormhole-tunnel-auth-fortinet", "wormhole-tunnel-auth-watchguard", "wormhole-tunnel-auth-watchguard-0123456789abcdef", "wormhole-web-ext-abcdef0123456789"} {
		if !legacyBrowserProfileName(name) || !legacyBrowserOwnedName(name) {
			t.Fatal("valid profile refused")
		}
	}
	for _, name := range []string{"", "wormhole-web-ext-ABCDEF0123456789", "wormhole-tunnel-auth-azure-extra", "wormhole-tunnel-auth-watchguard-0123456789abcdeg", "wormhole-web-ext-short", "../wormhole-tunnel-auth-azure", "web"} {
		if legacyBrowserProfileName(name) {
			t.Fatal("invalid profile accepted")
		}
	}
	for _, path := range []string{"Cookies", "Local Storage/leveldb/clé", "IndexedDB/.settings"} {
		if !legacyBrowserRelativePath(path) {
			t.Fatal("valid relative path refused")
		}
	}
	for _, path := range []string{"", ".", "..", "../outside", "/absolute", "C:/absolute", "\\server\\share", "a\\b", "a//b", "a/../b", "a\x00b", "a\nb", "a/.. /b", "a.", "name ", string([]byte{255}), strings.Repeat("x", 4097), strings.Repeat("a/", 32) + "b"} {
		if legacyBrowserRelativePath(path) {
			t.Fatal("unsafe relative path accepted")
		}
	}
	for _, workspace := range []string{"", "bad", uuid.Nil.String(), strings.ToUpper("abcdefab-cdef-4abc-8def-abcdefabcdef")} {
		if legacyBrowserFileScope(workspace, "", "Local State") != "" {
			t.Fatal("invalid scope namespace accepted")
		}
	}
	workspace := uuid.NewString()
	if legacyBrowserFileScope(workspace, "profile", "file") == legacyBrowserFileScope(workspace, "", "profile/file") {
		t.Fatal("scope ambiguity")
	}
}

func TestVaultMigrationBrowserInventoryEmptyAndAdmission(t *testing.T) {
	ctx := context.Background()
	workspace, key := uuid.NewString(), bytes.Repeat([]byte{1}, 32)
	root := t.TempDir()
	for _, path := range []string{root, filepath.Join(root, "absent")} {
		inventory, err := captureLegacyBrowserInventory(ctx, path, workspace, key, nil)
		if err != nil || len(inventory.Profiles) != 0 || inventory.RootState != nil {
			t.Fatal("empty source not distinguished", err)
		}
	}
	for _, path := range []string{"relative", root + string(filepath.Separator) + ".", root + string(rune(0))} {
		if _, err := captureLegacyBrowserInventory(ctx, path, workspace, key, nil); err == nil {
			t.Fatal("unsafe root accepted")
		}
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLegacyBrowserRoot(file); err == nil {
		t.Fatal("file accepted as profile root")
	}
	if err := os.Mkdir(filepath.Join(root, "Partitions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "Partitions", "other"), 0700); err != nil {
		t.Fatal(err)
	}
	if inventory, err := captureLegacyBrowserInventory(ctx, root, workspace, key, nil); err != nil || len(inventory.Profiles) != 0 {
		t.Fatal("ordinary profile admitted to SSO migration", err)
	}
	if err := os.Mkdir(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-unknown"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLegacyBrowserInventory(ctx, root, workspace, key, nil); err == nil {
		t.Fatal("unknown owned profile silently omitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := captureLegacyBrowserInventory(cancelled, root, workspace, key, nil); err == nil {
		t.Fatal("cancelled inventory accepted")
	}
	if _, err := captureLegacyBrowserInventory(ctx, root, workspace, nil, nil); err == nil {
		t.Fatal("missing MAC key accepted")
	}
}

func TestVaultMigrationBrowserInventoryRejectsUnsafeFilesAndBounds(t *testing.T) {
	for _, scenario := range []string{"profile-file", "root-state-directory", "oversized", "depth", "profile-count", "callback"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := browserInventoryFixture(t)
			profile := filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure")
			switch scenario {
			case "profile-file":
				if err := os.WriteFile(filepath.Join(root, "Partitions", "wormhole-web-ext-1111111111111111"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "root-state-directory":
				if err := os.Remove(filepath.Join(root, "Local State")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "Local State"), 0700); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				file, err := os.Create(filepath.Join(profile, "large"))
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(vaultstore.MaxLocalStateBytes + 1); err != nil {
					t.Fatal(err)
				}
				file.Close()
			case "depth":
				if err := os.MkdirAll(filepath.Join(profile, filepath.FromSlash(strings.Repeat("a/", 33))), 0700); err != nil {
					t.Fatal(err)
				}
			case "profile-count":
				for i := 0; i < maxMigrationBrowserProfiles; i++ {
					if err := os.Mkdir(filepath.Join(root, "Partitions", fmt.Sprintf("wormhole-web-ext-%016x", i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			stop := errors.New("native archive unavailable")
			var visit func(legacyBrowserFile, []byte) error
			if scenario == "callback" {
				visit = func(legacyBrowserFile, []byte) error { return stop }
			}
			_, err := captureLegacyBrowserInventory(context.Background(), root, uuid.NewString(), bytes.Repeat([]byte{1}, 32), visit)
			if err == nil || scenario == "callback" && !errors.Is(err, stop) {
				t.Fatal("unsafe or incomplete archive accepted", err)
			}
		})
	}
}

func TestVaultMigrationBrowserInventoryValidation(t *testing.T) {
	root, _ := browserInventoryFixture(t)
	workspace, key := uuid.NewString(), bytes.Repeat([]byte{1}, 32)
	original, err := captureLegacyBrowserInventory(context.Background(), root, workspace, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validateLegacyBrowserInventory(nil, workspace) != vault.ErrFormat {
		t.Fatal("nil inventory accepted")
	}
	raw, _ := json.Marshal(original)
	for _, mutation := range []string{"version", "workspace", "root", "profiles", "profile-name", "profile-order", "directories", "directory-parent", "directory-order", "files", "file-order", "file-profile", "file-scope", "file-size", "file-mac", "file-parent", "root-state", "total-size", "entry-count"} {
		t.Run(mutation, func(t *testing.T) {
			var copy legacyBrowserInventory
			if err := json.Unmarshal(raw, &copy); err != nil {
				t.Fatal(err)
			}
			p := &copy.Profiles[0]
			switch mutation {
			case "version":
				copy.Version++
			case "workspace":
				copy.WorkspaceID = uuid.NewString()
			case "root":
				copy.UserData = "relative"
			case "profiles":
				copy.Profiles = nil
			case "profile-name":
				p.Name = "unrelated"
			case "profile-order":
				copy.Profiles[0], copy.Profiles[1] = copy.Profiles[1], copy.Profiles[0]
			case "directories":
				p.Directories = nil
			case "directory-parent":
				p.Directories = []string{"missing/child"}
			case "directory-order":
				p.Directories = []string{"z", "a"}
			case "files":
				p.Files = nil
			case "file-order":
				p.Files[0], p.Files[1] = p.Files[1], p.Files[0]
			case "file-profile":
				p.Files[0].Profile = "other"
			case "file-scope":
				p.Files[0].ScopeID = uuid.NewString()
			case "file-size":
				p.Files[0].Bytes = -1
			case "file-mac":
				p.Files[0].Authentication = nil
			case "file-parent":
				p.Files[0].Path = "missing/file"
				p.Files[0].ScopeID = legacyBrowserFileScope(workspace, p.Name, p.Files[0].Path)
			case "root-state":
				copy.RootState.Path = "other"
			case "total-size":
				copy.RootState.Bytes = vaultstore.MaxLocalStateBytes
				for i := range p.Files {
					p.Files[i].Bytes = vaultstore.MaxLocalStateBytes
				}
			case "entry-count":
				p.Directories = []string{}
				for i := 0; i <= maxMigrationBrowserEntries; i++ {
					p.Directories = append(p.Directories, fmt.Sprintf("dir-%04d", i))
				}
				p.Files = []legacyBrowserFile{}
			}
			if err := validateLegacyBrowserInventory(&copy, workspace); err != vault.ErrFormat {
				t.Fatal("invalid inventory accepted", mutation, err)
			}
		})
	}
}

func TestVaultMigrationBrowserSymlinksAreNeverFollowed(t *testing.T) {
	for _, target := range []string{"root", "partitions", "profile", "child", "file"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside native profile"), 0600); err != nil {
				t.Fatal(err)
			}
			path, destination := root, outside
			if target != "root" {
				path = filepath.Join(root, "Partitions")
				if target != "partitions" {
					path = filepath.Join(path, "wormhole-tunnel-auth-azure")
					if target == "child" || target == "file" {
						path = filepath.Join(path, "linked")
					}
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			if target == "file" {
				destination = filepath.Join(outside, "secret")
			}
			if err := os.Symlink(destination, path); err != nil {
				t.Skip("native symlink creation unavailable")
			}
			if _, err := captureLegacyBrowserInventory(context.Background(), root, uuid.NewString(), bytes.Repeat([]byte{1}, 32), nil); err == nil {
				t.Fatal("followed profile link")
			}
			value, err := os.ReadFile(filepath.Join(outside, "secret"))
			if err != nil || string(value) != "outside native profile" {
				t.Fatal("outside source changed", err)
			}
		})
	}
}

func TestVaultMigrationBrowserNativeProfileFixture(t *testing.T) {
	root, token := os.Getenv("WORMHOLE_TEST_BROWSER_ROOT"), os.Getenv("WORMHOLE_TEST_BROWSER_TOKEN")
	if root == "" && token == "" {
		t.Skip("run by the isolated Electron migration integration fixture")
	}
	id, err := uuid.Parse(token)
	if err != nil || id == uuid.Nil || id.String() != token || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(filepath.Base(root), "wormhole-browser-migration-") {
		t.Fatal("invalid native fixture authority")
	}
	// Chromium expands Windows short names and macOS temporary-directory aliases.
	// Verify the physical parent before permitting fixture retirement.
	parent, parentErr := os.Stat(filepath.Dir(root))
	temp, tempErr := os.Stat(os.TempDir())
	fixture, fixtureErr := os.Lstat(root)
	if parentErr != nil || tempErr != nil || !os.SameFile(parent, temp) || fixtureErr != nil || !fixture.IsDir() {
		t.Fatal("native fixture must be a directory directly inside the system temporary directory")
	}
	marker, err := os.ReadFile(filepath.Join(root, "wormhole-browser-migration-fixture"))
	if err != nil || string(marker) != token {
		t.Fatal("native fixture marker mismatch")
	}
	db, source, document, key, plan, _ := migrationStageFixture(t)
	stop := errors.New("verify native archive before retirement")
	_, err = continueLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(string) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	stage := source + ".migrating-" + document.FileID
	owner := openNativeMigrationStage(t, stage, key)
	defer owner.Close()
	doc, _ := readVaultSlotFile(stage)
	inventory, _, _, err := readLegacyRetirementInventory(context.Background(), owner, doc, source)
	if err != nil || inventory.Browser == nil || len(inventory.Browser.Profiles) != 5 {
		t.Fatal("native Chromium profiles omitted", err)
	}
	for _, profile := range inventory.Browser.Profiles {
		cookieFile := false
		for _, file := range profile.Files {
			if strings.HasSuffix(file.Path, "Cookies") {
				cookieFile = true
			}
			original, err := os.ReadFile(filepath.Join(root, "Partitions", profile.Name, filepath.FromSlash(file.Path)))
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.WithLocalState(context.Background(), migrationBrowserFileKind, file.ScopeID, 1, equalLegacyVaultValue(original)); err != nil {
				vault.Wipe(original)
				t.Fatal("native persisted browser bytes changed", err)
			}
			vault.Wipe(original)
		}
		if !cookieFile {
			t.Fatal("native cookie store absent from archive")
		}
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// Electron has exited and flushed these test-only profiles before this Go
	// process starts. Retirement never runs while a native Chromium context lives.
	db.Close()
	path, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal("native migration could not advance", err)
	}
	got, gotErr := os.Stat(path)
	want, wantErr := os.Stat(stage)
	if gotErr != nil || wantErr != nil || filepath.Base(path) != filepath.Base(stage) || !os.SameFile(got, want) {
		t.Fatal("native migration returned a different staging database")
	}
	check := openNativeMigrationStage(t, stage, key)
	defer check.Close()
	doc, _ = readVaultSlotFile(stage)
	_, journal, err := readLegacyRetirementJournal(context.Background(), check, doc, 0, 0)
	if err != nil || journal.Browser == nil || journal.Browser.Completed != 5 || journal.SQL == nil || journal.SQL.Phase != "compacted" {
		t.Fatal("native coordinator left an unfinished phase", err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal("native Chromium migration could not publish", err)
	}
	defer publication.close()
	macKey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(macKey)
	if err := verifyLegacyBrowserArchives(context.Background(), inventory.Browser, macKey, publication.owner); err != nil {
		t.Fatal("published native browser archive changed", err)
	}
	final, err := readVaultSlotFile(source)
	if err != nil || final.Migration != nil || len(final.Nodes) != 3 || final.ProfileSequence == 0 {
		t.Fatal("native Chromium cutover did not finalize its floors", err)
	}
}

func TestVaultMigrationBrowserInventoryRefusesUnhandledRegisteredBitwardenRoots(t *testing.T) {
	for _, path := range []string{bitwardenBrowserProfileMarkerFile, filepath.Join("Default", bitwardenBrowserProfileMarkerFile), filepath.Join("Partitions", "older-custom-profile", bitwardenBrowserProfileMarkerFile)} {
		t.Run(path, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, path)
			if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("registered legacy storage"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := captureLegacyBrowserInventory(context.Background(), root, uuid.NewString(), bytes.Repeat([]byte{1}, 32), nil); err == nil {
				t.Fatal("unhandled storage mistaken for an empty browser inventory")
			}
		})
	}
}

func TestVaultMigrationBrowserArchiveRejectsWrongKeyAndOverwrite(t *testing.T) {
	_, source, document, key, plan, _ := migrationStageFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, "", document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	defer owner.Close()
	root, _ := browserInventoryFixture(t)
	subkey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(subkey)
	expected, err := captureLegacyBrowserInventory(context.Background(), root, document.VaultID, subkey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := copyLegacyBrowserInventory(context.Background(), root, document.VaultID, nil, owner, expected); err == nil {
		t.Fatal("missing root key admitted")
	}
	if _, count, err := copyLegacyBrowserInventory(context.Background(), root, document.VaultID, key, owner, expected); err != nil || count != 6 {
		t.Fatal(count, err)
	}
	if _, _, err := copyLegacyBrowserInventory(context.Background(), root, document.VaultID, key, owner, expected); err == nil {
		t.Fatal("existing native archive overwritten without revision authority")
	}
}

func TestVaultMigrationBrowserArchiveBindsInitialCheckpointBeforeEveryWrite(t *testing.T) {
	for _, mutation := range []string{"changed-file", "new-file", "new-directory", "root-state", "wrong-key", "missing-proof"} {
		t.Run(mutation, func(t *testing.T) {
			_, source, document, key, plan, _ := migrationStageFixture(t)
			stage, err := stageLegacyVaultDomains(context.Background(), source, "", document, key, plan)
			if err != nil {
				t.Fatal(err)
			}
			owner := openNativeMigrationStage(t, stage.Path, key)
			defer owner.Close()
			root, _ := browserInventoryFixture(t)
			macKey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(macKey)
			expected, err := captureLegacyBrowserInventory(context.Background(), root, document.VaultID, macKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			original := expected
			bad := []byte("uncommitted-browser-source-B")
			switch mutation {
			case "changed-file":
				err = os.WriteFile(filepath.Join(root, "Partitions", expected.Profiles[0].Name, "Cookies"), bad, 0600)
			case "new-file":
				err = os.WriteFile(filepath.Join(root, "Partitions", expected.Profiles[0].Name, "new"), bad, 0600)
			case "new-directory":
				err = os.Mkdir(filepath.Join(root, "Partitions", expected.Profiles[0].Name, "new-directory"), 0700)
			case "root-state":
				err = os.WriteFile(filepath.Join(root, "Local State"), bad, 0600)
			case "wrong-key":
				key = bytes.Repeat([]byte{8}, 32)
			case "missing-proof":
				expected = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := copyLegacyBrowserInventory(context.Background(), root, document.VaultID, key, owner, expected); err == nil {
				t.Fatal("unbound copy accepted")
			}
			states, err := owner.ListLocalStates(context.Background(), "", 64)
			if err != nil {
				t.Fatal(err)
			}
			entries := map[string]legacyBrowserFile{}
			entries[original.RootState.ScopeID] = *original.RootState
			for _, profile := range original.Profiles {
				for _, file := range profile.Files {
					entries[file.ScopeID] = file
				}
			}
			for _, state := range states {
				if state.Kind != migrationBrowserFileKind {
					continue
				}
				file, ok := entries[state.ScopeID]
				if !ok {
					t.Fatal("uncommitted file persisted")
				}
				if err := owner.WithLocalState(context.Background(), migrationBrowserFileKind, state.ScopeID, state.RowVersion, func(raw []byte) error {
					if !matchesLegacyBrowserFile(macKey, root, file, raw) || bytes.Contains(raw, bad) {
						return vault.ErrAuthentication
					}
					return nil
				}); err != nil {
					t.Fatal("uncommitted bytes persisted before rejection", err)
				}
			}
		})
	}
}
