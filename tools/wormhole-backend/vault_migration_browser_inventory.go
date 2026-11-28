package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const (
	migrationBrowserFileKind          = "legacy-browser-file"
	maxMigrationBrowserProfiles       = 256
	maxMigrationBrowserEntries        = 4096
	maxMigrationBrowserBytes    int64 = 128 * 1024 * 1024
)

// These records are native encrypted local state. Neither paths nor profile
// contents are renderer DTOs. The caller must first quiesce Chromium, including
// its storage checkpoints and background extension contexts.
type legacyBrowserInventory struct {
	Version     int                    `json:"version"`
	WorkspaceID string                 `json:"workspaceId"`
	UserData    string                 `json:"userData"`
	RootState   *legacyBrowserFile     `json:"rootState,omitempty"`
	Profiles    []legacyBrowserProfile `json:"profiles"`
}

type legacyBrowserProfile struct {
	Name        string              `json:"name"`
	Directories []string            `json:"directories"`
	Files       []legacyBrowserFile `json:"files"`
}

type legacyBrowserFile struct {
	Profile        string `json:"profile"`
	Path           string `json:"path"`
	ScopeID        string `json:"scopeId"`
	Bytes          int64  `json:"bytes"`
	Authentication []byte `json:"authentication"`
}

// Ordinary web cookie profiles are outside #495. Unknown names in an owned SSO
// or extension namespace are refused rather than silently left behind.
func legacyBrowserProfileName(name string) bool {
	if name == "wormhole-tunnel-auth-azure" || name == "wormhole-tunnel-auth-fortinet" || name == "wormhole-tunnel-auth-watchguard" {
		return true
	}
	for _, prefix := range []string{"wormhole-tunnel-auth-watchguard-", "wormhole-web-ext-"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		return len(suffix) == 16 && strings.IndexFunc(suffix, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) < 0
	}
	return false
}

func legacyBrowserOwnedName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "wormhole-tunnel-auth-") || strings.HasPrefix(strings.ToLower(name), "wormhole-web-ext-")
}

func legacyBrowserRelativePath(path string) bool {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) || strings.Contains(path, "\\") || strings.HasPrefix(path, "/") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.Contains(part, ":") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}

func legacyBrowserFileScope(workspace, profile, path string) string {
	id, err := uuid.Parse(workspace)
	if err != nil || id == uuid.Nil || id.String() != workspace {
		return ""
	}
	return uuid.NewSHA1(id, []byte("wormhole/v1/migration-browser-file\x00"+profile+"\x00"+path)).String()
}

// The root handle confines every subsequent traversal. A renamed root or a
// symlink/junction supplied instead of the native user-data directory is refused.
func openLegacyBrowserRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return nil, errVaultMigrationSource
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errVaultMigrationSource
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	file, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errVaultMigrationSource
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	current, pathErr := os.Lstat(path)
	if statErr != nil || closeErr != nil || pathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, current) {
		root.Close()
		return nil, errVaultMigrationSource
	}
	return root, nil
}

func legacyBrowserDirectory(root *os.Root, path string) ([]os.DirEntry, error) {
	info, err := root.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errVaultMigrationSource
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errVaultMigrationSource
	}
	entries := []os.DirEntry{}
	for {
		page, err := file.ReadDir(128)
		if err != nil && err != io.EOF || len(page) > maxMigrationBrowserEntries-len(entries) {
			return nil, errVaultMigrationSource
		}
		entries = append(entries, page...)
		if err == io.EOF {
			break
		}
	}
	current, err := root.Lstat(path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) || !current.ModTime().Equal(info.ModTime()) || file.Close() != nil {
		return nil, errVaultMigrationSource
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readLegacyBrowserFile(root *os.Root, path string) (result []byte, err error) {
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > vaultstore.MaxLocalStateBytes {
		return nil, errVaultMigrationSource
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errVaultMigrationSource
	}
	result, err = io.ReadAll(io.LimitReader(file, info.Size()+1))
	defer func() {
		if err != nil {
			vault.Wipe(result)
			result = nil
		}
	}()
	end, statErr := file.Stat()
	current, pathErr := root.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || int64(len(result)) != info.Size() || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) || file.Close() != nil {
		return result, errVaultMigrationSource
	}
	return result, nil
}

func captureLegacyBrowserInventory(ctx context.Context, userData, workspace string, key []byte, visit func(legacyBrowserFile, []byte) error) (*legacyBrowserInventory, error) {
	return captureLegacyBrowserInventorySelected(ctx, userData, workspace, key, visit, "")
}

func captureLegacyBrowserInventorySelected(ctx context.Context, userData, workspace string, key []byte, visit func(legacyBrowserFile, []byte) error, selected string) (*legacyBrowserInventory, error) {
	if ctx.Err() != nil || len(key) != 32 || legacyBrowserFileScope(workspace, "", "Local State") == "" {
		return nil, errVaultMigrationSource
	}
	result := &legacyBrowserInventory{Version: 1, WorkspaceID: workspace, UserData: userData, Profiles: []legacyBrowserProfile{}}
	root, err := openLegacyBrowserRoot(userData)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Legacy readers also recognize registered default/custom Bitwarden roots.
	// Those need a selective storage adapter: never emit an empty/complete
	// browser proof while an unhandled registered secret store remains.
	for _, marker := range []string{bitwardenBrowserProfileMarkerFile, filepath.Join("Default", bitwardenBrowserProfileMarkerFile)} {
		if _, err := root.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			return nil, errVaultMigrationSource
		}
	}
	if _, err := root.Lstat("Partitions"); errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	entries, err := legacyBrowserDirectory(root, "Partitions")
	if err != nil {
		return nil, err
	}
	profileCount := 0
	for _, entry := range entries {
		if !legacyBrowserOwnedName(entry.Name()) {
			if entry.IsDir() {
				if _, err := root.Lstat(filepath.Join("Partitions", entry.Name(), bitwardenBrowserProfileMarkerFile)); !errors.Is(err, os.ErrNotExist) {
					return nil, errVaultMigrationSource
				}
			}
			continue
		}
		profileCount++
		if !legacyBrowserProfileName(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || profileCount > maxMigrationBrowserProfiles {
			return nil, errVaultMigrationSource
		}
		if selected != "" && entry.Name() != selected {
			continue
		}
		result.Profiles = append(result.Profiles, legacyBrowserProfile{Name: entry.Name(), Directories: []string{}, Files: []legacyBrowserFile{}})
	}
	remaining, count := maxMigrationBrowserBytes, 0
	add := func(profile, path, physical string) (legacyBrowserFile, error) {
		if ctx.Err() != nil || !legacyBrowserRelativePath(path) || count >= maxMigrationBrowserEntries {
			return legacyBrowserFile{}, errVaultMigrationSource
		}
		contents, err := readLegacyBrowserFile(root, physical)
		defer vault.Wipe(contents)
		if err != nil || int64(len(contents)) > remaining {
			return legacyBrowserFile{}, errVaultMigrationSource
		}
		remaining -= int64(len(contents))
		count++
		file := legacyBrowserFile{Profile: profile, Path: path, ScopeID: legacyBrowserFileScope(workspace, profile, path), Bytes: int64(len(contents))}
		file.Authentication, err = legacyInventoryMAC(key, userData, file, contents)
		if err == nil && visit != nil {
			err = visit(file, contents)
		}
		return file, err
	}
	if len(result.Profiles) != 0 && selected == "" {
		if _, err := root.Lstat("Local State"); err == nil {
			file, err := add("", "Local State", "Local State")
			if err != nil {
				return nil, err
			}
			result.RootState = &file
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errVaultMigrationSource
		}
	}
	for i := range result.Profiles {
		profile := &result.Profiles[i]
		var walk func(string) error
		walk = func(relative string) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			base := filepath.Join("Partitions", profile.Name, filepath.FromSlash(relative))
			entries, err := legacyBrowserDirectory(root, base)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				path := entry.Name()
				if relative != "" {
					path = relative + "/" + path
				}
				if !legacyBrowserRelativePath(path) || entry.Type()&os.ModeSymlink != 0 {
					return errVaultMigrationSource
				}
				if entry.IsDir() {
					count++
					if count > maxMigrationBrowserEntries {
						return errVaultMigrationSource
					}
					profile.Directories = append(profile.Directories, path)
					if err := walk(path); err != nil {
						return err
					}
				} else {
					file, err := add(profile.Name, path, filepath.Join(base, entry.Name()))
					if err != nil {
						return err
					}
					profile.Files = append(profile.Files, file)
				}
			}
			return nil
		}
		if err := walk(""); err != nil {
			return nil, err
		}
		sort.Strings(profile.Directories)
		sort.Slice(profile.Files, func(i, j int) bool { return profile.Files[i].Path < profile.Files[j].Path })
	}
	if err := validateLegacyBrowserInventory(result, workspace); err != nil {
		return nil, err
	}
	return result, ctx.Err()
}

func matchesLegacyBrowserFile(key []byte, userData string, file legacyBrowserFile, contents []byte) bool {
	expected := file.Authentication
	file.Authentication = nil
	actual, err := legacyInventoryMAC(key, userData, file, contents)
	return err == nil && int64(len(contents)) == file.Bytes && hmac.Equal(expected, actual)
}

func validateLegacyBrowserInventory(inventory *legacyBrowserInventory, workspace string) error {
	if inventory == nil || inventory.Version != 1 || inventory.WorkspaceID != workspace || !filepath.IsAbs(inventory.UserData) || filepath.Clean(inventory.UserData) != inventory.UserData || !utf8.ValidString(inventory.UserData) || strings.ContainsRune(inventory.UserData, 0) || inventory.Profiles == nil || len(inventory.Profiles) > maxMigrationBrowserProfiles {
		return vault.ErrFormat
	}
	count, total := 0, int64(0)
	seen := map[string]bool{}
	check := func(file legacyBrowserFile, profile string) bool {
		count++
		total += file.Bytes
		if file.Profile != profile || !legacyBrowserRelativePath(file.Path) || file.ScopeID == "" || file.ScopeID != legacyBrowserFileScope(workspace, profile, file.Path) || file.Bytes < 0 || file.Bytes > vaultstore.MaxLocalStateBytes || len(file.Authentication) != 32 || seen[file.ScopeID] {
			return false
		}
		seen[file.ScopeID] = true
		return true
	}
	if inventory.RootState != nil && (len(inventory.Profiles) == 0 || inventory.RootState.Path != "Local State" || !check(*inventory.RootState, "")) {
		return vault.ErrFormat
	}
	for i, profile := range inventory.Profiles {
		if !legacyBrowserProfileName(profile.Name) || i > 0 && inventory.Profiles[i-1].Name >= profile.Name || profile.Directories == nil || profile.Files == nil {
			return vault.ErrFormat
		}
		paths := map[string]bool{"": true}
		for j, dir := range profile.Directories {
			count++
			parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir)))
			if parent == "." {
				parent = ""
			}
			if !legacyBrowserRelativePath(dir) || j > 0 && profile.Directories[j-1] >= dir || !paths[parent] {
				return vault.ErrFormat
			}
			paths[dir] = true
		}
		for j, file := range profile.Files {
			parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path)))
			if parent == "." {
				parent = ""
			}
			if !check(file, profile.Name) || j > 0 && profile.Files[j-1].Path >= file.Path || paths[file.Path] || !paths[parent] {
				return vault.ErrFormat
			}
		}
	}
	raw, err := json.Marshal(inventory)
	defer vault.Wipe(raw)
	if err != nil || len(raw) > maxMigrationInventoryBytes || count > maxMigrationBrowserEntries || total > maxMigrationBrowserBytes {
		return vault.ErrFormat
	}
	return nil
}

func equalLegacyBrowserFile(a, b legacyBrowserFile) bool {
	return a.Profile == b.Profile && a.Path == b.Path && a.ScopeID == b.ScopeID && a.Bytes == b.Bytes && hmac.Equal(a.Authentication, b.Authentication)
}

func copyLegacyBrowserInventory(ctx context.Context, userData, workspace string, rootKey []byte, owner *localvault.Owner, expected *legacyBrowserInventory) (*legacyBrowserInventory, int, error) {
	key, err := vault.DeriveKey(rootKey, []byte(workspace), vault.PurposeLocalSeal)
	if err != nil {
		return nil, 0, err
	}
	defer vault.Wipe(key)
	if expected == nil || validateLegacyBrowserInventory(expected, workspace) != nil || expected.UserData != userData {
		return nil, 0, vault.ErrAuthentication
	}
	files := map[string]legacyBrowserFile{}
	if expected.RootState != nil {
		files[expected.RootState.ScopeID] = *expected.RootState
	}
	for _, profile := range expected.Profiles {
		for _, file := range profile.Files {
			files[file.ScopeID] = file
		}
	}
	count := 0
	inventory, err := captureLegacyBrowserInventory(ctx, userData, workspace, key, func(file legacyBrowserFile, contents []byte) error {
		original, ok := files[file.ScopeID]
		if !ok || !equalLegacyBrowserFile(original, file) {
			return vault.ErrAuthentication
		}
		if _, err := owner.PutLocalState(ctx, migrationBrowserFileKind, file.ScopeID, contents, 0); err != nil {
			return err
		}
		if err := owner.WithLocalState(ctx, migrationBrowserFileKind, file.ScopeID, 1, equalLegacyVaultValue(contents)); err != nil {
			return err
		}
		count++
		return nil
	})
	if err == nil && !equalLegacyBrowserInventory(expected, inventory) {
		err = vault.ErrAuthentication
	}
	return inventory, count, err
}

func equalLegacyBrowserInventory(a, b *legacyBrowserInventory) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	defer vault.Wipe(left)
	defer vault.Wipe(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}
