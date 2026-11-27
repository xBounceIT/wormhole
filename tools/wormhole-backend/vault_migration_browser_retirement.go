package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func verifyLegacyBrowserArchives(ctx context.Context, inventory *legacyBrowserInventory, key []byte, owner *localvault.Owner) error {
	check := func(file legacyBrowserFile) error {
		return owner.WithLocalState(ctx, migrationBrowserFileKind, file.ScopeID, 1, func(value []byte) error {
			if !matchesLegacyBrowserFile(key, inventory.UserData, file, value) {
				return vault.ErrAuthentication
			}
			return nil
		})
	}
	if inventory.RootState != nil {
		if err := check(*inventory.RootState); err != nil {
			return err
		}
	}
	for _, profile := range inventory.Profiles {
		for _, file := range profile.Files {
			if err := check(file); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchesLegacyBrowserProfile(expected, current legacyBrowserProfile, partial bool) bool {
	if expected.Name != current.Name || !partial && (len(expected.Files) != len(current.Files) || len(expected.Directories) != len(current.Directories)) {
		return false
	}
	directories := map[string]bool{}
	files := map[string]legacyBrowserFile{}
	for _, dir := range expected.Directories {
		directories[dir] = true
	}
	for _, file := range expected.Files {
		files[file.Path] = file
	}
	for _, dir := range current.Directories {
		if !directories[dir] {
			return false
		}
	}
	for _, file := range current.Files {
		original, ok := files[file.Path]
		if !ok || !equalLegacyBrowserFile(original, file) {
			return false
		}
	}
	return true
}

// The native root confines recursive deletion. Recheck its live pathname too:
// syncing a replacement directory must not acknowledge removal from the old one.
func verifyLegacyBrowserPartitionRoot(root *os.Root, userData string) error {
	if root == nil || root.Name() != filepath.Join(userData, "Partitions") {
		return vault.ErrAuthentication
	}
	file, err := root.Open(".")
	if err != nil {
		return errVaultMigrationSource
	}
	defer file.Close()
	bound, err := file.Stat()
	current, pathErr := os.Lstat(root.Name())
	if err != nil || pathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(bound, current) {
		return vault.ErrAuthentication
	}
	return nil
}

// Source/workspace/stage exclusion and Chromium quiescence belong to the native
// coordinator. No renderer supplies a root, profile name or removal callback.
// Pending intent permits only a matching subset after an interrupted RemoveAll.
func retireLegacyBrowserProfiles(ctx context.Context, inventory *legacyBrowserInventory, key []byte, owner *localvault.Owner, state *vaultstore.LocalState, journal *legacyRetirementJournal, remove func(*os.Root, string) error) error {
	if inventory == nil || validateLegacyBrowserInventory(inventory, inventory.WorkspaceID) != nil || owner == nil || state == nil || journal == nil || remove == nil || len(key) != 32 || journal.SQL != nil || journal.Pending != nil || journal.PendingKey != nil || journal.Version != 2 && journal.Version != 4 {
		return vault.ErrPolicy
	}
	if (journal.Version == 4) != (journal.Browser != nil) || journal.Browser != nil && (journal.Browser.Completed < 0 || journal.Browser.Completed > len(inventory.Profiles) || journal.Browser.Pending != nil && (*journal.Browser.Pending < 0 || *journal.Browser.Pending > journal.Browser.Completed || *journal.Browser.Pending >= len(inventory.Profiles))) {
		return vault.ErrAuthentication
	}
	if err := verifyLegacyBrowserArchives(ctx, inventory, key, owner); err != nil {
		return err
	}
	current, err := captureLegacyBrowserInventory(ctx, inventory.UserData, inventory.WorkspaceID, key, nil)
	if err != nil {
		return err
	}
	expected := map[string]int{}
	present := map[string]legacyBrowserProfile{}
	for i, profile := range inventory.Profiles {
		expected[profile.Name] = i
	}
	for _, profile := range current.Profiles {
		i, ok := expected[profile.Name]
		partial := journal.Browser != nil && (i < journal.Browser.Completed || journal.Browser.Pending != nil && *journal.Browser.Pending == i)
		if !ok || !matchesLegacyBrowserProfile(inventory.Profiles[i], profile, partial) {
			return vault.ErrAuthentication
		}
		present[profile.Name] = profile
	}
	for i, profile := range inventory.Profiles {
		if _, ok := present[profile.Name]; !ok && (journal.Browser == nil || i >= journal.Browser.Completed && (journal.Browser.Pending == nil || *journal.Browser.Pending != i)) {
			return vault.ErrAuthentication
		}
	}
	var root *os.Root
	if len(inventory.Profiles) != 0 {
		root, err = openLegacyBrowserRoot(filepath.Join(inventory.UserData, "Partitions"))
		if err != nil {
			return err
		}
		defer root.Close()
	}
	if journal.Browser == nil {
		journal.Version, journal.Browser = 4, &legacyRetirementBrowser{}
		*state, err = writeLegacyRetirementJournal(ctx, owner, inventory.WorkspaceID, *journal, state.RowVersion)
		if err != nil {
			return err
		}
	}
	order := make([]int, 0, len(inventory.Profiles))
	if journal.Browser.Pending != nil {
		order = append(order, *journal.Browser.Pending)
	}
	for i := range inventory.Profiles {
		if journal.Browser.Pending == nil || *journal.Browser.Pending != i {
			order = append(order, i)
		}
	}
	for _, i := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		profile := inventory.Profiles[i]
		if _, exists := present[profile.Name]; !exists && journal.Browser.Pending == nil {
			continue
		}
		if journal.Browser.Pending == nil {
			journal.Browser.Pending = &i
			*state, err = writeLegacyRetirementJournal(ctx, owner, inventory.WorkspaceID, *journal, state.RowVersion)
			if err != nil {
				return err
			}
		}
		// Read only this profile again, avoiding a quadratic rescan of the other
		// archives while retaining the post-intent source check.
		again, err := captureLegacyBrowserInventorySelected(ctx, inventory.UserData, inventory.WorkspaceID, key, nil, profile.Name)
		if err != nil {
			return err
		}
		if len(again.Profiles) > 1 || len(again.Profiles) == 1 && !matchesLegacyBrowserProfile(profile, again.Profiles[0], true) {
			return vault.ErrAuthentication
		}
		if err := verifyLegacyBrowserPartitionRoot(root, inventory.UserData); err != nil {
			return err
		}
		if len(again.Profiles) != 0 {
			if err := remove(root, profile.Name); err != nil {
				return errVaultMigrationSource
			}
		}
		if _, err := root.Lstat(profile.Name); !errors.Is(err, os.ErrNotExist) {
			return vault.ErrAuthentication
		}
		if err := verifyLegacyBrowserPartitionRoot(root, inventory.UserData); err != nil {
			return err
		}
		if syncPrivateFileDirectory(root.Name()) != nil {
			return errVaultMigrationSource
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		journal.Browser.Completed = max(journal.Browser.Completed, i+1)
		journal.Browser.Pending = nil
		*state, err = writeLegacyRetirementJournal(ctx, owner, inventory.WorkspaceID, *journal, state.RowVersion)
		if err != nil {
			return err
		}
	}
	return verifyLegacyBrowserSourcesAbsentWithKey(ctx, inventory, key)
}

func verifyLegacyBrowserSourcesAbsent(ctx context.Context, inventory *legacyBrowserInventory, rootKey []byte) error {
	if inventory == nil {
		return vault.ErrPolicy
	}
	key, err := vault.DeriveKey(rootKey, []byte(inventory.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return err
	}
	defer vault.Wipe(key)
	return verifyLegacyBrowserSourcesAbsentWithKey(ctx, inventory, key)
}

func verifyLegacyBrowserSourcesAbsentWithKey(ctx context.Context, inventory *legacyBrowserInventory, key []byte) error {
	if inventory == nil || validateLegacyBrowserInventory(inventory, inventory.WorkspaceID) != nil {
		return vault.ErrFormat
	}
	current, err := captureLegacyBrowserInventory(ctx, inventory.UserData, inventory.WorkspaceID, key, nil)
	if err != nil {
		return err
	}
	if len(current.Profiles) != 0 {
		return vault.ErrAuthentication
	}
	return nil
}
