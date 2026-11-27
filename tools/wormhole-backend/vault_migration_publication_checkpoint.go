package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Called under source/stage ownership, also on publishing retries. It proves
// current absence, not just a historical cursor. No legacy SQL reader is used
// here: after the move the source pathname holds the new vault schema.
func readLegacyPublicationCheckpoint(ctx context.Context, path, logicalSource, userData, binding string, document vault.SlotFile, key []byte, supplied ...*legacyPublicationFS) (result vault.SlotFile, resultErr error) {
	f, closeRoot, rootErr := borrowLegacyPublicationFS(path, supplied)
	if rootErr != nil {
		return result, rootErr
	}
	defer closeRoot()
	defer func() { resultErr = errors.Join(resultErr, f.verify()) }()
	verifyLogicalParent := func() error {
		actual, err := filepath.EvalSymlinks(filepath.Dir(logicalSource))
		if err != nil || actual != f.root.Name() {
			return vault.ErrAuthentication
		}
		return nil
	}
	if err := verifyLogicalParent(); err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, verifyLogicalParent()) }()
	if document.Migration != nil && document.Migration.Binding != binding {
		return result, vault.ErrAuthentication
	}
	options := localVaultOptions(document)
	options.AllowImport = true
	owner, err := localvault.Open(ctx, path, options, bytes.Clone(key))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, owner.Close()) }()
	inventory, files, keys, err := readLegacyRetirementInventory(ctx, owner, document, logicalSource)
	if err != nil {
		return result, err
	}
	if inventory.Browser == nil || inventory.Browser.UserData != userData {
		return result, vault.ErrAuthentication
	}
	// The authenticated owner was opened with the actual slot document. This
	// private projection supplies only the expected journal binding after cutover.
	journalDocument := document
	journalDocument.Migration = &vault.LocalMigration{Binding: binding}
	_, journal, err := readLegacyRetirementJournal(ctx, owner, journalDocument, len(files), len(keys))
	if journal.Pending != nil {
		vault.Wipe(journal.Pending.Protected)
	}
	if err != nil {
		return result, err
	}
	if journal.Completed != len(files) || journal.KeysCompleted != len(keys) || journal.Pending != nil || journal.PendingKey != nil || journal.Browser == nil || journal.Browser.Pending != nil || journal.Browser.Completed != len(inventory.Browser.Profiles) || journal.SQL == nil || journal.SQL.Phase != "compacted" {
		return result, vault.ErrPolicy
	}
	counts, immutable, err := owner.VerifyMigrationIntegrity(ctx)
	if err != nil {
		return result, err
	}
	if counts != journal.Inventory {
		return result, vault.ErrAuthentication
	}
	for _, file := range files {
		if _, err := os.Lstat(file.path); !errors.Is(err, os.ErrNotExist) {
			return result, vault.ErrAuthentication
		}
	}
	if err := rejectNewLegacyRetirementFiles(resolverCaptureReader{ctx: ctx}, logicalSource, document.VaultID, nil); err != nil {
		return result, err
	}
	if err := verifyLegacySQLKeyAbsence(ctx, keys, openMigrationCredentialStore); err != nil {
		return result, err
	}
	if err := verifyLegacyBrowserSourcesAbsent(ctx, inventory.Browser, key); err != nil {
		return result, err
	}
	result, err = readLegacyMigrationFloors(ctx, owner, document)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if document.Migration != nil {
		expected := document.Migration.Snapshot
		if expected == nil || len(expected.ContentAuthentication) != 32 {
			return vault.SlotFile{}, vault.ErrPolicy
		}
		if !hmac.Equal(immutable, expected.ContentAuthentication) {
			return vault.SlotFile{}, vault.ErrAuthentication
		}
	}
	if len(result.Nodes) != counts.Nodes {
		return vault.SlotFile{}, vault.ErrAuthentication
	}
	return result, nil
}
