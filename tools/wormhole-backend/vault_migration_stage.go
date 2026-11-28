package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Native-only progress, not a workspace or an authorization to publish it.
type legacyVaultStage struct {
	Path                                           string
	Credentials, Tunnels, Nodes, Pins, LocalStates int
	OrphanSecrets                                  int
}

// stageLegacyVaultDomains copies the three domains under the source file locks
// and one SQLite writer reservation. It never retires a source or publishes a
// destination. Both journal phases forbid ordinary unlock. Retrying authenticates
// the same source/choices and rebuilds the unpublished stage, including after a
// torn SQLite write. Final source retirement and cutover are subsequent phases.
// The caller owns fresh authentication; key is borrowed, never sent through IPC.
func stageLegacyVaultDomains(ctx context.Context, source, userData string, document vault.SlotFile, key []byte, plan resolver.MigrationPlan) (legacyVaultStage, error) {
	return stageLegacyVaultDomainsOwned(ctx, source, userData, document, key, plan, nil)
}

func stageLegacyVaultDomainsOwned(ctx context.Context, source, userData string, document vault.SlotFile, key []byte, plan resolver.MigrationPlan, ownership *legacyVaultMigrationOwnership) (legacyVaultStage, error) {
	if err := ctx.Err(); err != nil {
		return legacyVaultStage{}, err
	}
	if plan.Validate() != nil || plan.WorkspaceID != document.VaultID || document.Sequence != 1 || document.Initializing || document.Encrypted || document.Migration != nil || len(document.Nodes) != 0 {
		return legacyVaultStage{}, vault.ErrFormat
	}
	// Validate identifiers and slots before constructing a derived filename.
	raw, err := vault.EncodeSlotFile(key, document)
	if err != nil {
		return legacyVaultStage{}, err
	}
	document, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return legacyVaultStage{}, err
	}
	logicalSource := filepath.Clean(source)
	source, info, err := canonicalLegacyVaultSource(source)
	if err != nil {
		return legacyVaultStage{}, err
	}
	releaseSource, err := lockLegacyMigrationSourceOwned(ctx, source, ownership)
	if err != nil {
		return legacyVaultStage{}, err
	}
	defer releaseSource()
	database, err := openLegacyMigrationSource(source)
	if err != nil {
		return legacyVaultStage{}, err
	}
	defer database.Close()
	stage := source + ".migrating-" + document.FileID
	releaseStage, err := lockLegacyMigrationStageOwned(ctx, stage, ownership)
	if err != nil {
		return legacyVaultStage{}, errVaultSlotConflict
	}
	defer releaseStage()
	binding, err := legacyVaultStageBinding(key, document.VaultID, source, logicalSource, plan)
	if err != nil {
		return legacyVaultStage{}, err
	}
	var result legacyVaultStage
	err = withLegacyResolverMigration(ctx, database, document.VaultID, plan, func(reader resolverCaptureReader, _ legacyResolverBaseline) error {
		if err := verifyLegacyMigrationSource(reader, logicalSource, info); err != nil {
			return err
		}
		staged, err := prepareLegacyVaultStage(stage, key, document, binding)
		if err != nil {
			return err
		}
		options := localVaultOptions(staged)
		options.Create, options.AllowImport = true, true
		owner, err := localvault.Open(ctx, stage, options, bytes.Clone(key))
		if err != nil {
			return err
		}
		before, captureErr := captureLegacySourceInventory(reader, logicalSource, userData, document.VaultID, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
		defer vault.Wipe(before)
		if captureErr != nil {
			return errors.Join(captureErr, owner.Close())
		}
		// Keyring account names and Azure import directories bind the original
		// logical path. Canonicalization is for identity/locking, not decryption.
		result, err = copyLegacyVaultDomains(reader, logicalSource, userData, owner, plan)
		if err == nil && filepath.IsAbs(userData) {
			var initial struct {
				Browser *legacyBrowserInventory `json:"browser"`
			}
			if json.Unmarshal(before, &initial) != nil || initial.Browser == nil {
				return errors.Join(vault.ErrAuthentication, owner.Close())
			}
			var copied int
			_, copied, err = copyLegacyBrowserInventory(ctx, filepath.Clean(userData), document.VaultID, key, owner, initial.Browser)
			result.LocalStates += copied
		}
		if err == nil {
			err = persistLegacySourceInventory(reader, logicalSource, userData, document.VaultID, key, before, owner)
		}
		err = errors.Join(err, owner.Close())
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyLegacyMigrationSource(reader, logicalSource, info); err != nil {
			return err
		}
		// Reopen the persisted file; successful writes/readback in the first
		// connection are not sufficient evidence for the cutover checkpoint.
		options.Create = false
		check, err := localvault.Open(ctx, stage, options, bytes.Clone(key))
		if err != nil {
			return err
		}
		inventory, immutable, verifyErr := check.VerifyMigrationIntegrity(ctx)
		if verifyErr == nil {
			verifyErr = verifyLegacySourceInventory(reader, logicalSource, userData, document.VaultID, key, check)
		}
		if err := errors.Join(verifyErr, check.Close()); err != nil {
			return err
		}
		if inventory.Credentials != result.Credentials || inventory.Tunnels != result.Tunnels || inventory.Nodes != result.Nodes || inventory.LocalStates != result.LocalStates+result.OrphanSecrets+1 {
			return vault.ErrAuthentication
		}
		snapshot, err := vaultMigrationDatabaseDigest(ctx, stage, staged, key, true)
		if err != nil {
			return err
		}
		snapshot.ContentAuthentication = immutable

		staged.Sequence++
		staged.Migration = &vault.LocalMigration{Binding: binding, Phase: vault.MigrationDomainsCopied, Snapshot: snapshot}
		if err := writeVaultSlotFile(stage, key, staged, staged.Sequence-1); err != nil {
			return err
		}
		stored, err := readVaultSlotFile(stage)
		if err != nil {
			return err
		}
		return verifyVaultMigrationSnapshot(ctx, stage, stored, key)
	})
	if err != nil {
		return legacyVaultStage{}, err
	}
	result.Path = stage
	return result, nil
}

func canonicalLegacyVaultSource(source string) (string, os.FileInfo, error) {
	canonical, info, err := legacyVaultSourceIdentity(source)
	if err != nil || requireLegacySlotAbsent(source) != nil || requireLegacySlotAbsent(canonical) != nil {
		return "", nil, errVaultMigrationSource
	}
	return canonical, info, nil
}

func legacyVaultSourceIdentity(source string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(source) {
		return "", nil, errVaultMigrationSource
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, errVaultMigrationSource
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(source))
	if err != nil {
		return "", nil, errVaultMigrationSource
	}
	return canonical, info, nil
}

func openLegacyMigrationSource(path string) (*sql.DB, error) {
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	uri.RawQuery = url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(0)", "temp_store(MEMORY)"}}.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, errVaultMigrationSource
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Check the actual attached main file, not just the path supplied alongside an
// unrelated pool. Repeat before completing the copy to reject path replacement.
func verifyLegacyMigrationSource(reader resolverCaptureReader, path string, original os.FileInfo) error {
	if _, _, err := canonicalLegacyVaultSource(path); err != nil {
		return err
	}
	return verifyLegacyMigrationIdentity(reader, path, original)
}

func verifyLegacyMigrationIdentity(reader resolverCaptureReader, path string, original os.FileInfo) error {
	canonical, current, err := legacyVaultSourceIdentity(path)
	if err != nil || !os.SameFile(original, current) {
		return errVaultMigrationSource
	}
	rows, err := reader.Query("PRAGMA database_list;")
	if err != nil {
		return errVaultMigrationSource
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var sequence int
		var name, file string
		if rows.Scan(&sequence, &name, &file) != nil {
			return errVaultMigrationSource
		}
		if name != "main" {
			continue
		}
		bound, info, err := legacyVaultSourceIdentity(file)
		if err != nil || bound != canonical || !os.SameFile(original, info) || found {
			return errVaultMigrationSource
		}
		found = true
	}
	if rows.Err() != nil || !found {
		return errVaultMigrationSource
	}
	return nil
}

func legacyVaultStageBinding(key []byte, workspaceID, source, logicalSource string, plan resolver.MigrationPlan) (string, error) {
	subkey, err := vault.DeriveKey(key, []byte(workspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return "", err
	}
	defer vault.Wipe(subkey)
	// Keep existing bindings byte-compatible for ordinary physical paths.
	if logicalSource == source {
		logicalSource = ""
	}
	body, err := json.Marshal(struct {
		Source        string
		Plan          resolver.MigrationPlan
		LogicalSource string `json:"LogicalSource,omitempty"`
	}{source, plan, logicalSource})
	if err != nil {
		return "", vault.ErrFormat
	}
	defer vault.Wipe(body)
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-migration-source-and-choices\x00"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func prepareLegacyVaultStage(path string, key []byte, document vault.SlotFile, binding string) (vault.SlotFile, error) {
	expected := uint64(0)
	current, err := readVaultSlotFile(path)
	if errors.Is(err, errVaultSlotMissing) {
		// Never adopt or remove an unjournaled file, including SQLite sidecars.
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
				return vault.SlotFile{}, errVaultSlotConflict
			}
		}
	} else if err != nil {
		return vault.SlotFile{}, err
	} else {
		if err := vault.VerifySlotFile(key, current, document.VaultID, document.FileID, 1); err != nil {
			return vault.SlotFile{}, err
		}
		if current.Migration == nil || current.Migration.Phase == vault.MigrationRetiring || current.Migration.Binding != binding || current.RootKeyID != document.RootKeyID || current.RootKeyVersion != document.RootKeyVersion {
			return vault.SlotFile{}, vault.ErrPolicy
		}
		document = current
		expected = current.Sequence
		document.Sequence++
	}
	document = vault.MigrationSlotFile(document, &vault.LocalMigration{Binding: binding, Phase: vault.MigrationCopying})
	// Durable intent precedes any cleanup or import. If write outcome is
	// uncertain, stop; the next invocation must authenticate the on-disk marker.
	if err := writeVaultSlotFile(path, key, document, expected); err != nil {
		return vault.SlotFile{}, err
	}
	if err := removeVaultStaging(path); err != nil {
		return vault.SlotFile{}, err
	}
	return readVaultSlotFile(path)
}

func copyLegacyVaultDomains(reader resolverCaptureReader, source, userData string, owner *localvault.Owner, plan resolver.MigrationPlan) (legacyVaultStage, error) {
	var result legacyVaultStage
	ctx := reader.ctx
	err := visitLegacyVaultCredentials(reader, source, userData, func(record legacyVaultCredential, changes []localvault.SecretChange) error {
		if _, err := owner.ImportCredential(ctx, record.Metadata, record.CreatedAt, changes); err != nil {
			return err
		}
		if _, err := owner.ReadCredential(ctx, record.Metadata.ID, 1); err != nil {
			return err
		}
		for _, change := range changes {
			if err := owner.WithCredentialSecret(ctx, record.Metadata.ID, change.Field, 1, equalLegacyVaultValue(change.Value)); err != nil {
				return err
			}
		}
		result.Credentials++
		return nil
	})
	if err != nil {
		return legacyVaultStage{}, err
	}
	err = visitLegacyVaultTunnels(reader, source, userData, func(record legacyVaultTunnel, configuration []byte) error {
		if _, err := owner.ImportTunnel(ctx, record.Metadata, configuration, record.Times); err != nil {
			return err
		}
		if err := owner.WithTunnelConfiguration(ctx, record.Metadata.ID, 1, equalLegacyVaultValue(configuration)); err != nil {
			return err
		}
		result.Tunnels++
		return nil
	})
	if err != nil {
		return legacyVaultStage{}, err
	}
	err = visitLegacyVaultNodes(reader, userData, func(record legacyVaultNode, changes []localvault.SecretChange) error {
		if _, err := owner.ImportNode(ctx, record.Metadata, changes, record.Times); err != nil {
			return err
		}
		if _, err := owner.ReadNode(ctx, record.Metadata.ID, 1); err != nil {
			return err
		}
		for _, change := range changes {
			if err := owner.WithNodeField(ctx, record.Metadata.ID, change.Field, 1, equalLegacyVaultValue(change.Value)); err != nil {
				return err
			}
		}
		result.Nodes++
		return nil
	})
	if err != nil {
		return legacyVaultStage{}, err
	}
	for start := 0; start < len(plan.Entries); {
		id := plan.Entries[start].Legacy.NodeID
		end := start + 1
		for end < len(plan.Entries) && plan.Entries[end].Legacy.NodeID == id {
			end++
		}
		subset := plan
		subset.Entries = plan.Entries[start:end]
		if _, err := owner.ImportResolverMigration(ctx, id, subset, 1); err != nil {
			return legacyVaultStage{}, err
		}
		if _, err := owner.ReadResolverMigration(ctx, id, 2); err != nil {
			return legacyVaultStage{}, err
		}
		result.Pins += end - start
		start = end
	}
	result.LocalStates, err = copyLegacyVaultLocalState(reader, source, userData, plan.WorkspaceID, owner)
	if err != nil {
		return legacyVaultStage{}, err
	}
	result.OrphanSecrets, err = copyLegacyVaultOrphans(reader, source, userData, owner)
	if err != nil {
		return legacyVaultStage{}, err
	}
	return result, nil
}

func equalLegacyVaultValue(expected []byte) func([]byte) error {
	return func(actual []byte) error {
		if !bytes.Equal(actual, expected) {
			return vault.ErrAuthentication
		}
		return nil
	}
}
