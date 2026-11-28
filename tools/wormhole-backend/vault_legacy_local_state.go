package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type legacyLocalStateReaders struct {
	secret  legacyVaultSecretReader
	file    func(string, []byte) ([]byte, error)
	browser func(string, []byte) ([]byte, error)
}

type legacyLocalStateFile struct {
	path, kind, scope string
	maximum           int64
	browser, required bool
}

type legacyLocalStateDirectory struct {
	path, kind, suffix string
	maximum            int64
}

func legacyLocalStateFiles(source, workspace string) []legacyLocalStateFile {
	return []legacyLocalStateFile{
		{bitwardenSessionPath(source), "bitwarden-cli", workspace, 64 * 1024, false, false},
		{bitwardenBrowserStoragePath(source), "bitwarden-browser", workspace, bitwardenBrowserStorageMaxProtected, true, false},
		{bitwardenBrowserStoragePath(source) + ".bak", "bitwarden-browser-backup", workspace, bitwardenBrowserStorageMaxProtected, true, false},
	}
}

func legacyLocalStateDirectories(source, workspace string) []legacyLocalStateDirectory {
	root := filepath.Dir(source)
	return []legacyLocalStateDirectory{
		{filepath.Join(root, "azure-token-cache"), "azure-refresh", ".token", azureTokenMaxBytes + 65536},
		{filepath.Join(root, "azurevpn-cache"), "azure-legacy", ".tokencache", azureTokenMaxBytes + 65536},
		{filepath.Join(root, "electron-watchguard-cache"), "watchguard-cache", ".ovpncache", watchguardCacheMaxBytes + 65536},
		{filepath.Join(root, "watchguard-cache"), "watchguard-legacy", ".ovpncache", watchguardCacheMaxBytes + 65536},
		{filepath.Join(root, "electron-stormshield-cache"), "stormshield-cache", ".ovpncache", stormshieldCacheMaxBytes + 65536},
		{filepath.Join(root, "stormshield-cache"), "stormshield-legacy", ".ovpncache", stormshieldCacheMaxBytes + 65536},
		{filepath.Dir(azureImportKeyPath(source, workspace)), "azure-import", ".dpapi", 64 * 1024},
	}
}

// Native archive transfer preserves exact payloads, including expired/older
// provider formats and a distinct Bitwarden recovery copy. Consumers validate
// their format/expiry before use. Nothing here selects a fallback or retires a
// source. The coordinator supplies its reserved reader and authenticated stage.
func copyLegacyVaultLocalState(reader resolverCaptureReader, source, userData, workspace string, owner *localvault.Owner) (int, error) {
	count := 0
	readers := legacyLocalStateReaders{
		secret: migrationSecretReader(reader.ctx, maxStoredCredentialBytes),
		file:   unprotectFileContents, browser: unprotectBitwardenBrowserStorageContents,
	}
	err := readLegacyVaultLocalState(reader, source, userData, workspace, readers, func(kind, scope string, value []byte) error {
		if _, err := owner.PutLocalState(reader.ctx, kind, scope, value, 0); err != nil {
			return err
		}
		if err := owner.WithLocalState(reader.ctx, kind, scope, 1, equalLegacyVaultValue(value)); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func readLegacyVaultLocalState(reader resolverCaptureReader, source, userData, workspace string, readers legacyLocalStateReaders, visit func(string, string, []byte) error) error {
	id, err := uuid.Parse(workspace)
	if err != nil || id == uuid.Nil || id.String() != workspace || !filepath.IsAbs(source) || readers.secret == nil || readers.file == nil || readers.browser == nil || visit == nil {
		return errVaultMigrationSource
	}
	hasSecrets, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return err
	}
	if hasSecrets {
		encoded, encoding, present, err := readLegacyVaultSecretRow(reader, mcpTokenCredentialID)
		if err != nil {
			return err
		}
		if present {
			if err := borrowLegacyLocalToken(reader, encoded, encoding, userData, workspace, readers.secret, visit); err != nil {
				return err
			}
		}
	}
	for _, file := range legacyLocalStateFiles(source, workspace) {
		if err := borrowLegacyLocalFile(reader, file, readers, visit); err != nil {
			return err
		}
	}
	for _, directory := range legacyLocalStateDirectories(source, workspace) {
		err := visitLegacyLocalDirectory(reader, directory.path, directory.suffix, func(path, scope string) error {
			return borrowLegacyLocalFile(reader, legacyLocalStateFile{path, directory.kind, scope, directory.maximum, false, true}, readers, visit)
		})
		if err != nil {
			return err
		}
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}

func borrowLegacyLocalToken(reader resolverCaptureReader, encoded, encoding, userData, workspace string, decrypt legacyVaultSecretReader, visit func(string, string, []byte) error) error {
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	value, err := decrypt(mcpTokenCredentialID, encoded, encoding, userData)
	defer vault.Wipe(value)
	if err != nil || len(value) > maxStoredCredentialBytes || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return visit("mcp-token", workspace, value)
}

func borrowLegacyLocalFile(reader resolverCaptureReader, file legacyLocalStateFile, readers legacyLocalStateReaders, visit func(string, string, []byte) error) error {
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	protected, err := readBoundedRegularFile(file.path, file.maximum)
	defer vault.Wipe(protected)
	if errors.Is(err, os.ErrNotExist) && !file.required {
		return nil
	}
	if err != nil || len(protected) == 0 || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	decrypt := readers.file
	if file.browser {
		decrypt = readers.browser
	}
	value, err := decrypt(file.path, protected)
	defer vault.Wipe(value)
	if err != nil || len(value) > vaultstore.MaxLocalStateBytes || int64(len(value)) > file.maximum || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return visit(file.kind, file.scope, value)
}

func visitLegacyLocalDirectory(reader resolverCaptureReader, path, suffix string, visit func(string, string) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return errVaultMigrationSource
	}
	directory, err := os.Open(path)
	if err != nil {
		return errVaultMigrationSource
	}
	defer directory.Close()
	for {
		if reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return errVaultMigrationSource
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), suffix) {
				continue
			}
			compact := strings.TrimSuffix(entry.Name(), suffix)
			id, parseErr := uuid.Parse(compact)
			if parseErr != nil || id == uuid.Nil || strings.ReplaceAll(id.String(), "-", "") != compact || !entry.Type().IsRegular() {
				return errVaultMigrationSource
			}
			if err := visit(filepath.Join(path, entry.Name()), id.String()); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}
