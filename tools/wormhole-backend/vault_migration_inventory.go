package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const migrationSourceInventoryKind = "migration-source-inventory"
const maxMigrationInventoryBytes = vaultstore.MaxLocalStateBytes / 2

// This inventory is encrypted inside the unpublished vault, never in public
// slot metadata or renderer DTOs. It identifies exact sources, not permission
// to delete them. The retirement journal must still precede every deletion.
type legacySourceInventory struct {
	Version     int                     `json:"version"`
	WorkspaceID string                  `json:"workspaceId"`
	Source      string                  `json:"source"`
	DatabaseMAC []byte                  `json:"databaseMac"`
	Files       []legacyInventoryFile   `json:"files"`
	Secrets     []legacyInventoryRow    `json:"secrets"`
	Browser     *legacyBrowserInventory `json:"browser,omitempty"`
}

// Kind and scope identify a native allowlisted path, not an arbitrary pathname
// supplied by a future deletion caller. A keyed digest avoids exposing a hash
// of a low-entropy secret even inside the native archive.
type legacyInventoryFile struct {
	Kind           string `json:"kind"`
	ScopeID        string `json:"scopeId"`
	Bytes          int    `json:"bytes"`
	Authentication []byte `json:"authentication"`
}
type legacyInventoryRow struct {
	ID             string  `json:"id"`
	Encoding       string  `json:"encoding"`
	Reference      string  `json:"reference,omitempty"`
	UpdatedAt      *string `json:"updatedAt"`
	Authentication []byte  `json:"authentication"`
}

func captureLegacySourceInventory(reader resolverCaptureReader, source, userData, workspace string, key []byte, decrypt legacyVaultSecretReader) ([]byte, error) {
	id, err := uuid.Parse(workspace)
	if err != nil || id == uuid.Nil || id.String() != workspace || !filepath.IsAbs(source) || !utf8.ValidString(source) || decrypt == nil || reader.ctx.Err() != nil {
		return nil, errVaultMigrationSource
	}
	subkey, err := vault.DeriveKey(key, []byte(workspace), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	databaseMAC, err := captureLegacyDatabaseState(reader, subkey)
	if err != nil {
		return nil, err
	}
	result := legacySourceInventory{Version: 2, WorkspaceID: workspace, Source: filepath.Clean(source), DatabaseMAC: databaseMAC, Files: []legacyInventoryFile{}, Secrets: []legacyInventoryRow{}}
	remaining := maxMigrationInventoryBytes - len(source)*6 - 1024
	charge := func(value any) error {
		raw, err := json.Marshal(value)
		if err != nil || len(raw)+1 > remaining {
			return errVaultMigrationSource
		}
		remaining -= len(raw) + 1
		return nil
	}
	addFile := func(spec legacyLocalStateFile) error {
		contents, err := readLegacyInventoryFile(spec.path, spec.maximum)
		defer vault.Wipe(contents)
		if errors.Is(err, os.ErrNotExist) && !spec.required {
			return nil
		}
		if err != nil || reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		entry := legacyInventoryFile{Kind: spec.kind, ScopeID: spec.scope, Bytes: len(contents)}
		entry.Authentication, err = legacyInventoryMAC(subkey, result.Source, entry, contents)
		if err != nil {
			return err
		}
		if err := charge(entry); err != nil {
			return err
		}
		result.Files = append(result.Files, entry)
		return nil
	}
	for _, file := range legacyLocalStateFiles(source, workspace) {
		if err := addFile(file); err != nil {
			return nil, err
		}
	}
	for _, directory := range legacyInventoryDirectories(source, workspace) {
		if err := visitLegacyLocalDirectory(reader, directory.path, directory.suffix, func(path, scope string) error {
			return addFile(legacyLocalStateFile{path: path, kind: directory.kind, scope: scope, maximum: directory.maximum, required: true})
		}); err != nil {
			return nil, err
		}
	}
	sort.Slice(result.Files, func(i, j int) bool {
		a, b := result.Files[i], result.Files[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ScopeID < b.ScopeID
	})
	hasSecrets, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return nil, err
	}
	if hasSecrets {
		after := ""
		for {
			page, err := readLegacyOrphanPage(reader, after)
			if err != nil {
				return nil, err
			}
			for _, row := range page[:min(len(page), 64)] {
				entry, err := captureLegacyInventoryRow(reader, result.Source, userData, subkey, row, decrypt)
				if err != nil {
					return nil, err
				}
				if err := charge(entry); err != nil {
					return nil, err
				}
				result.Secrets = append(result.Secrets, entry)
				after = strings.ToLower(row.Source)
			}
			if len(page) <= 64 {
				break
			}
		}
	}
	// A missing native user-data path is not a browser retirement proof. Older
	// native-only imports remain readable; the eventual app cutover requires an
	// explicit browser inventory from its absolute main-owned user-data path.
	if filepath.IsAbs(userData) {
		result.Browser, err = captureLegacyBrowserInventory(reader.ctx, filepath.Clean(userData), workspace, subkey, nil)
		if err != nil {
			return nil, err
		}
	}
	if reader.ctx.Err() != nil {
		return nil, errVaultMigrationSource
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > maxMigrationInventoryBytes {
		vault.Wipe(raw)
		return nil, errVaultMigrationSource
	}
	return raw, nil
}

func legacyInventoryDirectories(source, workspace string) []legacyLocalStateDirectory {
	return append(legacyLocalStateDirectories(source, workspace),
		legacyLocalStateDirectory{filepath.Dir(credentialPrivateKeyPath(source, mcpTokenCredentialID)), "credential-private-key", ".dpapi", maxProtectedSshKeyBytes},
		legacyLocalStateDirectory{filepath.Dir(legacyTunnelSecretPath(source, mcpTokenCredentialID)), "tunnel-file", ".dpapi", maxTunnelProtectedBytes})
}

func captureLegacyInventoryRow(reader resolverCaptureReader, source, userData string, key []byte, row legacyVaultOrphan, decrypt legacyVaultSecretReader) (legacyInventoryRow, error) {
	kind, _ := legacyOrphanRowIdentity(row.Source)
	maximum, encodedMaximum := maxStoredCredentialBytes, 128*1024
	if kind == "legacy-tunnel-row" {
		maximum, encodedMaximum = backendMaxTunnelRequestBytes, 6*1024*1024
	}
	encoded, encoding, present, err := readLegacyVaultSecretRowMatch(reader, row.Source, encodedMaximum, true)
	if err != nil || !present || reader.ctx.Err() != nil {
		return legacyInventoryRow{}, errVaultMigrationSource
	}
	entry := legacyInventoryRow{ID: row.Source, Encoding: encoding, UpdatedAt: row.UpdatedAt}
	switch strings.TrimSpace(encoding) {
	case linuxLegacySecretServiceEncoding, linuxSecretServiceEncoding, darwinKeychainEncoding:
		if _, err := credentialSecretAccount(strings.ToLower(row.Source), encoded); err != nil {
			return legacyInventoryRow{}, errVaultMigrationSource
		}
		entry.Reference = encoded
	}
	value, err := decrypt(strings.ToLower(row.Source), encoded, encoding, userData)
	defer vault.Wipe(value)
	if err != nil || len(value) > maximum || reader.ctx.Err() != nil {
		return legacyInventoryRow{}, errVaultMigrationSource
	}
	protected := []byte(encoded)
	defer vault.Wipe(protected)
	entry.Authentication, err = legacyInventoryMAC(key, source, entry, protected, value)
	return entry, err
}

func legacyInventoryMAC(key []byte, source string, metadata any, contents ...[]byte) ([]byte, error) {
	header, err := json.Marshal(struct {
		Source   string
		Metadata any
	}{source, metadata})
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer vault.Wipe(header)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("wormhole/v1/migration-source-artifact\x00"))
	var size [8]byte
	for _, part := range append([][]byte{header}, contents...) {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		mac.Write(size[:])
		mac.Write(part)
	}
	return mac.Sum(nil), nil
}

// Inventory reads bind both path and opened file identity. An optional missing
// artifact is distinct from a dangling link, replacement or changing contents.
func readLegacyInventoryFile(path string, maximum int64) (result []byte, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errVaultMigrationSource
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errVaultMigrationSource
	}
	result, err = io.ReadAll(io.LimitReader(file, maximum+1))
	defer func() {
		if err != nil {
			vault.Wipe(result)
			result = nil
		}
	}()
	if err != nil {
		return result, errVaultMigrationSource
	}
	end, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || int64(len(result)) != info.Size() || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return result, errVaultMigrationSource
	}
	if err := file.Close(); err != nil {
		return result, errVaultMigrationSource
	}
	return result, nil
}

func persistLegacySourceInventory(reader resolverCaptureReader, source, userData, workspace string, key, before []byte, owner *localvault.Owner) error {
	after, err := captureLegacySourceInventory(reader, source, userData, workspace, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	defer vault.Wipe(after)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return errVaultMigrationSource
	}
	if _, err := owner.PutLocalState(reader.ctx, migrationSourceInventoryKind, workspace, after, 0); err != nil {
		return err
	}
	return owner.WithLocalState(reader.ctx, migrationSourceInventoryKind, workspace, 1, equalLegacyVaultValue(after))
}

// Compare the complete encrypted checkpoint with a fresh capture while source
// ownership and its reserved transaction are held. Version-one inventories lack
// the database commitment and deliberately require restaging. This verification
// does not authorize deletion; a durable retirement journal must precede that.
func verifyLegacySourceInventory(reader resolverCaptureReader, source, userData, workspace string, key []byte, owner *localvault.Owner) error {
	current, err := captureLegacySourceInventory(reader, source, userData, workspace, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	defer vault.Wipe(current)
	if err != nil {
		return err
	}
	return owner.WithLocalState(reader.ctx, migrationSourceInventoryKind, workspace, 1, equalLegacyVaultValue(current))
}
