package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxLegacyMigrationSetupBytes = 32 * 1024 * 1024
const maxLegacyMigrationCapsuleBytes = 48 * 1024 * 1024

// Native-only confirmed setup. The initial slots are duplicated inside the
// encrypted body so a resumed operation cannot silently change its authority.
// Neither paths nor account-bearing resolver snapshots are renderer metadata.
type legacyMigrationSetup struct {
	Version         int                    `json:"version"`
	LogicalSource   string                 `json:"logicalSource"`
	CanonicalSource string                 `json:"canonicalSource"`
	UserData        string                 `json:"userData"`
	Initial         vault.SlotFile         `json:"initial"`
	Plan            resolver.MigrationPlan `json:"plan"`
}

type legacyMigrationCapsule struct {
	Version  int              `json:"version"`
	Document vault.SlotFile   `json:"document"`
	Bytes    int              `json:"bytes"`
	Chunks   []vault.Envelope `json:"chunks"`
}

func legacyMigrationSetupPath(source, fileID string) string {
	return source + ".migrating-" + fileID + ".setup"
}

func validateLegacyMigrationSetup(setup legacyMigrationSetup, key []byte) error {
	if setup.Version != 1 || setup.Plan.Validate() != nil || setup.Plan.WorkspaceID != setup.Initial.VaultID || setup.Initial.Sequence != 1 || setup.Initial.Initializing || setup.Initial.Encrypted || setup.Initial.Migration != nil || len(setup.Initial.Nodes) != 0 {
		return vault.ErrFormat
	}
	for _, path := range []string{setup.LogicalSource, setup.CanonicalSource, setup.UserData} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) || strings.ContainsRune(path, 0) || len(path) > 4096 {
			return vault.ErrFormat
		}
	}
	if !legacyPublicationFilename(filepath.Base(setup.LogicalSource)) || !legacyPublicationFilename(filepath.Base(setup.CanonicalSource)) {
		return vault.ErrFormat
	}
	return vault.VerifySlotFile(key, setup.Initial, setup.Initial.VaultID, setup.Initial.FileID, 1)
}

func legacyMigrationSetupChunkBinding(document vault.SlotFile, size, count, index int) vault.Binding {
	return vault.Binding{WorkspaceID: document.VaultID, Table: "migration-setup-v1", OwnerID: document.FileID,
		Field: document.Migration.Binding + "/" + strconv.Itoa(size) + "/" + strconv.Itoa(count) + "/" + strconv.Itoa(index),
		KeyID: document.RootKeyID, KeyVersion: document.RootKeyVersion}
}

// Caller has already authenticated the legacy owner, confirmed recovery and
// holds source/workspace exclusion. One no-replace atomic file contains public
// password/recovery slots plus the complete encrypted setup, so an interruption
// before the separate staging marker is written remains recoverable.
func saveLegacyMigrationSetup(ctx context.Context, setup legacyMigrationSetup, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateLegacyMigrationSetup(setup, key); err != nil {
		return err
	}
	current, _, err := legacyVaultSourceIdentity(setup.LogicalSource)
	if err != nil || current != setup.CanonicalSource {
		return vault.ErrAuthentication
	}
	f, err := openLegacyPublicationFS(filepath.Dir(setup.CanonicalSource))
	if err != nil {
		return err
	}
	defer f.root.Close()
	plain, err := json.Marshal(setup)
	defer vault.Wipe(plain)
	if err != nil || len(plain) == 0 || len(plain) > maxLegacyMigrationSetupBytes {
		return vault.ErrFormat
	}
	binding, err := legacyVaultStageBinding(key, setup.Initial.VaultID, setup.CanonicalSource, setup.LogicalSource, setup.Plan)
	if err != nil {
		return err
	}
	document := setup.Initial
	document = vault.MigrationSlotFile(document, &vault.LocalMigration{Binding: binding, Phase: vault.MigrationCopying})
	signed, err := vault.EncodeSlotFile(key, document)
	if err != nil {
		return err
	}
	document, err = vault.DecodeSlotFile(signed)
	if err != nil {
		return err
	}
	count := (len(plain) + vault.MaxSecretBytes - 1) / vault.MaxSecretBytes
	capsule := legacyMigrationCapsule{Version: 1, Document: document, Bytes: len(plain), Chunks: make([]vault.Envelope, count)}
	subkey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return err
	}
	defer vault.Wipe(subkey)
	for i := range capsule.Chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := i * vault.MaxSecretBytes
		capsule.Chunks[i], err = vault.Seal(subkey, legacyMigrationSetupChunkBinding(document, capsule.Bytes, count, i), plain[start:min(start+vault.MaxSecretBytes, len(plain))])
		if err != nil {
			return err
		}
	}
	raw, err := json.Marshal(capsule)
	if err != nil || len(raw) > maxLegacyMigrationCapsuleBytes {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.writeFile(legacyMigrationSetupPath(setup.CanonicalSource, document.FileID), raw, maxLegacyMigrationCapsuleBytes, false)
}

func readLegacyMigrationSetup(ctx context.Context, source string, expected vault.SlotFile, key []byte) (legacyMigrationSetup, error) {
	var result legacyMigrationSetup
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := vault.VerifySlotFile(key, expected, expected.VaultID, expected.FileID, 1); err != nil {
		return result, err
	}
	f, err := openLegacyPublicationFS(filepath.Dir(source))
	if err != nil {
		return result, err
	}
	defer f.root.Close()
	raw, err := f.readFile(legacyMigrationSetupPath(source, expected.FileID), maxLegacyMigrationCapsuleBytes)
	if err != nil {
		return result, err
	}
	var capsule legacyMigrationCapsule
	if json.Unmarshal(raw, &capsule) != nil {
		return result, vault.ErrFormat
	}
	canonical, err := json.Marshal(capsule)
	if err != nil || !bytes.Equal(raw, canonical) || capsule.Version != 1 || capsule.Bytes < 1 || capsule.Bytes > maxLegacyMigrationSetupBytes || len(capsule.Chunks) != (capsule.Bytes+vault.MaxSecretBytes-1)/vault.MaxSecretBytes {
		return result, vault.ErrFormat
	}
	document := capsule.Document
	if vault.VerifySlotFile(key, document, expected.VaultID, expected.FileID, 1) != nil || document.Sequence != 1 || document.Migration == nil || document.Migration.Phase != vault.MigrationCopying {
		return result, vault.ErrAuthentication
	}
	subkey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return result, err
	}
	defer vault.Wipe(subkey)
	plain := make([]byte, 0, capsule.Bytes)
	defer func() { vault.Wipe(plain) }()
	for i, chunk := range capsule.Chunks {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		part, err := vault.Open(subkey, legacyMigrationSetupChunkBinding(document, capsule.Bytes, len(capsule.Chunks), i), chunk)
		if err != nil {
			return result, err
		}
		want := min(vault.MaxSecretBytes, capsule.Bytes-i*vault.MaxSecretBytes)
		if len(part) != want {
			vault.Wipe(part)
			return result, vault.ErrFormat
		}
		plain = append(plain, part...)
		vault.Wipe(part)
	}
	if json.Unmarshal(plain, &result) != nil {
		return legacyMigrationSetup{}, vault.ErrFormat
	}
	canonical, err = json.Marshal(result)
	defer vault.Wipe(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || validateLegacyMigrationSetup(result, key) != nil || result.CanonicalSource != source {
		return legacyMigrationSetup{}, vault.ErrAuthentication
	}
	binding, err := legacyVaultStageBinding(key, expected.VaultID, source, result.LogicalSource, result.Plan)
	if err != nil || document.Migration.Binding != binding || !matchingLegacySetupAuthority(key, result.Initial, document, binding) || !matchingLegacySetupAuthority(key, result.Initial, expected, binding) {
		return legacyMigrationSetup{}, vault.ErrAuthentication
	}
	return result, nil
}

func matchingLegacySetupAuthority(key []byte, initial, current vault.SlotFile, binding string) bool {
	if vault.VerifySlotFile(key, current, initial.VaultID, initial.FileID, 1) != nil || current.ProfileSequence < initial.ProfileSequence || current.Migration != nil && current.Migration.Binding != binding {
		return false
	}
	current = vault.MigrationSlotFile(current, nil)
	current.Sequence, current.Authentication = 1, nil
	current.ProfileSequence, current.Nodes = initial.ProfileSequence, initial.Nodes
	initial.Authentication = nil
	a, _ := json.Marshal(initial)
	b, _ := json.Marshal(current)
	return bytes.Equal(a, b)
}
