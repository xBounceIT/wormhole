package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// This native hint is unauthenticated until a factor opens its slot and the
// complete capsule authenticates. It may guide a protected unlock UI only.
type legacyMigrationSetupHint struct {
	CanonicalSource string
	Document        vault.SlotFile
}

func discoverLegacyMigrationSetup(ctx context.Context, source string) (*legacyMigrationSetupHint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !legacyPublicationFilename(filepath.Base(source)) {
		return nil, vault.ErrFormat
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(source))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errVaultSlotStorage
	}
	f, err := openLegacyPublicationFS(directory)
	if err != nil {
		return nil, err
	}
	defer f.root.Close()
	canonical, err := f.canonicalSource(source)
	if err != nil {
		return nil, err
	}
	entries, err := f.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer entries.Close()
	prefix := filepath.Base(canonical) + ".migrating-"
	var found *legacyMigrationSetupHint
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, readErr := entries.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return nil, errVaultSlotStorage
		}
		count += len(page)
		if count > 32768 {
			return nil, errVaultSlotStorage
		}
		for _, entry := range page {
			name := entry.Name()
			n, p := []rune(name), []rune(prefix)
			matches := strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".setup")
			if runtime.GOOS == "windows" {
				matches = len(n) >= len(p)+6 && strings.EqualFold(string(n[:len(p)]), prefix) && strings.EqualFold(string(n[len(n)-6:]), ".setup")
			}
			if !matches {
				continue
			}
			if found != nil || len(n) != len(p)+36+6 {
				return nil, errVaultSlotConflict
			}
			id := string(n[len(p) : len(n)-6])
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil || parsed.String() != id {
				return nil, errVaultSlotStorage
			}
			document, err := readLegacyMigrationSetupHeader(f, name)
			if err != nil || document.FileID != id {
				return nil, errVaultSlotStorage
			}
			found = &legacyMigrationSetupHint{CanonicalSource: canonical, Document: document}
		}
		if readErr == io.EOF {
			break
		}
	}
	if err := f.verify(); err != nil {
		return nil, err
	}
	return found, nil
}

// Consume only the bounded public prefix. No account-bearing plan is opened or
// decrypted during startup; the complete ciphertext is checked after a factor.
func readLegacyMigrationSetupHeader(f *legacyPublicationFS, name string) (vault.SlotFile, error) {
	info, err := f.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxLegacyMigrationCapsuleBytes {
		return vault.SlotFile{}, errVaultSlotStorage
	}
	file, err := f.root.Open(name)
	if err != nil {
		return vault.SlotFile{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return vault.SlotFile{}, errVaultSlotStorage
	}
	d := json.NewDecoder(io.LimitReader(file, vault.MaxSlotFileBytes+1024))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return vault.SlotFile{}, vault.ErrFormat
	}
	var version, size int
	var raw json.RawMessage
	for _, field := range []struct {
		name string
		out  any
	}{{"version", &version}, {"document", &raw}, {"bytes", &size}} {
		if token, err := d.Token(); err != nil || token != field.name || d.Decode(field.out) != nil {
			return vault.SlotFile{}, vault.ErrFormat
		}
	}
	if token, err := d.Token(); err != nil || token != "chunks" {
		return vault.SlotFile{}, vault.ErrFormat
	}
	if token, err := d.Token(); err != nil || token != json.Delim('[') || version != 1 || size < 1 || size > maxLegacyMigrationSetupBytes {
		return vault.SlotFile{}, vault.ErrFormat
	}
	document, err := vault.DecodeSlotFile(raw)
	current, pathErr := f.root.Lstat(name)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || document.Sequence != 1 || document.Migration == nil || document.Migration.Phase != vault.MigrationCopying {
		return vault.SlotFile{}, vault.ErrFormat
	}
	return document, nil
}
