package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Bind destructive operations to one native directory handle, not a pathname
// which another process could redirect after validation.
type legacyPublicationFS struct {
	root      *os.Root
	canonical string
}

func legacyPublicationFilename(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 4096 && utf8.ValidString(name) && !strings.ContainsAny(name, "/\\:") && strings.IndexFunc(name, unicode.IsControl) < 0 && !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ")
}

func openLegacyPublicationFS(directory string) (*legacyPublicationFS, error) {
	root, err := openLegacyBrowserRoot(directory)
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		root.Close()
		return nil, err
	}
	f := &legacyPublicationFS{root: root, canonical: canonical}
	if err := f.verify(); err != nil {
		root.Close()
		return nil, err
	}
	return f, nil
}

func (f *legacyPublicationFS) verify() error {
	if f == nil || f.root == nil {
		return vault.ErrPolicy
	}
	file, err := f.root.Open(".")
	if err != nil {
		return errVaultSlotStorage
	}
	defer file.Close()
	bound, err := file.Stat()
	current, pathErr := os.Lstat(f.root.Name())
	if err != nil || pathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(bound, current) {
		return vault.ErrAuthentication
	}
	if f.canonical != f.root.Name() {
		resolved, err := os.Lstat(f.canonical)
		if err != nil || !resolved.IsDir() || !os.SameFile(bound, resolved) {
			return vault.ErrAuthentication
		}
	}
	return nil
}

func (f *legacyPublicationFS) relative(path string) (string, error) {
	parent := filepath.Dir(path)
	if f == nil || f.root == nil || (parent != f.root.Name() && parent != f.canonical) || !legacyPublicationFilename(filepath.Base(path)) || filepath.Clean(path) != path {
		return "", vault.ErrPolicy
	}
	return filepath.Base(path), nil
}

func borrowLegacyPublicationFS(path string, supplied []*legacyPublicationFS) (*legacyPublicationFS, func(), error) {
	if len(supplied) > 1 {
		return nil, nil, vault.ErrPolicy
	}
	var f *legacyPublicationFS
	var err error
	close := func() {}
	if len(supplied) == 1 {
		f = supplied[0]
	} else {
		f, err = openLegacyPublicationFS(filepath.Dir(path))
		if err != nil {
			return nil, nil, err
		}
		close = func() { _ = f.root.Close() }
	}
	if _, err := f.relative(path); err != nil {
		close()
		return nil, nil, err
	}
	if err := f.verify(); err != nil {
		close()
		return nil, nil, err
	}
	return f, close, nil
}

func (f *legacyPublicationFS) lstat(path string) (os.FileInfo, error) {
	name, err := f.relative(path)
	if err != nil {
		return nil, err
	}
	return f.root.Lstat(name)
}

func (f *legacyPublicationFS) readSlots(path string) (vault.SlotFile, error) {
	raw, err := f.readFile(vaultSlotPath(path), vault.MaxSlotFileBytes)
	if err != nil {
		return vault.SlotFile{}, err
	}
	return vault.DecodeSlotFile(raw)
}

func (f *legacyPublicationFS) writeSlots(path string, raw []byte) error {
	return f.writeFile(vaultSlotPath(path), raw, vault.MaxSlotFileBytes, true)
}

func (f *legacyPublicationFS) readFile(path string, maximum int64) ([]byte, error) {
	if err := f.verify(); err != nil {
		return nil, err
	}
	name, err := f.relative(path)
	if err != nil {
		return nil, err
	}
	before, err := f.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errVaultSlotMissing
	}
	if err != nil || !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, errVaultSlotStorage
	}
	file, err := f.root.Open(name)
	if err != nil {
		return nil, errVaultSlotStorage
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errVaultSlotStorage
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, errVaultSlotStorage
	}
	current, err := f.root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, current) || file.Close() != nil {
		return nil, errVaultSlotStorage
	}
	return raw, nil
}

func (f *legacyPublicationFS) writeFile(path string, raw []byte, maximum int, replace bool) error {
	if len(raw) == 0 || len(raw) > maximum {
		return vault.ErrFormat
	}
	name, err := f.relative(path)
	if err != nil || f.verify() != nil {
		return errVaultSlotStorage
	}
	temporary := ".vault-slot-" + uuid.NewString() + ".tmp"
	file, err := f.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_SYNC, 0600)
	if err != nil {
		return errVaultSlotStorage
	}
	defer file.Close()
	defer f.root.Remove(temporary)
	n, writeErr := file.Write(raw)
	if writeErr != nil || n != len(raw) || file.Sync() != nil || file.Close() != nil {
		return errVaultSlotStorage
	}
	if err := renameLegacyPublicationRootFile(f.root, temporary, name, replace); err != nil {
		return errVaultSlotCommitUncertain
	}
	if err := syncLegacyPublicationRoot(f.root); err != nil || f.verify() != nil {
		return errVaultSlotCommitUncertain
	}
	return nil
}

// EvalSymlinks restores the source's native case while it exists. During the
// intentional missing-source window the durable guard's directory entry keeps
// that spelling, including on Windows when the logical selection used an alias.
func (f *legacyPublicationFS) canonicalSource(logical string) (string, error) {
	if err := f.verify(); err != nil {
		return "", err
	}
	if canonical, _, err := legacyVaultSourceIdentity(logical); err == nil {
		if _, err := f.relative(canonical); err != nil {
			return "", err
		}
		return canonical, nil
	}
	directory, err := f.root.Open(".")
	if err != nil {
		return "", err
	}
	defer directory.Close()
	guardName := filepath.Base(vaultSlotPath(logical))
	selected, count := "", 0
	for {
		page, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return "", err
		}
		count += len(page)
		if count > 32768 {
			return "", vault.ErrFormat
		}
		for _, entry := range page {
			if entry.Name() == guardName || runtime.GOOS == "windows" && strings.EqualFold(entry.Name(), guardName) {
				if selected != "" {
					return "", vault.ErrFormat
				}
				selected = entry.Name()[:len(entry.Name())-6]
			}
		}
		if err == io.EOF {
			break
		}
	}
	if selected == "" {
		selected = filepath.Base(logical)
	}
	canonical := filepath.Join(f.canonical, selected)
	if _, err := f.relative(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}
