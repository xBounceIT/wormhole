package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// The existing native adapters use RENAME_NOREPLACE, RENAME_EXCL or MoveFileEx
// without REPLACE_EXISTING. No fallback may replace an existing shared selection.
var publishSharedInitialDirectory = publishVaultExtensionDirectory
var publishSharedInitialFile = publishVaultExtensionDirectory

type sharedInitialFile interface {
	Write([]byte) (int, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
}

var openSharedInitialFile = func(root *os.Root, name string) (sharedInitialFile, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

var removeSharedInitialEntry = func(root *os.Root, name string) error { return root.Remove(name) }

// Ciphertext/public bytes and filesystem identities only. Retain this owner when
// cleanup fails; never recursively erase a directory that may contain new data.
type sharedInitialPublication struct {
	target, stage string
	directory     os.FileInfo
	files         map[string][]byte
	written       map[string][]byte
	identities    map[string]os.FileInfo
	directories   map[string]os.FileInfo
	published     bool
}

func publishSharedInitialBundle(ctx context.Context, o sharedAdmissionOptions, initial sharedJoinStartup, protection sharedStartupProtection) (*sharedInitialPublication, error) {
	if ctx == nil || (initial.FormatVersion != 3 && initial.FormatVersion != 4) || !initial.valid(o.TrustPath) || filepath.Base(o.TrustPath) != "device.trust" {
		return nil, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sealed, err := sealSharedJoinStartupValue(o.TrustPath, initial, protection)
	if err != nil {
		return nil, err
	}
	target := filepath.Dir(o.TrustPath)
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return nil, errSharedTrustConflict
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".wormhole-join-")
	if err != nil {
		return nil, errSharedTrustStorage
	}
	p := &sharedInitialPublication{target: target, stage: stage, files: map[string][]byte{
		"device.trust.join-startup": sealed, "device.trust.device": initial.DeviceFile,
		"device.trust.connection": initial.Transport, "device.trust.enrollment": initial.Pending,
	}, written: map[string][]byte{}, identities: map[string]os.FileInfo{}, directories: map[string]os.FileInfo{}}
	p.directory, err = captureInitialJoinDirectory(stage)
	if err != nil {
		return p, err
	}
	if o.Settings.TLSBundle != nil {
		path, err := sharedTLSCachePath(o.TrustPath, o.Settings.TLSBundle.Pin().Digest)
		if err != nil {
			return p, err
		}
		relative, err := filepath.Rel(target, path)
		if err != nil || filepath.IsAbs(relative) || filepath.Dir(relative) != "device.trust.tls" {
			return p, errSharedTrustStorage
		}
		p.files[relative] = o.Settings.TLSBundle.Encode()
	}
	if err := p.write(ctx); err != nil {
		return p, err
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	if err := privateFileDirectorySync(stage); err != nil {
		return p, errSharedTrustStorage
	}
	if err := p.check(false); err != nil {
		return p, fmt.Errorf("check pending selection before publish: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	moveErr := publishSharedInitialDirectory(stage, target)
	actual, statErr := captureInitialJoinDirectory(target)
	if moveErr != nil {
		if statErr == nil && os.SameFile(actual, p.directory) {
			p.published = true
			return p, errSharedTrustCommitUncertain
		}
		var errno syscall.Errno
		_ = errors.As(moveErr, &errno)
		return p, fmt.Errorf("publish pending selection (errno %d): %w", uint32(errno), errSharedTrustConflict)
	}
	p.published = true
	if statErr != nil || !os.SameFile(actual, p.directory) {
		return p, fmt.Errorf("identify published selection: %w", errSharedTrustConflict)
	}
	if err := p.check(false); err != nil {
		return p, fmt.Errorf("check pending selection after publish: %w", err)
	}
	if err := privateFileDirectorySync(filepath.Dir(target)); err != nil {
		return p, errSharedTrustCommitUncertain
	}
	return p, ctx.Err()
}

func (p *sharedInitialPublication) path() string {
	if p.published {
		return p.target
	}
	return p.stage
}

func (p *sharedInitialPublication) open() (*os.Root, error) {
	if p == nil || p.directory == nil {
		return nil, errSharedTrustStorage
	}
	info, err := captureInitialJoinDirectory(p.path())
	if err != nil || !os.SameFile(info, p.directory) {
		return nil, errSharedTrustConflict
	}
	root, err := os.OpenRoot(p.path())
	if err != nil {
		return nil, errSharedTrustStorage
	}
	f, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, errSharedTrustStorage
	}
	actual, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(actual, p.directory) {
		_ = root.Close()
		return nil, errSharedTrustConflict
	}
	return root, nil
}

func (p *sharedInitialPublication) write(ctx context.Context) error {
	root, err := p.open()
	if err != nil {
		return err
	}
	defer root.Close()
	paths := make([]string, 0, len(p.files))
	for name := range p.files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := filepath.Dir(name)
		if dir != "." && p.directories[dir] == nil {
			if err := root.Mkdir(dir, 0700); err != nil {
				return errSharedTrustStorage
			}
			d, err := root.Open(dir)
			if err != nil {
				return errSharedTrustStorage
			}
			info, statErr := d.Stat()
			closeErr := d.Close()
			if statErr != nil || closeErr != nil || !info.IsDir() {
				return errSharedTrustStorage
			}
			p.directories[dir] = info
		}
		part := filepath.Join(dir, ".stage-"+filepath.Base(name))
		f, err := openSharedInitialFile(root, part)
		if err != nil {
			return errSharedTrustStorage
		}
		info, statErr := f.Stat()
		if statErr != nil {
			_ = f.Close()
			return errSharedTrustStorage
		}
		p.identities[part] = info
		p.written[part] = nil
		n, writeErr := f.Write(p.files[name])
		p.written[part] = p.files[name][:n]
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || n != len(p.files[name]) || syncErr != nil || closeErr != nil {
			return errSharedTrustStorage
		}
		// Flush publication of each filename as well as its data. On Windows the
		// native adapter requests WRITE_THROUGH; Unix uses exclusive rename.
		moveErr := publishSharedInitialFile(filepath.Join(p.stage, part), filepath.Join(p.stage, name))
		if moveErr != nil {
			actual, targetErr := root.Stat(name)
			_, sourceErr := root.Lstat(part)
			if targetErr != nil || !errors.Is(sourceErr, os.ErrNotExist) || !os.SameFile(actual, info) {
				return errSharedTrustStorage
			}
		}
		p.identities[name], p.written[name] = info, p.files[name]
		delete(p.identities, part)
		delete(p.written, part)
		if moveErr != nil {
			return errSharedTrustStorage
		}
	}
	for dir := range p.directories {
		if privateFileDirectorySync(filepath.Join(p.stage, dir)) != nil {
			return errSharedTrustStorage
		}
	}
	return nil
}

func (p *sharedInitialPublication) check(allowMissing bool) error {
	root, err := p.open()
	if err != nil {
		return err
	}
	defer root.Close()
	return p.checkRoot(root, allowMissing)
}

func (p *sharedInitialPublication) checkRoot(root *os.Root, allowMissing bool) error {
	for _, dir := range append([]string{"."}, sortedPublicationDirectories(p.directories)...) {
		f, err := root.Open(dir)
		if errors.Is(err, os.ErrNotExist) && allowMissing && dir != "." {
			continue
		}
		if err != nil {
			return errSharedTrustStorage
		}
		info, statErr := f.Stat()
		entries, readErr := f.ReadDir(len(p.files) + len(p.directories) + 2)
		closeErr := f.Close()
		if statErr != nil || closeErr != nil || !info.IsDir() || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return errSharedTrustStorage
		}
		if dir != "." && !os.SameFile(info, p.directories[dir]) {
			return errSharedTrustConflict
		}
		for _, entry := range entries {
			name := filepath.Join(dir, entry.Name())
			if _, known := p.directories[name]; known {
				if !entry.IsDir() {
					return errSharedTrustConflict
				}
				continue
			}
			if _, known := p.written[name]; !known {
				if !(allowMissing && dir == "." && name == "device.trust.lock") {
					return errSharedTrustConflict
				}
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return errSharedTrustConflict
			}
			file, err := root.Open(name)
			if err != nil {
				return errSharedTrustStorage
			}
			actual, statErr := file.Stat()
			expected := p.written[name]
			var raw []byte
			if statErr == nil && actual.Mode().IsRegular() && actual.Size() == int64(len(expected)) {
				raw, err = io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
			} else {
				err = errSharedTrustConflict
			}
			closeErr := file.Close()
			if err != nil || closeErr != nil || !bytes.Equal(raw, expected) {
				return errSharedTrustConflict
			}
			if identity := p.identities[name]; identity != nil && !os.SameFile(actual, identity) {
				return errSharedTrustConflict
			}
		}
	}
	if !allowMissing {
		for name, expected := range p.files {
			if len(p.written[name]) != len(expected) {
				return errSharedTrustStorage
			}
			if _, err := root.Lstat(name); err != nil {
				return errSharedTrustStorage
			}
		}
	}
	return nil
}

func sortedPublicationDirectories(dirs map[string]os.FileInfo) []string {
	result := make([]string, 0, len(dirs))
	for name := range dirs {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Call for unpublished staging, or only after the coordinator has confirmed
// never-submitted cleanup of the four protected records. Unknown files survive.
func (p *sharedInitialPublication) cleanup() error {
	if p == nil {
		return nil
	}
	if _, err := os.Lstat(p.path()); errors.Is(err, os.ErrNotExist) {
		return privateFileDirectorySync(filepath.Dir(p.path()))
	}
	root, err := p.open()
	if err != nil {
		return err
	}
	if err := p.checkRoot(root, true); err != nil {
		_ = root.Close()
		return err
	}
	for name := range p.written {
		if err := removeSharedInitialEntry(root, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = root.Close()
			return errSharedInvitationPreparationCleanup
		}
	}
	if p.published {
		if err := removeSharedInitialEntry(root, "device.trust.lock"); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = root.Close()
			return errSharedInvitationPreparationCleanup
		}
	}
	for _, dir := range sortedPublicationDirectories(p.directories) {
		if err := removeSharedInitialEntry(root, dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = root.Close()
			return errSharedInvitationPreparationCleanup
		}
	}
	if err := root.Close(); err != nil {
		return errSharedInvitationPreparationCleanup
	}
	actual, err := captureInitialJoinDirectory(p.path())
	if err != nil || !os.SameFile(actual, p.directory) {
		return errSharedTrustConflict
	}
	if err := os.Remove(p.path()); err != nil {
		return errSharedInvitationPreparationCleanup
	}
	return privateFileDirectorySync(filepath.Dir(p.path()))
}
