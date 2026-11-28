package updateauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxInstalledBytes = 4 * MaxInstallerBytes

var innoMaintenanceFile = regexp.MustCompile(`(?i)^unins[0-9]{3}\.(exe|dat|msg)$`)

// InventoryInstallation hashes the entire staged tree. Fixed-size frames bind
// each relative name, entry type, size and digest to one unambiguous record.
// Each symlink contributes its literal target and must resolve inside the tree.
func InventoryInstallation(ctx context.Context, directory, tag, target string) (InstallationManifest, error) {
	m := InstallationManifest{FormatVersion: 1, Repository: Repository, ReleaseTag: tag, Target: target}
	if !tagPattern.MatchString(tag) || !installationTargetValid(target) {
		return InstallationManifest{}, ErrManifest
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return InstallationManifest{}, ErrArtifact
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return InstallationManifest{}, ErrArtifact
	}
	defer root.Close()
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		return InstallationManifest{}, ErrArtifact
	}
	var total int64
	buffer := make([]byte, 128*1024)
	tree := sha256.New()
	_, _ = io.WriteString(tree, "wormhole/installed-tree/v1\x00")
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return ErrArtifact
		}
		// Inno generates maintenance files during installation. The native
		// location check still checks their ACLs, and Wormhole never loads them.
		if name == "." || (strings.HasPrefix(target, "windows/") && entry.Type() == 0 && innoMaintenanceFile.MatchString(name)) {
			return nil
		}
		m.Entries++
		if m.Entries > MaxInstallationEntries || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:\x00") {
			return ErrArtifact
		}
		var kind byte
		var size int64
		var sum [sha256.Size]byte
		switch entry.Type() {
		case fs.ModeDir:
			kind = 'D'
		case fs.ModeSymlink:
			kind = 'L'
			relative := filepath.FromSlash(name)
			link, err := root.Readlink(relative)
			if err != nil || len(link) == 0 || len(link) > 4096 || filepath.IsAbs(link) || !utf8.ValidString(link) {
				return ErrArtifact
			}
			resolved, err := root.Stat(relative)
			if err != nil || (!resolved.IsDir() && !resolved.Mode().IsRegular()) {
				return ErrArtifact
			}
			size, sum = int64(len(link)), sha256.Sum256([]byte(link))
		case 0:
			kind = 'F'
			var err error
			size, sum, err = digestInstallationFile(ctx, root, filepath.FromSlash(name), entry, maxInstalledBytes-total, buffer)
			if err != nil {
				return err
			}
			total += size
		default:
			return ErrArtifact
		}
		var frame [13]byte
		frame[0] = kind
		binary.BigEndian.PutUint32(frame[1:], uint32(len(name)))
		binary.BigEndian.PutUint64(frame[5:], uint64(size))
		_, _ = tree.Write(frame[:])
		_, _ = io.WriteString(tree, name)
		_, _ = tree.Write(sum[:])
		return nil
	})
	if err != nil {
		return InstallationManifest{}, err
	}
	if m.Entries == 0 {
		return InstallationManifest{}, ErrArtifact
	}
	if err := ctx.Err(); err != nil {
		return InstallationManifest{}, err
	}
	m.TreeSHA256 = hex.EncodeToString(tree.Sum(nil))
	return m, nil
}

func digestInstallationFile(ctx context.Context, root *os.Root, name string, entry fs.DirEntry, remaining int64, buffer []byte) (int64, [sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	info, err := entry.Info()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > remaining {
		return 0, sum, ErrArtifact
	}
	file, err := root.OpenFile(name, os.O_RDONLY|artifactNonblocking, 0)
	if err != nil {
		return 0, sum, ErrArtifact
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameInstallationFile(info, opened) {
		return 0, sum, ErrArtifact
	}
	digest := sha256.New()
	reader := installationReader{ctx: ctx, reader: io.LimitReader(file, info.Size()+1)}
	n, err := io.CopyBuffer(digest, reader, buffer)
	if err != nil || n != info.Size() {
		if ctx.Err() != nil {
			return 0, sum, ctx.Err()
		}
		return 0, sum, ErrArtifact
	}
	finished, err := file.Stat()
	if err != nil || !sameInstallationFile(info, finished) {
		return 0, sum, ErrArtifact
	}
	copy(sum[:], digest.Sum(nil))
	return n, sum, nil
}

func sameInstallationFile(expected, actual fs.FileInfo) bool {
	return actual.Mode().IsRegular() && os.SameFile(expected, actual) && expected.Size() == actual.Size() && expected.ModTime().Equal(actual.ModTime())
}

type installationReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r installationReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
