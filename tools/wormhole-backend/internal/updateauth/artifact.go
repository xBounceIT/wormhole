package updateauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

var ErrArtifact = errors.New("update installer is invalid")

// Digest opens a regular flat artifact within root. Recheck the file handle
// rather than relying on the directory entry's size or a sidecar checksum.
func Digest(root *os.Root, name string) (int64, string, error) {
	f, err := OpenArtifact(root, name)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	return DigestFile(f)
}

// OpenArtifact allows the digest and publisher checks to share one handle.
func OpenArtifact(root *os.Root, name string) (*os.File, error) {
	if strings.ContainsAny(name, ":/\\\x00") {
		return nil, ErrArtifact
	}
	entry, err := root.Lstat(name)
	if err != nil || !entry.Mode().IsRegular() {
		return nil, ErrArtifact
	}
	f, err := root.OpenFile(name, os.O_RDONLY|artifactNonblocking, 0)
	if err != nil {
		return nil, ErrArtifact
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(entry, info) {
		_ = f.Close()
		return nil, ErrArtifact
	}
	return f, nil
}

// DigestFile checks and reads a bounded file from its start.
func DigestFile(f *os.File) (int64, string, error) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxInstallerBytes {
		return 0, "", ErrArtifact
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", ErrArtifact
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, info.Size()+1))
	if err != nil || n != info.Size() {
		return 0, "", ErrArtifact
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}
