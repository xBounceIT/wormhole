package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

var errVaultExtensionFiles = errors.New("vault_extension_files_unavailable")

// The caller supplies its native-owned installation root, never a settings.json
// path. OpenRoot confines later reads even if a filesystem link changes. This is
// a pre-load integrity check, not protection against unlocked same-user malware.
func verifyVaultBitwardenInstallation(ctx context.Context, base *os.Root, value localvault.BitwardenInstallation) error {
	if !value.Enabled {
		return errVaultExtensionFiles
	}
	root, err := openVaultBitwardenPackage(base, value.InstallationID)
	if err != nil {
		return errVaultExtensionFiles
	}
	digest, hashErr := hashVaultExtensionFiles(ctx, root.FS())
	closeErr := root.Close()
	if hashErr != nil || closeErr != nil || digest != value.ContentSHA256 {
		return errVaultExtensionFiles
	}
	return nil
}

// Versioned length-delimited encoding binds names, types, sizes and bytes. The
// legacy directory hash has a different format and cannot authorize this record.
func hashVaultExtensionFiles(ctx context.Context, tree fs.FS) (string, error) {
	if tree == nil || ctx.Err() != nil {
		return "", errVaultExtensionFiles
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/extension-files\x00"))
	names := make(map[string]struct{})
	total := int64(0)
	entries := 0
	manifest := false
	buffer := make([]byte, 64*1024)
	err := fs.WalkDir(boundedExtensionTree{FS: tree, ctx: ctx}, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return errVaultExtensionFiles
		}
		if path == "." {
			if !entry.IsDir() {
				return errVaultExtensionFiles
			}
			return nil
		}
		entries++
		if entries > bitwardenMaxExtractedFiles || len(path) > 1024 || !utf8.ValidString(path) || strings.Count(path, "/") > 32 || strings.ContainsAny(path, "\\:\x00") {
			return errVaultExtensionFiles
		}
		for _, part := range strings.Split(path, "/") {
			if strings.TrimRight(part, " .") != part {
				return errVaultExtensionFiles
			}
		}
		folded := strings.ToLower(path)
		if _, exists := names[folded]; exists {
			return errVaultExtensionFiles
		}
		names[folded] = struct{}{}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errVaultExtensionFiles
		}
		size := info.Size()
		tag := byte('F')
		if info.IsDir() {
			tag = 'D'
			size = 0
		}
		if size < 0 || size > bitwardenMaxExtractedBytes-total {
			return errVaultExtensionFiles
		}
		total += size
		var header [13]byte
		header[0] = tag
		binary.BigEndian.PutUint32(header[1:5], uint32(len(path)))
		binary.BigEndian.PutUint64(header[5:], uint64(size))
		h.Write(header[:])
		h.Write([]byte(path))
		if info.IsDir() {
			return nil
		}
		file, err := tree.Open(path)
		if err != nil {
			return errVaultExtensionFiles
		}
		readErr := streamVaultExtensionFile(ctx, h, file, size, buffer)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errVaultExtensionFiles
		}
		if path == "manifest.json" {
			manifest = true
		}
		return nil
	})
	if err != nil || !manifest {
		return "", errVaultExtensionFiles
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func streamVaultExtensionFile(ctx context.Context, out io.Writer, file fs.File, size int64, buffer []byte) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return errVaultExtensionFiles
	}
	remaining := size
	for remaining > 0 {
		if ctx.Err() != nil {
			return errVaultExtensionFiles
		}
		n, err := io.ReadFull(file, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return errVaultExtensionFiles
		}
		if _, err = out.Write(buffer[:n]); err != nil {
			return errVaultExtensionFiles
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if ctx.Err() != nil || n != 0 || err != io.EOF {
		return errVaultExtensionFiles
	}
	return nil
}

// WalkDir normally reads an entire directory before visiting any entry. Bound
// that allocation too, including a malicious directory containing only files.
type boundedExtensionTree struct {
	fs.FS
	ctx context.Context
}

func (tree boundedExtensionTree) ReadDir(path string) (entries []fs.DirEntry, err error) {
	file, e := tree.Open(path)
	if e != nil {
		return nil, errVaultExtensionFiles
	}
	defer func() {
		if file.Close() != nil {
			entries = nil
			err = errVaultExtensionFiles
		}
	}()
	dir, ok := file.(fs.ReadDirFile)
	if !ok {
		return nil, errVaultExtensionFiles
	}
	for {
		if tree.ctx.Err() != nil {
			return nil, errVaultExtensionFiles
		}
		batch, e := dir.ReadDir(128)
		if len(entries)+len(batch) > bitwardenMaxExtractedFiles {
			return nil, errVaultExtensionFiles
		}
		entries = append(entries, batch...)
		if e == io.EOF {
			break
		}
		if e != nil || len(batch) == 0 {
			return nil, errVaultExtensionFiles
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}
