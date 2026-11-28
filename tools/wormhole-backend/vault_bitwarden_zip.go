package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"strings"
	"unicode/utf8"
)

const vaultExtensionZipDirectoryLimit = 32 << 20

// Freeze the central directory before the standard parser allocates entries.
// Payload bytes are streamed and CRC/digest checked, never trusted as metadata.
type vaultExtensionZipSnapshot struct {
	source io.ReaderAt
	offset int64
	tail   []byte
}

func (s vaultExtensionZipSnapshot) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errVaultExtensionFiles
	}
	if off >= s.offset {
		return bytes.NewReader(s.tail).ReadAt(p, off-s.offset)
	}
	prefix := min(int64(len(p)), s.offset-off)
	n, err := s.source.ReadAt(p[:prefix], off)
	if err != nil || n != int(prefix) {
		return n, err
	}
	if n == len(p) {
		return n, nil
	}
	m, err := bytes.NewReader(s.tail).ReadAt(p[n:], 0)
	return n + m, err
}

func readVaultExtensionZip(ctx context.Context, source io.ReaderAt, size int64) (*zip.Reader, error) {
	if source == nil || size < 22 || size > bitwardenMaxExtractedBytes || ctx.Err() != nil {
		return nil, errVaultExtensionFiles
	}
	bounded := io.NewSectionReader(source, 0, size)
	tail := make([]byte, min(size, 22+65535))
	if _, err := bounded.ReadAt(tail, size-int64(len(tail))); err != nil {
		return nil, errVaultExtensionFiles
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, errVaultExtensionFiles
	}
	e := tail[end:]
	count := binary.LittleEndian.Uint16(e[10:])
	length := int64(binary.LittleEndian.Uint32(e[12:]))
	offset := int64(binary.LittleEndian.Uint32(e[16:]))
	endOffset := size - int64(len(tail)) + int64(end)
	// Multi-disk and ZIP64 metadata are unnecessary for bounded extension packages.
	if binary.LittleEndian.Uint16(e[4:]) != 0 || binary.LittleEndian.Uint16(e[6:]) != 0 || count == 0 || count == 65535 || binary.LittleEndian.Uint16(e[8:]) != count || length > vaultExtensionZipDirectoryLimit || length < int64(count)*46 || offset+length != endOffset {
		return nil, errVaultExtensionFiles
	}
	frozen := make([]byte, size-offset)
	if _, err := bounded.ReadAt(frozen, offset); err != nil || !bytes.Equal(frozen[length:], e) {
		return nil, errVaultExtensionFiles
	}
	position := int64(0)
	for i := 0; i < int(count); i++ {
		if ctx.Err() != nil || length-position < 46 {
			return nil, errVaultExtensionFiles
		}
		h := frozen[position : position+46]
		if binary.LittleEndian.Uint32(h) != 0x02014b50 || binary.LittleEndian.Uint32(h[20:]) == 0xffffffff || binary.LittleEndian.Uint32(h[24:]) == 0xffffffff || binary.LittleEndian.Uint32(h[42:]) == 0xffffffff || binary.LittleEndian.Uint16(h[34:]) != 0 {
			return nil, errVaultExtensionFiles
		}
		position += 46 + int64(binary.LittleEndian.Uint16(h[28:])) + int64(binary.LittleEndian.Uint16(h[30:])) + int64(binary.LittleEndian.Uint16(h[32:]))
		if position > length {
			return nil, errVaultExtensionFiles
		}
	}
	if position != length {
		return nil, errVaultExtensionFiles
	}
	reader, err := zip.NewReader(vaultExtensionZipSnapshot{bounded, offset, frozen}, size)
	if err != nil || len(reader.File) != int(count) {
		return nil, errVaultExtensionFiles
	}
	names := make(map[string]bool)
	var total uint64
	for _, entry := range reader.File {
		name := strings.TrimSuffix(entry.Name, "/")
		mode := entry.Mode()
		if ctx.Err() != nil || !fs.ValidPath(name) || name == "." || !utf8.ValidString(name) || len(name) > 1024 || strings.Count(name, "/") > 32 || strings.Contains(name, "\\") || unsafePortableZipPath(name) || names[strings.ToLower(name)] || (mode&os.ModeType != 0 && !mode.IsDir()) || entry.Flags&0x41 != 0 || (entry.Method != zip.Store && entry.Method != zip.Deflate) || entry.UncompressedSize64 > uint64(bitwardenMaxExtractedBytes)-total {
			return nil, errVaultExtensionFiles
		}
		if mode.IsDir() && entry.UncompressedSize64 != 0 {
			return nil, errVaultExtensionFiles
		}
		names[strings.ToLower(name)] = true
		total += entry.UncompressedSize64
	}
	return reader, nil
}

func installVaultBitwardenZip(ctx context.Context, owner vaultBitwardenInstallerOwner, base *os.Root, source io.ReaderAt, size int64, expected uint64) (uint64, error) {
	archive, err := readVaultExtensionZip(ctx, source, size)
	if err != nil {
		return 0, err
	}
	return installVaultBitwardenTree(ctx, owner, base, archive, expected)
}

func installVaultBitwardenZipFile(ctx context.Context, owner vaultBitwardenInstallerOwner, base *os.Root, path string, expected uint64) (uint64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0, errVaultExtensionFiles
	}
	source, err := os.Open(path)
	if err != nil {
		return 0, errVaultExtensionFiles
	}
	defer source.Close()
	info, err = source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, errVaultExtensionFiles
	}
	return installVaultBitwardenZip(ctx, owner, base, source, info.Size(), expected)
}
