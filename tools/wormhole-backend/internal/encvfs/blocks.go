//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bytes"
	"encoding/binary"
	"math"
	"unsafe"

	"lukechampine.com/adiantum"
	"lukechampine.com/adiantum/hbsh"
	"modernc.org/libc"
	sqlite "modernc.org/sqlite/lib"
)

const maxFileSize = math.MaxInt64 &^ (PageSize - 1)

var databaseMagic = []byte("SQLite format 3\x00")

func blockStart(offset int64) int64 {
	return offset &^ (PageSize - 1)
}

func roundedSize(size int64) int64 {
	return blockStart(size + (PageSize - 1))
}

func validRange(address uintptr, length int32, offset int64) bool {
	return length >= 0 && offset >= 0 && offset <= maxFileSize-int64(length) &&
		(length == 0 || address != 0)
}

func (f *databaseFile) scratch() []byte {
	return (*[PageSize]byte)(unsafe.Pointer(f.buffer))[:]
}

func (f *databaseFile) withCipher(use func(*hbsh.HBSH) int32) int32 {
	var result int32
	if err := f.key.With(func(key []byte) error {
		defer clear(f.scratch())
		result = use(adiantum.New(key))
		return nil
	}); err != nil {
		return sqlite.SQLITE_IOERR
	}
	return result
}

func (f *databaseFile) readBlock(tls *libc.TLS, cipher *hbsh.HBSH, offset int64) int32 {
	read := *(*func(*libc.TLS, uintptr, uintptr, int32, int64) int32)(unsafe.Pointer(&f.methods().FxRead))
	if rc := read(tls, f.parent, f.buffer, PageSize, offset); rc != sqlite.SQLITE_OK {
		return rc
	}
	var tweak [8]byte
	binary.LittleEndian.PutUint64(tweak[:], uint64(offset))
	cipher.Decrypt(f.scratch(), tweak[:])
	return sqlite.SQLITE_OK
}

func (f *databaseFile) writeBlock(tls *libc.TLS, cipher *hbsh.HBSH, offset int64) int32 {
	var tweak [8]byte
	binary.LittleEndian.PutUint64(tweak[:], uint64(offset))
	cipher.Encrypt(f.scratch(), tweak[:])
	write := *(*func(*libc.TLS, uintptr, uintptr, int32, int64) int32)(unsafe.Pointer(&f.methods().FxWrite))
	return write(tls, f.parent, f.buffer, PageSize, offset)
}

func readFile(tls *libc.TLS, p, dst uintptr, amount int32, offset int64) int32 {
	if !validRange(dst, amount, offset) {
		return sqlite.SQLITE_IOERR_READ
	}
	if amount == 0 {
		return sqlite.SQLITE_OK
	}
	f := getFile(p)
	data := unsafe.Slice((*byte)(unsafe.Pointer(dst)), int(amount))
	return f.withCipher(func(cipher *hbsh.HBSH) int32 {
		for len(data) > 0 {
			start := blockStart(offset)
			if rc := f.readBlock(tls, cipher, start); rc != sqlite.SQLITE_OK {
				// SQLite requires zero padding for short reads. Never expose
				// an incomplete ciphertext block from a torn trailing write.
				clear(data)
				return rc
			}
			block := f.scratch()
			if f.main && start == 0 && bytes.HasPrefix(block, databaseMagic) &&
				binary.BigEndian.Uint16(block[16:18]) != PageSize {
				clear(data)
				return sqlite.SQLITE_NOTADB
			}
			n := copy(data, block[offset-start:])
			data = data[n:]
			offset += int64(n)
		}
		return sqlite.SQLITE_OK
	})
}

func (f *databaseFile) fillGap(tls *libc.TLS, cipher *hbsh.HBSH, start, end int64) int32 {
	for offset := start; offset < end; offset += PageSize {
		clear(f.scratch())
		if rc := f.writeBlock(tls, cipher, offset); rc != sqlite.SQLITE_OK {
			return rc
		}
	}
	return sqlite.SQLITE_OK
}

// A size hint is advisory. Reserve only initialized files and keep the work
// speculative: a large import must not fill the disk before its first write.
// Normal writes can grow a file past this per-hint limit.
func (f *databaseFile) reserve(tls *libc.TLS, size int64) int32 {
	const maxHintGrowth = 4 << 20
	if f.chunkSize == 0 || size <= 0 || size > maxFileSize {
		return sqlite.SQLITE_OK
	}
	target := size
	if remainder := size % f.chunkSize; remainder != 0 {
		padding := f.chunkSize - remainder
		if size > maxFileSize-padding {
			return sqlite.SQLITE_OK
		}
		target += padding
	}
	return f.withCipher(func(cipher *hbsh.HBSH) int32 {
		current, rc := f.currentSize(tls)
		if rc != sqlite.SQLITE_OK || current == 0 || target <= current || target-current > maxHintGrowth {
			return rc
		}
		return f.fillGap(tls, cipher, current, target)
	})
}

func (f *databaseFile) writeRange(tls *libc.TLS, cipher *hbsh.HBSH, data []byte, offset int64) int32 {
	for len(data) > 0 {
		start := blockStart(offset)
		block := f.scratch()
		if offset != start || len(data) < PageSize {
			switch rc := f.readBlock(tls, cipher, start); rc {
			case sqlite.SQLITE_OK:
			case sqlite.SQLITE_IOERR_SHORT_READ:
				clear(block)
			default:
				return rc
			}
		}
		n := copy(block[offset-start:], data)
		if f.main && start == 0 && (!bytes.HasPrefix(block, databaseMagic) ||
			binary.BigEndian.Uint16(block[16:18]) != PageSize) {
			return sqlite.SQLITE_NOTADB
		}
		if rc := f.writeBlock(tls, cipher, start); rc != sqlite.SQLITE_OK {
			return rc
		}
		offset += int64(n)
		data = data[n:]
	}
	return sqlite.SQLITE_OK
}

func writeFile(tls *libc.TLS, p, src uintptr, amount int32, offset int64) int32 {
	if !validRange(src, amount, offset) {
		return sqlite.SQLITE_IOERR_WRITE
	}
	if amount == 0 {
		return sqlite.SQLITE_OK
	}
	f := getFile(p)
	data := unsafe.Slice((*byte)(unsafe.Pointer(src)), int(amount))
	return f.withCipher(func(cipher *hbsh.HBSH) int32 {
		if start := blockStart(offset); start != 0 {
			size, rc := f.currentSize(tls)
			if rc != sqlite.SQLITE_OK {
				return rc
			}
			if rc := f.fillGap(tls, cipher, size, start); rc != sqlite.SQLITE_OK {
				return rc
			}
		}
		return f.writeRange(tls, cipher, data, offset)
	})
}

func truncateFile(tls *libc.TLS, p uintptr, size int64) int32 {
	f := getFile(p)
	if size < 0 || size > maxFileSize || f.main && size != blockStart(size) {
		return sqlite.SQLITE_IOERR_TRUNCATE
	}
	return f.withCipher(func(cipher *hbsh.HBSH) int32 {
		target := roundedSize(size)
		current, rc := f.currentSize(tls)
		if rc != sqlite.SQLITE_OK {
			return rc
		}
		if rc := f.fillGap(tls, cipher, current, target); rc != sqlite.SQLITE_OK {
			return rc
		}
		// Erase the logical tail before physically retaining the last block.
		if target <= current && size != target {
			var zero [PageSize]byte
			if rc := f.writeRange(tls, cipher, zero[:target-size], size); rc != sqlite.SQLITE_OK {
				return rc
			}
		}
		truncate := *(*func(*libc.TLS, uintptr, int64) int32)(unsafe.Pointer(&f.methods().FxTruncate))
		return truncate(tls, f.parent, target)
	})
}

func (f *databaseFile) currentSize(tls *libc.TLS) (int64, int32) {
	// The int64 after the block is native and naturally aligned. The caller
	// has exclusive use of the scratch allocation while borrowing the key.
	out := f.buffer + PageSize
	if rc := f.size(tls, out); rc != sqlite.SQLITE_OK {
		return 0, rc
	}
	return *(*int64)(unsafe.Pointer(out)), sqlite.SQLITE_OK
}

func (f *databaseFile) size(tls *libc.TLS, out uintptr) int32 {
	size := *(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&f.methods().FxFileSize))
	if rc := size(tls, f.parent, out); rc != sqlite.SQLITE_OK {
		return rc
	}
	value := (*int64)(unsafe.Pointer(out))
	if *value < 0 {
		return sqlite.SQLITE_IOERR_FSTAT
	}
	*value = blockStart(*value)
	return sqlite.SQLITE_OK
}

func sizeFile(tls *libc.TLS, p, out uintptr) int32 {
	return getFile(p).size(tls, out)
}
