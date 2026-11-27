//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"testing"
	"unsafe"

	"lukechampine.com/adiantum"
	"modernc.org/libc"
	sqlite "modernc.org/sqlite/lib"
)

func TestSQLiteEncryptedAllocationHints(t *testing.T) {
	path := reserveDB(t, "allocation.sqlite")
	key := bytes.Repeat([]byte{0x37}, 32)
	reg := registerTestDB(t, path, key)
	uri := reg.URI()
	tls := libc.NewTLS()
	defer tls.Close()
	filename, err := libc.CString(uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, filename)
	arg := tls.Alloc(8)
	defer tls.Free(8)
	rc := sqlite.Xsqlite3_open_v2(tls, filename, arg, sqlite.SQLITE_OPEN_URI|sqlite.SQLITE_OPEN_READWRITE, 0)
	conn := *(*uintptr)(unsafe.Pointer(arg))
	defer func() {
		if conn != 0 {
			sqlite.Xsqlite3_close_v2(tls, conn)
		}
	}()
	if rc != sqlite.SQLITE_OK {
		t.Fatalf("open encrypted database: %d", rc)
	}
	chunk := func(size int32) {
		t.Helper()
		*(*int32)(unsafe.Pointer(arg)) = size
		if rc := sqlite.Xsqlite3_file_control(tls, conn, 0, sqlite.SQLITE_FCNTL_CHUNK_SIZE, arg); rc != sqlite.SQLITE_OK {
			t.Fatalf("set chunk size: %d", rc)
		}
	}
	reserve := func(size int64) {
		t.Helper()
		*(*int64)(unsafe.Pointer(arg)) = size
		if rc := sqlite.Xsqlite3_file_control(tls, conn, 0, sqlite.SQLITE_FCNTL_SIZE_HINT, arg); rc != sqlite.SQLITE_OK {
			t.Fatalf("size hint: %d", rc)
		}
	}
	contents := func() []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	chunk(PageSize + 1)
	reserve(3 * PageSize)
	if len(contents()) != 0 {
		t.Fatal("size hint initialized an empty database")
	}
	chunk(0)
	statement, err := libc.CString("PRAGMA locking_mode=EXCLUSIVE; CREATE TABLE item(value); INSERT INTO item VALUES(17)")
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, statement)
	if rc := sqlite.Xsqlite3_exec(tls, conn, statement, 0, 0, 0); rc != sqlite.SQLITE_OK {
		t.Fatalf("initialize encrypted database: %d", rc)
	}
	before := contents()
	if len(before) != 2*PageSize {
		t.Fatalf("unexpected initial size %d", len(before))
	}
	reserve(3 * PageSize)
	if !bytes.Equal(contents(), before) {
		t.Fatal("disabled chunking changed the file")
	}
	chunk(PageSize + 1)
	reserve(int64(len(before)) + 1)
	after := contents()
	if len(after) != 4*PageSize || !bytes.HasPrefix(after, before) {
		t.Fatal("size hint changed existing pages or reserved the wrong size")
	}
	for offset := len(before); offset < len(after); offset += PageSize {
		zeros := make([]byte, PageSize)
		var tweak [8]byte
		binary.LittleEndian.PutUint64(tweak[:], uint64(offset))
		adiantum.New(key).Encrypt(zeros, tweak[:])
		if !bytes.Equal(zeros, after[offset:offset+PageSize]) {
			t.Fatal("preallocation did not write encrypted zeros at their physical offset")
		}
	}
	for _, size := range []int64{-1, 1, int64(len(after)), 1 << 40, maxFileSize, math.MaxInt64} {
		reserve(size)
	}
	if !bytes.Equal(after, contents()) {
		t.Fatal("redundant or excessive hint changed the database")
	}
	if rc := sqlite.Xsqlite3_close_v2(tls, conn); rc != sqlite.SQLITE_OK {
		t.Fatalf("close encrypted database: %d", rc)
	}
	conn = 0
	db := openTestDB(t, reg)
	requireSQL(t, db, "SELECT value FROM item", "17")
	requireSQL(t, db, "PRAGMA integrity_check", "ok")
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode+"-torn-reservation", func(t *testing.T) {
			path := reserveDB(t, "recovered.sqlite")
			// Power was lost after one reserved sector and part of the next.
			if err := os.WriteFile(path, after[:len(before)+PageSize+PageSize/2], 0600); err != nil {
				t.Fatal(err)
			}
			reg := registerTestDB(t, path, key)
			db := openTestDB(t, reg)
			requireSQL(t, db, "PRAGMA journal_mode="+mode, mode)
			requireSQL(t, db, "SELECT value FROM item", "17")
			execSQL(t, db, "INSERT INTO item VALUES(zeroblob(20000))")
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = openTestDB(t, reg)
			requireSQL(t, db, "SELECT count(*) FROM item WHERE value=17 OR length(value)=20000", "2")
			requireSQL(t, db, "PRAGMA integrity_check", "ok")
		})
	}
}

func TestTemporaryFileSparseWritesAndTruncation(t *testing.T) {
	if err := registerVFS(); err != nil {
		t.Fatal(err)
	}
	tls := libc.NewTLS()
	defer tls.Close()
	parent := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(parentVFS))
	p := libc.Xmalloc(tls, uint64(parent.FszOsFile)+parentOffset)
	buffer := libc.Xmalloc(tls, PageSize)
	if p == 0 || buffer == 0 {
		t.Fatal("allocate native test buffers")
	}
	defer libc.Xfree(tls, p)
	defer libc.Xfree(tls, buffer)
	data := (*[PageSize]byte)(unsafe.Pointer(buffer))[:]
	requireCode := func(got, want int32) {
		t.Helper()
		if got != want {
			t.Fatalf("SQLite code %d, want %d", got, want)
		}
	}
	flags := int32(sqlite.SQLITE_OPEN_READWRITE | sqlite.SQLITE_OPEN_CREATE |
		sqlite.SQLITE_OPEN_EXCLUSIVE | sqlite.SQLITE_OPEN_DELETEONCLOSE | sqlite.SQLITE_OPEN_TEMP_DB)
	requireCode(openFile(tls, 0, 0, p, flags|sqlite.SQLITE_OPEN_SUPER_JOURNAL, 0), sqlite.SQLITE_CANTOPEN)
	requireCode(openFile(tls, 0, 0, p, flags, 0), sqlite.SQLITE_OK)
	defer func() { requireCode(closeFile(tls, p), sqlite.SQLITE_OK) }()
	f := getFile(p)
	if f.db != nil || !f.key.Locked() {
		t.Fatal("temporary file lacks an independent locked key")
	}
	requireCode(readFile(tls, p, 0, 0, 0), sqlite.SQLITE_OK)
	requireCode(writeFile(tls, p, 0, 0, 0), sqlite.SQLITE_OK)
	requireCode(readFile(tls, p, buffer, -1, 0), sqlite.SQLITE_IOERR_READ)
	requireCode(writeFile(tls, p, buffer, 1, maxFileSize), sqlite.SQLITE_IOERR_WRITE)
	requireCode(truncateFile(tls, p, -1), sqlite.SQLITE_IOERR_TRUNCATE)
	requireCode(reservedLock(tls, p, buffer), sqlite.SQLITE_OK)
	size := func(want int64) {
		t.Helper()
		requireCode(sizeFile(tls, p, buffer), sqlite.SQLITE_OK)
		if got := *(*int64)(unsafe.Pointer(buffer)); got != want {
			t.Fatalf("logical file size %d, want %d", got, want)
		}
	}

	const marker = "independent-encrypted-temp-data"
	const markerSize = int32(len(marker))
	copy(data, marker)
	const atEnd = 3*PageSize - 5
	requireCode(writeFile(tls, p, buffer, markerSize, atEnd), sqlite.SQLITE_OK)
	size(4 * PageSize)
	requireCode(readFile(tls, p, buffer, PageSize, PageSize), sqlite.SQLITE_OK)
	if !bytes.Equal(data, make([]byte, PageSize)) {
		t.Fatal("gap does not decrypt to zeros")
	}
	requireCode(readFile(tls, p, buffer, markerSize, atEnd), sqlite.SQLITE_OK)
	if string(data[:len(marker)]) != marker {
		t.Fatal("cross-block partial I/O changed data")
	}
	if !bytes.Equal(f.scratch(), make([]byte, PageSize)) {
		t.Fatal("plaintext remained in VFS scratch")
	}
	parentRead := *(*func(*libc.TLS, uintptr, uintptr, int32, int64) int32)(unsafe.Pointer(&f.methods().FxRead))
	requireCode(parentRead(tls, f.parent, buffer, PageSize, 0), sqlite.SQLITE_OK)
	if bytes.Equal(data, make([]byte, PageSize)) {
		t.Fatal("encrypted gap contains raw zeros")
	}
	requireCode(parentRead(tls, f.parent, buffer, PageSize, 3*PageSize), sqlite.SQLITE_OK)
	if bytes.Contains(data, []byte(marker[5:])) {
		t.Fatal("temporary file contains plaintext")
	}

	requireCode(truncateFile(tls, p, atEnd+1), sqlite.SQLITE_OK)
	size(3 * PageSize)
	requireCode(truncateFile(tls, p, 4*PageSize), sqlite.SQLITE_OK)
	size(4 * PageSize)
	requireCode(readFile(tls, p, buffer, markerSize, atEnd), sqlite.SQLITE_OK)
	if data[0] != marker[0] || !bytes.Equal(data[1:len(marker)], make([]byte, len(marker)-1)) {
		t.Fatal("truncate followed by growth resurrected discarded bytes")
	}
	copy(data, marker)
	requireCode(readFile(tls, p, buffer, markerSize, 4*PageSize), sqlite.SQLITE_IOERR_SHORT_READ)
	if !bytes.Equal(data[:len(marker)], make([]byte, len(marker))) {
		t.Fatal("short read did not zero its output")
	}
}

func FuzzBlockRanges(f *testing.F) {
	f.Add(int64(0), int32(0), false)
	f.Add(int64(PageSize-1), int32(2), true)
	f.Add(int64(maxFileSize-1), int32(1), true)
	f.Add(int64(maxFileSize), int32(1), true)
	f.Add(int64(-1), int32(1), true)
	f.Add(int64(0), int32(-1), true)
	f.Fuzz(func(t *testing.T, offset int64, amount int32, hasBuffer bool) {
		var address uintptr
		if hasBuffer {
			address = 1
		}
		end := uint64(offset) + uint64(amount)
		want := offset >= 0 && amount >= 0 && end <= uint64(maxFileSize) && (hasBuffer || amount == 0)
		if validRange(address, amount, offset) != want {
			t.Fatalf("range validation disagrees at offset %d, amount %d, buffer %t", offset, amount, hasBuffer)
		}
		if want {
			first, last := blockStart(offset), roundedSize(int64(end))
			if first < 0 || first > offset || offset-first >= PageSize ||
				last < int64(end) || last-int64(end) >= PageSize || last > maxFileSize ||
				first%PageSize != 0 || last%PageSize != 0 {
				t.Fatalf("invalid block bounds %d..%d for range %d..%d", first, last, offset, end)
			}
		}
	})
}
