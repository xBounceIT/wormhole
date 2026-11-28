//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bytes"
	"path/filepath"
	"testing"
	"unsafe"

	"modernc.org/libc"
	sqlite "modernc.org/sqlite/lib"
)

type diskOperation struct {
	file   string
	kind   string
	offset int64
	data   []byte
}

type diskTrace struct {
	path   string
	delete uintptr
	temp   bool
	ops    []diskOperation
}

type tracedFile struct {
	trace    *diskTrace
	suffix   string
	original uintptr
}

// The power-loss test runs serially, with the tracing callbacks installed
// only while its one connection is open. Production never uses this shim.
var currentDiskTrace *diskTrace
var tracedFiles = map[uintptr]tracedFile{}

func traceNativeDisk(t *testing.T, db *Database) (*diskTrace, func()) {
	t.Helper()
	tls := libc.NewTLS()
	defer tls.Close()
	name, err := libc.CString(Name)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, name)
	address := sqlite.Xsqlite3_vfs_find(tls, name)
	if address == 0 || currentDiskTrace != nil {
		t.Fatal("unexpected VFS tracing state")
	}
	vfs := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(address))
	savedOpen, savedDelete := vfs.FxOpen, vfs.FxDelete
	trace := &diskTrace{path: db.path, delete: savedDelete}
	currentDiskTrace = trace
	vfs.FxOpen, vfs.FxDelete = pointer(traceOpen), pointer(traceDelete)
	restore := func() {
		vfs.FxOpen, vfs.FxDelete = savedOpen, savedDelete
		currentDiskTrace = nil
	}
	t.Cleanup(restore)
	return trace, restore
}

func traceOpen(tls *libc.TLS, vfs, name, out uintptr, flags int32, outFlags uintptr) int32 {
	rc := openFile(tls, vfs, name, out, flags, outFlags)
	if rc != sqlite.SQLITE_OK {
		return rc
	}
	file := getFile(out)
	trace := currentDiskTrace
	if file.db == nil && !trace.temp || file.db != nil && file.db.path != trace.path {
		return rc
	}
	suffix := ""
	if file.db == nil {
		suffix = "temp"
	} else if flags&sqlite.SQLITE_OPEN_MAIN_JOURNAL != 0 {
		suffix = "-journal"
	} else if flags&sqlite.SQLITE_OPEN_WAL != 0 {
		suffix = "-wal"
	}
	p := (*sqlite.Tsqlite3_file)(unsafe.Pointer(file.parent))
	original := p.FpMethods
	methods := *(*sqlite.Tsqlite3_io_methods)(unsafe.Pointer(original))
	address := libc.Xmalloc(tls, uint64(unsafe.Sizeof(methods)))
	if address == 0 {
		closeFile(tls, out)
		return sqlite.SQLITE_NOMEM
	}
	methods.FxClose = pointer(traceClose)
	methods.FxWrite = pointer(traceWrite)
	methods.FxTruncate = pointer(traceTruncate)
	methods.FxSync = pointer(traceSync)
	*(*sqlite.Tsqlite3_io_methods)(unsafe.Pointer(address)) = methods
	tracedFiles[file.parent] = tracedFile{trace: trace, suffix: suffix, original: original}
	p.FpMethods = address
	return rc
}

func (f tracedFile) methods() *sqlite.Tsqlite3_io_methods {
	return (*sqlite.Tsqlite3_io_methods)(unsafe.Pointer(f.original))
}

func traceClose(tls *libc.TLS, p uintptr) int32 {
	f := tracedFiles[p]
	delete(tracedFiles, p)
	file := (*sqlite.Tsqlite3_file)(unsafe.Pointer(p))
	libc.Xfree(tls, file.FpMethods)
	file.FpMethods = f.original
	closeParent := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&f.methods().FxClose))
	return closeParent(tls, p)
}

func traceWrite(tls *libc.TLS, p, src uintptr, amount int32, offset int64) int32 {
	f := tracedFiles[p]
	write := *(*func(*libc.TLS, uintptr, uintptr, int32, int64) int32)(unsafe.Pointer(&f.methods().FxWrite))
	rc := write(tls, p, src, amount, offset)
	if rc == sqlite.SQLITE_OK {
		data := bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(src)), int(amount)))
		f.trace.ops = append(f.trace.ops, diskOperation{file: f.suffix, kind: "write", offset: offset, data: data})
	}
	return rc
}

func traceTruncate(tls *libc.TLS, p uintptr, size int64) int32 {
	f := tracedFiles[p]
	truncate := *(*func(*libc.TLS, uintptr, int64) int32)(unsafe.Pointer(&f.methods().FxTruncate))
	rc := truncate(tls, p, size)
	if rc == sqlite.SQLITE_OK {
		f.trace.ops = append(f.trace.ops, diskOperation{file: f.suffix, kind: "truncate", offset: size})
	}
	return rc
}

func traceSync(tls *libc.TLS, p uintptr, flags int32) int32 {
	f := tracedFiles[p]
	sync := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&f.methods().FxSync))
	rc := sync(tls, p, flags)
	if rc == sqlite.SQLITE_OK {
		f.trace.ops = append(f.trace.ops, diskOperation{file: f.suffix, kind: "sync"})
	}
	return rc
}

func traceDelete(tls *libc.TLS, vfs, name uintptr, syncDir int32) int32 {
	trace := currentDiskTrace
	remove := *(*func(*libc.TLS, uintptr, uintptr, int32) int32)(unsafe.Pointer(&trace.delete))
	rc := remove(tls, vfs, name, syncDir)
	if rc == sqlite.SQLITE_OK {
		path := filepath.Clean(libc.GoString(name))
		for _, suffix := range []string{"-wal", "-journal"} {
			if path == trace.path+suffix {
				trace.ops = append(trace.ops, diskOperation{file: suffix, kind: "delete"})
			}
		}
	}
	return rc
}
