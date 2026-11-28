//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"crypto/rand"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"modernc.org/libc"
	sqlite "modernc.org/sqlite/lib"
)

// These layouts are part of the pinned modernc.org/sqlite and libc ABI.
// The padding preserves the parent file struct's alignment.
const parentOffset = 16

var (
	_ [8]byte   = [unsafe.Sizeof(sqlite.Tsqlite3_file{})]byte{}
	_ [0]byte   = [unsafe.Offsetof(sqlite.Tsqlite3_file{}.FpMethods)]byte{}
	_ [152]byte = [unsafe.Sizeof(sqlite.Tsqlite3_io_methods{})]byte{}
	_ [0]byte   = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FiVersion)]byte{}
	_ [8]byte   = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxClose)]byte{}
	_ [16]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxRead)]byte{}
	_ [24]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxWrite)]byte{}
	_ [32]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxTruncate)]byte{}
	_ [40]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxSync)]byte{}
	_ [48]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxFileSize)]byte{}
	_ [56]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxLock)]byte{}
	_ [64]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxUnlock)]byte{}
	_ [72]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxCheckReservedLock)]byte{}
	_ [80]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxFileControl)]byte{}
	_ [88]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxSectorSize)]byte{}
	_ [96]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxDeviceCharacteristics)]byte{}
	_ [144]byte = [unsafe.Offsetof(sqlite.Tsqlite3_io_methods{}.FxUnfetch)]byte{}

	_ [168]byte = [unsafe.Sizeof(sqlite.Tsqlite3_vfs{})]byte{}
	_ [4]byte   = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FszOsFile)]byte{}
	_ [8]byte   = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FmxPathname)]byte{}
	_ [16]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FpNext)]byte{}
	_ [24]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FzName)]byte{}
	_ [40]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FxOpen)]byte{}
	_ [64]byte  = [unsafe.Offsetof(sqlite.Tsqlite3_vfs{}.FxFullPathname)]byte{}
)

var (
	registerVFS = sync.OnceValue(installVFS)
	parentVFS   uintptr
	fileMethods uintptr
	uriKey      uintptr
	activeFiles sync.Map // map[uintptr]*databaseFile, keyed by the native file address
)

type databaseFile struct {
	db        *Database
	key       *securemem.Buffer
	parent    uintptr
	buffer    uintptr
	main      bool
	chunkSize int64
}

// modernc's translated SQLite stores function values in pointer-sized slots.
// The registered callbacks below are top-level functions without environments.
func pointer[T any](fn T) uintptr { return *(*uintptr)(unsafe.Pointer(&fn)) }

func installVFS() error {
	tls := libc.NewTLS()
	defer tls.Close()
	parent := sqlite.Xsqlite3_vfs_find(tls, 0)
	if parent == 0 {
		return ErrUnavailable
	}
	vfs := *(*sqlite.Tsqlite3_vfs)(unsafe.Pointer(parent))
	if vfs.FszOsFile < 8 || vfs.FszOsFile > math.MaxInt32-parentOffset ||
		vfs.FmxPathname <= 0 || vfs.FmxPathname == math.MaxInt32 {
		return ErrUnavailable
	}
	name, err := libc.CString(Name)
	if err != nil {
		return ErrUnavailable
	}
	param, err := libc.CString("whk")
	if err != nil {
		libc.Xfree(tls, name)
		return ErrUnavailable
	}
	vfsAddr := libc.Xmalloc(tls, uint64(unsafe.Sizeof(vfs)))
	ioAddr := libc.Xmalloc(tls, uint64(unsafe.Sizeof(sqlite.Tsqlite3_io_methods{})))
	if vfsAddr != 0 && ioAddr != 0 {
		*(*sqlite.Tsqlite3_io_methods)(unsafe.Pointer(ioAddr)) = sqlite.Tsqlite3_io_methods{
			FiVersion: 1, FxClose: pointer(closeFile), FxRead: pointer(readFile), FxWrite: pointer(writeFile),
			FxTruncate: pointer(truncateFile), FxSync: pointer(syncFile), FxFileSize: pointer(sizeFile),
			FxLock: pointer(lockFile), FxUnlock: pointer(unlockFile), FxCheckReservedLock: pointer(reservedLock),
			FxFileControl: pointer(controlFile), FxSectorSize: pointer(sectorSize), FxDeviceCharacteristics: pointer(deviceCharacteristics),
		}
		vfs.FzName, vfs.FpNext = name, 0
		vfs.FszOsFile += parentOffset
		vfs.FxOpen = pointer(openFile)
		*(*sqlite.Tsqlite3_vfs)(unsafe.Pointer(vfsAddr)) = vfs
		parentVFS, fileMethods, uriKey = parent, ioAddr, param
		if sqlite.Xsqlite3_vfs_register(tls, vfsAddr, 0) == sqlite.SQLITE_OK {
			return nil
		}
	}
	libc.Xfree(tls, ioAddr)
	libc.Xfree(tls, vfsAddr)
	libc.Xfree(tls, param)
	libc.Xfree(tls, name)
	return ErrUnavailable
}

func canonicalPath(path string) (string, error) {
	tls := libc.NewTLS()
	defer tls.Close()
	in, err := libc.CString(filepath.ToSlash(path))
	if err != nil {
		return "", ErrConfiguration
	}
	defer libc.Xfree(tls, in)
	parent := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(parentVFS))
	capacity := parent.FmxPathname + 1
	out := libc.Xmalloc(tls, uint64(capacity))
	if out == 0 {
		return "", ErrUnavailable
	}
	defer libc.Xfree(tls, out)

	fullPath := *(*func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&parent.FxFullPathname))
	rc := fullPath(tls, parentVFS, in, capacity, out)
	if rc != sqlite.SQLITE_OK && rc != sqlite.SQLITE_OK_SYMLINK {
		return "", ErrConfiguration
	}
	return filepath.Clean(libc.GoString(out)), nil
}

func openFile(tls *libc.TLS, _, name, out uintptr, flags int32, outFlags uintptr) int32 {
	wrapper := (*sqlite.Tsqlite3_file)(unsafe.Pointer(out))
	wrapper.FpMethods = 0
	file := databaseFile{parent: out + parentOffset, main: flags&sqlite.SQLITE_OPEN_MAIN_DB != 0}
	if flags&(sqlite.SQLITE_OPEN_MAIN_DB|sqlite.SQLITE_OPEN_MAIN_JOURNAL|sqlite.SQLITE_OPEN_WAL) != 0 && name != 0 {
		dbName := sqlite.Xsqlite3_filename_database(tls, name)
		if dbName != 0 {
			handle := sqlite.Xsqlite3_uri_parameter(tls, dbName, uriKey)
			if handle != 0 {
				file.db = acquireDatabase(libc.GoString(handle), libc.GoString(dbName), file.main)
			}
		}
		if file.db == nil {
			return sqlite.SQLITE_CANTOPEN
		}
		file.key = file.db.key
	} else if flags&sqlite.SQLITE_OPEN_DELETEONCLOSE != 0 && flags&sqlite.SQLITE_OPEN_SUPER_JOURNAL == 0 {
		key, err := securemem.New(32, true)
		if err != nil {
			return sqlite.SQLITE_CANTOPEN
		}
		file.key = key
		if err := key.With(func(data []byte) error { rand.Read(data); return nil }); err != nil {
			key.Close()
			return sqlite.SQLITE_CANTOPEN
		}
	} else {
		return sqlite.SQLITE_CANTOPEN
	}

	parent := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(parentVFS))
	open := *(*func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&parent.FxOpen))
	(*sqlite.Tsqlite3_file)(unsafe.Pointer(file.parent)).FpMethods = 0
	result := open(tls, parentVFS, name, file.parent, flags|sqlite.SQLITE_OPEN_NOFOLLOW, outFlags)
	if result == sqlite.SQLITE_OK {
		file.buffer = libc.Xmalloc(tls, PageSize+8)
		if file.buffer != 0 {
			activeFiles.Store(out, &file)
			wrapper.FpMethods = fileMethods
			return sqlite.SQLITE_OK
		}
		result = sqlite.SQLITE_NOMEM
	}
	file.close(tls)
	return result
}

func getFile(p uintptr) *databaseFile {
	f, _ := activeFiles.Load(p)
	return f.(*databaseFile)
}

func (f *databaseFile) methods() *sqlite.Tsqlite3_io_methods {
	return (*sqlite.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite.Tsqlite3_file)(unsafe.Pointer(f.parent)).FpMethods))
}

func (f *databaseFile) close(tls *libc.TLS) int32 {
	result := int32(sqlite.SQLITE_OK)
	if methods := f.methods(); methods != nil {
		closeParent := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&methods.FxClose))
		result = closeParent(tls, f.parent)
	}
	if f.buffer != 0 {
		clear(f.scratch())
		libc.Xfree(tls, f.buffer)
	}
	if f.db != nil {
		f.db.release(f.main)
	} else if err := f.key.Close(); err != nil && result == sqlite.SQLITE_OK {
		result = sqlite.SQLITE_IOERR_CLOSE
	}
	return result
}

func closeFile(tls *libc.TLS, p uintptr) int32 {
	f := getFile(p)
	activeFiles.Delete(p)
	(*sqlite.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods = 0
	return f.close(tls)
}

func syncFile(tls *libc.TLS, p uintptr, flags int32) int32 {
	f := getFile(p)
	sync := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&f.methods().FxSync))
	return sync(tls, f.parent, flags)
}

func lockFile(tls *libc.TLS, p uintptr, level int32) int32 {
	f := getFile(p)
	lock := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&f.methods().FxLock))
	return lock(tls, f.parent, level)
}

func unlockFile(tls *libc.TLS, p uintptr, level int32) int32 {
	f := getFile(p)
	unlock := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&f.methods().FxUnlock))
	return unlock(tls, f.parent, level)
}

func reservedLock(tls *libc.TLS, p uintptr, result uintptr) int32 {
	f := getFile(p)
	check := *(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&f.methods().FxCheckReservedLock))
	return check(tls, f.parent, result)
}

func sectorSize(tls *libc.TLS, p uintptr) int32 {
	f := getFile(p)
	sector := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&f.methods().FxSectorSize))
	return max(PageSize, sector(tls, f.parent))
}

func deviceCharacteristics(tls *libc.TLS, p uintptr) int32 {
	f := getFile(p)
	characteristics := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&f.methods().FxDeviceCharacteristics))
	return characteristics(tls, f.parent) & sqlite.SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
}

func controlFile(tls *libc.TLS, p uintptr, operation int32, argument uintptr) int32 {
	switch operation {
	case sqlite.SQLITE_FCNTL_PRAGMA:
		return controlPragma(argument)
	case sqlite.SQLITE_FCNTL_MMAP_SIZE:
		*(*int64)(unsafe.Pointer(argument)) = 0
		return sqlite.SQLITE_OK
	case sqlite.SQLITE_FCNTL_POWERSAFE_OVERWRITE:
		*(*int32)(unsafe.Pointer(argument)) = 0
		return sqlite.SQLITE_OK
	case sqlite.SQLITE_FCNTL_CHUNK_SIZE:
		// Keep the native VFS chunk size disabled. Its truncate/size hint
		// would otherwise extend the file with unencrypted sectors.
		f := getFile(p)
		f.chunkSize = roundedSize(max(0, int64(*(*int32)(unsafe.Pointer(argument)))))
		return sqlite.SQLITE_OK
	case sqlite.SQLITE_FCNTL_SIZE_HINT:
		return getFile(p).reserve(tls, *(*int64)(unsafe.Pointer(argument)))
	case sqlite.SQLITE_FCNTL_LOCKSTATE, sqlite.SQLITE_FCNTL_LAST_ERRNO, sqlite.SQLITE_FCNTL_HAS_MOVED,
		sqlite.SQLITE_FCNTL_PERSIST_WAL, sqlite.SQLITE_FCNTL_SYNC, sqlite.SQLITE_FCNTL_COMMIT_PHASETWO:
		f := getFile(p)
		control := *(*func(*libc.TLS, uintptr, int32, uintptr) int32)(unsafe.Pointer(&f.methods().FxFileControl))
		return control(tls, f.parent, operation, argument)
	default:
		return sqlite.SQLITE_NOTFOUND
	}
}

func controlPragma(argument uintptr) int32 {
	args := (*[3]uintptr)(unsafe.Pointer(argument))
	if args[2] == 0 {
		return sqlite.SQLITE_NOTFOUND
	}
	name := strings.ToLower(libc.GoString(args[1]))
	value := strings.ToLower(libc.GoString(args[2]))
	var allowed bool
	switch name {
	case "journal_mode":
		allowed = value == "delete" || value == "wal"
	case "locking_mode":
		allowed = value == "exclusive"
	case "synchronous":
		allowed = value == "full" || value == "2"
	case "page_size":
		allowed = value == "4096"
	default:
		return sqlite.SQLITE_NOTFOUND
	}
	if !allowed {
		return sqlite.SQLITE_AUTH
	}
	return sqlite.SQLITE_NOTFOUND
}
