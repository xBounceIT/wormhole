// Package encvfs provides the opt-in Adiantum VFS for local SQLite vaults.
// The vault owner authenticates the slot file and derives the page key before
// registering its database. A registration does not authenticate the database.
package encvfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
)

const Name = "wormhole-adiantum-v1"
const PageSize = 4096

var (
	ErrConfiguration = errors.New("invalid encrypted SQLite configuration")
	ErrUnavailable   = errors.New("encrypted SQLite VFS unavailable")
	ErrBusy          = errors.New("encrypted SQLite database is in use")
)

var registry = struct {
	sync.Mutex
	databases map[string]*Database
}{databases: make(map[string]*Database)}

// Database owns a page key and its opaque URI handle. Close it after SQLite
// closes all handles to the database and its sidecars.
type Database struct {
	path     string
	handle   string
	key      *securemem.Buffer
	file     os.FileInfo
	opens    int
	mainOpen bool
	retiring bool
}

func Register(path string, pageKey []byte) (*Database, error) {
	if len(pageKey) != 32 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConfiguration
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	if err := registerVFS(); err != nil {
		return nil, err
	}
	// Bind the handle to the same filename the OS VFS passes to xOpen.
	path, err = canonicalPath(path)
	if err != nil {
		return nil, err
	}
	registry.Lock()
	defer registry.Unlock()
	for _, db := range registry.databases {
		if db.path == path || os.SameFile(db.file, info) {
			return nil, ErrBusy
		}
	}
	key, err := securemem.New(len(pageKey), true)
	if err != nil {
		return nil, err
	}
	if err := key.With(func(slot []byte) error {
		copy(slot, pageKey)
		return nil
	}); err != nil {
		return nil, errors.Join(err, key.Close())
	}
	var random [16]byte
	for {
		rand.Read(random[:])
		handle := hex.EncodeToString(random[:])
		if _, exists := registry.databases[handle]; !exists {
			db := &Database{path: path, handle: handle, key: key, file: info}
			registry.databases[handle] = db
			return db, nil
		}
	}
}

// URI opens an existing or exclusively reserved file. It does not carry the
// page key and cannot select any other path with this registration.
func (db *Database) URI() url.URL {
	path := filepath.ToSlash(db.path)
	if runtime.GOOS == "windows" {
		path = "/" + path
	}
	query := url.Values{
		"vfs": {Name}, "whk": {db.handle}, "mode": {"rw"},
		"_pragma": {"locking_mode(EXCLUSIVE)", "synchronous(FULL)", "temp_store(MEMORY)", "mmap_size(0)", "page_size(4096)"},
	}
	return url.URL{Scheme: "file", Path: path, RawQuery: query.Encode()}
}

func (db *Database) Close() error {
	registry.Lock()
	defer registry.Unlock()
	if registry.databases[db.handle] != db {
		return nil
	}
	if db.opens != 0 {
		return ErrBusy
	}
	db.retiring = true
	if err := db.key.Close(); err != nil {
		return err
	}
	delete(registry.databases, db.handle)
	return nil
}

func acquireDatabase(handle, path string, main bool) *Database {
	registry.Lock()
	defer registry.Unlock()
	db := registry.databases[handle]
	if db == nil || db.retiring || db.path != filepath.Clean(path) {
		return nil
	}
	if main {
		if db.mainOpen {
			return nil
		}
		db.mainOpen = true
	} else if !db.mainOpen {
		return nil
	}
	db.opens++
	return db
}

func (db *Database) release(main bool) {
	registry.Lock()
	defer registry.Unlock()
	db.opens--
	if main {
		db.mainOpen = false
	}
}
