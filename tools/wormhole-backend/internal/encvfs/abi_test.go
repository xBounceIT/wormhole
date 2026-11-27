//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"modernc.org/libc"
	sqlite "modernc.org/sqlite/lib"
)

func TestRegisteredABI(t *testing.T) {
	if err := registerVFS(); err != nil {
		t.Fatal(err)
	}
	tls := libc.NewTLS()
	defer tls.Close()
	name, err := libc.CString(Name)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, name)
	address := sqlite.Xsqlite3_vfs_find(tls, name)
	if address == 0 || address == parentVFS || sqlite.Xsqlite3_vfs_find(tls, 0) != parentVFS {
		t.Fatal("VFS registration changed the default")
	}
	vfs := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(address))
	original := (*sqlite.Tsqlite3_vfs)(unsafe.Pointer(parentVFS))
	if vfs.FszOsFile != original.FszOsFile+parentOffset || vfs.FxOpen != pointer(openFile) {
		t.Fatal("registered VFS does not wrap the parent's file ABI")
	}
	methods := (*sqlite.Tsqlite3_io_methods)(unsafe.Pointer(fileMethods))
	want := sqlite.Tsqlite3_io_methods{
		FiVersion: 1, FxClose: pointer(closeFile), FxRead: pointer(readFile), FxWrite: pointer(writeFile),
		FxTruncate: pointer(truncateFile), FxSync: pointer(syncFile), FxFileSize: pointer(sizeFile),
		FxLock: pointer(lockFile), FxUnlock: pointer(unlockFile), FxCheckReservedLock: pointer(reservedLock),
		FxFileControl: pointer(controlFile), FxSectorSize: pointer(sectorSize), FxDeviceCharacteristics: pointer(deviceCharacteristics),
	}
	if *methods != want {
		t.Fatal("registered SQLite I/O methods differ from the encrypted file callbacks")
	}
}

func TestCallbackAddressesAreTopLevelFunctions(t *testing.T) {
	files := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sources []*ast.File
	topLevel := make(map[string]bool)
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(files, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, file)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				topLevel[fn.Name.Name] = true
			}
		}
	}
	count := 0
	for _, file := range sources {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "pointer" {
				return true
			}
			count++
			arg, ok := call.Args[0].(*ast.Ident)
			if !ok || !topLevel[arg.Name] || (arg.Obj != nil && arg.Obj.Kind != ast.Fun) {
				t.Errorf("%s: callback must be a top-level function", files.Position(call.Pos()))
			}
			return true
		})
	}
	if count != 13 {
		t.Fatalf("checked %d callback addresses, want 13", count)
	}
}
