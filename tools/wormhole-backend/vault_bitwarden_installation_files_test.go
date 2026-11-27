package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

func extensionTree() fstest.MapFS {
	return fstest.MapFS{"manifest.json": {Data: []byte(`{"manifest_version":2}`)}, "background.js": {Data: []byte("fixture")}, "icons/x.png": {Data: []byte{1, 2, 3}}}
}
func TestVaultExtensionContentDigest(t *testing.T) {
	ctx := context.Background()
	tree := extensionTree()
	first, err := hashVaultExtensionFiles(ctx, tree)
	if err != nil || len(first) != 64 {
		t.Fatal(first, err)
	}
	again, err := hashVaultExtensionFiles(ctx, extensionTree())
	if err != nil || again != first {
		t.Fatal("unstable digest", err)
	}
	for _, mutate := range []func(fstest.MapFS){
		func(f fstest.MapFS) { f["background.js"].Data = []byte("modified") },
		func(f fstest.MapFS) { f["renamed.js"] = f["background.js"]; delete(f, "background.js") },
		func(f fstest.MapFS) { delete(f, "background.js") },
		func(f fstest.MapFS) { f["empty"] = &fstest.MapFile{Mode: fs.ModeDir} },
	} {
		f := extensionTree()
		mutate(f)
		got, err := hashVaultExtensionFiles(ctx, f)
		if err != nil || got == first {
			t.Fatal("change not bound", err)
		}
	}
	// Legacy unframed filename/content concatenation could not distinguish these.
	a := fstest.MapFS{"manifest.json": {Data: nil}, "a": {Data: []byte("Xb\x00Y")}}
	b := fstest.MapFS{"manifest.json": {Data: nil}, "a": {Data: []byte("X")}, "b": {Data: []byte("Y")}}
	da, e := hashVaultExtensionFiles(ctx, a)
	db, f := hashVaultExtensionFiles(ctx, b)
	if e != nil || f != nil || da == db {
		t.Fatal("ambiguous framing", e, f)
	}
}
func TestVaultExtensionRejectsUnsafeTrees(t *testing.T) {
	for _, name := range []string{"bad\\path", "bad:name", "bad ", "bad.", strings.Repeat("x", 1025), strings.Repeat("d/", 34) + "x", string([]byte{0xff})} {
		tree := extensionTree()
		tree[name] = &fstest.MapFile{Data: []byte("x")}
		if _, err := hashVaultExtensionFiles(context.Background(), tree); !errors.Is(err, errVaultExtensionFiles) {
			t.Fatalf("unsafe name accepted: %q %v", name, err)
		}
	}
	for _, mode := range []fs.FileMode{fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeSocket} {
		tree := extensionTree()
		tree["unsafe"] = &fstest.MapFile{Mode: mode}
		if _, err := hashVaultExtensionFiles(context.Background(), tree); !errors.Is(err, errVaultExtensionFiles) {
			t.Fatal(mode, err)
		}
	}
	tree := extensionTree()
	tree["BACKGROUND.js"] = &fstest.MapFile{}
	if _, err := hashVaultExtensionFiles(context.Background(), tree); err == nil {
		t.Fatal("case collision")
	}
	if _, err := hashVaultExtensionFiles(context.Background(), fstest.MapFS{}); err == nil {
		t.Fatal("missing manifest")
	}
	if _, err := hashVaultExtensionFiles(context.Background(), nil); err == nil {
		t.Fatal("nil tree")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashVaultExtensionFiles(canceled, extensionTree()); err == nil {
		t.Fatal("canceled tree")
	}
}
func TestVaultExtensionNativeInstallationVerification(t *testing.T) {
	directory := t.TempDir()
	id := uuid.NewString()
	path := filepath.Join(directory, id)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	base, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	root, err := base.OpenRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashVaultExtensionFiles(context.Background(), root.FS())
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	value := localvault.BitwardenInstallation{Enabled: true, InstallationID: id, ExtensionID: strings.Repeat("a", 32), ContentSHA256: digest}
	if err := verifyVaultBitwardenInstallation(context.Background(), base, value); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []localvault.BitwardenInstallation{{}, {Enabled: true, InstallationID: "../outside"}, {Enabled: true, InstallationID: uuid.NewString()}, {Enabled: true, InstallationID: id, ContentSHA256: strings.Repeat("0", 64)}} {
		if err := verifyVaultBitwardenInstallation(context.Background(), base, bad); !errors.Is(err, errVaultExtensionFiles) {
			t.Fatal("untrusted accepted", err)
		}
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyVaultBitwardenInstallation(context.Background(), base, value); err == nil {
		t.Fatal("changed content accepted")
	}
	if err := verifyVaultBitwardenInstallation(context.Background(), nil, value); err == nil {
		t.Fatal("missing root")
	}
}

type extensionFaultFS struct {
	fs.FS
	path, failure string
}

func (s extensionFaultFS) Open(path string) (fs.File, error) {
	if path == s.path && s.failure == "open" {
		return nil, fs.ErrPermission
	}
	f, err := s.FS.Open(path)
	if err != nil {
		return nil, err
	}
	if path == s.path {
		return extensionFaultFile{File: f, failure: s.failure}, nil
	}
	return f, nil
}

type extensionFaultFile struct {
	fs.File
	failure string
}

func (f extensionFaultFile) Read(b []byte) (int, error) {
	if f.failure == "read" {
		return 0, fs.ErrInvalid
	}
	return f.File.Read(b)
}
func (f extensionFaultFile) Stat() (fs.FileInfo, error) {
	if f.failure == "stat" {
		return nil, fs.ErrInvalid
	}
	return f.File.Stat()
}
func (f extensionFaultFile) Close() error {
	e := f.File.Close()
	if f.failure == "close" {
		return fs.ErrInvalid
	}
	return e
}
func TestVaultExtensionFilesystemFailures(t *testing.T) {
	for _, failure := range []string{"open", "read", "stat", "close"} {
		tree := extensionFaultFS{FS: extensionTree(), path: "background.js", failure: failure}
		if _, err := hashVaultExtensionFiles(context.Background(), tree); !errors.Is(err, errVaultExtensionFiles) {
			t.Fatal(failure, err)
		}
	}
	for _, failure := range []string{"open", "stat", "close", "no-readdir"} {
		tree := extensionFaultFS{FS: extensionTree(), path: ".", failure: failure}
		if _, err := hashVaultExtensionFiles(context.Background(), tree); !errors.Is(err, errVaultExtensionFiles) {
			t.Fatal(failure, err)
		}
	}
	f, err := extensionTree().Open("background.js")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := streamVaultExtensionFile(context.Background(), io.Discard, f, 100, make([]byte, 16)); err == nil {
		t.Fatal("size changed")
	}
}
func TestVaultExtensionBoundsDirectoryEnumeration(t *testing.T) {
	tree := fstest.MapFS{}
	for i := 0; i <= bitwardenMaxExtractedFiles; i++ {
		tree[fmt.Sprintf("entry-%06d", i)] = &fstest.MapFile{}
	}
	if _, err := hashVaultExtensionFiles(context.Background(), tree); !errors.Is(err, errVaultExtensionFiles) {
		t.Fatal("unbounded directory", err)
	}
}
