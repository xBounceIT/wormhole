package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vaultZipEntry struct {
	name, data string
	mode       fs.FileMode
}

func vaultZipBytes(t *testing.T, entries []vaultZipEntry, method uint16) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: method}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(f, e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func vaultZipPackage() []vaultZipEntry {
	return []vaultZipEntry{{"manifest.json", vaultExtensionTestManifest, 0}, {"popup.html", "<p>fixture</p>", 0}, {"background.js", "void 0;", 0}, {"nested/asset.txt", "asset", 0}}
}
func TestVaultBitwardenZipInstall(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		t.Run(string(rune('A'+method)), func(t *testing.T) {
			ctx := context.Background()
			h := vaultCredentialFixture(t)
			base, _ := installerRoots(t)
			raw := vaultZipBytes(t, vaultZipPackage(), method)
			rev, err := installVaultBitwardenZip(ctx, h.owner, base, bytes.NewReader(raw), int64(len(raw)), 0)
			if err != nil || rev != 1 {
				t.Fatal(rev, err)
			}
			plan, _, err := planVaultBitwardenInstallation(ctx, h.owner, base, 1)
			if err != nil || plan.Version != "1.0" {
				t.Fatal(plan, err)
			}
			if _, err = installVaultBitwardenZip(ctx, h.owner, base, bytes.NewReader(raw), int64(len(raw)), 0); err == nil {
				t.Fatal("stale ZIP committed")
			}
			if method == zip.Store {
				bad := bytes.Replace(bytes.Clone(raw), []byte("void 0;"), []byte("VOID 0;"), 1)
				if _, err = installVaultBitwardenZip(ctx, h.owner, base, bytes.NewReader(bad), int64(len(bad)), 1); err == nil {
					t.Fatal("CRC corruption accepted")
				}
			}
			entries, err := fs.ReadDir(base.FS(), ".")
			if err != nil || len(entries) != 1 {
				t.Fatal("failed stage retained", entries, err)
			}
		})
	}
	h := vaultCredentialFixture(t)
	base, _ := installerRoots(t)
	raw := vaultZipBytes(t, []vaultZipEntry{{"manifest.json", "{}", 0}}, zip.Store)
	if _, err := installVaultBitwardenZip(context.Background(), h.owner, base, bytes.NewReader(raw), int64(len(raw)), 0); err == nil {
		t.Fatal("invalid package")
	}
	entries, err := fs.ReadDir(base.FS(), ".")
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	if _, err := installVaultBitwardenZip(context.Background(), h.owner, base, nil, 0, 0); err == nil {
		t.Fatal("nil archive")
	}
}
func TestVaultExtensionZipUnsafeEntries(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a/../x", "a\\x", "C:/x", "CON", "a.", "a ", "./x", "x//y", string([]byte{0xff}), strings.Repeat("x", 1025), strings.Repeat("a/", 34) + "x"} {
		raw := vaultZipBytes(t, []vaultZipEntry{{name, "payload", 0}}, zip.Store)
		if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, entries := range [][]vaultZipEntry{{{"same", "1", 0}, {"same", "2", 0}}, {{"Same", "1", 0}, {"same", "2", 0}}, {{"link", "target", os.ModeSymlink | 0600}}, {{"pipe", "", os.ModeNamedPipe | 0600}}} {
		raw := vaultZipBytes(t, entries, zip.Store)
		if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatal("unsafe entries")
		}
	}
	raw := vaultZipBytes(t, []vaultZipEntry{{"empty/", "", os.ModeDir | 0700}}, zip.Store)
	if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
}
func TestVaultExtensionZipMetadataBounds(t *testing.T) {
	original := vaultZipBytes(t, vaultZipPackage(), zip.Store)
	mutate := func(change func([]byte, []byte)) {
		t.Helper()
		raw := bytes.Clone(original)
		end := raw[len(raw)-22:]
		offset := binary.LittleEndian.Uint32(end[16:])
		change(end, raw[offset:])
		if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatal("metadata accepted")
		}
	}
	for _, field := range []int{4, 6, 8, 10, 12, 16, 20} {
		mutate(func(e, c []byte) { e[field] = 0xff })
	}
	for _, field := range []int{20, 24, 42} {
		mutate(func(e, c []byte) { binary.LittleEndian.PutUint32(c[field:], 0xffffffff) })
	}
	mutate(func(e, c []byte) { c[0] = 0 })
	mutate(func(e, c []byte) { binary.LittleEndian.PutUint16(c[28:], 65535) })
	mutate(func(e, c []byte) { c[8] |= 1 })
	mutate(func(e, c []byte) { binary.LittleEndian.PutUint16(c[10:], 99) })
	mutate(func(e, c []byte) { binary.LittleEndian.PutUint32(c[24:], uint32(bitwardenMaxExtractedBytes+1)) })
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{0}, 22), append(bytes.Clone(original), 1)} {
		if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatal("invalid ending")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readVaultExtensionZip(ctx, bytes.NewReader(original), int64(len(original))); err == nil {
		t.Fatal("cancelled")
	}
	if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(original), bitwardenMaxExtractedBytes+1); err == nil {
		t.Fatal("oversized")
	}
	if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(nil), 22); err == nil {
		t.Fatal("short reader")
	}
}
func TestVaultExtensionZipSnapshot(t *testing.T) {
	raw := vaultZipBytes(t, vaultZipPackage(), zip.Store)
	archive, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	offset := binary.LittleEndian.Uint32(raw[len(raw)-22+16:])
	clear(raw[offset:])
	if _, err = hashVaultExtensionFiles(context.Background(), archive); err != nil {
		t.Fatal("source mutation changed snapshot", err)
	}
	snapshot := vaultExtensionZipSnapshot{bytes.NewReader([]byte("abc")), 3, []byte("DEF")}
	for _, tc := range []struct {
		offset int64
		n      int
		want   string
	}{{0, 2, "ab"}, {2, 3, "cDE"}, {3, 3, "DEF"}, {6, 2, ""}} {
		out := make([]byte, tc.n)
		n, e := snapshot.ReadAt(out, tc.offset)
		if string(out[:n]) != tc.want || (e != nil && e != io.EOF) {
			t.Fatal(n, e, string(out))
		}
	}
	if _, err = snapshot.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative offset")
	}
	snapshot.source = bytes.NewReader(nil)
	if _, err = snapshot.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("source failure")
	}
}

type vaultZipReaderFault struct {
	*bytes.Reader
	calls  int
	action func(int)
}

func (r *vaultZipReaderFault) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	r.action(r.calls)
	return r.Reader.ReadAt(p, off)
}
func TestVaultExtensionZipFrozenMetadataFailures(t *testing.T) {
	for _, kind := range []string{"short", "changed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			raw := vaultZipBytes(t, vaultZipPackage(), zip.Store)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &vaultZipReaderFault{Reader: bytes.NewReader(raw)}
			reader.action = func(call int) {
				if call == 2 {
					switch kind {
					case "short":
						reader.Reader = bytes.NewReader(nil)
					case "changed":
						raw[len(raw)-1] = 1
					case "cancelled":
						cancel()
					}
				}
			}
			if _, err := readVaultExtensionZip(ctx, reader, int64(len(raw))); err == nil {
				t.Fatal("metadata race accepted")
			}
		})
	}
	for _, count := range []uint16{3, 5} {
		raw := vaultZipBytes(t, vaultZipPackage(), zip.Store)
		end := raw[len(raw)-22:]
		binary.LittleEndian.PutUint16(end[8:], count)
		binary.LittleEndian.PutUint16(end[10:], count)
		if _, err := readVaultExtensionZip(context.Background(), bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatal("wrong record count")
		}
	}
}
func TestVaultBitwardenZipWire(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "extension.zip")
	if err = os.WriteFile(path, vaultZipBytes(t, vaultZipPackage(), zip.Deflate), 0600); err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"workspaceId": workspace, "sourceFile": path, "expectedRevision": "0"}
	result, err := h.Handle(ctx, "bitwarden-install-zip", browserTransferJSON(t, q))
	if err != nil || !bytes.Contains(result, []byte(`"revision":"1"`)) {
		t.Fatal(string(result), err)
	}
	if _, err = h.Handle(ctx, "bitwarden-install-zip", browserTransferJSON(t, q)); err == nil {
		t.Fatal("stale zip")
	}
	for _, bad := range []map[string]any{
		{"workspaceId": workspace, "sourceDirectory": path, "expectedRevision": "1"},
		{"workspaceId": workspace, "sourceFile": "relative", "expectedRevision": "1"},
		{"workspaceId": workspace, "sourceFile": filepath.Dir(path), "expectedRevision": "1"},
		{"workspaceId": workspace, "sourceFile": path + "missing", "expectedRevision": "1"},
	} {
		if _, err = h.Handle(ctx, "bitwarden-install-zip", browserTransferJSON(t, bad)); err == nil {
			t.Fatal("invalid source")
		}
	}
	if !vaultFreshAction("bitwarden-install-zip") || !h.ExitOnCancel("bitwarden-install-zip") {
		t.Fatal("missing native action gates")
	}
	if _, err = installVaultBitwardenTree(ctx, nil, nil, nil, 0); err == nil {
		t.Fatal("missing owner")
	}
}
