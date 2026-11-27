package localvault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/encvfs"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func backupOptions(t *testing.T) (OpenOptions, []byte, []byte) {
	t.Helper()
	opts, root := options(t)
	opts.Slots.Encrypted = true
	opts.Slots = signBackupSlots(t, opts.Slots, root)
	t.Cleanup(func() { vault.Wipe(root) })
	return opts, root, bytes.Repeat([]byte{3}, 32)
}

func signBackupSlots(t *testing.T, slots vault.SlotFile, root []byte) vault.SlotFile {
	t.Helper()
	result, err := vault.DecodeSlotFile(encodeBackupSlots(t, slots, root))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func encodeBackupSlots(t *testing.T, slots vault.SlotFile, root []byte) []byte {
	t.Helper()
	result, err := vault.EncodeSlotFile(root, slots)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEncryptedBackupRestoresLiveDatabaseAndExactSlots(t *testing.T) {
	ctx := context.Background()
	opts, root, recoveryKey := backupOptions(t)
	parent := t.TempDir()
	sourcePath := filepath.Join(parent, "source.db")
	owner, err := Open(ctx, sourcePath, opts, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	node := nodeDraft()
	node.Name = "metadata visible only in the encrypted database"
	saved, err := owner.PutNode(ctx, node, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ref := secretRef()
	secret := []byte("synthetic secret before backup")
	if _, err := owner.Put(ctx, ref, secret, 0); err != nil {
		t.Fatal(err)
	}
	opts.Slots.Nodes = []vault.NodeHighWater{{NodeID: node.ID, Revision: saved.RowVersion}}
	slots := encodeBackupSlots(t, opts.Slots, root)
	var archive bytes.Buffer
	if err := owner.WriteEncryptedBackup(ctx, parent, slots, &archive); err != nil {
		t.Fatal(err)
	}
	if err := owner.WithSecret(ctx, ref, 1, func(plain []byte) error {
		if !bytes.Equal(plain, secret) {
			t.Fatalf("source secret changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{[]byte(node.Name), secret, root, recoveryKey, []byte("SQLite format 3")} {
		if bytes.Contains(archive.Bytes(), plaintext) {
			t.Fatal("found unencrypted vault data in the backup")
		}
	}
	backup, err := ReadEncryptedBackup(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	restoreParent := t.TempDir()
	stage, err := backup.Stage(ctx, restoreParent, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveryKey, make([]byte, 32)) {
		t.Fatal("recovery key retained")
	}
	restoredPath := filepath.Join(stage, backupDatabase)
	restoredSlots, err := os.ReadFile(restoredPath + ".slots")
	if err != nil || !bytes.Equal(slots, restoredSlots) {
		t.Fatalf("restored slot file differs: %v", err)
	}
	opts.Slots, opts.Create = backup.document, false
	restored, err := Open(ctx, restoredPath, opts, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.ReadNode(ctx, node.ID, saved.RowVersion)
	if err != nil || got.Name != node.Name {
		t.Fatalf("node not restored: %v", err)
	}
	if err := restored.WithSecret(ctx, ref, 1, func(plain []byte) error {
		if !bytes.Equal(plain, secret) {
			t.Fatal("secret not restored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedBackupRejectsInvalidAndModifiedArchives(t *testing.T) {
	opts, root, recoveryKey := backupOptions(t)
	ctx := context.Background()
	slots := encodeBackupSlots(t, opts.Slots, root)
	var archive bytes.Buffer
	db := bytes.Repeat([]byte{42}, encvfs.PageSize)
	if err := writeBackup(ctx, &archive, bytes.NewReader(db), int64(len(db)), slots, opts.Slots, root); err != nil {
		t.Fatal(err)
	}
	for name, modify := range map[string]func([]byte) []byte{
		"shortHeader": func(raw []byte) []byte { return raw[:10] },
		"truncated":   func(raw []byte) []byte { return raw[:len(raw)-1] },
		"trailing":    func(raw []byte) []byte { return append(raw, 1) },
		"version":     func(raw []byte) []byte { raw[7]++; return raw },
		"slotLength": func(raw []byte) []byte {
			binary.BigEndian.PutUint32(raw[8:], vault.MaxSlotFileBytes+1)
			return raw
		},
		"dbLength": func(raw []byte) []byte {
			binary.BigEndian.PutUint64(raw[12:], 1<<63)
			return raw
		},
		"unaligned": func(raw []byte) []byte {
			binary.BigEndian.PutUint64(raw[12:], encvfs.PageSize-1)
			return raw[:len(raw)-1]
		},
		"slotContent": func(raw []byte) []byte { raw[backupHeaderBytes] = 0; return raw },
	} {
		t.Run(name, func(t *testing.T) {
			raw := modify(bytes.Clone(archive.Bytes()))
			if _, err := ReadEncryptedBackup(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, vault.ErrFormat) {
				t.Fatalf("malformed archive accepted: %v", err)
			}
		})
	}
	plain := opts.Slots
	plain.Encrypted = false
	initializing := opts.Slots
	initializing.Initializing = true
	for _, doc := range []vault.SlotFile{plain, initializing} {
		var raw bytes.Buffer
		if err := writeBackup(ctx, &raw, bytes.NewReader(db), int64(len(db)), encodeBackupSlots(t, doc, root), doc, root); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEncryptedBackup(bytes.NewReader(raw.Bytes()), int64(raw.Len())); err != vault.ErrPolicy {
			t.Fatalf("slot policy ignored: %v", err)
		}
	}
	parent := t.TempDir()
	for _, mutation := range []string{"wrong recovery", "page", "tag", "different authentic slots", "unopenable sqlite"} {
		t.Run(mutation, func(t *testing.T) {
			raw, input := bytes.Clone(archive.Bytes()), bytes.Clone(recoveryKey)
			switch mutation {
			case "wrong recovery":
				input[0] ^= 1
			case "page":
				raw[backupHeaderBytes+len(slots)+2] ^= 1
			case "tag":
				raw[len(raw)-1] ^= 1
			case "different authentic slots":
				doc := opts.Slots
				doc.Sequence++
				if replacement := encodeBackupSlots(t, doc, root); len(replacement) != len(slots) {
					t.Fatal("substitution changed framing")
				} else {
					copy(raw[backupHeaderBytes:], replacement)
				}
			}
			backup, err := ReadEncryptedBackup(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}
			stage, err := backup.Stage(ctx, parent, input)
			if stage != "" || !bytes.Equal(input, make([]byte, 32)) {
				t.Fatal("denied restore retained a path or key")
			}
			want := vault.ErrAuthentication
			if mutation == "unopenable sqlite" {
				want = vaultstore.ErrStorage
			}
			if !errors.Is(err, want) {
				t.Fatalf("restore error: %v, want %v", err, want)
			}
			if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
				t.Fatalf("denied restore retained staging: %v, %v", entries, err)
			}
		})
	}
}

func TestEncryptedBackupExportRefusesBadInputsAndCleansUpOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	opts, root, _ := backupOptions(t)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	o, err := Open(ctx, sourcePath, opts, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	slots := encodeBackupSlots(t, opts.Slots, root)
	doc := opts.Slots
	doc.RootKeyID = secretRef().OwnerID
	badIdentity := encodeBackupSlots(t, doc, root)
	doc = opts.Slots
	doc.Sequence++
	newer := encodeBackupSlots(t, doc, root)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		ctx   context.Context
		path  string
		slots []byte
		err   error
	}{
		{cancelled, parent, slots, context.Canceled},
		{ctx, parent, []byte("invalid"), vault.ErrFormat},
		{ctx, parent, badIdentity, vaultstore.ErrIdentity},
		{ctx, "relative", slots, vault.ErrFormat},
		{ctx, filepath.Join(parent, "missing"), slots, vaultstore.ErrStorage},
		{ctx, parent, newer, io.ErrShortWrite},
		{ctx, parent, slots, vault.ErrRollback},
	} {
		if err := o.WriteEncryptedBackup(tc.ctx, tc.path, tc.slots, backupShortWriter{}); !errors.Is(err, tc.err) {
			t.Fatalf("export error: %v, want %v", err, tc.err)
		}
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("failed export retained staging: %v, %v", entries, err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.WriteEncryptedBackup(ctx, parent, slots, io.Discard); err != vaultstore.ErrClosed {
		t.Fatalf("closed owner accepted export: %v", err)
	}
	plain, _, plainOpts, plainRoot := owner(t)
	if err := plain.WriteEncryptedBackup(ctx, parent, encodeBackupSlots(t, plainOpts.Slots, plainRoot), io.Discard); err != vault.ErrPolicy {
		t.Fatalf("plaintext owner accepted export: %v", err)
	}
}

type backupShortWriter struct{}

func (backupShortWriter) Write([]byte) (int, error) { return 0, nil }

func TestEncryptedBackupCancelsDuringCopyAndRejectsTruncatedSnapshot(t *testing.T) {
	opts, root, recovery := backupOptions(t)
	slots := encodeBackupSlots(t, opts.Slots, root)
	ctx, cancel := context.WithCancel(context.Background())
	db := bytes.Repeat([]byte{17}, encvfs.PageSize)
	writer := &cancelBackupWriter{cancel: cancel}
	if err := writeBackup(ctx, writer, bytes.NewReader(db), int64(len(db)), slots, opts.Slots, root); err != context.Canceled {
		t.Fatalf("copy continued on canceled export: %v", err)
	}
	if writer.Len() != backupHeaderBytes+len(slots) {
		t.Fatal("canceled export copied ciphertext")
	}
	var truncated bytes.Buffer
	if err := writeBackup(context.Background(), &truncated, bytes.NewReader(db[:len(db)-1]), int64(len(db)), slots, opts.Slots, root); err != io.EOF {
		t.Fatalf("short ciphertext write accepted: %v", err)
	}
	parent := t.TempDir()
	backupCtx, cancelRestore := context.WithCancel(context.Background())
	defer cancelRestore()
	var raw bytes.Buffer
	if err := writeBackup(backupCtx, &raw, bytes.NewReader(db), int64(len(db)), slots, opts.Slots, root); err != nil {
		t.Fatal(err)
	}
	reader := cancelBackupReader{ReaderAt: bytes.NewReader(raw.Bytes()), cancel: cancelRestore, offset: int64(backupHeaderBytes + len(slots))}
	archive, err := ReadEncryptedBackup(reader, int64(raw.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if stage, err := archive.Stage(backupCtx, parent, recovery); !errors.Is(err, context.Canceled) || stage != "" {
		t.Fatalf("canceled restore promoted ciphertext: %v", err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("canceled restore retained staging: %v %v", entries, err)
	}
}

type cancelBackupWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelBackupWriter) Write(p []byte) (int, error) {
	if w.Len() == backupHeaderBytes {
		w.cancel()
	}
	return w.Buffer.Write(p)
}

type cancelBackupReader struct {
	io.ReaderAt
	cancel context.CancelFunc
	offset int64
}

func (r cancelBackupReader) ReadAt(dst []byte, offset int64) (int, error) {
	if offset == r.offset {
		r.cancel()
	}
	return r.ReaderAt.ReadAt(dst, offset)
}
