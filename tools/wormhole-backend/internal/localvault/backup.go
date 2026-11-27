package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/encvfs"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const (
	backupMagic       = "WHVLBK01"
	backupMagicBytes  = 8
	backupHeaderBytes = backupMagicBytes + 4 + 8
	maxBackupDatabase = 1 << 40
	backupDatabase    = "wormhole.db"
)

// EncryptedBackup holds an untrusted archive until Stage authenticates it.
// The caller retains ownership of the reader and keeps it open through Stage.
type EncryptedBackup struct {
	reader   io.ReaderAt
	header   [backupHeaderBytes]byte
	tag      [sha256.Size]byte
	slots    []byte
	document vault.SlotFile
	size     int64
}

func ReadEncryptedBackup(reader io.ReaderAt, size int64) (*EncryptedBackup, error) {
	b := &EncryptedBackup{reader: reader}
	if size < backupHeaderBytes+sha256.Size || size > backupHeaderBytes+vault.MaxSlotFileBytes+maxBackupDatabase+sha256.Size {
		return nil, vault.ErrFormat
	}
	if _, err := reader.ReadAt(b.header[:], 0); err != nil || string(b.header[:backupMagicBytes]) != backupMagic {
		return nil, vault.ErrFormat
	}
	slotSize := binary.BigEndian.Uint32(b.header[backupMagicBytes:])
	dbSize := binary.BigEndian.Uint64(b.header[backupMagicBytes+4:])
	if slotSize == 0 || slotSize > vault.MaxSlotFileBytes || dbSize == 0 || dbSize > maxBackupDatabase || dbSize%encvfs.PageSize != 0 ||
		size != backupHeaderBytes+int64(slotSize)+int64(dbSize)+sha256.Size {
		return nil, vault.ErrFormat
	}
	b.size = int64(dbSize)
	b.slots = make([]byte, slotSize)
	if _, err := reader.ReadAt(b.slots, backupHeaderBytes); err != nil {
		return nil, vault.ErrFormat
	}
	if _, err := reader.ReadAt(b.tag[:], size-sha256.Size); err != nil {
		return nil, vault.ErrFormat
	}
	doc, err := decodeBackupSlots(b.slots)
	if err != nil {
		return nil, err
	}
	b.document = doc
	return b, nil
}

// RecoveryContext projects untrusted metadata for the recovery prompt. The
// fingerprint binds the reviewed header and slots to the tag later verified
// against the complete ciphertext by Stage.
func (b *EncryptedBackup) RecoveryContext() (vault.SlotFileDescriptor, [32]byte) {
	descriptor := b.document.Descriptor()
	for i, slot := range b.document.Slots {
		if slot.Kind == vault.SlotRecovery && slot.WrappedKey.KeyVersion == b.document.RootKeyVersion {
			descriptor.Slots = []vault.SlotDescriptor{descriptor.Slots[i]}
			break
		}
	}
	digest := sha256.New()
	digest.Write(b.header[:])
	digest.Write(b.slots)
	digest.Write(b.tag[:])
	var fingerprint [32]byte
	digest.Sum(fingerprint[:0])
	return descriptor, fingerprint
}

func decodeBackupSlots(raw []byte) (vault.SlotFile, error) {
	doc, err := vault.DecodeSlotFile(raw)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if !doc.Encrypted || doc.Initializing || doc.Migration != nil || doc.Rotation != nil {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	return doc, nil
}

func backupMAC(root []byte, doc vault.SlotFile) (hash.Hash, error) {
	key, err := vault.DeriveKey(root, []byte(doc.VaultID), vault.PurposeLocalBackup)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	return hmac.New(sha256.New, key), nil
}

type backupReader struct {
	ctx context.Context
	io.Reader
}

func (r backupReader) Read(dst []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(dst)
}

// WriteEncryptedBackup streams a consistent, encrypted snapshot and its
// authenticated slot file. The destination must be staged by the caller until
// this returns successfully and the destination file has been synced.
func (o *Owner) WriteEncryptedBackup(ctx context.Context, stageParent string, slots []byte, dst io.Writer) (resultErr error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return vaultstore.ErrClosed
	}
	if !o.encrypted {
		return vault.ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	doc, err := decodeBackupSlots(slots)
	if err != nil {
		return err
	}
	store, ok := o.store.(vaultstore.RootRotationStore)
	if !ok {
		return vaultstore.ErrStorage
	}
	i := store.Identity()
	if doc.RootKeyID != i.Root.ID || doc.RootKeyVersion != i.Root.Version {
		return vaultstore.ErrIdentity
	}
	if err := o.root.With(func(key []byte) error {
		return vault.VerifySlotFile(key, doc, i.WorkspaceID, i.FileID, o.slotFloor)
	}); err != nil {
		return err
	}
	if err := o.importRootRotationFloors(doc); err != nil {
		return err
	}
	if err := o.checkRootRotationFloors(ctx, doc); err != nil {
		return err
	}
	stage, err := createBackupStage(stageParent)
	if err != nil {
		return err
	}
	defer func() {
		if os.RemoveAll(stage) != nil {
			resultErr = errors.Join(resultErr, vaultstore.ErrStorage)
		}
	}()
	path := filepath.Join(stage, backupDatabase)
	return o.root.With(func(key []byte) error {
		pageKey, err := vault.DeriveKey(key, []byte(i.WorkspaceID), vault.PurposeSQLite)
		if err != nil {
			return err
		}
		target, err := store.BeginEncryptedRootRotation(ctx, path, pageKey)
		if err != nil {
			return err
		}
		_, auditErr := target.Audit(ctx, o.rootRotationTransforms(ctx, i, i, key, key, false))
		if err := errors.Join(auditErr, target.Close()); err != nil {
			return err
		}
		db, err := os.Open(path)
		if err != nil {
			return vaultstore.ErrStorage
		}
		defer db.Close()
		info, err := db.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return vaultstore.ErrStorage
		}
		return writeBackup(ctx, dst, db, info.Size(), slots, doc, key)
	})
}

func writeBackup(ctx context.Context, dst io.Writer, db io.Reader, size int64, slots []byte, doc vault.SlotFile, key []byte) error {
	if size <= 0 || size > maxBackupDatabase || size%encvfs.PageSize != 0 {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	mac, err := backupMAC(key, doc)
	if err != nil {
		return err
	}
	var header [backupHeaderBytes]byte
	copy(header[:], backupMagic)
	binary.BigEndian.PutUint32(header[backupMagicBytes:], uint32(len(slots)))
	binary.BigEndian.PutUint64(header[backupMagicBytes+4:], uint64(size))
	w := io.MultiWriter(dst, mac)
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.Write(slots); err != nil {
		return err
	}
	if _, err := io.CopyN(w, backupReader{ctx, db}, size); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = io.MultiWriter(dst).Write(mac.Sum(nil))
	return err
}

func createBackupStage(parent string) (string, error) {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return "", vault.ErrFormat
	}
	stage, err := os.MkdirTemp(parent, ".vault-backup-")
	if err != nil {
		return "", vaultstore.ErrStorage
	}
	return stage, nil
}

// Stage consumes the recovery key and returns a newly created private directory
// containing wormhole.db and wormhole.db.slots. The caller owns publication.
// SQLite only opens after the slots and every ciphertext byte pass authentication.
func (b *EncryptedBackup) Stage(ctx context.Context, stageParent string, recoveryKey []byte) (_ string, resultErr error) {
	defer vault.Wipe(recoveryKey)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(recoveryKey) != 32 {
		return "", vault.ErrFormat
	}
	root, err := b.recoverRoot(recoveryKey)
	vault.Wipe(recoveryKey)
	if err != nil {
		return "", err
	}
	defer vault.Wipe(root)
	// Keep the root locked while processing the potentially large ciphertext.
	locked, err := securemem.New(32, true)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, locked.Close()) }()
	if err := locked.With(func(key []byte) error { copy(key, root); return nil }); err != nil {
		return "", err
	}
	vault.Wipe(root)
	stage, err := createBackupStage(stageParent)
	if err != nil {
		return "", err
	}
	retain := false
	defer func() {
		if !retain && os.RemoveAll(stage) != nil {
			resultErr = errors.Join(resultErr, vaultstore.ErrStorage)
		}
	}()
	path := filepath.Join(stage, backupDatabase)
	err = locked.With(func(key []byte) error {
		if err := b.extract(ctx, path, key); err != nil {
			return err
		}
		doc := b.document
		i := vaultstore.Identity{WorkspaceID: doc.VaultID, FileID: doc.FileID, Root: vaultstore.KeyRef{ID: doc.RootKeyID, Version: doc.RootKeyVersion}}
		o, err := Open(ctx, path, OpenOptions{Identity: i, Slots: doc}, append([]byte(nil), key...))
		if err != nil {
			return err
		}
		auditErr := o.checkRootRotationFloors(ctx, doc)
		if auditErr == nil {
			auditErr = o.VerifyRootRotation(ctx)
		}
		return errors.Join(auditErr, o.Close())
	})
	if err != nil {
		return "", err
	}
	if err := locked.Close(); err != nil {
		return "", err
	}
	if err := writeBackupSlots(path+".slots", b.slots); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	retain = true
	return stage, nil
}

func (b *EncryptedBackup) recoverRoot(recoveryKey []byte) ([]byte, error) {
	doc := b.document
	for _, slot := range doc.Slots {
		if slot.Kind != vault.SlotRecovery || slot.WrappedKey.KeyVersion != doc.RootKeyVersion {
			continue
		}
		root, err := vault.OpenRecoverySlot(doc.VaultID, slot, recoveryKey)
		if err != nil {
			continue
		}
		if err := vault.VerifySlotFile(root, doc, doc.VaultID, doc.FileID, 0); err == nil {
			return root, nil
		}
		vault.Wipe(root)
	}
	return nil, vault.ErrAuthentication
}

func (b *EncryptedBackup) extract(ctx context.Context, path string, key []byte) (resultErr error) {
	mac, err := backupMAC(key, b.document)
	if err != nil {
		return err
	}
	mac.Write(b.header[:])
	mac.Write(b.slots)
	offset := backupHeaderBytes + int64(len(b.slots))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return vaultstore.ErrStorage
	}
	defer func() {
		if file.Close() != nil {
			resultErr = errors.Join(resultErr, vaultstore.ErrStorage)
		}
	}()
	if _, err := io.CopyN(io.MultiWriter(file, mac), backupReader{ctx, io.NewSectionReader(b.reader, offset, b.size)}, b.size); err != nil {
		return err
	}
	if !hmac.Equal(b.tag[:], mac.Sum(nil)) {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if file.Sync() != nil {
		return vaultstore.ErrStorage
	}
	return ctx.Err()
}

func writeBackupSlots(path string, slots []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return vaultstore.ErrStorage
	}
	_, writeErr := file.Write(slots)
	if errors.Join(writeErr, file.Sync(), file.Close()) != nil {
		return vaultstore.ErrStorage
	}
	return nil
}
