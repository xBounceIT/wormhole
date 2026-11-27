package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const (
	rootCustodyRetained   = "retained"
	rootCustodyIntent     = "intent"
	rootCustodyKeyRetired = "key-retired"
	rootCustodyRetired    = "retired"
)

// This ciphertext inventory lives only inside the new-root encrypted journal.
// Retiring is a database phase; it is never substituted for these receipts.
type rootRotationCustody struct {
	Platform  string                  `json:"platform"`
	SlotID    string                  `json:"slotId"`
	File      rootRotationFingerprint `json:"file"`
	Protected []byte                  `json:"protected"`
	State     string                  `json:"state"`
}

type rootRotationCustodyAdapter struct {
	open   vaultPlatformKeyTransform
	retire func(string, []byte) error
}

func nativeRootRotationCustodyAdapter() rootRotationCustodyAdapter {
	return rootRotationCustodyAdapter{unprotectFileContents, retireLegacyFileProtectionKey}
}

func validateRootRotationCustody(j rootRotationJournal) error {
	if j.Version == 1 {
		if j.Custody != nil {
			return vault.ErrFormat
		}
		for _, slot := range j.Source.Slots {
			switch slot.Kind {
			case vault.SlotPassword, vault.SlotRecovery, vault.SlotHello, vault.SlotTouchID:
			default:
				return vault.ErrPolicy
			}
		}
		return nil
	}
	c := j.Custody
	if j.Version != 2 || c == nil || c.Platform != runtime.GOOS || len(j.Source.Slots) != 1 || j.Source.Slots[0].Kind != vault.SlotUnprotected || c.SlotID != j.Source.Slots[0].ID || len(c.Protected) == 0 || len(c.Protected) > maxVaultUnprotectedKeyBlob || c.File.Bytes != int64(len(c.Protected)) {
		return vault.ErrFormat
	}
	digest := sha256.Sum256(c.Protected)
	if c.File.Digest != hex.EncodeToString(digest[:]) {
		return vault.ErrAuthentication
	}
	switch c.State {
	case rootCustodyRetained, rootCustodyIntent, rootCustodyKeyRetired, rootCustodyRetired:
	default:
		return vault.ErrFormat
	}
	if (j.Phase == vault.RotationPrepared && c.State != rootCustodyRetained) || (j.Phase == vault.RotationPublishing && c.State != rootCustodyRetired) {
		return vault.ErrFormat
	}
	_, _, err := vaultUnprotectedKeyIdentity(j.SourcePath, j.Source.VaultID, c.SlotID)
	return err
}

func retireRotatedBiometricCredentials(ctx context.Context, document vault.SlotFile) bool {
	attempted := false
	for _, slot := range document.Slots {
		if slot.Kind != vault.SlotHello && slot.Kind != vault.SlotTouchID {
			continue
		}
		attempted = true
		cleanup, cancel := context.WithTimeout(ctx, 3*time.Second)
		if slot.Kind == vault.SlotHello {
			platformRemoveVaultHello(cleanup, vaultHelloKeyName(document.VaultID, slot.ID))
		} else {
			factor, _ := platformVaultTouchID(cleanup, touchIDRemove, document.VaultID, slot.ID)
			vault.Wipe(factor)
		}
		cancel()
	}
	return attempted
}

// No ordinary OS unlock occurs here. The caller holds workspace ownership and
// later authenticates this exact document against its resident source owner.
func inventoryRootRotationCustody(ctx context.Context, f *legacyPublicationFS, source string, doc vault.SlotFile) (*rootRotationCustody, error) {
	if len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected {
		return nil, vault.ErrPolicy
	}
	path, _, err := vaultUnprotectedKeyIdentity(source, doc.VaultID, doc.Slots[0].ID)
	if err != nil {
		return nil, err
	}
	protected, err := f.readFile(path, maxVaultUnprotectedKeyBlob)
	if err != nil {
		return nil, err
	}
	if err := verifyRootRotationCustodyMaterial(ctx, source, doc, protected, nativeRootRotationCustodyAdapter()); err != nil {
		return nil, err
	}
	current, err := f.readFile(path, maxVaultUnprotectedKeyBlob)
	if err != nil || !bytes.Equal(current, protected) {
		return nil, vault.ErrAuthentication
	}
	digest := sha256.Sum256(protected)
	return &rootRotationCustody{Platform: runtime.GOOS, SlotID: doc.Slots[0].ID, File: rootRotationFingerprint{int64(len(protected)), hex.EncodeToString(digest[:])}, Protected: protected, State: rootCustodyRetained}, nil
}

func verifyRootRotationCustodyMaterial(ctx context.Context, source string, doc vault.SlotFile, protected []byte, adapter rootRotationCustodyAdapter) error {
	key, err := openRootRotationCustodyMaterial(ctx, source, doc, protected, adapter)
	defer vault.Wipe(key)
	return err
}

// Native forward staging only. This key is consumed by the purpose-limited
// source scope; it never becomes an ordinary owner or a transport result.
func openRootRotationCustodyMaterial(ctx context.Context, source string, doc vault.SlotFile, protected []byte, adapter rootRotationCustodyAdapter) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if adapter.open == nil || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected {
		return nil, vault.ErrPolicy
	}
	path, header, err := vaultUnprotectedKeyIdentity(source, doc.VaultID, doc.Slots[0].ID)
	if err != nil {
		return nil, err
	}
	plaintext, err := adapter.open(path, protected)
	defer vault.Wipe(plaintext)
	if err != nil || len(plaintext) != len(header)+32 || !bytes.Equal(plaintext[:len(header)], header) {
		return nil, vault.ErrAuthentication
	}
	key, err := vault.OpenUnprotectedSlot(doc.VaultID, doc.Slots[0], plaintext[len(header):])
	if err != nil {
		vault.Wipe(key)
		return nil, err
	}
	if err := vault.VerifySlotFile(key, doc, doc.VaultID, doc.FileID, doc.Sequence); err != nil {
		vault.Wipe(key)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		vault.Wipe(key)
		return nil, err
	}
	return key, nil
}

// Compare-and-replace the exact encrypted journal under the workspace lease.
// A failed acknowledgement is left for restart; callers never infer a receipt.
func replaceRootRotationJournal(ctx context.Context, f *legacyPublicationFS, j rootRotationJournal, key, previous []byte) ([]byte, error) {
	next, err := encodeRootRotationJournal(ctx, j, key)
	if err != nil {
		return nil, err
	}
	current, err := f.readFile(rootRotationJournalPath(j.SourcePath), maxRootRotationJournalBytes)
	if err != nil || !bytes.Equal(current, previous) {
		return nil, vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.writeFile(rootRotationJournalPath(j.SourcePath), next, maxRootRotationJournalBytes, true); err != nil {
		return nil, err
	}
	return next, nil
}

func retireRootRotationCustody(ctx context.Context, f *legacyPublicationFS, j *rootRotationJournal, key []byte, raw *[]byte, step func(string) error, adapter rootRotationCustodyAdapter) error {
	if err := validateRootRotationCustody(*j); err != nil {
		return err
	}
	if j.Custody == nil {
		return nil
	}
	if step == nil || adapter.open == nil || adapter.retire == nil || (j.Phase != vault.RotationRetiring && j.Phase != vault.RotationPublishing) {
		return vault.ErrPolicy
	}
	c := j.Custody
	path, _, err := vaultUnprotectedKeyIdentity(j.SourcePath, j.Source.VaultID, c.SlotID)
	if err != nil {
		return err
	}
	read := func(required bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := f.readFile(path, maxVaultUnprotectedKeyBlob)
		if errors.Is(err, errVaultSlotMissing) && !required {
			return nil
		}
		if err != nil || !bytes.Equal(current, c.Protected) {
			return vault.ErrAuthentication
		}
		return nil
	}
	persist := func(state, event string) error {
		// Do not retain an unacknowledged in-memory intent on write failure.
		// A caller retry must reload any uncertain publication from disk.
		pending := *c
		pending.State = state
		journal := *j
		journal.Custody = &pending
		next, err := replaceRootRotationJournal(ctx, f, journal, key, *raw)
		if err != nil {
			return err
		}
		c.State = state
		*raw = next
		return step(event)
	}
	if c.State == rootCustodyRetained {
		if err := read(true); err != nil {
			return err
		}
		if err := verifyRootRotationCustodyMaterial(ctx, j.SourcePath, j.Source, c.Protected, adapter); err != nil {
			return err
		}
		if err := read(true); err != nil {
			return err
		}
		if err := persist(rootCustodyIntent, "custody-intent"); err != nil {
			return err
		}
	}
	if c.State == rootCustodyIntent {
		if err := read(false); err != nil {
			return err
		}
		// Only durable intent permits an absent OS key to acknowledge a retry.
		if err := adapter.retire(path, c.Protected); err != nil {
			return errVaultUnprotectedKeyStorage
		}
		if err := step("custody-key-deleted"); err != nil {
			return err
		}
		if err := persist(rootCustodyKeyRetired, "custody-key-retired"); err != nil {
			return err
		}
	}
	if c.State == rootCustodyKeyRetired {
		if err := read(false); err != nil {
			return err
		}
		if err := adapter.retire(path, c.Protected); err != nil {
			return errVaultUnprotectedKeyStorage
		}
		if err := removeRootRotationCustodyFile(ctx, f, path, c.Protected); err != nil {
			return err
		}
		if err := step("custody-file-removed"); err != nil {
			return err
		}
		if err := persist(rootCustodyRetired, "custody-file-retired"); err != nil {
			return err
		}
	}
	// Revalidate even when resuming publishing or a lost receipt acknowledgement.
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := f.readFile(path, maxVaultUnprotectedKeyBlob); !errors.Is(err, errVaultSlotMissing) {
		return vault.ErrAuthentication
	}
	if err := adapter.retire(path, c.Protected); err != nil {
		return errVaultUnprotectedKeyStorage
	}
	return ctx.Err()
}

func removeRootRotationCustodyFile(ctx context.Context, f *legacyPublicationFS, path string, protected []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := f.relative(path)
	if err != nil {
		return err
	}
	before, err := f.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} // Caller has authenticated intent.
	if err != nil || !before.Mode().IsRegular() {
		return vault.ErrAuthentication
	}
	current, err := f.readFile(path, maxVaultUnprotectedKeyBlob)
	if err != nil || !bytes.Equal(current, protected) {
		return vault.ErrAuthentication
	}
	after, err := f.root.Lstat(name)
	if err != nil || !os.SameFile(before, after) {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.root.Remove(name); err != nil {
		return errVaultUnprotectedKeyStorage
	}
	if err := syncLegacyPublicationRoot(f.root); err != nil {
		return errVaultUnprotectedKeyStorage
	}
	return f.verify()
}
