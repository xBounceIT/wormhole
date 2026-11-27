package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The caller holds native workspace ownership for this entire operation and
// has quiesced all runtimes. This native-only primitive consumes the new key.
// OS-only source retirement is journaled separately from database phases.
// Ordinary Unprotected startup remains disabled until its native UI is wired.
func beginLocalRootRotation(ctx context.Context, source string, owner *localvault.Owner, slots []vault.Slot, key []byte, step func(string) error) error {
	return beginLocalRootRotationMode(ctx, source, owner, slots, key, step, false)
}

// encrypt is selected by native maintenance. Ordinary rotation retains the
// source storage mode and an encrypted source can never downgrade.
func beginLocalRootRotationMode(ctx context.Context, source string, owner *localvault.Owner, slots []vault.Slot, key []byte, step func(string) error, encrypt bool) error {
	defer vault.Wipe(key)
	if owner == nil || step == nil {
		return vault.ErrPolicy
	}
	intentAttempted := false
	err := prepareLocalRootRotation(ctx, source, slots, key, step, func(ctx context.Context, _ *legacyPublicationFS, j rootRotationJournal, slots []vault.Slot, next []byte, record rootRotationIntentWriter) (*localvault.RootRotationStage, error) {
		recordIntent := func(target vault.SlotFile, recovery vault.Envelope) error {
			intentAttempted = true
			return record(target, recovery)
		}
		return owner.StageRootRotationWithIntent(ctx, j.stagePath(), j.Source, slots, next, localvault.RootRotationPreparation{Encrypt: encrypt, Record: recordIntent})
	})
	if intentAttempted {
		return errors.Join(err, owner.Close())
	}
	return err
}

// The two native admissions share publication, inventory and recovery. The
// callback is internal Go authority, never an IPC field or a source-policy flag.
type rootRotationIntentWriter func(vault.SlotFile, vault.Envelope) error
type rootRotationStageFactory func(context.Context, *legacyPublicationFS, rootRotationJournal, []vault.Slot, []byte, rootRotationIntentWriter) (*localvault.RootRotationStage, error)

func prepareLocalRootRotation(ctx context.Context, source string, slots []vault.Slot, key []byte, step func(string) error, createStage rootRotationStageFactory) error {
	defer vault.Wipe(key)
	if step == nil || createStage == nil {
		return vault.ErrPolicy
	}
	f, err := openLegacyPublicationFS(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer f.root.Close()
	source, err = f.canonicalSource(source)
	if err != nil {
		return err
	}
	if err := requireNoRootRotation(source); err != nil {
		return err
	}
	doc, err := f.readSlots(source)
	if err != nil {
		return err
	}
	j := rootRotationJournal{Version: 1, ID: uuid.NewString(), Phase: vault.RotationPrepared, SourcePath: source, Source: doc}
	if len(doc.Slots) == 1 && doc.Slots[0].Kind == vault.SlotUnprotected {
		j.Version = 2
		j.Custody, err = inventoryRootRotationCustody(ctx, f, source, doc)
		if err != nil {
			return err
		}
	}
	if err := validateRootRotationCustody(j); err != nil {
		return err
	}
	var pendingRaw []byte
	stage, err := createStage(ctx, f, j, slots, bytes.Clone(key), func(target vault.SlotFile, recovery vault.Envelope) error {
		j.Phase, j.Target, j.SourceRecovery = vault.RotationStaging, target, recovery
		var err error
		pendingRaw, err = writeRootRotationIntent(ctx, f, j, key, step)
		return err
	})
	if err != nil {
		return err
	}
	_, err = publishRootRotationStage(ctx, f, &j, stage, key, pendingRaw, step)
	return err
}

func publishRootRotationStage(ctx context.Context, f *legacyPublicationFS, j *rootRotationJournal, stage *localvault.RootRotationStage, key, previous []byte, step func(string) error) (_ []byte, resultErr error) {
	retireSource := false
	defer func() {
		if retireSource {
			resultErr = errors.Join(resultErr, stage.RetireSource())
		}
		resultErr = errors.Join(resultErr, stage.Close())
	}()
	target, err := stage.Document()
	if err != nil {
		return nil, err
	}
	if previous == nil {
		j.Target = target
		_, j.SourceRecovery, err = stage.SealSourceRecovery(key)
		if err != nil {
			return nil, err
		}
	} else if !sameRootRotationDocument(j.Target, target) {
		return nil, vault.ErrAuthentication
	}
	if err := stage.CloseDatabases(); err != nil {
		return nil, err
	}
	if previous != nil {
		if err := step("copy-staged"); err != nil {
			return nil, err
		}
	}
	j.SourceDatabase, err = rootRotationFileFingerprint(ctx, f, j.SourcePath, true)
	if err != nil {
		return nil, fmt.Errorf("root_rotation_source_fingerprint: %w", err)
	}
	j.TargetDatabase, err = rootRotationFileFingerprint(ctx, f, j.stagePath(), true)
	if err != nil {
		return nil, fmt.Errorf("root_rotation_target_fingerprint: %w", err)
	}
	j.Phase = vault.RotationPrepared
	// After any journal-publication attempt, retire this source owner even if a
	// sync/rename acknowledgement is uncertain. Never unfreeze a live old writer.
	retireSource = true
	var raw []byte
	if previous == nil {
		raw, err = encodeRootRotationJournal(ctx, *j, key)
		if err == nil {
			err = f.writeFile(rootRotationJournalPath(j.SourcePath), raw, maxRootRotationJournalBytes, false)
		}
	} else {
		raw, err = replaceRootRotationJournal(ctx, f, *j, key, previous)
	}
	if err != nil {
		return nil, err
	}
	if err := step("journal-prepared"); err != nil {
		return nil, err
	}
	old, err := authenticateRootRotationJournal(*j, key)
	defer vault.Wipe(old)
	if err != nil {
		return nil, err
	}
	if err := writeRootRotationBarrier(f, *j, old); err != nil {
		return nil, err
	}
	if err := step("barrier-prepared"); err != nil {
		return nil, err
	}
	return raw, nil
}

// Ordinary entry points fail closed on any journal, including an invalid file
// type or a crash before the separate source-slot barrier was published.
func requireNoRootRotation(source string) error {
	_, err := os.Lstat(rootRotationJournalPath(source))
	if errors.Is(err, os.ErrNotExist) {
		if doc, readErr := readVaultSlotFile(source); readErr == nil && doc.Rotation != nil {
			return vault.ErrPolicy
		}
		return nil
	}
	return vault.ErrPolicy
}

func readRootRotationJournal(ctx context.Context, f *legacyPublicationFS, source string, key []byte) (rootRotationJournal, []byte, error) {
	raw, err := f.readFile(rootRotationJournalPath(source), maxRootRotationJournalBytes)
	if err != nil {
		return rootRotationJournal{}, nil, err
	}
	j, err := decodeRootRotationJournal(ctx, raw, key)
	if err != nil {
		return rootRotationJournal{}, nil, err
	}
	if j.SourcePath != source {
		return rootRotationJournal{}, nil, vault.ErrAuthentication
	}
	return j, raw, nil
}

// A scoped writer: the source document may change only by the deterministic
// rotation marker and sequence. No generic slot-write permission is weakened.
func writeRootRotationBarrier(f *legacyPublicationFS, j rootRotationJournal, old []byte) error {
	release, err := tryAcquireExclusiveFileLock(vaultSlotPath(j.SourcePath) + ".lock")
	if err != nil {
		return errVaultSlotConflict
	}
	defer release()
	current, err := f.readSlots(j.SourcePath)
	if err != nil {
		return err
	}
	if sameRootRotationDocument(current, j.Target) {
		if j.Phase != vault.RotationPublishing {
			return vault.ErrRollback
		}
		return nil
	}
	if current.Rotation == nil {
		if !sameRootRotationDocument(current, j.Source) {
			return vault.ErrAuthentication
		}
	} else {
		if current.Rotation.Phase.Step() > j.Phase.Step() {
			return vault.ErrRollback
		}
		expected, err := rootRotationBarrier(j, current.Rotation.Phase, old)
		if err != nil || !sameRootRotationDocument(current, expected) {
			return vault.ErrAuthentication
		}
	}
	next, err := rootRotationBarrier(j, j.Phase, old)
	if err != nil {
		return err
	}
	if sameRootRotationDocument(current, next) {
		return nil
	}
	raw, err := vault.EncodeSlotFile(old, next)
	if err != nil {
		return err
	}
	return f.writeSlots(j.SourcePath, raw)
}

func verifyRootRotationTarget(ctx context.Context, path string, doc vault.SlotFile, key []byte) (resultErr error) {
	owner, err := localvault.Open(ctx, path, localVaultOptions(doc), bytes.Clone(key))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, owner.Close()) }()
	return owner.VerifyRootRotation(ctx)
}

// Resume authenticates the new factors, both slot documents, the recovery
// envelope and every file before publishing. Only a pre-copy intent may reopen
// the authenticated source, solely to rebuild the unpublished encrypted stage.
// The caller retains native workspace ownership until this function returns.
func resumeLocalRootRotation(ctx context.Context, source string, key []byte, step func(string) error) error {
	if step == nil {
		return vault.ErrPolicy
	}
	f, err := openLegacyPublicationFS(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer f.root.Close()
	source, err = f.canonicalSource(source)
	if err != nil {
		return err
	}
	j, raw, err := readRootRotationJournal(ctx, f, source, key)
	if err != nil {
		if errors.Is(err, errVaultSlotMissing) {
			doc, slotErr := f.readSlots(source)
			if slotErr != nil {
				return slotErr
			}
			if doc.Rotation != nil || doc.Migration != nil || doc.Initializing || doc.FormatVersion != vault.SlotFileFormatVersion || doc.RootKeyVersion < 2 {
				return vault.ErrPolicy
			}
			// The final acknowledgement may have been lost after journal removal.
			// Authenticate and audit the published epoch before acknowledging it.
			return verifyRootRotationTarget(ctx, source, doc, key)
		}
		return err
	}
	old, err := authenticateRootRotationJournal(j, key)
	defer vault.Wipe(old)
	if err != nil {
		return err
	}
	if j.Phase == vault.RotationStaging {
		raw, err = resumeRootRotationIntent(ctx, f, &j, key, old, raw, step)
		if err != nil {
			return err
		}
	}
	if err := validateRootRotationFiles(ctx, f, j); err != nil {
		return err
	}
	// Validate the existing barrier before advancing an older journal: a replay
	// cannot be laundered into a newer phase by this controller.
	if err := writeRootRotationBarrier(f, j, old); err != nil {
		return err
	}
	for j.Phase != vault.RotationPublishing {
		if err := verifyRootRotationFile(ctx, f, source, j.SourceDatabase); err != nil {
			return err
		}
		if err := verifyRootRotationFile(ctx, f, j.stagePath(), j.TargetDatabase); err != nil {
			return err
		}
		if err := verifyRootRotationTarget(ctx, j.stagePath(), j.Target, key); err != nil {
			return err
		}
		if err := verifyRootRotationFile(ctx, f, j.stagePath(), j.TargetDatabase); err != nil {
			return err
		}
		if j.Phase == vault.RotationPrepared {
			j.Phase = vault.RotationRetiring
		} else {
			if err := retireRootRotationCustody(ctx, f, &j, key, &raw, step, nativeRootRotationCustodyAdapter()); err != nil {
				return err
			}
			j.Phase = vault.RotationPublishing
		}
		nextRaw, err := replaceRootRotationJournal(ctx, f, j, key, raw)
		if err != nil {
			return err
		}
		raw = nextRaw
		if err := step("journal-" + string(j.Phase)); err != nil {
			return err
		}
		if err := writeRootRotationBarrier(f, j, old); err != nil {
			return err
		}
		if err := step("barrier-" + string(j.Phase)); err != nil {
			return err
		}
	}
	if err := retireRootRotationCustody(ctx, f, &j, key, &raw, step, nativeRootRotationCustodyAdapter()); err != nil {
		return err
	}
	if err := finishRootRotationFiles(ctx, f, j, key, step); err != nil {
		return err
	}
	// Final slots become ordinary unlock authority only after old-copy removal.
	current, err := f.readSlots(source)
	if err != nil {
		return err
	}
	expected, err := rootRotationBarrier(j, vault.RotationPublishing, old)
	if err != nil {
		return err
	}
	if !sameRootRotationDocument(current, expected) && !sameRootRotationDocument(current, j.Target) {
		return vault.ErrAuthentication
	}
	// The authenticated target has new software slots only. Attempt native key
	// cleanup before removing the journal so a crash can replay the retirement.
	// A vault restored on another device must still be able to rotate its root.
	if retireRotatedBiometricCredentials(ctx, j.Source) {
		if err := step("biometric-custody-checked"); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	final, err := vault.EncodeSlotFile(key, j.Target)
	if err != nil {
		return err
	}
	if err := f.writeSlots(source, final); err != nil {
		return err
	}
	if err := step("slots-published"); err != nil {
		return err
	}
	before, err := f.lstat(rootRotationJournalPath(source))
	if err != nil {
		return err
	}
	currentRaw, err := f.readFile(rootRotationJournalPath(source), maxRootRotationJournalBytes)
	after, statErr := f.lstat(rootRotationJournalPath(source))
	if err != nil || statErr != nil || !os.SameFile(before, after) || !bytes.Equal(currentRaw, raw) {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := f.relative(rootRotationJournalPath(source))
	if err != nil {
		return err
	}
	if f.root.Remove(name) != nil || syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
		return errVaultSlotCommitUncertain
	}
	return step("journal-removed")
}

// Validate all present copies before advancing any journal/barrier. In the
// pre-publication phases a backup or missing stage cannot be a legitimate crash.
func validateRootRotationFiles(ctx context.Context, f *legacyPublicationFS, j rootRotationJournal) error {
	for _, item := range []struct {
		path        string
		fingerprint rootRotationFingerprint
	}{{j.stagePath(), j.TargetDatabase}, {j.backupPath(), j.SourceDatabase}} {
		present, err := legacyPublicationPresent(item.path, f)
		if err != nil {
			return err
		}
		if present {
			if err := verifyRootRotationFile(ctx, f, item.path, item.fingerprint); err != nil {
				return err
			}
		}
		if j.Phase != vault.RotationPublishing && (item.path == j.stagePath() && !present || item.path == j.backupPath() && present) {
			return vault.ErrAuthentication
		}
	}
	if j.Phase != vault.RotationPublishing {
		return verifyRootRotationFile(ctx, f, j.SourcePath, j.SourceDatabase)
	}
	return nil
}

func finishRootRotationFiles(ctx context.Context, f *legacyPublicationFS, j rootRotationJournal, key []byte, step func(string) error) error {
	stage, err := legacyPublicationPresent(j.stagePath(), f)
	if err != nil {
		return err
	}
	backup, err := legacyPublicationPresent(j.backupPath(), f)
	if err != nil {
		return err
	}
	source, err := legacyPublicationPresent(j.SourcePath, f)
	if err != nil {
		return err
	}
	if stage {
		if err := verifyRootRotationFile(ctx, f, j.stagePath(), j.TargetDatabase); err != nil {
			return err
		}
	}
	if backup {
		if err := verifyRootRotationFile(ctx, f, j.backupPath(), j.SourceDatabase); err != nil {
			return err
		}
	}
	sourceFinal := source && verifyRootRotationFile(ctx, f, j.SourcePath, j.TargetDatabase) == nil
	if source && !sourceFinal {
		if err := verifyRootRotationFile(ctx, f, j.SourcePath, j.SourceDatabase); err != nil {
			return err
		}
	}
	if !sourceFinal {
		if !stage || !source && !backup {
			return vault.ErrAuthentication
		}
		if err := verifyRootRotationTarget(ctx, j.stagePath(), j.Target, key); err != nil {
			return err
		}
		if err := verifyRootRotationFile(ctx, f, j.stagePath(), j.TargetDatabase); err != nil {
			return err
		}
		if source {
			if backup {
				a, ea := f.lstat(j.SourcePath)
				b, eb := f.lstat(j.backupPath())
				if ea != nil || eb != nil || !os.SameFile(a, b) {
					return vault.ErrAuthentication
				}
				if err := removeRootRotationFile(ctx, f, j.SourcePath, j.SourceDatabase); err != nil {
					return err
				}
			} else if err := moveLegacyPublicationFile(ctx, j.SourcePath, j.backupPath(), f); err != nil {
				return err
			}
		}
		if err := step("source-retired"); err != nil {
			return err
		}
		if err := moveLegacyPublicationFile(ctx, j.stagePath(), j.SourcePath, f); err != nil {
			return err
		}
		if err := step("database-published"); err != nil {
			return err
		}
	}
	if err := verifyRootRotationTarget(ctx, j.SourcePath, j.Target, key); err != nil {
		return err
	}
	if err := verifyRootRotationFile(ctx, f, j.SourcePath, j.TargetDatabase); err != nil {
		return err
	}
	if err := removeRootRotationFile(ctx, f, j.stagePath(), j.TargetDatabase); err != nil {
		return err
	}
	if err := removeRootRotationFile(ctx, f, j.backupPath(), j.SourceDatabase); err != nil {
		return err
	}
	return step("old-copies-removed")
}
