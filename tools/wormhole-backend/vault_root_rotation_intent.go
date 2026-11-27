package main

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func writeRootRotationIntent(ctx context.Context, f *legacyPublicationFS, j rootRotationJournal, key []byte, step func(string) error) ([]byte, error) {
	// Reserve the namespace by recording a fresh ID while all its paths are
	// absent. Only this authenticated intent can later discard a partial copy.
	for _, path := range []string{j.stagePath(), j.backupPath()} {
		if err := requireAbsentRotationArtifacts(f, path); err != nil {
			return nil, err
		}
	}
	raw, err := encodeRootRotationJournal(ctx, j, key)
	if err != nil {
		return nil, err
	}
	old, err := authenticateRootRotationJournal(j, key)
	defer vault.Wipe(old)
	if err != nil {
		return nil, err
	}
	// Reject an intent whose slot barrier would exceed the slot-file bound.
	if _, err := rootRotationBarrier(j, vault.RotationStaging, old); err != nil {
		return nil, err
	}
	if err := f.writeFile(rootRotationJournalPath(j.SourcePath), raw, maxRootRotationJournalBytes, false); err != nil {
		return nil, err
	}
	if err := step("intent-journal"); err != nil {
		return nil, err
	}
	if err := writeRootRotationBarrier(f, j, old); err != nil {
		return nil, err
	}
	if err := step("intent-slots"); err != nil {
		return nil, err
	}
	return raw, nil
}

var rotationSQLiteSuffixes = [...]string{"", "-journal", "-wal", "-shm"}

func requireAbsentRotationArtifacts(f *legacyPublicationFS, path string) error {
	for _, suffix := range rotationSQLiteSuffixes {
		_, err := f.lstat(path + suffix)
		if err == nil {
			return errVaultSlotConflict
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errVaultSlotStorage
		}
	}
	return nil
}

func resumeRootRotationIntent(ctx context.Context, f *legacyPublicationFS, j *rootRotationJournal, key, old, raw []byte, step func(string) error) (_ []byte, resultErr error) {
	if err := requireAbsentRotationArtifacts(f, j.backupPath()); err != nil {
		return nil, err
	}
	if err := writeRootRotationBarrier(f, *j, old); err != nil {
		return nil, err
	}
	// Reconfirm the barrier's directory entry if the previous process did not
	// receive the durability acknowledgement for its atomic slot replacement.
	if syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
		return nil, errVaultSlotCommitUncertain
	}
	owner, err := localvault.Open(ctx, j.SourcePath, localVaultOptions(j.Source), bytes.Clone(old))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, owner.Close()) }()
	reconcile := func(next vault.SlotFile, _ vault.Envelope) error {
		if !sameRootRotationDocument(next, j.Target) {
			return vault.ErrAuthentication
		}
		return discardRootRotationPartialStage(ctx, f, j.stagePath())
	}
	prep := localvault.RootRotationPreparation{Encrypt: true, Pending: &j.Target, Record: reconcile}
	stage, err := owner.StageRootRotationWithIntent(ctx, j.stagePath(), j.Source, j.Target.Slots, bytes.Clone(key), prep)
	if err != nil {
		return nil, err
	}
	return publishRootRotationStage(ctx, f, j, stage, key, raw, step)
}

func discardRootRotationPartialStage(ctx context.Context, f *legacyPublicationFS, path string) error {
	if err := f.verify(); err != nil {
		return err
	}
	type artifact struct {
		name string
		info os.FileInfo
	}
	var owned []artifact
	for _, suffix := range rotationSQLiteSuffixes {
		name, err := f.relative(path + suffix)
		if err != nil {
			return err
		}
		info, err := f.root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errVaultSlotStorage
		}
		owned = append(owned, artifact{name, info})
	}
	for _, item := range owned {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := f.root.Lstat(item.name)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(item.info, current) {
			return vault.ErrAuthentication
		}
		if err := f.root.Remove(item.name); err != nil {
			return errVaultSlotStorage
		}
	}
	if len(owned) != 0 && syncLegacyPublicationRoot(f.root) != nil {
		return errVaultSlotCommitUncertain
	}
	return f.verify()
}
