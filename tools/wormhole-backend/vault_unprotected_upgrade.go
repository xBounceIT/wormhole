package main

import (
	"bytes"
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The native enrollment controller must confirm the replacement groups first,
// own the workspace lease, and retain scope as a cleanup obligation until Close
// succeeds. No ordinary source Owner is adopted, including under Standard.
func beginUnprotectedRootUpgrade(ctx context.Context, source string, scope *localvault.UnprotectedRootUpgrade, slots []vault.Slot, key []byte, step func(string) error) error {
	defer vault.Wipe(key)
	if scope == nil || step == nil {
		return vault.ErrPolicy
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return err
	}
	if floor != vault.Default && floor != vault.Standard {
		return vault.ErrPolicy
	}
	if err := requireNoSharedWorkspace(source); err != nil {
		return err
	}
	if err := requireNoLegacyMigrationSetup(source); err != nil {
		return err
	}
	return prepareLocalRootRotation(ctx, source, slots, key, step, func(ctx context.Context, fs *legacyPublicationFS, j rootRotationJournal, slots []vault.Slot, next []byte, _ rootRotationIntentWriter) (*localvault.RootRotationStage, error) {
		defer vault.Wipe(next)
		doc := j.Source
		if len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected || j.Custody == nil {
			return nil, vault.ErrPolicy
		}
		path, _, err := vaultUnprotectedKeyIdentity(j.SourcePath, doc.VaultID, doc.Slots[0].ID)
		if err != nil {
			return nil, err
		}
		// Reuse the exact inventoried preimage and canonical path; revalidate the
		// current file after the OS operation before opening any source database.
		protected := j.Custody.Protected
		old, err := openRootRotationCustodyMaterial(ctx, j.SourcePath, doc, protected, nativeRootRotationCustodyAdapter())
		defer vault.Wipe(old)
		if err != nil {
			return nil, err
		}
		current, err := fs.readFile(path, maxVaultUnprotectedKeyBlob)
		if err != nil || !bytes.Equal(current, protected) {
			return nil, vault.ErrAuthentication
		}
		return scope.Stage(ctx, j.SourcePath, j.stagePath(), localVaultOptions(doc), slots, old, next)
	})
}
