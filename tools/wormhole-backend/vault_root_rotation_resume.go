package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This descriptor is an unauthenticated hint for the protected factor prompt.
// Paths, old-source recovery and policy never become startup metadata.
type rootRotationStartupHint struct {
	source   string
	document vault.SlotFile
}

func discoverRootRotation(ctx context.Context, source string) (*rootRotationStartupHint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !legacyPublicationFilename(filepath.Base(source)) {
		return nil, vault.ErrFormat
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(source))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errVaultSlotStorage
	}
	f, err := openLegacyPublicationFS(directory)
	if err != nil {
		return nil, err
	}
	defer f.root.Close()
	source, err = f.canonicalSource(source)
	if err != nil {
		return nil, err
	}
	raw, err := f.readFile(rootRotationJournalPath(source), maxRootRotationJournalBytes)
	if errors.Is(err, errVaultSlotMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	capsule, err := decodeRootRotationCapsule(raw)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &rootRotationStartupHint{source: source, document: capsule.Document}, nil
}

// The operation is admitted only by the native isolated-maintenance launch.
// Neither the app renderer nor a wire field can grant Chromium quiescence.
func (h *vaultFoundationHandler) resumeRootRotation(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if !h.migrationQuiesced || h.owner != nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.databasePath == "" {
		return nil, vaultwire.ErrProtocol
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return nil, err
	}
	input, err := decodeVaultUnlock(payload)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil || floor != vault.Default && floor != vault.Standard {
		return nil, vault.ErrPolicy
	}
	hint, err := discoverRootRotation(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	if hint == nil {
		return nil, vault.ErrAuthentication
	}
	release, err := acquireWorkspaceOwnership(hint.source, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if h.owner == nil && h.rotationMaterial == nil {
			release()
		} else {
			h.releaseWorkspace = release
		}
	}()
	key, err := openVaultUnlockFactor(ctx, hint.document, &input)
	defer vault.Wipe(key)
	if err != nil {
		return nil, err
	}
	locked, err := securemem.New(32, true)
	if err != nil {
		return nil, err
	}
	h.rotationMaterial = locked
	err = locked.With(func(storage []byte) error {
		copy(storage, key)
		vault.Wipe(key)
		if err := resumeLocalRootRotation(ctx, hint.source, storage, func(string) error { return ctx.Err() }); err != nil {
			return h.retire(err)
		}
		final, err := readVaultSlotFile(hint.source)
		if err != nil {
			return h.retire(err)
		}
		if !sameRootRotationDocument(final, hint.document) {
			return h.retire(vault.ErrAuthentication)
		}
		h.owner, err = openVaultFiles(ctx, hint.source, final, storage)
		if err != nil {
			return h.retire(err)
		}
		h.databasePath = hint.source
		return nil
	})
	if closeErr := locked.Close(); closeErr != nil {
		return nil, h.retire(errors.Join(err, closeErr))
	}
	h.rotationMaterial = nil
	if err != nil {
		return nil, err
	}
	return marshalLocalVaultUnlock(h.owner)
}
