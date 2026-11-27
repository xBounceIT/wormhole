package main

import (
	"context"
	"errors"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

func (o *scopedVaultBitwardenInstaller) beginIntent(ctx context.Context, id string, expected uint64) error {
	o.intent = localvault.BitwardenInstallationIntent{ID: id, Namespace: o.namespace, InstallationRevision: expected, Phase: "prepared"}
	version, err := o.Owner.BeginBitwardenInstallationIntent(ctx, o.intent)
	if err == nil {
		o.intentRevision = version
	}
	return err
}

func (o *scopedVaultBitwardenInstaller) advanceIntent(ctx context.Context, phase string) error {
	value := o.intent
	value.Phase = phase
	version, err := o.Owner.AdvanceBitwardenInstallationIntent(ctx, value, o.intentRevision)
	if err == nil {
		o.intent = value
		o.intentRevision = version
	}
	return err
}

func (o *scopedVaultBitwardenInstaller) recoverIntent(ctx context.Context, base *os.Root) error {
	return o.Owner.ResolveBitwardenInstallationIntent(ctx, o.namespace, func(ctx context.Context, intent localvault.BitwardenInstallationIntent, referenced bool) error {
		return reconcileVaultBitwardenIntent(ctx, base, intent, referenced)
	})
}

func recoverVaultBitwardenIntent(ctx context.Context, owner *localvault.Owner, database string) error {
	return owner.ResolveBitwardenInstallationIntent(ctx, vaultBitwardenDatabaseNamespace(database), func(ctx context.Context, intent localvault.BitwardenInstallationIntent, referenced bool) error {
		base, err := openVaultBitwardenInstallRoot(database, 1, true)
		if err != nil {
			return errVaultExtensionCleanup
		}
		defer base.Close()
		return reconcileVaultBitwardenIntent(ctx, base, intent, referenced)
	})
}

// Unknown outcomes remain recorded. A prepared phase proves no directory
// ownership. Created proves only stage ownership; published proves only final
// ownership. Neither authorizes deleting an active or retired installation.
func reconcileVaultBitwardenIntent(ctx context.Context, base *os.Root, intent localvault.BitwardenInstallationIntent, referenced bool) error {
	if ctx.Err() != nil || base == nil || !vaultCredentialID(intent.ID) {
		return errVaultExtensionCleanup
	}
	stage := ".stage-" + intent.ID
	stageInfo, stageErr := base.Lstat(stage)
	_, finalErr := base.Lstat(intent.ID)
	stageMissing, finalMissing := errors.Is(stageErr, os.ErrNotExist), errors.Is(finalErr, os.ErrNotExist)
	switch intent.Phase {
	case "prepared":
		if !stageMissing || !finalMissing {
			return errVaultExtensionCleanup
		}
	case "created":
		if !finalMissing || referenced {
			return errVaultExtensionCleanup
		}
		if !stageMissing {
			if stageErr != nil || !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 {
				return errVaultExtensionCleanup
			}
			if base.RemoveAll(stage) != nil {
				return errVaultExtensionCleanup
			}
		}
	case "published":
		if !stageMissing {
			return errVaultExtensionCleanup
		}
		if !referenced {
			if err := removeVaultBitwardenRetiredPackage(ctx, base, intent.ID); err != nil {
				return err
			}
		}
	default:
		return errVaultExtensionCleanup
	}
	if syncPrivateFileDirectory(base.Name()) != nil || ctx.Err() != nil {
		return errVaultExtensionCleanup
	}
	return nil
}
