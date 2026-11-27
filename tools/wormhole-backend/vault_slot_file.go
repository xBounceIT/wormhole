package main

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	errVaultSlotMissing         = errors.New("vault_slot_file_missing")
	errVaultSlotStorage         = errors.New("vault_slot_storage_unavailable")
	errVaultSlotConflict        = errors.New("vault_slot_file_conflict")
	errVaultSlotCommitUncertain = errors.New("vault_slot_commit_uncertain")
)

func vaultSlotPath(databasePath string) string { return databasePath + ".slots" }

func readVaultSlotFile(databasePath string) (vault.SlotFile, error) {
	raw, err := readVaultSlotBytes(databasePath)
	if err != nil {
		return vault.SlotFile{}, err
	}
	return vault.DecodeSlotFile(raw)
}

func readVaultSlotBytes(databasePath string) ([]byte, error) {
	path := vaultSlotPath(databasePath)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errVaultSlotMissing
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, errVaultSlotStorage
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errVaultSlotStorage
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, vault.MaxSlotFileBytes+1))
	if err != nil {
		return nil, errVaultSlotStorage
	}
	return raw, nil
}

// The caller owns an unlocked vault and fresh-auth authorization. This is a
// persistence primitive, deliberately not a renderer IPC operation. A new file
// uses expectedSequence=0; updates authenticate the old file before replacing it.
func writeVaultSlotFile(databasePath string, key []byte, next vault.SlotFile, expectedSequence uint64) error {
	if err := requireNoRootRotation(databasePath); err != nil {
		return err
	}
	if next.Rotation != nil || next.Migration != nil && next.Migration.Phase == vault.MigrationPublishing {
		return vault.ErrPolicy
	}
	if expectedSequence == math.MaxUint64 || next.Sequence != expectedSequence+1 {
		return errVaultSlotConflict
	}
	path := vaultSlotPath(databasePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errVaultSlotStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errVaultSlotConflict
	}
	defer release()
	current, err := readVaultSlotFile(databasePath)
	if errors.Is(err, errVaultSlotMissing) {
		if expectedSequence != 0 {
			return errVaultSlotConflict
		}
	} else if err != nil {
		return err
	} else {
		if current.Rotation != nil || current.Migration != nil && current.Migration.Phase == vault.MigrationPublishing {
			return vault.ErrPolicy
		}
		if current.Sequence != expectedSequence {
			return errVaultSlotConflict
		}
		if next.FormatVersion < current.FormatVersion {
			return vault.ErrRollback
		}
		if err := vault.VerifySlotFile(key, current, next.VaultID, next.FileID, expectedSequence); err != nil {
			return err
		}
		if next.ProfileSequence < current.ProfileSequence || next.FileEpoch < current.FileEpoch {
			return vault.ErrRollback
		}
		// Ordinary slot updates cannot publish an incomplete migration or rebind
		// its source. Publication needs its own completed retirement protocol.
		if (current.Migration == nil) != (next.Migration == nil) || (current.Migration != nil && current.Migration.Binding != next.Migration.Binding) {
			return vault.ErrPolicy
		}
		if current.Migration != nil && current.Migration.Phase == vault.MigrationRetiring && next.Migration.Phase != vault.MigrationRetiring {
			return vault.ErrPolicy
		}
		if (!current.Initializing && next.Initializing) || next.RootKeyVersion < current.RootKeyVersion || (next.RootKeyID != current.RootKeyID && next.RootKeyVersion <= current.RootKeyVersion) {
			return vault.ErrRollback
		}
		marks := make(map[string]uint64, len(next.Nodes))
		for _, mark := range next.Nodes {
			marks[mark.NodeID] = mark.Revision
		}
		for _, mark := range current.Nodes {
			if marks[mark.NodeID] < mark.Revision {
				return vault.ErrRollback
			}
		}
		anchors := make(map[string]vault.VPNSSOHighWater, len(next.VPNSSO))
		for _, mark := range next.VPNSSO {
			anchors[mark.ScopeID] = mark
		}
		for _, mark := range current.VPNSSO {
			if !anchors[mark.ScopeID].Advances(mark) {
				return vault.ErrRollback
			}
		}
		tunnels := make(map[string]uint64, len(next.Tunnels))
		for _, mark := range next.Tunnels {
			tunnels[mark.TunnelID] = mark.Revision
		}
		for _, mark := range current.Tunnels {
			if tunnels[mark.TunnelID] < mark.Revision {
				return vault.ErrRollback
			}
		}
	}
	raw, err := vault.EncodeSlotFile(key, next)
	if err != nil {
		return err
	}
	if err := writePrivateFileAtomic(path, raw); err != nil {
		if privateFileDestinationWasReplaced(err) {
			return errVaultSlotCommitUncertain
		}
		return errVaultSlotStorage
	}
	return nil
}

func describeVaultSlots(databasePath string) (*vault.SlotFileDescriptor, error) {
	document, err := readVaultSlotFile(databasePath)
	if errors.Is(err, errVaultSlotMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	descriptor := document.Descriptor()
	return &descriptor, nil
}
