package main

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Only the native completed-retirement protocol calls this. Generic slot writes
// must continue to forbid publishing or clearing a migration marker.
func writeLegacyPublicationSlots(path string, key []byte, expected, next vault.SlotFile, supplied ...*legacyPublicationFS) error {
	f, closeRoot, rootErr := borrowLegacyPublicationFS(path, supplied)
	if rootErr != nil {
		return rootErr
	}
	defer closeRoot()
	if expected.Sequence == math.MaxUint64 || next.Sequence != expected.Sequence+1 || vault.VerifySlotFile(key, expected, next.VaultID, next.FileID, expected.Sequence) != nil || expected.Migration == nil {
		return vault.ErrPolicy
	}
	before, after := expected, next
	before.Authentication, after.Authentication = nil, nil
	after.Sequence = before.Sequence
	switch expected.Migration.Phase {
	case vault.MigrationRetiring:
		if next.Migration == nil || next.Migration.Phase != vault.MigrationPublishing || next.Migration.Binding != expected.Migration.Binding || next.ProfileSequence < expected.ProfileSequence {
			return vault.ErrPolicy
		}
		floors := map[string]uint64{}
		for _, mark := range next.Nodes {
			floors[mark.NodeID] = mark.Revision
		}
		for _, mark := range expected.Nodes {
			if floors[mark.NodeID] < mark.Revision {
				return vault.ErrRollback
			}
		}
		after.Migration, after.ProfileSequence, after.Nodes = before.Migration, before.ProfileSequence, before.Nodes
	case vault.MigrationPublishing:
		if next.Migration != nil {
			return vault.ErrPolicy
		}
		after = vault.MigrationSlotFile(after, before.Migration)
	default:
		return vault.ErrPolicy
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		return vault.ErrPolicy
	}
	raw, err := vault.EncodeSlotFile(key, next)
	if err != nil {
		return err
	}
	release, err := tryAcquireExclusiveFileLock(vaultSlotPath(path) + ".lock")
	if err != nil {
		return errVaultSlotConflict
	}
	defer release()
	current, err := f.readSlots(path)
	if err != nil {
		return err
	}
	a, _ = json.Marshal(current)
	b, _ = json.Marshal(expected)
	if !bytes.Equal(a, b) {
		return errVaultSlotConflict
	}
	if err := f.writeSlots(path, raw); err != nil {
		return err
	}

	return nil
}
