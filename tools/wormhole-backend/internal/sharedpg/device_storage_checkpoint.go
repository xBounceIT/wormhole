package sharedpg

import (
	"context"
	"math"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// AdvanceDeviceStorageCheckpoints prepares, but never publishes, the device's
// original enrollment file. Authentication slots and account facts stay intact;
// no second password capsule is created for personal browser state. The native
// caller must publish with a file CAS and advance the protected startup floor.
func AdvanceDeviceStorageCheckpoints(ctx context.Context, key, previous []byte, vaultID, fileID string, minimumSequence uint64, next vault.SlotFile) ([]byte, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	old, envelope, err := DecodeDeviceEnrollmentFile(previous)
	if err != nil {
		return nil, err
	}
	metadata, err := OpenDeviceEnrollment(key, old, vaultID, fileID, minimumSequence, envelope)
	if err != nil {
		return nil, err
	}
	if old.Sequence == math.MaxUint64 || next.Sequence != old.Sequence+1 || next.FormatVersion < old.FormatVersion || next.ProfileSequence < old.ProfileSequence {
		return nil, vault.ErrRollback
	}
	// Normalize only fields this operation may advance. Everything else, including
	// the slot ciphertexts and root/file identity, must remain byte-exact.
	fixed := next
	fixed.FormatVersion, fixed.Sequence, fixed.ProfileSequence = old.FormatVersion, old.Sequence, old.ProfileSequence
	fixed.Nodes, fixed.Tunnels, fixed.VPNSSO = old.Nodes, old.Tunnels, old.VPNSSO
	fixed.Authentication, fixed.KeyCheck = old.Authentication, old.KeyCheck
	if !reflect.DeepEqual(fixed, old) {
		return nil, vault.ErrAuthentication
	}
	nodes := make(map[string]uint64, len(next.Nodes))
	for _, mark := range next.Nodes {
		nodes[mark.NodeID] = mark.Revision
	}
	for _, mark := range old.Nodes {
		if nodes[mark.NodeID] < mark.Revision {
			return nil, vault.ErrRollback
		}
	}
	tunnels := make(map[string]uint64, len(next.Tunnels))
	for _, mark := range next.Tunnels {
		tunnels[mark.TunnelID] = mark.Revision
	}
	for _, mark := range old.Tunnels {
		if tunnels[mark.TunnelID] < mark.Revision {
			return nil, vault.ErrRollback
		}
	}
	sso := make(map[string]vault.VPNSSOHighWater, len(next.VPNSSO))
	for _, mark := range next.VPNSSO {
		sso[mark.ScopeID] = mark
	}
	for _, mark := range old.VPNSSO {
		if !sso[mark.ScopeID].Advances(mark) {
			return nil, vault.ErrRollback
		}
	}
	raw, err := vault.EncodeSlotFile(key, next)
	if err != nil {
		return nil, err
	}
	next, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return nil, err
	}
	metadata.record.SlotSequence = next.Sequence
	envelope, err = sealDeviceEnrollmentRecord(key, next, metadata.record)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return EncodeDeviceEnrollmentFile(key, next, envelope)
}
