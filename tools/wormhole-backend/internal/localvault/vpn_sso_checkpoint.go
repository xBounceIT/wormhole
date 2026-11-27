package localvault

import (
	"context"
	"math"
	"reflect"
	"sort"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func vpnSSOFloorFromMark(mark vault.VPNSSOHighWater) VPNSSOFloor {
	c := VPNSSOCheckpoint{Revision: mark.Revision, Deleted: mark.Deleted}
	copy(c.Digest[:], mark.Digest)
	return VPNSSOFloor{Checkpoint: c, RowVersion: mark.RowVersion}
}

// PersistVPNSSOCheckpoints authenticates the current native slot document and
// merges every complete/partial observation, including failed-read observations.
// The callback is a Go-owned atomic slot writer, not a renderer callback. It
// cannot reenter Owner or retain key. No fresh factor is needed: authentication
// slots/policy are unchanged. It remains available after policy denial.
// Local DB+slot whole-file replay retains the documented local rollback limit.
func (o *Owner) PersistVPNSSOCheckpoints(ctx context.Context, document vault.SlotFile, persist func(vault.SlotFile, []byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if persist == nil {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.closed {
		return vaultstore.ErrClosed
	}
	if document.Rotation != nil {
		return vault.ErrPolicy
	}
	i := o.store.Identity()
	if document.RootKeyID != i.Root.ID || document.RootKeyVersion != i.Root.Version || document.Encrypted != o.encrypted {
		return vault.ErrAuthentication
	}
	return o.root.With(func(key []byte) error {
		if err := vault.VerifySlotFile(key, document, i.WorkspaceID, i.FileID, o.slotFloor); err != nil {
			return err
		}
		for _, mark := range document.VPNSSO {
			if _, err := o.importVPNSSOFloor(mark.ScopeID, vpnSSOFloorFromMark(mark)); err != nil {
				return err
			}
		}
		for _, mark := range document.Tunnels {
			if o.tunnelFloors == nil {
				o.tunnelFloors = make(map[string]uint64)
			}
			o.tunnelFloors[mark.TunnelID] = max(o.tunnelFloors[mark.TunnelID], mark.Revision)
		}
		next := document
		next.ProfileSequence = max(document.ProfileSequence, o.profileFloor)
		nodes := make(map[string]uint64, len(document.Nodes)+len(o.vpnSSONodeFloors))
		for _, mark := range document.Nodes {
			nodes[mark.NodeID] = max(mark.Revision, o.nodeFloors[mark.NodeID])
			o.nodeFloors[mark.NodeID] = max(o.nodeFloors[mark.NodeID], mark.Revision)
		}
		for id, revision := range o.vpnSSONodeFloors {
			nodes[id] = max(nodes[id], revision, o.nodeFloors[id])
		}
		next.Nodes = nil
		if len(nodes) == 0 {
			next.Nodes = document.Nodes
		}
		for id, revision := range nodes {
			next.Nodes = append(next.Nodes, vault.NodeHighWater{NodeID: id, Revision: revision})
		}
		sort.Slice(next.Nodes, func(i, j int) bool { return next.Nodes[i].NodeID < next.Nodes[j].NodeID })
		next.Tunnels = nil
		for id, revision := range o.tunnelFloors {
			next.Tunnels = append(next.Tunnels, vault.TunnelHighWater{TunnelID: id, Revision: revision})
		}
		sort.Slice(next.Tunnels, func(i, j int) bool { return next.Tunnels[i].TunnelID < next.Tunnels[j].TunnelID })
		next.VPNSSO = nil
		for scope, floor := range o.vpnSSOFloors {
			if floor.RowVersion == 0 {
				continue
			}
			next.VPNSSO = append(next.VPNSSO, vault.VPNSSOHighWater{ScopeID: scope, RowVersion: floor.RowVersion, Revision: floor.Checkpoint.Revision, Deleted: floor.Checkpoint.Deleted, Digest: append([]byte(nil), floor.Checkpoint.Digest[:]...)})
		}
		sort.Slice(next.VPNSSO, func(i, j int) bool { return next.VPNSSO[i].ScopeID < next.VPNSSO[j].ScopeID })
		if reflect.DeepEqual(document.VPNSSO, next.VPNSSO) && reflect.DeepEqual(document.Nodes, next.Nodes) && reflect.DeepEqual(document.Tunnels, next.Tunnels) && document.ProfileSequence == next.ProfileSequence {
			o.slotFloor = document.Sequence
			return nil
		}
		if document.Sequence == math.MaxUint64 {
			return vault.ErrPolicy
		}
		next.Sequence++
		next.FormatVersion = max(next.FormatVersion, 2)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := persist(next, key); err != nil {
			return err
		}
		o.slotFloor = next.Sequence
		return nil
	})
}
