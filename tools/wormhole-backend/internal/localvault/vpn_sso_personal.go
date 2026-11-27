package localvault

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// OpenPersonalVPNSSO opens ONLY a native personal/device-state cache, not an
// application workspace or a second tree. The root and slot selection must be
// borrowed from authenticated native device enrollment. security must authenticate
// the effective SOURCE policy for the current operation; it may not reenter Owner.
// The cache has no independent local-workspace policy or credential authority.
// key is consumed on every path. The caller owns source admission and checkpoints.
func OpenPersonalVPNSSO(ctx context.Context, path string, identity vaultstore.Identity, slots vault.SlotFile, key []byte, create, requireLocked bool, security func(context.Context) (SecurityProfile, error)) (*Owner, error) {
	defer vault.Wipe(key)
	if ctx == nil || !filepath.IsAbs(path) || security == nil {
		return nil, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := vault.VerifySlotFile(key, slots, identity.WorkspaceID, identity.FileID, slots.Sequence); err != nil {
		return nil, err
	}
	if slots.Sequence == 0 || slots.RootKeyID != identity.Root.ID || slots.RootKeyVersion != identity.Root.Version {
		return nil, vault.ErrAuthentication
	}
	if slots.Encrypted || slots.Initializing || slots.Migration != nil {
		return nil, vault.ErrPolicy
	}
	root, err := securemem.New(32, requireLocked)
	if err != nil {
		return nil, err
	}
	if err := root.With(func(dst []byte) error { copy(dst, key); return nil }); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	store, err := vaultstore.OpenSQLite(ctx, path, identity, create)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	o := &Owner{store: store, root: root, nodeFloors: make(map[string]uint64), tunnelFloors: make(map[string]uint64), vpnSSOFloors: make(map[string]VPNSSOFloor), profileFloor: slots.ProfileSequence, slotFloor: slots.Sequence, vpnSSONativeSecurity: security}
	for _, mark := range slots.Nodes {
		o.nodeFloors[mark.NodeID] = mark.Revision
	}
	for _, mark := range slots.Tunnels {
		o.tunnelFloors[mark.TunnelID] = mark.Revision
	}
	for _, mark := range slots.VPNSSO {
		o.vpnSSOFloors[mark.ScopeID] = vpnSSOFloorFromMark(mark)
	}
	return o, nil
}

// BeginAuthorizedVPNSSOTransfer is native-only. The SOURCE owner must hold its
// original admission/lifetime gate around this and every later action. check
// validates a fresh authenticated source receipt in ctx and must not reenter Owner
// or the source gate. Cancellation/Close never needs renewed source Use authority.
func (o *Owner) BeginAuthorizedVPNSSOTransfer(ctx context.Context, binding VPNSSOBinding, request VPNSSOTransferRequest, check func(context.Context) error) (vaultOffer VPNSSOTransferOffer, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if check == nil {
		return vaultOffer, vault.ErrPolicy
	}
	if err := check(ctx); err != nil {
		return vaultOffer, err
	}
	result, err := o.beginVPNSSOTransfer(ctx, binding, request, vpnSSOTransferLifetime)
	if err != nil {
		return result, err
	}
	o.vpnSSOTransfers[result.Context.TransferID].sourceCheck = check
	return result, nil
}
