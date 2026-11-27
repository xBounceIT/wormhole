package localvault

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type QuickSerialTarget struct {
	PortName string               `json:"portName"`
	Settings vault.SerialSettings `json:"settings"`
}

// A saved target is always resolved from authenticated metadata. A Quick
// target is a local device selection for this one recipient and session.
func (o *Owner) SealSerialConnection(ctx context.Context, q TunnelBundleRequest, quick *QuickSerialTarget) (vault.SerialConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil || q.CredentialOverride != "" {
		return vault.SerialConnectionBundle{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return vault.SerialConnectionBundle{}, err
	}
	var host, workspace string
	var settings vault.SerialSettings
	if quick == nil {
		r, err := o.resolveCandidateRequest(ctx, q.Plan())
		if err != nil {
			return vault.SerialConnectionBundle{}, err
		}
		if r.Plan.Protocol != 5 || r.Plan.Credential.Kind != "none" || r.Plan.TunnelID != "" || r.Plan.Port != 0 {
			return vault.SerialConnectionBundle{}, vault.ErrPolicy
		}
		host, workspace, settings = r.Plan.Host, r.Identity.WorkspaceID, r.serialSettings
	} else {
		store, err := o.nodeStore()
		if err != nil {
			return vault.SerialConnectionBundle{}, err
		}
		security, err := o.readSecurityProfile(ctx)
		if err != nil || !security.Effective.AllowsDirectRoute() {
			return vault.SerialConnectionBundle{}, vault.ErrPolicy
		}
		host, workspace, settings = quick.PortName, store.Identity().WorkspaceID, quick.Settings
	}
	b := vault.BundleBinding{WorkspaceID: workspace, NodeID: q.NodeID, SessionID: q.SessionID,
		RequestID: q.RequestID, Epoch: q.Epoch, Protocol: "serial", Host: host}
	return vault.SealSerialConnection(q.PublicKey, b, settings)
}
