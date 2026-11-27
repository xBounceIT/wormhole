package localvault

import (
	"context"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type BitwardenPreparation struct {
	Required bool                             `json:"required"`
	Revision string                           `json:"revision,omitempty"`
	Ticket   *vault.ConnectionBitwardenTicket `json:"release,omitempty"`
	RDPBase  *vault.SealedBundle              `json:"rdpBase,omitempty"`
}

// The route, destination and selected credential are resolved under the owner
// lock before the CLI session is read. Changes since the probe deny the release.
func (o *Owner) PrepareVNCBitwarden(ctx context.Context, q TunnelBundleRequest, route *vault.TunnelBundleBinding, endpoint string, recipient []byte, reviewed string) (BitwardenPreparation, error) {
	if q.Validate() != nil || (route != nil && !vault.ValidRouteEndpoint(endpoint)) || (route == nil && endpoint != "") ||
		(len(recipient) == 0) != (reviewed == "") {
		return BitwardenPreparation{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q.Plan(), false)
	if err != nil {
		return BitwardenPreparation{}, err
	}
	binding, err := vncConnectionBinding(r, q.Plan(), route != nil)
	if err != nil {
		return BitwardenPreparation{}, err
	}
	if route != nil {
		current, err := connectionTunnelBinding(r, q.Plan())
		if err != nil || current != *route {
			return BitwardenPreparation{}, vault.ErrPolicy
		}
	}
	credential := r.Credential
	if r.Account.SourceKind != "saved" || credential == nil || credential.Provider != "bitwarden" {
		if len(recipient) != 0 {
			return BitwardenPreparation{}, vault.ErrPolicy
		}
		return BitwardenPreparation{}, nil
	}
	if credential.Kind != "password" || (credential.BitwardenFieldPath != "" && credential.BitwardenFieldPath != "login.password") {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	return o.prepareBitwardenTicket(ctx, binding, vault.ConnectionBitwardenTicketPayload{
		TargetPublicKey: q.PublicKey, ItemID: credential.BitwardenItemID,
		Route: route, Endpoint: endpoint,
	}, recipient, connectionResolutionRevision(r, q.Plan()), reviewed)
}

// Plan and exact Bitwarden session are authenticated under the same owner lock.
// A probe without a recipient never reads or lends the session.
func (o *Owner) PrepareSSHBitwarden(ctx context.Context, q SSHBundleRequest, route *vault.TunnelBundleBinding, endpoint string, recipient []byte, reviewed string) (BitwardenPreparation, error) {
	request := TunnelBundleRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch, q.PublicKey}
	if request.Validate() != nil || (route != nil && !vault.ValidRouteEndpoint(endpoint)) || (route == nil && endpoint != "") ||
		(len(recipient) == 0) != (reviewed == "") {
		return BitwardenPreparation{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	host, resolution, err := o.planSSHHost(ctx, request.Plan(), route)
	if err != nil {
		return BitwardenPreparation{}, err
	}
	credential := resolution.Credential
	if credential == nil || credential.Provider != "bitwarden" {
		if len(recipient) != 0 {
			return BitwardenPreparation{}, vault.ErrPolicy
		}
		return BitwardenPreparation{}, nil
	}
	if credential.Kind != "password" || (credential.BitwardenFieldPath != "" && credential.BitwardenFieldPath != "login.password") ||
		!vault.ValidSSHFingerprint(host.Fingerprint) {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	return o.prepareBitwardenTicket(ctx, host.Binding, vault.ConnectionBitwardenTicketPayload{
		TargetPublicKey: q.PublicKey, ItemID: credential.BitwardenItemID,
		Username: resolution.Plan.Username, Fingerprint: host.Fingerprint,
		SFTPOnly: q.SFTPOnly, AutoSudo: !q.SFTPOnly && resolution.Plan.Protocol == 0 && resolution.Plan.SSHAutoSudo,
		Route: route, Endpoint: endpoint,
	}, recipient, host.Revision, reviewed)
}

// Caller holds the owner lock for resolution and session release.
func (o *Owner) prepareBitwardenTicket(ctx context.Context, binding vault.BundleBinding, payload vault.ConnectionBitwardenTicketPayload, recipient []byte, revision, reviewed string) (BitwardenPreparation, error) {
	result := BitwardenPreparation{Required: true, Revision: revision}
	if len(recipient) == 0 {
		return result, nil
	}
	if reviewed != revision {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	now := time.Now()
	payload.ExpiresAt = now.Add(vault.BitwardenTicketLifetime).UnixMilli()
	err := o.withLocalState(ctx, "bitwarden-cli", binding.WorkspaceID, 1, func(session []byte) error {
		input := payload
		input.SavedSession = session
		ticket, err := vault.SealConnectionBitwardenTicket(recipient, binding, input, now)
		if err == nil {
			result.Ticket = &ticket
		}
		return err
	})
	if err != nil {
		return BitwardenPreparation{}, err
	}
	return result, nil
}
