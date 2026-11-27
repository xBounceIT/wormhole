package localvault

import (
	"bytes"
	"context"
	"runtime"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type RDPConnectionBundle struct {
	Binding vault.BundleBinding `json:"binding"`
	Bundle  vault.SealedBundle  `json:"bundle"`
}
type RoutedRDPConnectionBundle struct {
	Binding  vault.TunnelBundleBinding `json:"binding"`
	Endpoint string                    `json:"endpoint"`
	Bundle   vault.SealedBundle        `json:"bundle"`
}

func (o *Owner) SealRDPConnection(ctx context.Context, q TunnelBundleRequest) (RDPConnectionBundle, error) {
	return o.sealRDPConnection(ctx, q, nil, "")
}
func (o *Owner) SealRoutedRDPConnection(ctx context.Context, q TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint string) (RoutedRDPConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return RoutedRDPConnectionBundle{}, vault.ErrFormat
	}
	value, err := o.sealRDPConnection(ctx, q, &route, endpoint)
	if err != nil {
		return RoutedRDPConnectionBundle{}, err
	}
	return RoutedRDPConnectionBundle{route, endpoint, value.Bundle}, nil
}
func (o *Owner) sealRDPConnection(ctx context.Context, q TunnelBundleRequest, route *vault.TunnelBundleBinding, endpoint string) (RDPConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return RDPConnectionBundle{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, binding, settings, err := o.planRDPBundle(ctx, q.Plan(), route, false)
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	payload, err := o.rdpBundlePayload(ctx, q.NodeID, r, settings, 0)
	defer func() { vault.Wipe(payload.Password); vault.Wipe(payload.GatewayPassword) }()
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	raw, err := vault.EncodeRDPBundle(payload)
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	if err = ctx.Err(); err != nil {
		return RDPConnectionBundle{}, err
	}
	var bundle vault.SealedBundle
	if route == nil {
		bundle, err = vault.SealBundle(q.PublicKey, binding, raw)
	} else {
		bundle, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
	}
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	if err = ctx.Err(); err != nil {
		vault.Wipe(bundle.Enc)
		vault.Wipe(bundle.Ciphertext)
		return RDPConnectionBundle{}, err
	}
	return RDPConnectionBundle{binding, bundle}, nil
}

func (o *Owner) planRDPBundle(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding, manual bool) (Resolution, vault.BundleBinding, vault.RDPSettings, error) {
	r, err := o.resolveConnectionRequest(ctx, q, manual)
	if err != nil {
		return Resolution{}, vault.BundleBinding{}, vault.RDPSettings{}, err
	}
	binding, settings, err := rdpConnectionProjection(r, q, route != nil)
	if err != nil {
		return Resolution{}, vault.BundleBinding{}, vault.RDPSettings{}, err
	}
	if route != nil {
		current, err := connectionTunnelBinding(r, q)
		if err != nil {
			return Resolution{}, vault.BundleBinding{}, vault.RDPSettings{}, err
		}
		if current != *route {
			return Resolution{}, vault.BundleBinding{}, vault.RDPSettings{}, vault.ErrPolicy
		}
	}
	return r, binding, settings, nil
}

// Returned password buffers belong to the caller, including on error.
func (o *Owner) rdpBundlePayload(ctx context.Context, nodeID string, r Resolution, settings vault.RDPSettings, skip vault.RDPBitwardenSlots) (vault.RDPBundlePayload, error) {
	payload := vault.RDPBundlePayload{Settings: settings, Username: r.Plan.Username}
	var err error
	if skip&vault.RDPBitwardenPrimary == 0 {
		if payload.Password, payload.PasswordProvided, err = o.borrowRDPAccount(ctx, nodeID, r, r.Account, r.Credential); err != nil {
			return payload, err
		}
	}
	if r.Plan.GatewayMethod != 0 && !r.Plan.GatewaySameCredentials {
		payload.GatewayUsername, payload.GatewayDomain = r.GatewayAccount.Username, r.GatewayAccount.Domain
		if skip&vault.RDPBitwardenGateway == 0 {
			payload.GatewayPassword, payload.GatewayPasswordProvided, err = o.borrowRDPAccount(ctx, nodeID, r, r.GatewayAccount, r.GatewayCredential)
		}
	}
	return payload, err
}

func rdpConnectionProjection(r Resolution, q TunnelPlanRequest, routed bool) (vault.BundleBinding, vault.RDPSettings, error) {
	p := r.Plan
	if p.Protocol != 1 || (!routed && p.TunnelID != "") || p.Port < 1 || p.Port > 65535 || !vault.ValidRDPHost(p.Host) || p.Host == "" {
		return vault.BundleBinding{}, vault.RDPSettings{}, vault.ErrPolicy
	}
	settings := r.rdpSettings
	settings.Domain = p.Domain
	settings.GatewayUsageMethod = p.GatewayMethod
	settings.GatewayHostname = p.GatewayHost
	settings.GatewayUseSameCreds = p.GatewaySameCredentials
	settings.GatewayCredentialID = p.GatewayCredentialID
	settings.UseExternalClient = p.ExternalRDPClient
	settings = vault.RDPSettingsForPlatform(settings, runtime.GOOS)
	settings, err := vault.NormalizeRDPSettings(&settings)
	if err != nil {
		return vault.BundleBinding{}, vault.RDPSettings{}, err
	}
	if err = vault.ValidateRDPRoute(settings, routed); err != nil {
		return vault.BundleBinding{}, vault.RDPSettings{}, err
	}
	return vault.BundleBinding{WorkspaceID: r.Identity.WorkspaceID, SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: "rdp", Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}, settings, nil
}
func (o *Owner) borrowRDPAccount(ctx context.Context, nodeID string, r Resolution, account resolver.EffectiveCredentialSnapshot, c *vaultstore.Credential) ([]byte, bool, error) {

	var fields []vaultstore.CredentialField
	ref := vaultstore.SecretRef{OwnerKind: "node", OwnerID: nodeID, Field: "inlinePassword"}
	if account.SourceKind == "none" {
		return nil, false, nil
	}
	if account.SourceKind == "inline" {
		for _, field := range r.leaf.Fields {
			fields = append(fields, vaultstore.CredentialField{Field: field.Field, Version: field.Version, Present: field.Present})
		}
	} else if account.SourceKind == "saved" && c != nil && c.Provider == "local" && c.Kind == "password" {
		fields = c.Fields
		ref = vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: "password"}
	} else {
		return nil, false, vault.ErrPolicy
	}
	for _, field := range fields {
		if field.Field == ref.Field && field.Present {
			var secret []byte
			err := o.withSecret(ctx, ref, field.Version, true, func(value []byte) error { secret = bytes.Clone(value); return nil })
			return secret, err == nil, err
		}
	}
	return nil, false, nil
}
