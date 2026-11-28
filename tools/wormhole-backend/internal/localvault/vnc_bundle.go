package localvault

import (
	"context"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type VNCConnectionBundle struct {
	Binding vault.BundleBinding `json:"binding"`
	Bundle  vault.SealedBundle  `json:"bundle"`
}
type RoutedVNCConnectionBundle struct {
	Binding  vault.TunnelBundleBinding `json:"binding"`
	Endpoint string                    `json:"endpoint"`
	Bundle   vault.SealedBundle        `json:"bundle"`
}

func (o *Owner) SealVNCConnection(ctx context.Context, q TunnelBundleRequest) (VNCConnectionBundle, error) {
	return o.sealVNCConnection(ctx, q, nil, "")
}
func (o *Owner) SealRoutedVNCConnection(ctx context.Context, q TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint string) (RoutedVNCConnectionBundle, error) {
	result, err := o.sealVNCConnection(ctx, q, &route, endpoint)
	if err != nil {
		return RoutedVNCConnectionBundle{}, err
	}
	return RoutedVNCConnectionBundle{Binding: route, Endpoint: endpoint, Bundle: result.Bundle}, nil
}

func (o *Owner) sealVNCConnection(ctx context.Context, q TunnelBundleRequest, route *vault.TunnelBundleBinding, endpoint string) (VNCConnectionBundle, error) {
	if err := q.Validate(); err != nil {
		return VNCConnectionBundle{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q.Plan(), false)
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	binding, err := vncConnectionBinding(r, q.Plan(), route != nil)
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	if route != nil {
		current, err := connectionTunnelBinding(r, q.Plan())
		if err != nil {
			return VNCConnectionBundle{}, err
		}
		if current != *route {
			return VNCConnectionBundle{}, vault.ErrPolicy
		}
	}
	fields := r.leaf.Fields
	ref := vaultstore.SecretRef{OwnerKind: "node", OwnerID: q.NodeID, Field: "inlinePassword"}
	switch r.Account.SourceKind {
	case "inline":
	case "none":
		fields = nil
	case "saved":
		c := r.Credential
		if c == nil || c.Provider != "local" || c.Kind != "password" {
			return VNCConnectionBundle{}, vault.ErrPolicy
		}
		fields = c.Fields
		ref = vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: "password"}
	default:
		return VNCConnectionBundle{}, vault.ErrPolicy
	}

	var result VNCConnectionBundle
	seal := func(secret []byte, present bool) error {
		raw, err := vault.EncodeVNCBundle(vault.VNCBundlePayload{Password: secret, PasswordProvided: present})
		if err != nil {
			return err
		}
		defer vault.Wipe(raw)
		if err := ctx.Err(); err != nil {
			return err
		}
		var bundle vault.SealedBundle
		if route == nil {
			bundle, err = vault.SealBundle(q.PublicKey, binding, raw)
		} else {
			bundle, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
		}
		if err != nil {
			return err
		}
		result = VNCConnectionBundle{Binding: binding, Bundle: bundle}
		return nil
	}
	found := false
	for _, field := range fields {
		if field.Field == ref.Field && field.Present {
			found = true
			err = o.withSecret(ctx, ref, field.Version, true, func(secret []byte) error { return seal(secret, true) })
			break
		}
	}
	if !found {
		err = seal(nil, false)
	}
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return VNCConnectionBundle{}, err
	}
	return result, nil
}

func vncConnectionBinding(r Resolution, q TunnelPlanRequest, routed bool) (vault.BundleBinding, error) {
	p := r.Plan
	if p.Protocol != 6 || p.Port < 1 || p.Port > 65535 || p.Host == "" || len(p.Host) > 1024 || strings.IndexFunc(p.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 || (!routed && p.TunnelID != "") {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	return vault.BundleBinding{WorkspaceID: r.Identity.WorkspaceID, SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: "vnc", Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}, nil
}
