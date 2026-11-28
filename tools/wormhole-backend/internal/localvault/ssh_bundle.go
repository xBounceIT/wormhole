package localvault

import (
	"bytes"
	"context"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type SSHBundleRequest struct {
	SFTPOnly                                         bool
	NodeID, CredentialOverride, SessionID, RequestID string
	Epoch                                            uint64
	PublicKey                                        []byte
}

type SSHConnectionBundle struct {
	SFTPOnly bool                `json:"sftpOnly,omitempty"`
	Binding  vault.BundleBinding `json:"binding"`
	Bundle   vault.SealedBundle  `json:"bundle"`
}

// SealSSHConnection resolves and borrows all fields under one owner lock. A
// concurrent edit cannot combine one account's password with another route.
// Profile admission is enforced by the native handler before this local API.
// VPN routes and unpinned hosts require their dedicated controllers; never
// degrade them to a direct connection or permissive host-key callback.
func (o *Owner) SealSSHConnection(ctx context.Context, q SSHBundleRequest) (SSHConnectionBundle, error) {
	return o.sealSSHConnection(ctx, q, nil, "")
}

type RoutedSSHConnectionBundle struct {
	SFTPOnly bool                      `json:"sftpOnly,omitempty"`
	Binding  vault.TunnelBundleBinding `json:"binding"`
	Endpoint string                    `json:"endpoint"`
	Bundle   vault.SealedBundle        `json:"bundle"`
}

func (o *Owner) SealRoutedSSHConnection(ctx context.Context, q SSHBundleRequest, route vault.TunnelBundleBinding, endpoint string) (RoutedSSHConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return RoutedSSHConnectionBundle{}, vault.ErrFormat
	}
	result, err := o.sealSSHConnection(ctx, q, &route, endpoint)
	if err != nil {
		return RoutedSSHConnectionBundle{}, err
	}
	return RoutedSSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: route, Endpoint: endpoint, Bundle: result.Bundle}, nil
}
func (o *Owner) sealSSHConnection(ctx context.Context, q SSHBundleRequest, route *vault.TunnelBundleBinding, endpoint string) (SSHConnectionBundle, error) {
	request := TunnelBundleRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch, q.PublicKey}
	if err := request.Validate(); err != nil {
		return SSHConnectionBundle{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, request.Plan(), false)
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	p := r.Plan
	if (p.Protocol != 0 && p.Protocol != 7) || (route == nil && p.TunnelID != "") || p.Port < 1 || p.Port > 65535 || p.Host == "" || strings.IndexFunc(p.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 {
		return SSHConnectionBundle{}, vault.ErrPolicy
	}
	if route != nil {
		current, err := connectionTunnelBinding(r, request.Plan())
		if err != nil {
			return SSHConnectionBundle{}, err
		}
		if current != *route {
			return SSHConnectionBundle{}, vault.ErrPolicy
		}
	}
	payload := vault.SSHBundlePayload{Username: p.Username, Fingerprint: p.HostKeyFingerprint, AutoSudo: !q.SFTPOnly && p.Protocol == 0 && p.SSHAutoSudo, SFTPOnly: q.SFTPOnly}
	defer func() {
		vault.Wipe(payload.Password)
		vault.Wipe(payload.PrivateKey)
		vault.Wipe(payload.Passphrase)
		vault.Wipe(payload.Certificate)
	}()
	borrow := func(ref vaultstore.SecretRef, version uint64, dst *[]byte) error {
		return o.withSecret(ctx, ref, version, true, func(value []byte) error { *dst = bytes.Clone(value); return nil })
	}
	if r.Account.SourceKind == "inline" {
		for _, field := range r.leaf.Fields {
			if field.Field == "inlinePassword" && field.Present {
				err = borrow(vaultstore.SecretRef{OwnerKind: "node", OwnerID: q.NodeID, Field: field.Field}, field.Version, &payload.Password)
				if err != nil {
					return SSHConnectionBundle{}, err
				}
			}
		}
	} else {
		c := r.Credential
		if c == nil || c.Provider != "local" {
			return SSHConnectionBundle{}, vault.ErrPolicy
		}
		for _, field := range c.Fields {
			if !field.Present {
				continue
			}
			var dst *[]byte
			switch field.Field {
			case "password":
				dst = &payload.Password
			case "privateKey":
				dst = &payload.PrivateKey
			case "passphrase":
				dst = &payload.Passphrase
			case "certificate":
				dst = &payload.Certificate
			default:
				return SSHConnectionBundle{}, vault.ErrFormat
			}
			if err := borrow(vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: field.Field}, field.Version, dst); err != nil {
				return SSHConnectionBundle{}, err
			}
		}
	}
	raw, err := vault.EncodeSSHBundle(payload)
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	if err := ctx.Err(); err != nil {
		return SSHConnectionBundle{}, err
	}
	binding := vault.BundleBinding{WorkspaceID: r.Identity.WorkspaceID, SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: resolver.DefaultPath(p.Protocol), Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}
	var sealed vault.SealedBundle
	if route == nil {
		sealed, err = vault.SealBundle(q.PublicKey, binding, raw)
	} else {
		sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
	}
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	return SSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: binding, Bundle: sealed}, nil
}
