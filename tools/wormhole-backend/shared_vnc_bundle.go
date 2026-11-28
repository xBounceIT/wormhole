package main

import (
	"context"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedVNCBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest) (vault.BundleBinding, error) {
	return sharedVNCRouteBinding(workspace, p, q, false)
}

func sharedVNCRouteBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest, routed bool) (vault.BundleBinding, error) {
	if q.Validate() != nil || q.CredentialOverride != "" || p.NodeID != q.NodeID || p.Protocol != 6 || (!routed && p.TunnelID != "") || p.Port < 1 || p.Port > 65535 || p.Host == "" || len(p.Host) > 1024 || strings.IndexFunc(p.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	return vault.BundleBinding{WorkspaceID: workspace.String(), NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Protocol: "vnc", Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}, nil
}

// SealVNCConnection reauthorizes and audits the current graph before borrowing
// a password. Only the main-owned VNC recipient can open the resulting packet.
func (c *sharedAdmissionController) SealVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, source string) (localvault.VNCConnectionBundle, error) {
	return c.sealVNCConnection(ctx, q, source, "", nil, "")
}

func (c *sharedAdmissionController) SealRoutedVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint, fileID, source string) (localvault.RoutedVNCConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return localvault.RoutedVNCConnectionBundle{}, vault.ErrFormat
	}
	value, err := c.sealVNCConnection(ctx, q, source, fileID, &route, endpoint)
	if err != nil {
		return localvault.RoutedVNCConnectionBundle{}, err
	}
	return localvault.RoutedVNCConnectionBundle{Binding: route, Endpoint: endpoint, Bundle: value.Bundle}, nil
}

func (c *sharedAdmissionController) sealVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, source, fileID string, route *vault.TunnelBundleBinding, endpoint string) (localvault.VNCConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return localvault.VNCConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.VNCConnectionBundle{}, vault.ErrPolicy
	}
	var result localvault.VNCConnectionBundle
	err := c.withConnectionValues(ctx, uuid.MustParse(q.NodeID), source, "vnc", func(p resolver.Plan) error {
		_, err := sharedVNCRouteBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		return err
	}, c.checkConnectionRoute(fileID, q.Plan(), route, endpoint), false, func(p resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		binding, err := sharedVNCRouteBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		if err != nil {
			return err
		}
		payload := vault.VNCBundlePayload{}
		switch p.Credential.Kind {
		case "none":
			if values.Primary != nil {
				return vault.ErrPolicy
			}
		case "saved":
			if values.Primary == nil || values.Primary.Metadata.Provider != "local" || values.Primary.Metadata.Kind != "password" {
				return vault.ErrPolicy
			}
			payload.Password, payload.PasswordProvided = values.Primary.Fields["password"]
		default:
			return vault.ErrPolicy
		}
		frame, err := vault.EncodeVNCBundle(payload)
		if err != nil {
			return err
		}
		defer vault.Wipe(frame)
		var sealed vault.SealedBundle
		if route == nil {
			sealed, err = vault.SealBundle(q.PublicKey, binding, frame)
		} else {
			sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, frame)
		}
		if err != nil {
			return err
		}
		result = localvault.VNCConnectionBundle{Binding: binding, Bundle: sealed}
		return nil
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.VNCConnectionBundle{}, err
	}
	return result, nil
}
