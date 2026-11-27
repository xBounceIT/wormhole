package main

import (
	"context"
	"runtime"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedRDPBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest, routed bool) (vault.BundleBinding, error) {
	if q.Validate() != nil || q.CredentialOverride != "" || p.NodeID != q.NodeID || p.Protocol != 1 || resolver.RequiresExternalRDP(runtime.GOOS, p) || (!routed && p.TunnelID != "") || p.Port < 1 || p.Port > 65535 || p.Host == "" || !utf8.ValidString(p.Host) || !vault.ValidRDPHost(p.Host) || !utf8.ValidString(p.Username) || !vault.ValidRDPText(p.Username, 513) {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	return vault.BundleBinding{WorkspaceID: workspace.String(), NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Protocol: "rdp", Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}, nil
}
func (c *sharedAdmissionController) SealRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, source string) (localvault.RDPConnectionBundle, error) {
	return c.sealRDPConnection(ctx, q, source, "", nil, "")
}
func (c *sharedAdmissionController) SealRoutedRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint, fileID, source string) (localvault.RoutedRDPConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return localvault.RoutedRDPConnectionBundle{}, vault.ErrFormat
	}
	result, err := c.sealRDPConnection(ctx, q, source, fileID, &route, endpoint)
	if err != nil {
		return localvault.RoutedRDPConnectionBundle{}, err
	}
	return localvault.RoutedRDPConnectionBundle{Binding: route, Endpoint: endpoint, Bundle: result.Bundle}, nil
}
func (c *sharedAdmissionController) sealRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, source, fileID string, route *vault.TunnelBundleBinding, endpoint string) (localvault.RDPConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return localvault.RDPConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.RDPConnectionBundle{}, vault.ErrPolicy
	}
	var result localvault.RDPConnectionBundle
	var settings vault.RDPSettings
	routeCheck := c.checkConnectionRoute(fileID, q.Plan(), route, endpoint)
	err := c.withConnectionValues(ctx, uuid.MustParse(q.NodeID), source, "rdp", func(p resolver.Plan) error {
		_, err := sharedRDPBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		return err
	}, func(graph *sharedpg.VerifiedCredentialRelease) error {
		if err := routeCheck(graph); err != nil {
			return err
		}
		var err error
		settings, err = graph.RDPSettings()
		if err != nil {
			return err
		}
		settings = vault.RDPSettingsForPlatform(settings, runtime.GOOS)
		return vault.ValidateRDPRoute(settings, route != nil)
	}, false, func(p resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		binding, err := sharedRDPBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		if err != nil {
			return err
		}
		payload := vault.RDPBundlePayload{Settings: settings, Username: p.Username}
		switch p.Credential.Kind {
		case "none":
			if values.Primary != nil || values.Inline != nil {
				return vault.ErrPolicy
			}
		case "inline":
			if values.Inline == nil || values.Inline.NodeID != q.NodeID || values.Primary != nil {
				return vault.ErrPolicy
			}
			payload.Password, payload.PasswordProvided = values.Inline.Fields["inlinePassword"]
		case "saved", "override":
			if values.Primary == nil || values.Inline != nil || values.Primary.Metadata.Provider != "local" || values.Primary.Metadata.Kind != "password" {
				return vault.ErrPolicy
			}
			payload.Password, payload.PasswordProvided = values.Primary.Fields["password"]
		default:
			return vault.ErrPolicy
		}
		if p.GatewayMethod != 0 && !p.GatewaySameCredentials {
			gateway := values.Gateway
			if gateway == nil && p.GatewayCredentialID != "" {
				return vault.ErrPolicy
			}
			if gateway != nil {
				if gateway.Metadata.ID != p.GatewayCredentialID || gateway.Metadata.Provider != "local" || gateway.Metadata.Kind != "password" {
					return vault.ErrPolicy
				}
				payload.GatewayUsername, payload.GatewayDomain = gateway.Metadata.Username, gateway.Metadata.Domain
				payload.GatewayPassword, payload.GatewayPasswordProvided = gateway.Fields["password"]
			}
		} else if values.Gateway != nil {
			return vault.ErrPolicy
		}
		raw, err := vault.EncodeRDPBundle(payload)
		if err != nil {
			return err
		}
		defer vault.Wipe(raw)
		var sealed vault.SealedBundle
		if route == nil {
			sealed, err = vault.SealBundle(q.PublicKey, binding, raw)
		} else {
			sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
		}
		if err != nil {
			return err
		}
		result = localvault.RDPConnectionBundle{Binding: binding, Bundle: sealed}
		return nil
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.RDPConnectionBundle{}, err
	}
	return result, nil
}
