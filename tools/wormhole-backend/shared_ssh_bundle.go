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

func sharedSSHBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest) (vault.BundleBinding, error) {
	return sharedSSHRouteBinding(workspace, p, q, false)
}

func sharedSSHRouteBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest, routed bool) (vault.BundleBinding, error) {
	if q.Validate() != nil || q.CredentialOverride != "" || p.NodeID != q.NodeID || (p.Protocol != 0 && p.Protocol != 7) || (!routed && p.TunnelID != "") || p.Port < 1 || p.Port > 65535 || p.Host == "" || len(p.Host) > vault.MaxContextBytes || strings.IndexFunc(p.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	return vault.BundleBinding{WorkspaceID: workspace.String(), SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: resolver.DefaultPath(p.Protocol), Host: p.Host, Port: uint16(p.Port), Epoch: q.Epoch, TunnelConfigID: p.TunnelID}, nil
}

// SealSSHConnection seals only to the main-owned child recipient. Re-resolve the
// connection inside the audited release; an earlier direct-route plan never
// allows falling back to direct after the node acquires a VPN route.
func (c *sharedAdmissionController) SealSSHConnection(ctx context.Context, q localvault.SSHBundleRequest, source string) (localvault.SSHConnectionBundle, error) {
	return c.sealSSHConnection(ctx, q, source, "", nil, "")
}

func (c *sharedAdmissionController) SealRoutedSSHConnection(ctx context.Context, q localvault.SSHBundleRequest, route vault.TunnelBundleBinding, endpoint, fileID, source string) (localvault.RoutedSSHConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return localvault.RoutedSSHConnectionBundle{}, vault.ErrFormat
	}
	value, err := c.sealSSHConnection(ctx, q, source, fileID, &route, endpoint)
	if err != nil {
		return localvault.RoutedSSHConnectionBundle{}, err
	}
	return localvault.RoutedSSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: route, Endpoint: endpoint, Bundle: value.Bundle}, nil
}

func (c *sharedAdmissionController) sealSSHConnection(ctx context.Context, q localvault.SSHBundleRequest, source, fileID string, route *vault.TunnelBundleBinding, endpoint string) (localvault.SSHConnectionBundle, error) {
	request := localvault.TunnelBundleRequest{NodeID: q.NodeID, CredentialOverride: q.CredentialOverride, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}
	if ctx == nil || request.Validate() != nil {
		return localvault.SSHConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.SSHConnectionBundle{}, vault.ErrPolicy
	}
	var result localvault.SSHConnectionBundle
	// A file tab reconnects with the saved connection's account. The SFTPOnly
	// flag restricts the child to the file subsystem within that connection.
	err := c.withConnectionValues(ctx, uuid.MustParse(q.NodeID), source, sharedpg.DefaultConnectionPath, func(p resolver.Plan) error {
		if _, e := sharedSSHRouteBinding(c.trustBinding.WorkspaceID, p, request.Plan(), route != nil); e != nil {
			return e
		}
		if !vault.ValidSSHFingerprint(p.HostKeyFingerprint) || p.Username == "" || len(p.Username) > 2048 || strings.IndexFunc(p.Username, unicode.IsControl) >= 0 {
			return vault.ErrPolicy
		}
		return nil
	}, c.checkConnectionRoute(fileID, request.Plan(), route, endpoint), false, func(p resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		binding, e := sharedSSHRouteBinding(c.trustBinding.WorkspaceID, p, request.Plan(), route != nil)
		if e != nil {
			return e
		}
		payload := vault.SSHBundlePayload{Username: p.Username, Fingerprint: p.HostKeyFingerprint, AutoSudo: !q.SFTPOnly && p.Protocol == 0 && p.SSHAutoSudo, SFTPOnly: q.SFTPOnly}
		switch p.Credential.Kind {
		case "inline":
			if values.Inline == nil || values.Inline.NodeID != q.NodeID || values.Primary != nil {
				return vault.ErrPolicy
			}
			payload.Password = values.Inline.Fields["inlinePassword"]
		default:
			if values.Primary == nil || values.Primary.Metadata.Provider != "local" || values.Inline != nil {
				return vault.ErrPolicy
			}
			fields := values.Primary.Fields
			payload.Password, payload.PrivateKey, payload.Passphrase, payload.Certificate = fields["password"], fields["privateKey"], fields["passphrase"], fields["certificate"]
		}
		frame, e := vault.EncodeSSHBundle(payload)
		if e != nil {
			return e
		}
		defer vault.Wipe(frame)
		var sealed vault.SealedBundle
		if route == nil {
			sealed, e = vault.SealBundle(q.PublicKey, binding, frame)
		} else {
			sealed, e = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, frame)
		}
		if e != nil {
			return e
		}
		result = localvault.SSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: binding, Bundle: sealed}
		return nil
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.SSHConnectionBundle{}, err
	}
	return result, nil
}
