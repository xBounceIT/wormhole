package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Native/main-only. The isolated document supplies ciphertext, never a recipient
// key chosen by the ordinary app. Planning and manual sealing borrow no password.
func (h *vaultFoundationHandler) vncManual(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 32*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelBundleRequest
	var epoch, endpoint string
	var binding, route, envelope json.RawMessage
	fields := map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch"}
	switch operation {
	case "vnc-plan":
	case "vnc-manual-bundle", "vnc-manual-route-bundle":
		fields["publicKey"], fields["manual"] = &q.PublicKey, &envelope
		required = append(required, "publicKey", "manual")
		if operation == "vnc-manual-bundle" {
			fields["binding"] = &binding
			required = append(required, "binding")
		} else {
			fields["route"], fields["endpoint"] = &route, &endpoint
			required = append(required, "route", "endpoint")
		}
	default:
		return nil, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch {
		return nil, vaultwire.ErrProtocol
	}
	var shared *sharedAdmissionController
	if h.shared != nil {
		if q.Plan().Validate() != nil || (operation != "vnc-plan" && q.Validate() != nil) {
			return nil, vaultwire.ErrProtocol
		}
		shared, err = h.sharedProtocolController(ctx)
		if err != nil {
			return nil, err
		}
	}
	if operation == "vnc-plan" {
		var result vault.BundleBinding
		if shared != nil {
			result, err = shared.PlanVNCConnection(ctx, q.Plan())
		} else {
			result, err = h.owner.PlanVNCConnection(ctx, q.Plan())
		}
		if err != nil {
			if shared != nil {
				return nil, h.retire(err)
			}
			return nil, err
		}
		return json.Marshal(struct {
			Binding vault.BundleBinding `json:"binding"`
		}{result})
	}
	var inner vault.SealedBundle
	if decodeVaultObject(envelope, map[string]any{"formatVersion": &inner.FormatVersion, "suiteId": &inner.SuiteID, "enc": &inner.Enc, "ciphertext": &inner.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var expected vault.BundleBinding
	var routed *vault.TunnelBundleBinding
	if operation == "vnc-manual-bundle" {
		expected, err = decodeVNCConnectionBinding(binding)
	} else {
		value, e := decodeTunnelBundleBinding(route)
		err = e
		expected = value.BundleBinding
		routed = &value
	}
	if err != nil {
		return nil, err
	}
	var result localvault.VNCConnectionBundle
	if shared != nil {
		if routed != nil {
			result, err = shared.SealRoutedManualVNCConnection(ctx, q, *routed, endpoint, h.shared.fileID, inner, "ui")
		} else {
			result, err = shared.SealManualVNCConnection(ctx, q, expected, inner, "ui")
		}
	} else {
		result, err = h.owner.SealManualVNCConnection(ctx, q, expected, routed, endpoint, inner)
	}
	if err != nil {
		if shared != nil {
			return nil, h.retire(err)
		}
		return nil, err
	}
	if routed != nil {
		return json.Marshal(localvault.RoutedVNCConnectionBundle{Binding: *routed, Endpoint: endpoint, Bundle: result.Bundle})
	}
	return json.Marshal(result)
}
