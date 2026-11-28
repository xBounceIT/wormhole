package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func selectNativeIPsecFallback(configuration []byte) (string, error) {
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return "", err
	}
	defer clearTunnelSettingsMap(settings)
	return selectNativeIPsecFallbackSettings(settings)
}

func selectNativeIPsecFallbackSettings(settings map[string]json.RawMessage) (string, error) {
	if validateFortinetIPsecSettings(settings) != nil {
		return "", vault.ErrFormat
	}
	configured := tunnelSettingString(settings, "FallbackTunnelId")
	if configured == "" {
		return "", nil
	}
	id := normalizeTunnelID(configured)
	if id == "" || id == "00000000-0000-0000-0000-000000000000" {
		return "", vault.ErrFormat
	}
	return id, nil
}

type nativeTunnelFallbackRequest struct {
	request localvault.TunnelPlanRequest
	binding vault.TunnelFallbackBinding
	public  []byte
	attempt string
}

func decodeNativeTunnelFallback(operation string, raw []byte) (q nativeTunnelFallbackRequest, err error) {
	var epoch, public string
	var primaryRaw, bindingRaw json.RawMessage
	fields := map[string]any{"nodeId": &q.request.NodeID, "credentialOverride": &q.request.CredentialOverride, "sessionId": &q.request.SessionID, "requestId": &q.request.RequestID, "epoch": &epoch}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch"}
	switch operation {
	case "tunnel-fallback-plan":
		fields["primary"], fields["fallbackRequestId"] = &primaryRaw, &q.attempt
		required = append(required, "primary", "fallbackRequestId")
	case "tunnel-fallback-bundle":
		fields["binding"], fields["publicKey"] = &bindingRaw, &public
		required = append(required, "binding", "publicKey")
	default:
		return q, vaultwire.ErrProtocol
	}
	if len(raw) > 16384 || decodeVaultObject(raw, fields, required...) != nil {
		return q, vaultwire.ErrProtocol
	}
	q.request.Epoch, err = strconv.ParseUint(epoch, 10, 53)
	if err != nil || strconv.FormatUint(q.request.Epoch, 10) != epoch || q.request.Validate() != nil {
		return q, vaultwire.ErrProtocol
	}
	if operation == "tunnel-fallback-plan" {
		q.binding.Primary, err = decodeTunnelBundleBinding(primaryRaw)
		secondary := q.request
		secondary.RequestID = q.attempt
		if err != nil || secondary.Validate() != nil || secondary.RequestID == q.request.RequestID {
			return q, vaultwire.ErrProtocol
		}
		return q, nil
	}
	var fallbackRaw json.RawMessage
	if decodeVaultObject(bindingRaw, map[string]any{"primary": &primaryRaw, "fallback": &fallbackRaw}, "primary", "fallback") != nil {
		return q, vaultwire.ErrProtocol
	}
	q.binding.Primary, err = decodeTunnelBundleBinding(primaryRaw)
	if err == nil {
		q.binding.Fallback, err = decodeTunnelBundleBinding(fallbackRaw)
	}
	if err == nil {
		q.public, err = browserTransferBytes(public, 32, 32)
	}
	if err != nil {
		return q, vaultwire.ErrProtocol
	}
	q.attempt = q.binding.Fallback.RequestID
	secondary := q.request
	secondary.RequestID = q.attempt
	if secondary.Validate() != nil || q.attempt == q.request.RequestID {
		return q, vaultwire.ErrProtocol
	}
	return q, nil
}

// Native-only source API. Main/actor wiring is not enabled yet; callers
// must establish original process retirement before asking for a secondary
// recipient. Shared mode uses an independent audited source/target graph.
func (h *vaultFoundationHandler) tunnelFallback(ctx context.Context, operation string, raw []byte) (result json.RawMessage, resultErr error) {
	if ctx == nil {
		return nil, vaultwire.ErrProtocol
	}
	if h.shared != nil {
		return h.sharedTunnelFallback(ctx, operation, raw)
	}
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	q, err := decodeNativeTunnelFallback(operation, raw)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := h.checkpointVPNSSO(ctx); err != nil {
		return nil, h.retire(err)
	}
	profile, err := h.owner.ReadSecurityProfile(ctx)
	if err != nil {
		return h.rejectLocalPolicy(ctx, err)
	}
	if profile.Effective != vault.Default && profile.Effective != vault.Standard {
		return h.rejectLocalPolicy(ctx, vault.ErrPolicy)
	}
	var expected vault.TunnelFallbackBinding
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		// Keep independent authenticated observations before any error retires
		// the owner, including target deletion and source/context mismatch.
		if err := h.checkpointVPNSSO(cleanup); err != nil {
			result, resultErr = nil, errors.Join(resultErr, h.retire(err))
			return
		}
		if resultErr == nil {
			fresh, err := h.owner.PlanConnectionFallback(cleanup, q.request, expected.Primary, expected.Fallback.RequestID, selectNativeIPsecFallback)
			if err != nil {
				resultErr = err
			} else if fresh != expected {
				resultErr = vault.ErrAuthentication
			}
			if err := h.checkpointVPNSSO(cleanup); err != nil {
				result, resultErr = nil, errors.Join(resultErr, h.retire(err))
				return
			}
			current, err := h.owner.ReadSecurityProfile(cleanup)
			if err != nil || current.Sequence != profile.Sequence || current.Effective != profile.Effective {
				result, resultErr = h.rejectLocalPolicy(cleanup, errors.Join(resultErr, err, vault.ErrPolicy))
				return
			}
		}
		if resultErr == nil {
			resultErr = ctx.Err()
		}
		if resultErr != nil {
			result, resultErr = h.domainResult(nil, resultErr)
		}
	}()
	if operation == "tunnel-fallback-plan" {
		expected, resultErr = h.owner.PlanConnectionFallback(ctx, q.request, q.binding.Primary, q.attempt, selectNativeIPsecFallback)
		if resultErr != nil {
			return nil, resultErr
		}
		return json.Marshal(expected)
	}
	packet, err := h.owner.SealConnectionFallback(ctx, q.request, q.binding, q.public, selectNativeIPsecFallback)
	defer vault.Wipe(packet.Bundle.Enc)
	defer vault.Wipe(packet.Bundle.Ciphertext)
	if err != nil {
		return nil, err
	}
	expected = packet.Binding
	return json.Marshal(packet)
}

func (h *vaultFoundationHandler) sharedTunnelFallback(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	q, err := decodeNativeTunnelFallback(operation, raw)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return nil, err
	}
	if operation == "tunnel-fallback-plan" {
		binding, err := c.PlanConnectionFallback(ctx, q.request, q.binding.Primary, q.attempt, h.shared.fileID, "ui")
		if err != nil {
			return nil, h.retire(err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return json.Marshal(binding)
	}
	packet, err := c.SealConnectionFallback(ctx, q.request, q.binding, q.public, h.shared.fileID, "ui")
	defer vault.Wipe(packet.Bundle.Enc)
	defer vault.Wipe(packet.Bundle.Ciphertext)
	if err != nil {
		return nil, h.retire(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(packet)
}
