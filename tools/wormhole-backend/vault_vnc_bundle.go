package main

import (
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Native/main-only. Recipient keys belong to the VNC process, never a renderer.
func (h *vaultFoundationHandler) vncBundle(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	q, binding, endpoint, err := decodeVaultProtocolBundleRequest(operation, "vnc", raw)
	if err != nil {
		return nil, err
	}
	if binding != nil {
		if h.shared != nil {
			if q.Validate() != nil {
				return nil, vaultwire.ErrProtocol
			}
			c, err := h.sharedProtocolController(ctx)
			if err != nil {
				return nil, err
			}
			result, err := c.SealRoutedVNCConnection(ctx, q, *binding, endpoint, h.shared.fileID, "ui")
			if err != nil {
				return nil, h.retire(err)
			}
			return json.Marshal(result)
		}
		result, err := h.owner.SealRoutedVNCConnection(ctx, q, *binding, endpoint)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if h.shared != nil {
		if q.Validate() != nil {
			return nil, vaultwire.ErrProtocol
		}
		controller, err := h.sharedProtocolController(ctx)
		if err != nil {
			return nil, err
		}
		result, err := controller.SealVNCConnection(ctx, q, "ui")
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(result)
	}
	result, err := h.owner.SealVNCConnection(ctx, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
