package main

import (
	"context"
	"encoding/json"
	"math"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedWorkspaceAccessSession interface {
	WorkspaceAccessSupported(context.Context) (bool, error)
	WorkspaceAccess(context.Context, sharedpg.TrustState, sharedpg.WorkspaceAccessRequest) (sharedpg.WorkspaceAccessReply, error)
}

func decodeSharedWorkspaceAccess(raw []byte) (request sharedpg.WorkspaceAccessRequest, err error) {
	var revision json.RawMessage
	fields := map[string]any{"action": &request.Action, "targetId": &request.TargetID, "revision": &revision}
	if len(raw) > 512 || decodeVaultObject(raw, fields, "action", "targetId") != nil ||
		(len(revision) != 0 && (json.Unmarshal(revision, &request.Revision) != nil || request.Revision == "")) || !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedWorkspaceAccess(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedWorkspaceAccess(raw)
	if err != nil {
		return nil, err
	}
	reply := sharedpg.WorkspaceAccessReply{Status: "unavailable"}
	if request.Action == "disable-account" && request.Revision != "" {
		c, err := h.sharedOwner(ctx)
		if err != nil {
			return nil, err
		}
		reply, err = c.confirmAccountSuspension(ctx, request)
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(reply)
	}
	err = h.withVerifiedSharedRuntime(ctx, func(ctx context.Context, native sharedAdmissionSession, trust sharedpg.TrustState, runtime sharedRuntimeSnapshot) error {
		if request.Action != "revoke-device" && !runtime.Administrator {
			return nil
		}
		session, ok := native.(sharedWorkspaceAccessSession)
		if !ok {
			return sharedpg.ErrConfiguration
		}
		supported, err := session.WorkspaceAccessSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		reply, err = session.WorkspaceAccess(ctx, trust, request)
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}

func (c *sharedAdmissionController) confirmAccountSuspension(ctx context.Context, request sharedpg.WorkspaceAccessRequest) (sharedpg.WorkspaceAccessReply, error) {
	reply := sharedpg.WorkspaceAccessReply{Status: "unavailable"}
	access, ok := c.session.(sharedWorkspaceAccessSession)
	runtime, hasRuntime := c.session.(sharedRuntimeStateSession)
	if !ok || !hasRuntime {
		return reply, sharedpg.ErrConfiguration
	}
	revision, err := strconv.ParseUint(request.Revision, 10, 63)
	if err != nil || revision == math.MaxInt64 {
		return reply, nil
	}
	var confirmed bool
	err = c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		state, err := c.observeRuntime(ctx, runtime, trust, pending)
		if err != nil || !state.Administrator || state.TLS != sharedpg.TLSVerified || request.TargetID == trust.UserID.String() {
			return err
		}
		supported, err := access.WorkspaceAccessSupported(ctx)
		if err != nil || !supported {
			reply.Status = "unsupported"
			return err
		}
		// Pin the actual account revision before authorizing any future rotation.
		preview, err := access.WorkspaceAccess(ctx, *pending, sharedpg.WorkspaceAccessRequest{Action: request.Action, TargetID: request.TargetID})
		if err != nil || preview.Status != "review" {
			reply = preview
			return err
		}
		if preview.Review == nil || preview.Review.WorkspaceAccessRequest != request {
			reply.Status = "stale"
			return nil
		}
		if rotations, ok := c.session.(sharedAccountBoundaryRotationSession); ok && c.tlsManaged {
			available, err := rotations.AccountBoundaryRotationSupported(ctx)
			if err != nil {
				return err
			}
			if available {
				next, err := pending.TrackSuspension(request.TargetID, revision+1, false)
				if err != nil {
					return err
				}
				*pending = next
			}
		}
		confirmed = true
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if !confirmed {
			return nil
		}
		if issuer, ok := access.(sharedSuspensionReceiptSession); ok && c.rotationEpoch > 0 && c.tlsManaged {
			supported, e := issuer.SuspensionReceiptsSupported(ctx)
			if e != nil {
				return e
			}
			if supported {
				bundle, e := readSharedTLSCache(c.trustPath, trust)
				if e != nil {
					return e
				}
				return c.privateKeys.With(func(raw []byte) error {
					if len(raw) != 64 {
						return sharedpg.ErrAuthentication
					}
					keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
					reply, e = issuer.SuspendWithReceipt(ctx, trust, bundle, c.rotationEpoch, request, keys)
					return e
				})
			}
		}
		var err error
		reply, err = access.WorkspaceAccess(ctx, trust, request)
		return err
	}, false)
	return reply, err
}
