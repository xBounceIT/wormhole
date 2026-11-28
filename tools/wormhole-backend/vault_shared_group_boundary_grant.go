package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedGroupBoundaryGrantSession interface {
	sharedRuntimeStateSession
	GroupBoundaryGrantsSupported(context.Context) (bool, error)
	PrepareGroupBoundaryGrant(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupBoundaryGrantRequest) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, *sharedpg.GroupBoundaryGrantPreparation, error)
	CommitPreparedGroupBoundaryGrant(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupBoundaryGrantPreparation, *vault.UserKeys) (sharedpg.GroupBoundaryGrantReply, error)
	GroupBoundaryRotationSupported(context.Context) (bool, error)
	PrepareGroupBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupBoundaryGrantRequest) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, *sharedpg.GroupBoundaryRotationPreparation, error)
	CommitPreparedGroupBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupBoundaryRotationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, error)
}

func decodeSharedGroupBoundarySelection(raw []byte, rotation bool) (sharedpg.GroupBoundaryGrantRequest, error) {
	var request sharedpg.GroupBoundaryGrantRequest
	var review *string
	if len(raw) > 1024 || decodeVaultObject(raw, map[string]any{
		"nodeId": &request.NodeID, "nodeRevision": &request.NodeRevision, "boundaryId": &request.BoundaryID,
		"groupId": &request.GroupID, "groupRevision": &request.GroupRevision, "mask": &request.Mask, "review": &review,
	}, "nodeId", "nodeRevision", "boundaryId", "groupId", "groupRevision", "mask") != nil {
		return request, vaultwire.ErrProtocol
	}
	if review != nil {
		if *review == "" {
			return request, vaultwire.ErrProtocol
		}
		request.Review = *review
	}
	if rotation && !request.ValidRotation() || !rotation && !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedGroupBoundaryChange(ctx context.Context, raw []byte, rotation bool) (json.RawMessage, error) {
	request, err := decodeSharedGroupBoundarySelection(raw, rotation)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedGroupBoundaryGrantSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	var plan *sharedpg.GroupBoundaryGrantPreparation
	var rotationPlan *sharedpg.GroupBoundaryRotationPreparation
	var bundle *sharedpg.VerifiedTLSBundle
	reply := sharedpg.GroupBoundaryGrantReply{Status: "unavailable"}
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		runtime, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !runtime.Administrator {
			return err
		}
		check := session.GroupBoundaryGrantsSupported
		if rotation {
			check = session.GroupBoundaryRotationSupported
		}
		supported, err := check(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		bundle, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		var next sharedpg.TrustState
		var result sharedpg.GroupBoundaryGrantReply
		if rotation {
			next, result, rotationPlan, err = session.PrepareGroupBoundaryRotation(ctx, *pending, bundle, request)
		} else {
			next, result, plan, err = session.PrepareGroupBoundaryGrant(ctx, *pending, bundle, request)
		}
		if next.Revision != 0 {
			*pending = next
		}
		if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
			return nil
		}
		if err != nil {
			return err
		}
		reply = result
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if plan == nil && rotationPlan == nil {
			return nil
		}
		return c.privateKeys.With(func(material []byte) error {
			if len(material) != 64 {
				return sharedpg.ErrAuthentication
			}
			keys := &vault.UserKeys{EncryptionPrivate: material[:32:32], SigningSeed: material[32:]}
			var result sharedpg.GroupBoundaryGrantReply
			var err error
			if rotationPlan != nil {
				var next sharedpg.TrustState
				next, result, err = session.CommitPreparedGroupBoundaryRotation(ctx, trust, bundle, rotationPlan, keys)
				if next.Revision != 0 && next.Revision != trust.Revision {
					if persistErr := c.commitCatalogTrust(trust, next); persistErr != nil {
						return persistErr
					}
				}
			} else {
				result, err = session.CommitPreparedGroupBoundaryGrant(ctx, trust, bundle, plan, keys)
			}
			if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
				reply = sharedpg.GroupBoundaryGrantReply{Status: "unavailable"}
				return nil
			}
			reply = result
			return err
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
