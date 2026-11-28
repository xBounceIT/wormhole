package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAccountResetQueueSession interface {
	sharedRuntimeStateSession
	AccountResetTargetsSupported(context.Context) (bool, error)
	ReadAccountResetTargets(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID) (sharedpg.AccountResetTargets, error)
	MarkAccountResetHandover(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, uuid.UUID) (string, error)
}

type sharedAccountResetQueueReply struct {
	Status string                        `json:"status"`
	Page   *sharedpg.AccountResetTargets `json:"page,omitempty"`
}

func (h *vaultFoundationHandler) sharedAccountResetQueue(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	if len(payload) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var use func(context.Context, sharedAccountResetQueueSession, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle) (sharedAccountResetQueueReply, error)
	switch operation {
	case "shared-account-reset-targets":
		var cursor *string
		if len(payload) != 0 && (decodeVaultObject(payload, map[string]any{"after": &cursor}) != nil || (cursor != nil && !vaultCredentialID(*cursor))) {
			return nil, vaultwire.ErrProtocol
		}
		var after uuid.UUID
		if cursor != nil {
			after, _ = uuid.Parse(*cursor)
		}
		use = func(ctx context.Context, session sharedAccountResetQueueSession, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) (sharedAccountResetQueueReply, error) {
			page, err := session.ReadAccountResetTargets(ctx, trust, bundle, after)
			return sharedAccountResetQueueReply{Status: "ready", Page: &page}, err
		}
	case "shared-account-reset-mark-handover":
		var user, offer string
		if decodeVaultObject(payload, map[string]any{"userId": &user, "offerId": &offer}, "userId", "offerId") != nil ||
			!vaultCredentialID(user) || !vaultCredentialID(offer) {
			return nil, vaultwire.ErrProtocol
		}
		userID, _ := uuid.Parse(user)
		offerID, _ := uuid.Parse(offer)
		use = func(ctx context.Context, session sharedAccountResetQueueSession, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) (sharedAccountResetQueueReply, error) {
			status, err := session.MarkAccountResetHandover(ctx, trust, bundle, userID, offerID)
			return sharedAccountResetQueueReply{Status: status}, err
		}
	default:
		return nil, vaultwire.ErrProtocol
	}

	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := controller.session.(sharedAccountResetQueueSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := sharedAccountResetQueueReply{Status: "unavailable"}
	err = controller.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil {
			return nil
		}
		supported, err := session.AccountResetTargetsSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		result, err := use(ctx, session, trust, bundle)
		if errors.Is(err, sharedpg.ErrAccountRecovery) || errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
			return nil
		}
		if errors.Is(err, sharedpg.ErrChangeInProgress) {
			reply.Status = "busy"
			return nil
		}
		if err != nil {
			return err
		}
		reply = result
		return nil
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
