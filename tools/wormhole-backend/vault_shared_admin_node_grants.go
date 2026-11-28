package main

import (
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAdminNodeGrantSession interface {
	AdminNodeGrantsSupported(context.Context) (bool, error)
	AdminNodeGrants(context.Context, sharedpg.TrustState, sharedpg.AdminNodeGrantRequest) (sharedpg.AdminNodeGrantReply, error)
}

func decodeSharedAdminNodeGrant(raw []byte) (request sharedpg.AdminNodeGrantRequest, err error) {
	if len(raw) > 2048 || decodeVaultObject(raw, map[string]any{
		"nodeId": &request.NodeID, "nodeRevision": &request.NodeRevision, "kind": &request.Kind,
		"after": &request.After, "epoch": &request.Epoch, "changeSeq": &request.ChangeSeq,
		"subjectId": &request.SubjectID, "login": &request.Login, "grantRevision": &request.GrantRevision,
		"mask": &request.Mask,
	}, "nodeId", "nodeRevision", "kind") != nil || !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedAdminNodeGrant(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedAdminNodeGrant(raw)
	if err != nil {
		return nil, err
	}
	reply := sharedpg.AdminNodeGrantReply{Status: "unavailable"}
	err = h.withSharedAdministration(ctx, func(ctx context.Context, native sharedAdmissionSession, trust sharedpg.TrustState) error {
		session, ok := native.(sharedAdminNodeGrantSession)
		if !ok {
			return sharedpg.ErrConfiguration
		}
		supported, err := session.AdminNodeGrantsSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		reply, err = session.AdminNodeGrants(ctx, trust, request)
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}
