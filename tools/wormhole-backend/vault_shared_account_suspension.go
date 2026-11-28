package main

import (
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAccountSuspensionSession interface {
	AccountSuspensionSupported(context.Context) (bool, error)
	AccountSuspensionInventory(context.Context, sharedpg.TrustState, sharedpg.AccountSuspensionRequest) (sharedpg.AccountSuspensionReply, error)
}

func decodeSharedAccountSuspension(raw []byte) (request sharedpg.AccountSuspensionRequest, err error) {
	var revision, after json.RawMessage
	fields := map[string]any{"accountId": &request.AccountID, "kind": &request.Kind, "revision": &revision, "after": &after}
	if len(raw) > 512 || decodeVaultObject(raw, fields, "accountId", "kind") != nil || (len(revision) == 0) != (len(after) == 0) {
		return request, vaultwire.ErrProtocol
	}
	if len(revision) != 0 && (json.Unmarshal(revision, &request.Revision) != nil ||
		json.Unmarshal(after, &request.After) != nil || request.Revision == "" || request.After == "") {
		return request, vaultwire.ErrProtocol
	}
	if !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedAccountSuspension(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedAccountSuspension(raw)
	if err != nil {
		return nil, err
	}
	reply := sharedpg.AccountSuspensionReply{Status: "unavailable"}
	err = h.withSharedAdministration(ctx, func(ctx context.Context, native sharedAdmissionSession, trust sharedpg.TrustState) error {
		session, ok := native.(sharedAccountSuspensionSession)
		if !ok {
			return sharedpg.ErrConfiguration
		}
		supported, err := session.AccountSuspensionSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		reply, err = session.AccountSuspensionInventory(ctx, trust, request)
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}
