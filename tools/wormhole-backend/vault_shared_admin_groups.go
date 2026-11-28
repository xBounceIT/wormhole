package main

import (
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAdminGroupSession interface {
	AdminGroupsSupported(context.Context) (bool, error)
	AdminGroups(context.Context, sharedpg.TrustState, sharedpg.AdminGroupRequest) (sharedpg.AdminGroupReply, error)
}

func decodeSharedAdminGroups(raw []byte) (request sharedpg.AdminGroupRequest, err error) {
	if len(raw) > 2048 || json.Unmarshal(raw, &request) != nil {
		return request, vaultwire.ErrProtocol
	}
	fields := map[string]any{"action": &request.Action}
	required := []string{"action"}
	if request.Action != "list" {
		fields["groupId"] = &request.GroupID
		required = append(required, "groupId")
		if request.Action != "create" {
			fields["revision"] = &request.Revision
			required = append(required, "revision")
		}
	}
	switch request.Action {
	case "list", "members":
		fields["after"] = &request.After
	case "create", "rename":
		fields["name"] = &request.Name
		required = append(required, "name")
	case "add-member":
		fields["login"] = &request.Login
		required = append(required, "login")
	case "remove-member":
		fields["memberId"] = &request.MemberID
		required = append(required, "memberId")
	}
	if decodeVaultObject(raw, fields, required...) != nil || !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedAdminGroups(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedAdminGroups(raw)
	if err != nil {
		return nil, err
	}
	reply := sharedpg.AdminGroupReply{Status: "unavailable"}
	err = h.withSharedAdministration(ctx, func(ctx context.Context, native sharedAdmissionSession, trust sharedpg.TrustState) error {
		session, ok := native.(sharedAdminGroupSession)
		if !ok {
			return sharedpg.ErrConfiguration
		}
		supported, err := session.AdminGroupsSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		reply, err = session.AdminGroups(ctx, trust, request)
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}
