package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type memberInvitationProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func TestMemberInvitationClipboardScopesAndDismissesCiphertext(t *testing.T) {
	root := bytes.Repeat([]byte{44}, 32)
	code := bytes.Repeat([]byte{54}, vault.InviteCodeBytes)
	trust := sharedpg.TrustState{WorkspaceID: uuid.New(), DeviceID: uuid.New(), UserID: uuid.New()}
	request, invite := uuid.New(), uuid.New()
	h := &vaultFoundationHandler{memberClipboard: &invitationClipboard{}}
	if err := h.memberClipboard.prepare(root, trust, request, invite, time.Now().Add(time.Hour).Unix(), code); err != nil {
		t.Fatal(err)
	}
	binding := h.memberClipboard.binding()
	raw, err := vault.Open(root, binding, h.memberClipboard.sealed)
	if err != nil || !bytes.Equal(code, raw) {
		t.Fatal("native clipboard delivery", err)
	}
	vault.Wipe(raw)
	binding.OwnerID = uuid.NewString()
	if raw, err := vault.Open(root, binding, h.memberClipboard.sealed); err == nil || raw != nil {
		t.Fatal("copy opened for a different invite")
	}
	for _, id := range []uuid.UUID{uuid.New(), request, request} {
		result, err := h.dismissMemberInvitation(vaultInput(t, map[string]any{"requestId": id.String()}))
		if err != nil || string(result) != "true" || (id == request) != (h.memberClipboard == nil) {
			t.Fatal("dismissal", err)
		}
	}
}

func (p memberInvitationProbe) MemberInvitationSupported(context.Context) (bool, error) {
	p.t.Fatal("queried an unmanaged workspace")
	return false, nil
}

func (p memberInvitationProbe) IssueMemberInvitation(context.Context, sharedpg.TrustState, sharedpg.Settings, *vault.UserKeys, sharedpg.MemberInvitationRequest) (sharedpg.MemberInvitationHandover, error) {
	p.t.Fatal("issued an invitation outside a managed workspace")
	return sharedpg.MemberInvitationHandover{}, nil
}

func TestMemberInvitationRequiresScopedProtectedRequest(t *testing.T) {
	ctx := context.Background()
	const op = "shared-member-invitation"
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = memberInvitationProbe{probe, t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	fields := func() map[string]any {
		return map[string]any{"login": "operator", "name": "Demo member", "workspaceId": uuid.NewString(), "requestId": uuid.NewString(),
			"recipient": make([]byte, 32), "authentication": []byte(vaultInput(t, map[string]any{"vaultId": uuid.NewString(), "slotId": uuid.NewString(), "password": []byte("synthetic confirmation")}))}
	}
	for key, value := range map[string]any{"login": "", "name": "invalid\nname", "workspaceId": uuid.Nil.String(), "requestId": "invalid", "recipient": []byte("short"), "authentication": nil, "groups": []string{"unknown"}} {
		input := fields()
		input[key] = value
		if reply, err := h.Handle(ctx, op, vaultInput(t, input)); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid request reached member issuance", key, err)
		}
	}
	input := fields()
	input["login"] = "demo\toperator"
	if reply, err := h.Handle(ctx, op, vaultInput(t, input)); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("login with a control character reached member issuance", err)
	}
	valid := vaultInput(t, fields())
	locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if reply, err := locked.Handle(ctx, op, valid); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("locked workspace answered issuance", err)
	}
	raw, err := h.Handle(ctx, op, valid)
	var result sharedMemberInvitationReply
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Status != "unavailable" || result.Handover != nil || !controller.Unlocked() || !h.ExitOnCancel(op) {
		t.Fatal("unmanaged workspace issuance", err)
	}
}
