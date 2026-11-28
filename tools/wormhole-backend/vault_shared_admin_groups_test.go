package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedAdminGroupRequestsAndMemberGate(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000001"
	for _, request := range []sharedpg.AdminGroupRequest{
		{Action: "list"}, {Action: "members", GroupID: id, Revision: "1"},
		{Action: "delete", GroupID: id, Revision: "1"},
		{Action: "create", GroupID: id, Name: "Group"},
		{Action: "rename", GroupID: id, Revision: "1", Name: "New name"},
		{Action: "add-member", GroupID: id, Revision: "1", Login: "account"},
		{Action: "remove-member", GroupID: id, Revision: "1", MemberID: id},
	} {
		raw, _ := json.Marshal(request)
		if value, err := decodeSharedAdminGroups(raw); err != nil || value != request {
			t.Fatal("could not parse the group request", request.Action, err)
		}
	}
	for _, raw := range []string{`{}`, `null`, `{"action":"list","name":""}`, `{"action":"list","after":null}`,
		`{"action":"list","action":"list"}`, `{"action":"drop"}`, `{"action":"delete","groupId":"bad","revision":"1"}`,
		`{"action":"create","groupId":"` + id + `","name":"` + strings.Repeat("x", 2048) + `"}`} {
		if _, err := decodeSharedAdminGroups([]byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid group request accepted", err)
		}
	}
	c, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	c.runtimeTLS = sharedpg.TLSVerified
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	result, err := h.Handle(context.Background(), "shared-admin-groups", []byte(`{"action":"list"}`))
	if err != nil || string(result) != `{"status":"unavailable"}` || !c.Unlocked() {
		t.Fatal("member group check returned data or terminated a normal session", err)
	}
}
