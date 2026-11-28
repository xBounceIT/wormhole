package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedAccountSuspensionRejectsInventedScope(t *testing.T) {
	account := uuid.NewString()
	base := `{"accountId":"` + account + `","kind":"passwords"`
	valid := []byte(base + `,"revision":"42","after":"25"}`)
	request, err := decodeSharedAccountSuspension(valid)
	if err != nil || request.After != "25" || request.Revision != "42" {
		t.Fatal("valid cursor was rejected", err)
	}
	h := &vaultFoundationHandler{}
	for _, raw := range []string{
		`{}`, base + `,"revision":"42"}`, base + `,"revision":null,"after":"25"}`,
		base + `,"revision":"42","after":25}`, base + `,"revision":"42","after":"025"}`,
		base + `,"revision":"42","after":"25","role":"admin"}`,
	} {
		if _, err := h.sharedAccountSuspension(context.Background(), []byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("accepted invalid protected inventory request", err)
		}
	}
	if _, err := h.sharedAccountSuspension(context.Background(), valid); err != vaultwire.ErrProtocol {
		t.Fatal("closed owner could read inventory", err)
	}
	controller, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.runtimeTLS = sharedpg.TLSVerified
	h.shared = &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}
	out, err := h.Handle(context.Background(), "shared-account-suspension", valid)
	var reply sharedpg.AccountSuspensionReply
	if err != nil || json.Unmarshal(out, &reply) != nil || reply.Status != "unavailable" || !controller.Unlocked() {
		t.Fatal("member could inspect another account's inventory or denial locked the workspace", reply.Status, err)
	}
}
