package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type adminInventoryMemberProbe struct{ *credentialReleaseProbe }

func (p *adminInventoryMemberProbe) AdminCredentialSlots(context.Context, sharedpg.TrustState, uuid.UUID) (sharedpg.TrustState, *sharedpg.AdminSlotPage, error) {
	panic("member reached the credential slots query")
}

func (p *adminInventoryMemberProbe) AdminInventorySupported(context.Context, string) (bool, error) {
	panic("member reached the administration capability probe")
}

func (p *adminInventoryMemberProbe) AdminInventory(context.Context, sharedpg.AdminInventoryRequest) (*sharedpg.AdminInventoryPage, error) {
	panic("member reached the administration query")
}

func TestSharedAdminInventoryRequestAndMemberGate(t *testing.T) {
	id := uuid.NewString()
	for _, raw := range []string{
		`{"kind":"accounts"}`,
		`{"kind":"slots","next":{"id":"` + id + `"}}`,
		`{"kind":"devices","next":{"id":"` + id + `"}}`,
		`{"kind":"unencrypted-clients","next":{"id":"` + id + `"}}`,
		`{"kind":"audit","next":{"id":"` + id + `","at":"2026-11-23T10:05:00.444555Z"}}`,
	} {
		if _, err := decodeSharedAdminInventory([]byte(raw)); err != nil {
			t.Fatal("valid request was rejected", err)
		}
	}
	h := &vaultFoundationHandler{}
	for _, raw := range []string{
		`{"kind":"passwords"}`,
		`{"kind":"accounts","kind":"audit"}`,
		`{"kind":"devices","next":null}`,
		`{"kind":"devices","next":{"id":"` + id + `","at":""}}`,
		`{"kind":"sessions","next":{"id":"` + id + `"}}`,
		`{"kind":"sessions","next":{"id":"invalid","at":"2026-11-23T10:05:00.444555Z"}}`,
		`{"kind":"accounts","password":"` + strings.Repeat("x", 512) + `"}`,
	} {
		if _, err := h.sharedAdminInventory(context.Background(), []byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid administration request accepted", err)
		}
	}
	raw := []byte(`{"kind":"audit"}`)
	for _, request := range [][]byte{raw, []byte(`{"kind":"slots"}`)} {
		if _, err := h.sharedAdminInventory(context.Background(), request); err != vaultwire.ErrProtocol {
			t.Fatal("an unavailable owner accepted administration", err)
		}
	}
	c, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	c.session = &adminInventoryMemberProbe{probe}
	c.runtimeTLS = sharedpg.TLSVerified
	h.shared = &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}
	for _, request := range [][]byte{raw, []byte(`{"kind":"unencrypted-clients"}`), []byte(`{"kind":"slots"}`)} {
		result, err := h.Handle(context.Background(), "shared-admin-inventory", request)
		var reply sharedAdminInventoryReply
		if err != nil || json.Unmarshal(result, &reply) != nil || reply.Status != "unavailable" || reply.Page != nil || !c.Unlocked() {
			t.Fatal("member denial leaked records or retired the workspace", err)
		}
	}
	probe.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) { return nil, sharedpg.ErrSessionClosed }
	if result, err := h.Handle(context.Background(), "shared-admin-inventory", []byte(`{"kind":"slots"}`)); !errors.Is(err, vaultwire.ErrRetired) || len(result) != 0 || c.Unlocked() {
		t.Fatal("slot inventory exposed a page after losing the session", err)
	}
}
