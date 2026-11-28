package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type createSlotMemberProbe struct{ *credentialReleaseProbe }

func (*createSlotMemberProbe) CreateCredentialSlotSupported(context.Context) (bool, error) {
	panic("member probed slot administration")
}
func (*createSlotMemberProbe) WorkspaceImportBoundary(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, workspaceimport.Destination) (sharedpg.TrustState, *vault.BoundaryManifest, error) {
	panic("member reached slot boundary selection")
}
func (*createSlotMemberProbe) CreateCredentialSlot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, vault.BoundaryManifest, sharedpg.AdminCredentialSlot, *vault.UserKeys) (sharedpg.TrustState, string, error) {
	panic("member signed a slot")
}

func TestSharedCreateSlotInputAndAuthority(t *testing.T) {
	slot := sharedpg.AdminCredentialSlot{ID: uuid.New(), Name: "Sistema", Protocol: "vnc", AllowSelfService: true}
	raw, err := json.Marshal(slot)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{}
	ctx := context.Background()
	for _, body := range []string{
		"{}", strings.Repeat(" ", 8193), strings.Replace(string(raw), "\"Sistema\"", "null", 1),
		strings.Replace(string(raw), "\"Sistema\"", "\"\" ", 1),
		strings.Replace(string(raw), "\"vnc\"", "\"web\"", 1),
		strings.Replace(string(raw), slot.ID.String(), "bad", 1),
		strings.TrimSuffix(string(raw), "}") + ",\"defaultCredentialId\":\"private\"}",
		strings.TrimSuffix(string(raw), "}") + ",\"name\":\"duplicate\"}",
	} {
		if _, err := h.Handle(ctx, "shared-create-credential-slot", []byte(body)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid slot request", err)
		}
	}
	if got, err := decodeSharedCreateSlot(raw); err != nil || got != slot {
		t.Fatal("metadata changed", err)
	}
	if _, err := h.Handle(ctx, "shared-create-credential-slot", raw); err != vaultwire.ErrProtocol {
		t.Fatal("locked owner accepted slot", err)
	}
	c, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	c.session = &createSlotMemberProbe{probe}
	c.runtimeTLS = sharedpg.TLSVerified
	h.shared = &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}
	result, err := h.Handle(ctx, "shared-create-credential-slot", raw)
	if err != nil || string(result) != `{"status":"unavailable"}` || !c.Unlocked() {
		t.Fatal("member slot request affected the session", err)
	}
	c.session = probe
	if result, err := h.Handle(ctx, "shared-create-credential-slot", raw); !errors.Is(err, vaultwire.ErrRetired) || len(result) != 0 {
		t.Fatal("owner without the slot protocol kept accepting requests", err)
	}
}
