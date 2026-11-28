package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func freshActionInput(t *testing.T, operation string, action []byte, factor []byte) []byte {
	doc, _ := localSlotFixture(t)
	auth := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": factor})
	return vaultInput(t, map[string]any{"operation": operation, "action": action, "authentication": []byte(auth)})
}

func TestVaultFreshActionIsSingleOperation(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	factor := bytes.Repeat([]byte{0x32}, 32)
	id := uuid.NewString()
	action := vaultCredentialSave(t, id, "0", []map[string]any{{"field": "password", "remove": false, "value": []byte("new secret")}})
	wrong := freshActionInput(t, "credential-save", action, bytes.Repeat([]byte{8}, 32))
	if _, err := h.Handle(ctx, "fresh-action", wrong); !errors.Is(err, vault.ErrAuthentication) || h.closed {
		t.Fatal(err)
	}
	if _, err := h.owner.ReadCredential(ctx, id, 0); err == nil {
		t.Fatal("wrong factor applied mutation")
	}
	request := freshActionInput(t, "credential-save", action, factor)
	response, err := h.Handle(ctx, "fresh-action", request)
	if !bytes.Equal(request, make([]byte, len(request))) {
		t.Fatal("outer request retained the verified factor")
	}
	if err != nil || !json.Valid(response) || h.reauthenticationFailures != 0 {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "fresh-action", wrong); !errors.Is(err, vault.ErrAuthentication) || h.closed {
		t.Fatal("success granted another action", err)
	}
	if !h.ExitOnCancel("fresh-action") {
		t.Fatal("cancel leaves a pending authority")
	}
	for i := 0; i < 2; i++ {
		_, _ = h.Handle(ctx, "fresh-action", wrong)
	}
	if !h.closed {
		t.Fatal("repeated authentication failures did not retire process")
	}
}

func TestVaultFreshActionRefusesMalformedAndChangedSlots(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"operation":"fresh-action","action":"e30=","authentication":"e30="}`), []byte(`{"operation":"folder-save","action":{},"authentication":"e30="}`), freshActionInput(t, "folder-save", nil, nil), freshActionInput(t, "unlock", []byte(`{}`), nil), []byte(`{"operation":"folder-save","action":"e30=","authentication":"bad!"}`)} {
		if _, err := h.Handle(ctx, "fresh-action", raw); err == nil {
			t.Fatal("malformed fresh action accepted")
		}
	}
	if h.closed {
		t.Fatal("malformed request killed valid owner")
	}
	if err := os.WriteFile(vaultSlotPath(h.databasePath), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "fresh-action", freshActionInput(t, "folder-save", []byte(`{}`), bytes.Repeat([]byte{0x32}, 32))); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("tampered slots did not retire owner", err)
	}
}

func TestVaultFreshActionRecoveryCodeAndAuthenticationShape(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	doc, _ := localSlotFixture(t)
	code := []byte("WHREC1-GIZDE-MRSGI-ZDEMR-SGIZD-EMRSG-IZDEM-RSGIZ-DEMRS-GIZDE-MRSGI-ZA7A2-6Z4")
	wrap := func(authentication map[string]any, action []byte) []byte {
		return vaultInput(t, map[string]any{"operation": "credential-save", "action": action, "authentication": []byte(vaultInput(t, authentication))})
	}
	id := uuid.NewString()
	action := vaultCredentialSave(t, id, "0", []map[string]any{{"field": "password", "remove": false, "value": []byte("recovery authorized value")}})
	for _, authentication := range []map[string]any{
		map[string]any{"vaultId": uuid.NewString(), "slotId": doc.Slots[0].ID, "recoveryCode": code},
		map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": bytes.Repeat([]byte{'X'}, 76)},
		map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)},
		map[string]any{"unknown": "rejected"},
	} {
		if _, err := h.Handle(ctx, "fresh-action", wrap(authentication, action)); err == nil || h.closed {
			t.Fatal("malformed authentication disposition", err)
		}
	}
	if _, err := h.Handle(ctx, "fresh-action", wrap(map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code}, action)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.owner.ReadCredential(ctx, id, 1); err != nil {
		t.Fatal("confirmed recovery action missing", err)
	}
	locked := &vaultFoundationHandler{}
	if _, err := locked.Handle(ctx, "fresh-action", wrap(map[string]any{}, action)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "fresh-action", make([]byte, vaultwire.MaxFrameBytes)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("oversize action admitted", err)
	}
	h.owner.Close()
	if _, err := h.Handle(ctx, "fresh-action", wrap(map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code}, action)); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("closed owner remained usable", err)
	}
}
