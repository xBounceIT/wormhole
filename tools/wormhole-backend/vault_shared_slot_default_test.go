package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedSlotDefaultWireChecksBeforeOpeningWorkspace(t *testing.T) {
	slot, workspace, account := uuid.NewString(), uuid.NewString(), uuid.NewString()
	confirm := map[string]string{"workspaceId": workspace, "slotRevision": "1", "credentialId": account, "credentialRevision": "7"}
	encode := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := decodeSlotDefaultConfirmation(encode(confirm), "Shared"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{
		{"workspaceId": slot, "slotRevision": "9223372036854775807", "credentialId": account, "credentialRevision": "7"},
		{"workspaceId": "other", "slotRevision": "1", "credentialId": account, "credentialRevision": "7"},
		{"workspaceId": slot, "slotRevision": "1", "credentialId": account, "credentialRevision": "0"},
		{"workspaceId": slot, "slotRevision": "1", "credentialId": "", "credentialRevision": "7"},
	} {
		if _, err := decodeSlotDefaultConfirmation(encode(bad), "Shared"); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("accepted invalid review")
		}
	}
	if _, err := decodeSlotDefaultConfirmation(encode(confirm), ""); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("clearing with a credential")
	}
	confirm["credentialId"], confirm["credentialRevision"] = "", ""
	if _, err := decodeSlotDefaultConfirmation(encode(confirm), ""); err != nil {
		t.Fatal(err)
	}
	request := map[string]string{"slotId": slot, "credentialName": "Shared"}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte("X"), 32769), encode(map[string]any{"action": request}),
		encode(map[string]any{"action": request, "authentication": "no-review"}),
		encode(map[string]any{"action": map[string]any{"slotId": slot, "credentialName": "", "confirmation": confirm}, "authentication": "invalid"}),
		encode(map[string]any{"action": map[string]any{"slotId": slot, "credentialName": "Shared", "confirmation": confirm}}),
		encode(map[string]any{"action": map[string]any{"slotId": slot, "credentialName": "bad\nname"}})} {
		h := new(vaultFoundationHandler)
		if result, err := h.sharedSlotDefault(context.Background(), raw); !errors.Is(err, vaultwire.ErrProtocol) || len(result) != 0 || h.closed {
			t.Fatal("invalid or unadmitted request changed owner")
		}
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("retained input")
		}
	}
}
