package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultNotesDisplay(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	input := vaultConnectionInput("", "0", "ssh")
	input["notesAction"], input["notes"] = "set", []byte("private note <script>literal</script> 🌍")
	n := saveVaultConnectionFixture(t, h, input)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request := map[string]any{"nodeId": n.ID, "rowVersion": "1", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()}
	raw, err := h.Handle(ctx, "notes-display", vaultInput(t, request))
	if err != nil || bytes.Contains(raw, []byte("private note")) {
		t.Fatal("plaintext response or failed display", err)
	}
	var result localvault.NotesDisplay
	if json.Unmarshal(raw, &result) != nil || result.NodeID != n.ID || result.RowVersion != "1" || result.RequestID != request["requestId"] {
		t.Fatal("bad binding")
	}
	info := []byte("wormhole/v1/notes-display")
	for _, v := range []string{result.WorkspaceID, result.NodeID, result.RequestID, result.RowVersion} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(v)))
		info = append(info, []byte(v)...)
	}
	recipientKey, _ := hpke.NewDHKEMPrivateKey(key)
	recipient, err := hpke.NewRecipient(result.Bundle.Enc, recipientKey, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := recipient.Open(nil, result.Bundle.Ciphertext)
	if err != nil || !bytes.Equal(notes, input["notes"].([]byte)) {
		t.Fatal("interop", err)
	}
	vault.Wipe(notes)
	info[len(info)-1] = '2'
	other, _ := hpke.NewRecipient(result.Bundle.Enc, recipientKey, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if _, err = other.Open(nil, result.Bundle.Ciphertext); err == nil {
		t.Fatal("revision binding bypass")
	}
	request["rowVersion"] = "2"
	if _, err = h.Handle(ctx, "notes-display", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal("future revision", err)
	}
	input["metadata"].(map[string]any)["id"] = n.ID
	input["rowVersion"] = "1"
	saveVaultConnectionFixture(t, h, input)
	request["rowVersion"] = "1"
	if _, err = h.Handle(ctx, "notes-display", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal("stale revision", err)
	}
	request["rowVersion"] = "2"
	if err = h.owner.DeleteNode(ctx, n.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "notes-display", vaultInput(t, request)); err != vaultstore.ErrMissing {
		t.Fatal("deleted", err)
	}
	request["nodeId"] = uuid.NewString()
	if _, err = h.Handle(ctx, "notes-display", vaultInput(t, request)); err != vaultstore.ErrMissing {
		t.Fatal("missing", err)
	}
	empty := saveVaultConnectionFixture(t, h, vaultConnectionInput("", "0", "ssh"))
	request["nodeId"], request["rowVersion"] = empty.ID, "1"
	if _, err = h.Handle(ctx, "notes-display", vaultInput(t, request)); err != nil {
		t.Fatal("absent notes should display empty text", err)
	}
	if err = h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = h.displayNotes(ctx, vaultInput(t, request)); err == nil {
		t.Fatal("closed owner")
	}
}

func TestVaultNotesRequestValidation(t *testing.T) {
	for _, operation := range []string{"notes-display", "credential-display"} {
		t.Run(operation, func(t *testing.T) { testVaultDisplayRequestValidation(t, operation) })
	}
}
func testVaultDisplayRequestValidation(t *testing.T, operation string) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	input := vaultConnectionInput("", "0", "ssh")
	input["notesAction"], input["notes"] = "set", []byte("fixture")
	n := saveVaultConnectionFixture(t, h, input)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	base := map[string]any{"nodeId": n.ID, "rowVersion": "1", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()}
	for field, values := range map[string][]any{"nodeId": {nil, "", uuid.Nil.String(), "bad"}, "requestId": {nil, "", uuid.Nil.String(), "bad"}, "rowVersion": {nil, 1, "0", "01", "9223372036854775808"}, "publicKey": {nil, []int{1, 2}, "!", []byte{1}, make([]byte, 32)}} {
		for _, value := range values {
			request := map[string]any{}
			for k, v := range base {
				request[k] = v
			}
			request[field] = value
			if _, err := h.Handle(ctx, operation, vaultInput(t, request)); err == nil {
				t.Fatalf("accepted %s", field)
			}
		}
	}
	for _, raw := range []string{"null", "{}", strings.Repeat(" ", 1025), `{"nodeId":"x","nodeId":"x"}`, `{"extra":true}`} {
		if _, err := h.Handle(ctx, operation, []byte(raw)); err == nil {
			t.Fatal("accepted malformed")
		}
	}
	if _, err := (&vaultFoundationHandler{}).displayNotes(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("locked")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(cancelled, "notes-display", vaultInput(t, base)); err == nil {
		t.Fatal("cancelled")
	}
}
