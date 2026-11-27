package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"strings"
	"testing"
)

func readClipboardRelease(t *testing.T, raw []byte, key *ecdh.PrivateKey, field string) []byte {
	t.Helper()
	var result localvault.NotesDisplay
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	info := []byte("wormhole/v1/clipboard/" + field)
	for _, v := range []string{result.WorkspaceID, result.NodeID, result.RequestID, result.RowVersion} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(v)))
		info = append(info, []byte(v)...)
	}
	private, _ := hpke.NewDHKEMPrivateKey(key)
	recipient, err := hpke.NewRecipient(result.Bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := recipient.Open(nil, result.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}
func TestVaultClipboardReleaseRejectsMalformedAndStaleRequests(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	input := vaultConnectionInput("", "0", "ssh")
	input["password"] = []byte("synthetic-clipboard-secret")
	input["metadata"].(map[string]any)["inlinePasswordAction"] = "set"
	n := saveVaultConnectionFixture(t, h, input)
	base := map[string]any{"nodeId": n.ID, "rowVersion": "1", "field": "secret", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()}
	raw, err := h.Handle(ctx, "credential-clipboard-release", vaultInput(t, base))
	if err != nil {
		t.Fatal(err)
	}
	plain := readClipboardRelease(t, raw, key, "secret")
	defer vault.Wipe(plain)
	if !bytes.Equal(plain, append([]byte{1, 30}, []byte("synthetic-clipboard-secret")...)) {
		t.Fatal("payload")
	}
	if bytes.Contains(raw, []byte("synthetic-clipboard-secret")) || h.clipboard != nil {
		t.Fatal("plaintext/native side effect")
	}
	for field, values := range map[string][]any{"nodeId": {nil, "bad"}, "rowVersion": {nil, "0", "2", 1}, "field": {nil, "privateKey", "domain"}, "requestId": {nil, "bad"}, "publicKey": {nil, []byte{1}, make([]byte, 32), "!!!"}, "ttl": {30}} {
		for _, value := range values {
			request := map[string]any{}
			for k, v := range base {
				request[k] = v
			}
			request[field] = value
			if _, err := h.Handle(ctx, "credential-clipboard-release", vaultInput(t, request)); err == nil {
				t.Fatal("accepted", field)
			}
		}
	}
	for _, raw := range []string{"null", "{}", strings.Repeat(" ", 1025), `{"field":"secret","field":"username"}`} {
		if _, err := h.releaseClipboard(ctx, []byte(raw)); err == nil {
			t.Fatal("malformed")
		}
	}
	if _, err := (&vaultFoundationHandler{}).releaseClipboard(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("locked")
	}
	h.owner.Close()
	if _, err := h.releaseClipboard(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("closed policy")
	}
}
func assertFreshClipboardRelease(t *testing.T, h *vaultFoundationHandler, node string) {
	t.Helper()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	action := vaultInput(t, map[string]any{"nodeId": node, "rowVersion": "2", "field": "username", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()})
	raw, err := h.Handle(context.Background(), "fresh-action", freshActionInput(t, "credential-clipboard-release", action, bytes.Repeat([]byte{0x32}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	plain := readClipboardRelease(t, raw, key, "username")
	defer vault.Wipe(plain)
	if len(plain) < 3 || plain[0] != 1 || plain[1] != 20 {
		t.Fatal("standard ttl")
	}
	if _, err := h.Handle(context.Background(), "credential-clipboard-release", action); err != vault.ErrPolicy {
		t.Fatal("authority persisted", err)
	}
}
