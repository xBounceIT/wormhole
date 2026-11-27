package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/secretclipboard"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type clipboardFixture struct {
	closeRemaining  time.Duration
	value, borrowed []byte
	writes          int
	closed          bool
	fail            bool
}

func (d *clipboardFixture) Write(_ context.Context, value []byte) (secretclipboard.Ticket, error) {
	d.writes++
	if d.fail {
		return 0, secretclipboard.ErrUnavailable
	}
	d.borrowed = value
	d.value = bytes.Clone(value)
	return 1, nil
}
func (d *clipboardFixture) Clear(ctx context.Context, _ secretclipboard.Ticket) error {
	if deadline, ok := ctx.Deadline(); ok {
		d.closeRemaining = time.Until(deadline)
	}
	vault.Wipe(d.value)
	d.value = nil
	return nil
}
func (d *clipboardFixture) Close() error { d.closed = true; return nil }
func TestVaultClipboardTypedCopyAndLockCleanup(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	d := &clipboardFixture{}
	h.clipboard = secretclipboard.New(d)
	input := vaultConnectionInput("", "0", "ssh")
	input["password"] = []byte("synthetic-clipboard-secret")
	input["metadata"].(map[string]any)["inlinePasswordAction"] = "set"
	n := saveVaultConnectionFixture(t, h, input)
	request := map[string]any{"nodeId": n.ID, "rowVersion": "1", "field": "secret"}
	for field, want := range map[string]string{"secret": "synthetic-clipboard-secret", "username": "alice"} {
		request["field"] = field
		result, err := h.Handle(ctx, "credential-copy", vaultInput(t, request))
		if err != nil || string(result) != `{"expiresInSeconds":30}` || string(d.value) != want {
			t.Fatal("copy", err)
		}
		if !bytes.Equal(d.borrowed, make([]byte, len(d.borrowed))) {
			t.Fatal("borrow retained")
		}
	}
	request["rowVersion"] = "2"
	if _, err := h.Handle(ctx, "credential-copy", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	request["rowVersion"] = "1"
	request["field"] = "domain"
	if _, err := h.Handle(ctx, "credential-copy", vaultInput(t, request)); err != secretclipboard.ErrInput {
		t.Fatal("empty copy", err)
	}
	request["field"] = "secret"
	d.fail = true
	if _, err := h.Handle(ctx, "credential-copy", vaultInput(t, request)); err != secretclipboard.ErrUnavailable {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil || d.value != nil || !d.closed {
		t.Fatal("lock cleanup", err)
	}
	if d.closeRemaining <= 0 || d.closeRemaining > vaultwire.ShutdownTimeout/2 {
		t.Fatal("clipboard cleanup exceeds transport shutdown budget")
	}
	if _, err := h.Handle(ctx, "credential-copy", vaultInput(t, request)); err == nil {
		t.Fatal("closed")
	}
}
func TestVaultClipboardRejectsUntrustedPayloads(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	d := &clipboardFixture{}
	h.clipboard = secretclipboard.New(d)
	base := map[string]any{"nodeId": uuid.NewString(), "rowVersion": "1", "field": "secret"}
	for field, values := range map[string][]any{"nodeId": {nil, "", uuid.Nil.String(), "bad"}, "rowVersion": {nil, 1, "0", "01", "9223372036854775808"}, "field": {nil, "", "privateKey", "password", []string{"secret"}}} {
		for _, value := range values {
			request := map[string]any{}
			for k, v := range base {
				request[k] = v
			}
			request[field] = value
			if _, err := h.Handle(ctx, "credential-copy", vaultInput(t, request)); err == nil {
				t.Fatal("accepted", field)
			}
		}
	}
	for _, raw := range []string{"null", "{}", strings.Repeat(" ", 513), `{"field":"secret","field":"username"}`, `{"value":"plaintext"}`, `{"ttl":999}`} {
		if _, err := h.Handle(ctx, "credential-copy", []byte(raw)); err == nil {
			t.Fatal("malformed")
		}
	}
	if _, err := (&vaultFoundationHandler{}).copyCredential(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("locked")
	}
	if d.writes != 0 {
		t.Fatal("invalid payload wrote")
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.copyCredential(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("closed policy")
	}
}
func assertFreshClipboard(t *testing.T, h *vaultFoundationHandler, node string) {
	t.Helper()
	d := &clipboardFixture{}
	h.clipboard = secretclipboard.New(d)
	action := vaultInput(t, map[string]any{"nodeId": node, "rowVersion": "2", "field": "username"})
	result, err := h.Handle(context.Background(), "fresh-action", freshActionInput(t, "credential-copy", action, bytes.Repeat([]byte{0x32}, 32)))
	var ack struct {
		ExpiresInSeconds int `json:"expiresInSeconds"`
	}
	if err != nil || json.Unmarshal(result, &ack) != nil || ack.ExpiresInSeconds != 20 || d.writes != 1 {
		t.Fatal("fresh copy", err)
	}
	if _, err := h.Handle(context.Background(), "credential-copy", action); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("copy authority persisted", err)
	}
}
