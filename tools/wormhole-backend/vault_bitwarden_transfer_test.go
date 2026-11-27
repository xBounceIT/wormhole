package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func browserTransferJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func browserTransferBeginInput(t *testing.T, h *vaultFoundationHandler, profile, action, source string) (map[string]any, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := h.owner.WorkspaceID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"workspaceId": workspace, "profileId": profile, "requestId": uuid.NewString(), "epoch": "2", "action": action, "sourceRevision": source, "restorePublicKey": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}, key.Bytes()
}

func browserTransferHandlerRun(t *testing.T, h *vaultFoundationHandler, profile, action, source, local, session string) (string, string, vault.BrowserTransferManifest) {
	t.Helper()
	ctx := context.Background()
	q, key := browserTransferBeginInput(t, h, profile, action, source)
	defer vault.Wipe(key)
	call := func(op string, value any) json.RawMessage {
		t.Helper()
		raw, err := h.Handle(ctx, op, browserTransferJSON(t, value))
		if err != nil {
			t.Fatal(op, err)
		}
		if bytes.Contains(raw, []byte("native-only-account")) {
			t.Fatal("plaintext in wire response")
		}
		return raw
	}
	var c vault.BrowserTransferContext
	if json.Unmarshal(call("bitwarden-transfer-begin", q), &c) != nil {
		t.Fatal("begin")
	}
	frame, err := vault.EncodeBrowserTransferFrame([]byte(local), []byte(session))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(frame)
	m := vault.BrowserTransferManifest{Bytes: len(frame), Revision: source}
	count, _ := vault.BrowserTransferChunkCount(m)
	for i := 0; i < count; i++ {
		size, _ := vault.BrowserTransferChunkSize(m, i)
		sealed, err := vault.SealBrowserTransferChunk(c, "capture", m, i, frame[i*vault.MaxSecretBytes:i*vault.MaxSecretBytes+size])
		if err != nil {
			t.Fatal(err)
		}
		var ack struct {
			Accepted bool
			Index    int
		}
		if json.Unmarshal(call("bitwarden-transfer-push", vault.BrowserTransferPacket{Context: c, Direction: "capture", Manifest: m, Index: i, Bundle: sealed}), &ack) != nil || !ack.Accepted || ack.Index != i {
			t.Fatal("push")
		}
		vault.Wipe(sealed.Enc)
		vault.Wipe(sealed.Ciphertext)
	}
	var committed struct{ Manifest vault.BrowserTransferManifest }
	if json.Unmarshal(call("bitwarden-transfer-commit", map[string]any{"context": c}), &committed) != nil {
		t.Fatal("commit")
	}
	count, _ = vault.BrowserTransferChunkCount(committed.Manifest)
	var opened []byte
	defer func() { vault.Wipe(opened) }()
	for i := 0; i < count; i++ {
		var packet vault.BrowserTransferPacket
		if json.Unmarshal(call("bitwarden-transfer-take", map[string]any{"context": c, "index": i}), &packet) != nil {
			t.Fatal("take")
		}
		chunk, err := vault.OpenBrowserTransferChunk(key, c, "restore", committed.Manifest, i, packet.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		opened = append(opened, chunk...)
		vault.Wipe(chunk)
	}
	payload, err := vault.DecodeBrowserTransferFrame(opened)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "bitwarden-transfer-take", browserTransferJSON(t, map[string]any{"context": c, "index": 0})); err == nil {
		t.Fatal("replay")
	}
	call("bitwarden-transfer-cancel", map[string]any{"context": c})
	return string(payload.LocalJSON), string(payload.SessionJSON), committed.Manifest
}

func TestVaultBitwardenTransferHandlerNativeRoundTrip(t *testing.T) {
	h := vaultCredentialFixture(t)
	profile := uuid.NewString()
	local, session, m := browserTransferHandlerRun(t, h, profile, "hydrate", "0", "{}", "{}")
	if local != "{}" || session != "{}" || m.Revision != "0" {
		t.Fatal("initial state")
	}
	local, session, m = browserTransferHandlerRun(t, h, profile, "capture", "0", `{"account":"native-only-account"}`, `{"session":"volatile"}`)
	if !strings.Contains(local, "native-only-account") || !strings.Contains(session, "volatile") || m.Revision != "1" {
		t.Fatal("capture state")
	}
	local, session, m = browserTransferHandlerRun(t, h, uuid.NewString(), "hydrate", "0", "{}", "{}")
	if !strings.Contains(local, "native-only-account") || !strings.Contains(session, "volatile") || !m.Restore {
		t.Fatal("shared restore")
	}
	if _, err := h.Handle(context.Background(), "bitwarden-profile-close", browserTransferJSON(t, map[string]any{"profileId": profile})); err != nil {
		t.Fatal(err)
	}
}

func TestVaultBitwardenTransferHandlerRejectsInvalidBoundaries(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	q, key := browserTransferBeginInput(t, h, uuid.NewString(), "hydrate", "0")
	defer vault.Wipe(key)
	for _, delta := range []map[string]any{{"epoch": "0"}, {"epoch": "02"}, {"epoch": "9007199254740992"}, {"epoch": 2}, {"epoch": nil}, {"workspaceId": uuid.NewString()}, {"profileId": "bad"}, {"action": "restore"}, {"sourceRevision": "01"}, {"restorePublicKey": "AA=="}, {"restorePublicKey": []int{1, 2}}, {"extra": true}} {
		bad := map[string]any{}
		for k, v := range q {
			bad[k] = v
		}
		for k, v := range delta {
			bad[k] = v
		}
		if _, err := h.Handle(ctx, "bitwarden-transfer-begin", browserTransferJSON(t, bad)); err == nil {
			t.Fatal("accepted begin", delta)
		}
	}
	raw, err := h.Handle(ctx, "bitwarden-transfer-begin", browserTransferJSON(t, q))
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeBrowserTransferContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"bitwarden-transfer-begin", "bitwarden-transfer-push", "bitwarden-transfer-commit", "bitwarden-transfer-take", "bitwarden-transfer-cancel", "bitwarden-profile-close"} {
		for _, input := range []string{`{}`, `null`, `{"context":null}`, `{"unknown":true}`, strings.Repeat(" ", 2400) + `{}`} {
			if _, err := h.Handle(ctx, op, []byte(input)); err == nil {
				t.Fatal("accepted malformed", op, input[:2])
			}
		}
		if _, err := (&vaultFoundationHandler{}).Handle(ctx, op, []byte(`{}`)); err == nil {
			t.Fatal("unowned operation")
		}
	}
	for _, op := range []string{"bitwarden-transfer-commit", "bitwarden-transfer-take"} {
		value := map[string]any{"context": c}
		if op == "bitwarden-transfer-take" {
			value["index"] = 0
		}
		if _, err := h.Handle(ctx, op, browserTransferJSON(t, value)); err == nil {
			t.Fatal("unstaged operation")
		}
	}
	if _, err := h.Handle(ctx, "bitwarden-transfer-cancel", browserTransferJSON(t, map[string]any{"context": c})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "bitwarden-profile-close", []byte(`{"profileId":"bad"}`)); err == nil {
		t.Fatal("bad close")
	}
	if _, err := h.bitwardenTransfer(ctx, "bad", nil); err == nil {
		t.Fatal("unknown operation")
	}
}

func TestVaultBitwardenTransferStrictNestedDecoders(t *testing.T) {
	h := vaultCredentialFixture(t)
	q, key := browserTransferBeginInput(t, h, uuid.NewString(), "hydrate", "0")
	defer vault.Wipe(key)
	raw, err := h.Handle(context.Background(), "bitwarden-transfer-begin", browserTransferJSON(t, q))
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeBrowserTransferContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := vault.EncodeBrowserTransferFrame([]byte(`{}`), []byte(`{}`))
	defer vault.Wipe(frame)
	m := vault.BrowserTransferManifest{Bytes: len(frame), Revision: "0"}
	sealed, err := vault.SealBrowserTransferChunk(c, "capture", m, 0, frame)
	if err != nil {
		t.Fatal(err)
	}
	p := browserTransferJSON(t, vault.BrowserTransferPacket{Context: c, Direction: "capture", Manifest: m, Bundle: sealed})
	if _, err := decodeBrowserTransferPacket(p); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`"context":{`, `"context":{"epoch":2,`}, {`"epoch":2`, `"epoch":2.0`}, {`"epoch":2`, `"epoch":9007199254740992`},
		{`"manifest":{`, `"manifest":{"revision":"0",`}, {`"bundle":{`, `"bundle":{"suiteId":2,`},
		{`"context":{`, `"context":{"unknown":1,`}, {`"manifest":{`, `"manifest":{"unknown":1,`}, {`"bundle":{`, `"bundle":{"unknown":1,`},
		{`"enc":"`, `"enc":"\\n`}, {`"restorePublicKey":"`, `"restorePublicKey":"\\n`}, {`"capturePublicKey":"`, `"capturePublicKey":"\\n`},
		{`"ciphertext":"`, `"ciphertext":"!`}, {`"formatVersion":1`, `"formatVersion":2`}, {`"suiteId":2`, `"suiteId":1`},
		{`"revision":"0"`, `"revision":"01"`}, {`"restore":false`, `"restore":true`}, {`"index":0`, `"index":-1`},
		{`"bytes":14`, `"bytes":15`}, {`"direction":"capture"`, `"direction":"bad"`}, {`"enc":"` + base64.StdEncoding.EncodeToString(sealed.Enc) + `"`, `"enc":[1,2]`},
	} {
		bad := strings.Replace(string(p), pair[0], pair[1], 1)
		if bad == string(p) {
			t.Fatal("ineffective mutation", pair[0])
		}
		if _, err := decodeBrowserTransferPacket([]byte(bad)); err == nil {
			t.Fatal("accepted nested mutation", pair[0])
		}
	}
	for _, raw := range []string{"", "AA==", strings.Repeat("A", 100), "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"} {
		if _, err := browserTransferBytes(raw, 32, 32); err == nil {
			t.Fatal("invalid key")
		}
	}
	if _, err := decodeBrowserTransferContext([]byte(strings.Repeat(" ", 2049))); err == nil {
		t.Fatal("large context")
	}
	if _, err := h.Handle(context.Background(), "bitwarden-transfer-cancel", []byte(`{"context":{"unknown":1}}`)); err == nil {
		t.Fatal("invalid nested control")
	}
}
