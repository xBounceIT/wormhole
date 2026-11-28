package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"strings"
	"testing"
)

func TestVaultTunnelBundleHandler(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	plain := []byte(`{"ProfileOvpn":"private-vpn-profile"}`)
	tunnel, e := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 1}, plain, 0)
	if e != nil {
		t.Fatal(e)
	}
	protocol, mode, enabled, host := 4, 1, true, "example.org"
	n, e := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "HTTPS", Kind: 1, Protocol: &protocol, Host: &host, CredentialMode: &mode, TunnelEnabled: &enabled, TunnelConfigID: &tunnel.ID}, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	q := map[string]any{"nodeId": n.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1", "publicKey": key.PublicKey().Bytes()}
	raw, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, q))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, plain) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(plain))) {
		t.Fatal("plaintext relay")
	}
	var response localvault.TunnelConnectionBundle
	if json.Unmarshal(raw, &response) != nil {
		t.Fatal("response")
	}
	planRequest := map[string]any{"nodeId": n.ID, "credentialOverride": "", "sessionId": q["sessionId"], "requestId": q["requestId"], "epoch": "1"}
	planRaw, e := h.Handle(ctx, "tunnel-plan", vaultInput(t, planRequest))
	if e != nil {
		t.Fatal(e)
	}
	var plan vault.TunnelBundleBinding
	if json.Unmarshal(planRaw, &plan) != nil || plan != response.Binding || bytes.Contains(planRaw, []byte("ciphertext")) || bytes.Contains(planRaw, plain) {
		t.Fatal("invalid plan")
	}
	if _, e := h.Handle(ctx, "tunnel-plan", vaultInput(t, q)); e != vaultwire.ErrProtocol {
		t.Fatal("plan accepted recipient", e)
	}
	decoded, e := vault.OpenTunnelBundle(key.Bytes(), response.Binding, response.Bundle)
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("handoff", e)
	}
	vault.Wipe(decoded)
	if response.Binding.Protocol != "https" || response.Binding.TunnelConfigID != tunnel.ID {
		t.Fatal("wrong binding")
	}
	m := n.NodeMetadata
	invalidHost := "bad host"
	m.Host = &invalidHost
	changed, e := h.owner.PutNode(ctx, m, nil, n.RowVersion)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, q)); e != vault.ErrPolicy {
		t.Fatal("unsafe target", e)
	}
	if _, e := h.owner.PutNode(ctx, n.NodeMetadata, nil, changed.RowVersion); e != nil {
		t.Fatal(e)
	}
	for _, epoch := range []any{"01", "-1", "bad", "0", "9007199254740992", 1, nil} {
		copy := map[string]any{}
		for k, v := range q {
			copy[k] = v
		}
		copy["epoch"] = epoch
		if _, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, copy)); e == nil {
			t.Fatal("bad epoch", epoch)
		}
	}
	for _, body := range [][]byte{nil, []byte(`{}`), []byte(`{"nodeId":null}`), []byte(strings.Repeat("x", 2049)), []byte(`{"nodeId":"x","nodeId":"y"}`)} {
		if _, e := h.Handle(ctx, "tunnel-bundle", body); e == nil {
			t.Fatal("bad body")
		}
	}
	q["tunnelId"] = tunnel.ID
	if _, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, q)); e == nil {
		t.Fatal("caller-selected route")
	}
	delete(q, "tunnelId")
	if _, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, q)); e != nil {
		t.Fatal("malformed input retired legitimate owner", e)
	}
	if _, e := (&vaultFoundationHandler{}).tunnelBundle(ctx, vaultInput(t, q)); e == nil {
		t.Fatal("locked owner")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := h.Handle(cancelled, "tunnel-bundle", vaultInput(t, q)); e == nil {
		t.Fatal("cancelled")
	}
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Handle(ctx, "tunnel-bundle", vaultInput(t, q)); e == nil {
		t.Fatal("closed")
	}
}
