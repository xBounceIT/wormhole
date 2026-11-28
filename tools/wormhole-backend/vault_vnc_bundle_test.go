package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultVNCBundleBoundary(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	protocol, port := 6, 5900
	host := "vnc.example"
	credential, err := h.owner.PutCredential(ctx, vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "VNC", Protocol: "vnc", Kind: "password", Provider: "local"}, []localvault.SecretChange{{Field: "password", Value: []byte("vnc-secret-native-only")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	node, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "VNC", Kind: 1, Protocol: &protocol, Port: &port, Host: &host, CredentialID: &credential.ID}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1", "publicKey": key.PublicKey().Bytes()}
	raw, err := h.Handle(ctx, "vnc-bundle", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("vnc-secret-native-only")) {
		t.Fatal("plaintext response")
	}
	var result localvault.VNCConnectionBundle
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid response")
	}
	plain, err := vault.OpenBundle(key.Bytes(), result.Binding, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	decoded, err := vault.DecodeVNCBundle(plain)
	if err != nil || string(decoded.Password) != "vnc-secret-native-only" {
		t.Fatal(err)
	}
	for _, field := range []string{"workspaceId", "password", "host", "route", "endpoint", "sftpOnly"} {
		bad := cloneSFTPPacket(q)
		bad[field] = "injected"
		if _, err := h.vncBundle(ctx, "vnc-bundle", vaultInput(t, bad)); err == nil {
			t.Fatal("injected field accepted", field)
		}
	}
	for field := range q {
		bad := cloneSFTPPacket(q)
		bad[field] = nil
		if _, err := h.vncBundle(ctx, "vnc-bundle", vaultInput(t, bad)); err == nil {
			t.Fatal("null field accepted", field)
		}
	}
	for _, epoch := range []string{"01", "0", "9007199254740992", "-1", "invalid"} {
		bad := cloneSFTPPacket(q)
		bad["epoch"] = epoch
		if _, err := h.vncBundle(ctx, "vnc-bundle", vaultInput(t, bad)); err == nil {
			t.Fatal("invalid epoch accepted")
		}
	}
	if _, err := (&vaultFoundationHandler{}).vncBundle(ctx, "vnc-bundle", nil); err == nil {
		t.Fatal("locked admitted")
	}
	if _, err := h.vncBundle(ctx, "unknown", vaultInput(t, q)); err == nil {
		t.Fatal("unknown operation admitted")
	}
	if _, err := h.vncBundle(ctx, "vnc-bundle", make([]byte, 4097)); err == nil {
		t.Fatal("oversized request admitted")
	}
	routeRaw := cloneSFTPPacket(q)
	routeRaw["route"] = map[string]any{}
	routeRaw["endpoint"] = "127.0.0.1:2345"
	if _, err := h.vncBundle(ctx, "vnc-route-bundle", vaultInput(t, routeRaw)); err == nil {
		t.Fatal("invalid route admitted")
	}
	tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte("native-route"), 0)
	if err != nil {
		t.Fatal(err)
	}
	m := node.NodeMetadata
	m.TunnelEnabled = &[]bool{true}[0]
	m.TunnelConfigID = &tunnel.ID
	node, err = h.owner.PutNode(ctx, m, nil, node.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	request := localvault.TunnelPlanRequest{NodeID: node.ID, SessionID: q["sessionId"].(string), RequestID: q["requestId"].(string), Epoch: 1}
	route, err := h.owner.PlanConnectionTunnel(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	routeRaw["route"] = route
	raw, err = h.Handle(ctx, "vnc-route-bundle", vaultInput(t, routeRaw))
	if err != nil {
		t.Fatal(err)
	}
	var routed localvault.RoutedVNCConnectionBundle
	if json.Unmarshal(raw, &routed) != nil {
		t.Fatal("invalid routed response")
	}
	opened, err := vault.OpenRoutedBundle(key.Bytes(), route, routed.Endpoint, routed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(opened)
	if p, err := vault.DecodeVNCBundle(opened); err != nil || string(p.Password) != "vnc-secret-native-only" {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "vnc-bundle", vaultInput(t, q)); err == nil {
		t.Fatal("VPN bypass accepted")
	}
}
