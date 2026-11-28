package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func nativeSSOFixture(t *testing.T) (*vaultFoundationHandler, map[string]any, vault.TunnelBundleBinding) {
	t.Helper()
	return nativeSSOProviderFixture(t, 2, `{"Host":"vpn.test","Port":443,"Realm":"staff","UseSingleSignOn":true}`)
}

func nativeSSOProviderFixture(t *testing.T, kind uint16, configuration string) (*vaultFoundationHandler, map[string]any, vault.TunnelBundleBinding) {
	t.Helper()
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Native SSO", Kind: int(kind)}, []byte(configuration), 0)
	if err != nil {
		t.Fatal(err)
	}
	protocol, mode, enabled, host := 4, 1, true, "protected.test"
	node, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "HTTPS", Kind: 1, Protocol: &protocol, Host: &host, CredentialMode: &mode, TunnelEnabled: &enabled, TunnelConfigID: &tunnel.ID}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "3"}
	raw, err := h.Handle(ctx, "tunnel-plan", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	var binding vault.TunnelBundleBinding
	if json.Unmarshal(raw, &binding) != nil {
		t.Fatal("native route")
	}
	return h, q, binding
}

func beginNativeSSO(t *testing.T, h *vaultFoundationHandler, q map[string]any, binding vault.TunnelBundleBinding) (localvault.VPNSSOTransferOffer, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, map[string]any{"request": q, "binding": binding, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": "https://vpn.test:443/remote/saml/start?realm=staff", "ignoreCertificateErrors": false, "restorePublicKey": key.PublicKey().Bytes()}))
	if err != nil {
		t.Fatal(err)
	}
	var offer localvault.VPNSSOTransferOffer
	if json.Unmarshal(raw, &offer) != nil {
		t.Fatal("native offer")
	}
	return offer, key.Bytes()
}

func TestNativeSSORPCCustodyAndCheckpointPublication(t *testing.T) {
	h, q, binding := nativeSSOFixture(t)
	ctx := context.Background()
	offer, private := beginNativeSSO(t, h, q, binding)
	defer vault.Wipe(private)
	if offer.Context.SourceRevision != "0" {
		t.Fatal("not a fresh source")
	}
	if _, err := h.Handle(ctx, "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": offer.Context, "manifest": offer.Manifest})); err != nil {
		t.Fatal(err)
	}
	plain := []byte("native SSO archive fixture")
	manifest, chunks, err := vault.SealVPNSSOTransferArchive(offer.Context, "capture", plain)
	if err != nil {
		t.Fatal(err)
	}
	for i, bundle := range chunks {
		packet := vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: manifest, Index: i, Bundle: bundle}
		encoded, err := json.Marshal(packet)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(ctx, "vpn-sso-push", encoded); err != nil {
			t.Fatal(err)
		}
		vault.Wipe(bundle.Ciphertext)
	}
	raw, err := h.Handle(ctx, "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, plain) {
		t.Fatal("plaintext in native response")
	}
	// Browser teardown always cancels its original transfer, including after a
	// successful commit. Repeated cleanup must positively confirm released keys.
	for range 2 {
		if _, err := h.Handle(ctx, "vpn-sso-cancel", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
			t.Fatal("completed native cleanup", err)
		}
	}
	var checkpoint localvault.VPNSSOCheckpoint
	if json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Revision != 1 {
		t.Fatal("commit receipt")
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if document.FormatVersion != 2 || len(document.VPNSSO) != 1 || document.VPNSSO[0].Revision != 1 || len(document.Tunnels) != 1 || len(document.Nodes) < 2 {
		t.Fatal("response preceded authenticated native checkpoint")
	}
	second, private2 := beginNativeSSO(t, h, q, binding)
	defer vault.Wipe(private2)
	response, err := h.Handle(ctx, "vpn-sso-take", vaultInput(t, map[string]any{"context": second.Context, "index": 0}))
	if err != nil {
		t.Fatal(err)
	}
	var packet vault.VPNSSOTransferPacket
	if json.Unmarshal(response, &packet) != nil {
		t.Fatal("native packet")
	}
	decoded, err := vault.OpenVPNSSOTransferArchive(private2, second.Context, "restore", second.Manifest, []vault.SealedBundle{packet.Bundle})
	defer vault.Wipe(decoded)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("native restore", err)
	}
	if _, err := h.Handle(ctx, "vpn-sso-cancel", vaultInput(t, map[string]any{"context": second.Context})); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSSOCustodySelectionIsStrictAndSourceBound(t *testing.T) {
	h, q, binding := nativeSSOFixture(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"request": q, "binding": binding, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": "https://vpn.test:443/remote/saml/start?realm=staff", "ignoreCertificateErrors": false, "restorePublicKey": key.PublicKey().Bytes()}
	for _, custody := range []any{nil, map[string]any{}, map[string]any{"workspaceId": "", "fileId": ""}, map[string]any{"workspaceId": "bad", "fileId": binding.FileID}, map[string]any{"workspaceId": uuid.Nil.String(), "fileId": binding.FileID}, map[string]any{"workspaceId": binding.WorkspaceID, "fileId": uuid.NewString()}, map[string]any{"workspaceId": binding.WorkspaceID, "fileId": binding.FileID, "extra": true}} {
		request["custody"] = custody
		if _, err := decodeNativeVPNSSOBegin(vaultInput(t, request)); err == nil {
			t.Fatal("malformed custody accepted")
		}
	}
	request["custody"] = map[string]any{"workspaceId": uuid.NewString(), "fileId": binding.FileID}
	if _, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request)); err == nil {
		t.Fatal("local owner admitted foreign personal custody")
	}
	request["custody"] = map[string]any{"workspaceId": binding.WorkspaceID, "fileId": binding.FileID}
	if _, err := decodeNativeVPNSSOBegin(vaultInput(t, request)); err != nil {
		t.Fatal("matching native custody rejected", err)
	}
}

func TestNativeSSORefusesMalformedSourcesAndMissingCheckpointFile(t *testing.T) {
	h, q, binding := nativeSSOFixture(t)
	ctx := context.Background()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	valid := map[string]any{"request": q, "binding": binding, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": "https://vpn.test:443/remote/saml/start?realm=staff", "ignoreCertificateErrors": false, "restorePublicKey": key.PublicKey().Bytes()}
	for _, field := range []string{"startURL", "ignoreCertificateErrors", "restorePublicKey", "challengeId", "request"} {
		bad := map[string]any{}
		for k, v := range valid {
			bad[k] = v
		}
		switch field {
		case "startURL":
			bad[field] = "https://another.test/remote/saml/start"
		case "ignoreCertificateErrors":
			bad[field] = true
		case "restorePublicKey":
			bad[field] = "AA=="
		case "challengeId":
			bad[field] = "bad"
		case "request":
			bad[field] = map[string]any{}
		}
		if _, err := h.Handle(ctx, "vpn-sso-begin", vaultInput(t, bad)); err == nil {
			t.Fatal("unverified source admitted", field)
		}
	}
	for _, operation := range []string{"vpn-sso-begin", "vpn-sso-take", "vpn-sso-push", "vpn-sso-restore-ack", "vpn-sso-commit", "vpn-sso-cancel"} {
		for _, raw := range []json.RawMessage{nil, json.RawMessage(`{}`), json.RawMessage(`{"context":null}`)} {
			if _, err := h.Handle(ctx, operation, raw); err == nil {
				t.Fatal("bad native request", operation)
			}
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "vpn-sso-begin", vaultInput(t, valid)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if err := os.Remove(vaultSlotPath(h.databasePath)); err != nil {
		t.Fatal(err)
	}
	if response, err := h.Handle(ctx, "vpn-sso-begin", vaultInput(t, valid)); err == nil || response != nil || !h.closed {
		t.Fatal("missing authenticated checkpoint recreated", err)
	}
}
