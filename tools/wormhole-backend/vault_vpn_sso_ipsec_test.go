package main

import (
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

func TestNativeIPsecSSODescribesOnlyConfiguredSAMLGateways(t *testing.T) {
	configuration := []byte(`{"Host":"vpn.test","RemoteGateways":" other.test, [::1] ","PreSharedKey":"fixture","SamlPort":1001,"UserAuth":3}`)
	first, err := describeNativeVPNSSO("https://vpn.test:1001/saml?request=first", false)(9, configuration)
	if err != nil || first.GatewayOrigin != "https://vpn.test:1001" || first.Realm != "" || first.TrustDigest == [32]byte{} {
		t.Fatal("primary SAML source", err)
	}
	second, err := describeNativeVPNSSO("https://vpn.test:1001/saml?request=second", false)(9, configuration)
	if err != nil || first != second {
		t.Fatal("attempt query changed retained scope", err)
	}
	for _, gateway := range []string{"other.test", "[::1]"} {
		p, err := describeNativeVPNSSO("https://"+gateway+":1001/saml?state=fixture", false)(9, configuration)
		if err != nil || p.GatewayOrigin != "https://"+gateway+":1001" || p == first {
			t.Fatal("configured gateway scope", err)
		}
	}
	legacy, err := describeNativeVPNSSO("https://vpn.test:1001/saml", false)(9, []byte(`{"Host":"vpn.test","PreSharedKey":"fixture"}`))
	if err != nil || legacy != first {
		t.Fatal("legacy SAML defaults", err)
	}
	trusted, err := describeNativeVPNSSO("https://vpn.test:1001/saml", true)(9, []byte(`{"Host":"vpn.test","PreSharedKey":"fixture","TrustServerCertificate":true}`))
	if err != nil || trusted.TrustDigest == first.TrustDigest {
		t.Fatal("TLS policy missing from scope", err)
	}
	if _, err := describeNativeVPNSSO("https://vpn.test:443/remote/saml/start", false)(2, []byte(`{"Host":"vpn.test","UseSingleSignOn":true}`)); err != nil {
		t.Fatal("SSL adapter drift", err)
	}
	if _, err := describeNativeVPNSSO("https://vpn.test:1001/saml", false)(3, configuration); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	for _, raw := range []string{`{`, `{}`, `{"Host":"vpn.test"}`, `{"Host":"vpn.test","PreSharedKey":"fixture","UserAuth":0}`, `{"Host":"vpn.test","PreSharedKey":"fixture","UserAuth":1}`, `{"Host":"vpn.test","PreSharedKey":"fixture","UserAuth":2,"Username":"u","Password":"p"}`, `{"Host":"vpn.test","PreSharedKey":"fixture","RemoteGateways":"invalid/path"}`} {
		if _, err := describeNativeVPNSSO("https://vpn.test:1001/saml", false)(9, []byte(raw)); err == nil {
			t.Fatal("non-SAML or invalid source admitted")
		}
	}
	for _, target := range []string{"%", "http://vpn.test:1001/saml", "https://vpn.test:1001/other", "https://vpn.test:1001/s%61ml", "https://u:p@vpn.test:1001/saml", "https://vpn.test:1001/saml#fragment", "https://vpn.test:1002/saml", "https://foreign.test:1001/saml", "https://vpn.test:1001/saml?state=\nunsafe"} {
		if _, err := describeNativeVPNSSO(target, false)(9, configuration); err == nil {
			t.Fatal("foreign SAML origin/path admitted")
		}
	}
	if _, err := describeNativeVPNSSO("https://vpn.test:1001/saml", true)(9, configuration); err == nil {
		t.Fatal("caller changed TLS policy")
	}
}

func TestNativeIPsecSSORPCPersistsAcrossFreshAttemptsAndRechecksSource(t *testing.T) {
	h, q, binding := nativeSSOProviderFixture(t, 9, `{"Host":"vpn.test","PreSharedKey":"fixture","SamlPort":1001,"UserAuth":3}`)
	ctx := context.Background()
	begin := func(target string) localvault.VPNSSOTransferOffer {
		t.Helper()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := h.Handle(ctx, "vpn-sso-begin", vaultInput(t, map[string]any{"request": q, "binding": binding, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": target, "ignoreCertificateErrors": false, "restorePublicKey": key.PublicKey().Bytes()}))
		if err != nil {
			t.Fatal(err)
		}
		var offer localvault.VPNSSOTransferOffer
		if json.Unmarshal(raw, &offer) != nil {
			t.Fatal("offer")
		}
		return offer
	}
	first := begin("https://vpn.test:1001/saml?request=first")
	if _, err := h.Handle(ctx, "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": first.Context, "manifest": first.Manifest})); err != nil {
		t.Fatal(err)
	}
	manifest, chunks, err := vault.SealVPNSSOTransferArchive(first.Context, "capture", []byte("native IPsec SSO profile"))
	if err != nil {
		t.Fatal(err)
	}
	for i, bundle := range chunks {
		packet := vault.VPNSSOTransferPacket{Context: first.Context, Direction: "capture", Manifest: manifest, Index: i, Bundle: bundle}
		encoded, err := json.Marshal(packet)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(ctx, "vpn-sso-push", encoded); err != nil {
			t.Fatal(err)
		}
		vault.Wipe(bundle.Ciphertext)
	}
	if _, err := h.Handle(ctx, "vpn-sso-commit", vaultInput(t, map[string]any{"context": first.Context})); err != nil {
		t.Fatal(err)
	}
	q["sessionId"], q["requestId"], q["epoch"] = uuid.NewString(), uuid.NewString(), "4"
	raw, err := h.Handle(ctx, "tunnel-plan", vaultInput(t, q))
	if err != nil || json.Unmarshal(raw, &binding) != nil {
		t.Fatal("fresh route", err)
	}
	second := begin("https://vpn.test:1001/saml?request=second")
	if second.Context.SourceRevision != "1" || second.Manifest.Bytes != len("native IPsec SSO profile") {
		t.Fatal("profile not reused across fresh native attempt")
	}
	if _, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: binding.TunnelConfigID, Name: "Native SSO", Kind: 9}, []byte(`{"Host":"changed.test","PreSharedKey":"fixture","UserAuth":3}`), binding.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "vpn-sso-take", vaultInput(t, map[string]any{"context": second.Context, "manifest": second.Manifest, "index": 0})); err == nil {
		t.Fatal("changed source released ciphertext")
	}
	if _, err := h.Handle(ctx, "vpn-sso-cancel", vaultInput(t, map[string]any{"context": second.Context})); err != nil {
		t.Fatal(err)
	}
}
