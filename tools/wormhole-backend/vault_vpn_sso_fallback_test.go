package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const fallbackSSLSSOSettings = `{"Host":"ssl.test","Port":443,"Realm":"staff","UseSingleSignOn":true}`

func fallbackSSOBeginBody(request map[string]any, pair vault.TunnelFallbackBinding, public []byte) map[string]any {
	return map[string]any{"request": request, "binding": pair.Fallback, "fallback": pair, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": "https://ssl.test:443/remote/saml/start?realm=staff", "ignoreCertificateErrors": false, "restorePublicKey": public}
}

func nativeFallbackSSOFixture(t *testing.T) (nativeFallbackTestData, map[string]any) {
	t.Helper()
	f := nativeFallbackFixture(t)
	target, err := f.h.owner.ReadTunnel(context.Background(), f.binding.Fallback.TunnelConfigID, 0)
	if err != nil {
		t.Fatal(err)
	}
	target, err = f.h.owner.PutTunnel(context.Background(), target.TunnelMetadata, []byte(fallbackSSLSSOSettings), target.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	f.binding.Fallback.RowVersion, f.binding.Fallback.ConfigurationVersion = target.RowVersion, target.ConfigurationVersion
	return f, fallbackSSOBeginBody(f.request, f.binding, f.public)
}

func fallbackSSOBegin(t *testing.T, h *vaultFoundationHandler, body map[string]any) localvault.VPNSSOTransferOffer {
	t.Helper()
	raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, body))
	var offer localvault.VPNSSOTransferOffer
	if err != nil || json.Unmarshal(raw, &offer) != nil {
		t.Fatal("fallback SSO begin", err)
	}
	return offer
}

func fallbackSSOCapture(t *testing.T, h *vaultFoundationHandler, offer localvault.VPNSSOTransferOffer, archive []byte) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.Handle(ctx, "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": offer.Context, "manifest": offer.Manifest})); err != nil {
		t.Fatal(err)
	}
	manifest, chunks, err := vault.SealVPNSSOTransferArchive(offer.Context, "capture", archive)
	if err != nil {
		t.Fatal(err)
	}
	for index, bundle := range chunks {
		encoded, err := json.Marshal(vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: manifest, Index: index, Bundle: bundle})
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.Handle(ctx, "vpn-sso-push", encoded)
		vault.Wipe(bundle.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeFallbackSSOCustodyAndCheckpointRoundtrip(t *testing.T) {
	f, body := nativeFallbackSSOFixture(t)
	ctx := context.Background()
	offer := fallbackSSOBegin(t, f.h, body)
	archive := []byte("native personal fallback storage")
	fallbackSSOCapture(t, f.h, offer, archive)
	if _, err := f.h.Handle(ctx, "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
		t.Fatal(err)
	}
	document, err := readVaultSlotFile(f.h.databasePath)
	if err != nil || len(document.VPNSSO) != 1 || document.VPNSSO[0].Revision != 1 {
		t.Fatal("archive checkpoint", err)
	}
	floors := map[string]uint64{}
	for _, mark := range document.Tunnels {
		floors[mark.TunnelID] = mark.Revision
	}
	if floors[f.binding.Primary.TunnelConfigID] < f.binding.Primary.RowVersion || floors[f.binding.Fallback.TunnelConfigID] < f.binding.Fallback.RowVersion {
		t.Fatal("source observations not published")
	}
	body["profileId"], body["challengeId"] = uuid.NewString(), uuid.NewString()
	second := fallbackSSOBegin(t, f.h, body)
	raw, err := f.h.Handle(ctx, "vpn-sso-take", vaultInput(t, map[string]any{"context": second.Context, "index": 0}))
	var packet vault.VPNSSOTransferPacket
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenVPNSSOTransferArchive(f.private, second.Context, "restore", second.Manifest, []vault.SealedBundle{packet.Bundle})
	defer vault.Wipe(plain)
	if err != nil || !bytes.Equal(plain, archive) || bytes.Contains(raw, archive) {
		t.Fatal("fallback restore", err)
	}
	if _, err := f.h.Handle(ctx, "vpn-sso-cancel", vaultInput(t, map[string]any{"context": second.Context})); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFallbackSSOCommitRechecksAfterCheckpointPublication(t *testing.T) {
	f, body := nativeFallbackSSOFixture(t)
	offer := fallbackSSOBegin(t, f.h, body)
	fallbackSSOCapture(t, f.h, offer, []byte("pending fallback archive"))
	previous := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = previous })
	corrupted := false
	privateFileDirectorySync = func(path string) error {
		document, err := readVaultSlotFile(f.h.databasePath)
		if err != nil {
			return err
		}
		if !corrupted && len(document.VPNSSO) > 0 && document.VPNSSO[0].Revision == 1 {
			// Simulate discovering an authentic newer protected checkpoint, not
			// a concurrent SQLite write (the native owner holds an exclusive lock).
			for i := range document.Tunnels {
				if document.Tunnels[i].TunnelID == f.binding.Fallback.TunnelConfigID {
					document.Tunnels[i].Revision++
				}
			}
			document.Sequence++
			key := bytes.Repeat([]byte{0x91}, 32) // existing synthetic localSlotFixture root
			raw, err := vault.EncodeSlotFile(key, document)
			vault.Wipe(key)
			if err != nil {
				return err
			}
			if err := os.WriteFile(vaultSlotPath(f.h.databasePath), raw, 0600); err != nil {
				return err
			}
			corrupted = true
		}
		return previous(path)
	}
	raw, err := f.h.Handle(context.Background(), "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context}))
	if !corrupted || err == nil || len(raw) != 0 {
		t.Fatal("commit acknowledged an invalid source after publication", err)
	}
}

func TestNativeFallbackSSOPairSchemaAndActiveBindingAreExact(t *testing.T) {
	f, valid := nativeFallbackSSOFixture(t)
	for _, mode := range []string{"null", "extra", "ordinary", "primary-request", "active", "provider"} {
		var body map[string]any
		_ = json.Unmarshal(vaultInput(t, valid), &body)
		pair := body["fallback"].(map[string]any)
		switch mode {
		case "null":
			body["fallback"] = nil
		case "extra":
			pair["extra"] = true
		case "ordinary":
			delete(body, "fallback")
		case "primary-request":
			body["request"].(map[string]any)["requestId"] = uuid.NewString()
		case "active":
			body["binding"].(map[string]any)["rowVersion"] = "99"
		case "provider":
			pair["fallback"].(map[string]any)["kind"] = 9
		}
		if raw, err := f.h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, body)); err == nil || len(raw) != 0 {
			t.Fatal("invalid pair accepted", mode, err)
		}
	}
}

func TestNativeFallbackSSOAcceptsBoundedCompletePairAtMetadataLimits(t *testing.T) {
	pair := sealedFallbackBinding()
	pair.Primary.Host = strings.Repeat("h", 1024)
	pair.Fallback.Host = pair.Primary.Host
	request := map[string]any{"nodeId": pair.Primary.NodeID, "credentialOverride": "", "requestId": pair.Primary.RequestID, "sessionId": pair.Primary.SessionID, "epoch": "1"}
	pair.Primary.Epoch, pair.Fallback.Epoch = 1, 1
	body := fallbackSSOBeginBody(request, pair, bytes.Repeat([]byte{1}, 32))
	body["startURL"] = "https://ssl.test:443/remote/saml/start?realm=" + strings.Repeat("r", 4000)
	raw := vaultInput(t, body)
	if len(raw) <= 8192 || len(raw) > 16384 || pair.Validate() != nil {
		t.Fatal("invalid metadata limit fixture", len(raw))
	}
	if q, err := decodeNativeVPNSSOBegin(raw); err != nil || !q.hasFallback || q.fallback != pair {
		t.Fatal("complete valid pair exceeded legacy single-source limit", err, len(raw))
	}
	if _, err := decodeNativeVPNSSOBegin(append(raw, bytes.Repeat([]byte{' '}, 16384)...)); err == nil {
		t.Fatal("unbounded fallback request")
	}
	delete(body, "fallback")
	ordinary := vaultInput(t, body)
	ordinary = append(ordinary, bytes.Repeat([]byte{' '}, 8193-len(ordinary))...)
	if _, err := decodeNativeVPNSSOBegin(ordinary); err == nil {
		t.Fatal("ordinary frame lost its existing bound")
	}
}
