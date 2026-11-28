package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedFallbackSSOFixture(t *testing.T) (*sharedFallbackFixtureData, map[string]any) {
	t.Helper()
	d := sharedFallbackFixtureWithSettings(t, []byte(fallbackSSLSSOSettings))
	q := map[string]any{"nodeId": d.q.NodeID, "credentialOverride": "", "requestId": d.q.RequestID, "sessionId": d.q.SessionID, "epoch": "3"}
	body := fallbackSSOBeginBody(q, d.pair, d.public)
	body["custody"] = map[string]any{"workspaceId": d.h.shared.vaultID, "fileId": d.h.shared.fileID}
	return d, body
}

func TestSharedFallbackSSOPersonalCustodyAndIndependentUsePerAction(t *testing.T) {
	d, body := sharedFallbackSSOFixture(t)
	offer := fallbackSSOBegin(t, d.h, body)
	if offer.Context.WorkspaceID != d.h.shared.vaultID || offer.Context.WorkspaceID == d.binding.WorkspaceID.String() {
		t.Fatal("not personal custody")
	}
	archive := []byte("personal shared-source fallback archive")
	fallbackSSOCapture(t, d.h, offer, archive)
	if _, err := d.h.Handle(context.Background(), "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
		t.Fatal(err)
	}
	slots, _, err := readSharedDeviceEnrollment(d.c.trustPath)
	anchor, e := readSharedStartupAnchor(d.c.trustPath, startupTestProtection())
	if err != nil || e != nil || len(slots.VPNSSO) != 1 || slots.VPNSSO[0].Revision != 1 || slots.Sequence != anchor.MinimumSequence {
		t.Fatal("personal checkpoint not durable", err, e)
	}
	body["profileId"], body["challengeId"] = uuid.NewString(), uuid.NewString()
	second := fallbackSSOBegin(t, d.h, body)
	raw, err := d.h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": second.Context, "index": 0}))
	var packet vault.VPNSSOTransferPacket
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenVPNSSOTransferArchive(d.private, second.Context, "restore", second.Manifest, []vault.SealedBundle{packet.Bundle})
	defer vault.Wipe(plain)
	if err != nil || !bytes.Equal(plain, archive) || d.primaryUses != 0 || d.secondaryUses != 6 {
		t.Fatal("missing independent audited source action", err, d.primaryUses, d.secondaryUses)
	}
	cache, err := os.ReadFile(sharedVPNSSOPath(d.c.trustPath))
	if err != nil || bytes.Contains(cache, archive) {
		t.Fatal("plaintext cache", err)
	}
	d.p.beginFallback = func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*sharedpg.FallbackUseIntent, error) {
		return nil, vault.ErrPolicy
	}
	if raw, err := d.h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": second.Context, "index": 0})); err == nil || len(raw) != 0 || d.c.Unlocked() || d.c.vpnSSO != nil {
		t.Fatal("revocation left personal custody usable", err)
	}
}

func TestSharedFallbackSSORefusesInvalidSourceBeforeOfferingStorage(t *testing.T) {
	for _, mode := range []string{"custody", "target-revision", "source-proof", "target-proof", "target-cipher", "origin", "profile", "short-key"} {
		t.Run(mode, func(t *testing.T) {
			d, body := sharedFallbackSSOFixture(t)
			switch mode {
			case "custody":
				body["custody"] = map[string]any{"workspaceId": uuid.NewString(), "fileId": d.h.shared.fileID}
			case "target-revision":
				p := d.pair
				p.Fallback.RowVersion++
				body["fallback"], body["binding"] = p, p.Fallback
			case "source-proof":
				d.wire["source"].(map[string]any)["metadata"].(map[string]any)["chain"].([]any)[0].([]any)[11] = hex.EncodeToString(make([]byte, 64))
			case "target-proof":
				d.wire["target"].([]any)[11] = hex.EncodeToString(make([]byte, 64))
			case "target-cipher":
				row := d.wire["values"].([]any)[0].([]any)
				raw, _ := hex.DecodeString(row[8].(string))
				envelope, err := vault.DecodeSharedEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Ciphertext[0] ^= 1
				raw, err = vault.EncodeSharedEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
				row[8] = hex.EncodeToString(raw)
			case "origin":
				body["startURL"] = "https://other.test:443/remote/saml/start?realm=staff"
			case "profile":
				d.c.runtimeProfile = vault.Standard
			case "short-key":
				// A full public verification still precedes this private-key refusal.
				if err := d.c.privateKeys.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				d.c.privateKeys, err = securemem.New(32, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			if raw, err := d.h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, body)); err == nil || len(raw) != 0 || d.c.Unlocked() || d.c.vpnSSO != nil {
				t.Fatal("invalid source retained custody", err)
			}
			stored, err := readSharedTrustFile(d.path, d.root, d.binding, d.initial)
			if err != nil {
				t.Fatal(err)
			}
			floor := stored.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision
			if (mode == "target-proof" && floor != 0) || (mode != "target-proof" && floor == 0) {
				t.Fatal("independent authenticated target facts lost or invented", mode, floor)
			}
		})
	}
}
