package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func sharedSSOFixture(t *testing.T, kind int) (*vaultFoundationHandler, *credentialReleaseProbe, map[string]any, map[string]any) {
	t.Helper()
	f, account, anchor, slot := selectedDeviceFixture(t)
	if err := account.Close(); err != nil {
		t.Fatal(err)
	}
	selected, err := unlockSharedSelectedDevice(context.Background(), f.o, slot, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, startupTestProtection())
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	c, probe := selectedDeviceController(t, f)
	if err := selected.Open(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := c.adoptVPNSSOStorage(context.Background(), selected.account, startupTestProtection()); err != nil {
		t.Fatal(err)
	}
	var signing ed25519.PrivateKey
	if err := c.privateKeys.With(func(keys []byte) error { signing = ed25519.NewKeyFromSeed(keys[32:]); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(signing)
	_, p, o, _, material, _, node, wire := installCredentialControllerFixture(t, c, &catalogProbe{sharedAdmissionProbe: probe}, selected.options, f.root, f.account, f.org)

	c.catalogAnchor = func(ctx context.Context, path string, key []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
		_, err := refreshSharedCatalogAnchor(ctx, path, key, binding, trust, startupTestProtection())
		return err
	}
	editSharedConnectionFixture(t, o.Binding.WorkspaceID, material.Binding.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
		enabled, id := true, uuid.NewString()
		n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
	}, signing)
	settings, start := `{"Host":"vpn.test","Port":443,"Realm":"staff","UseSingleSignOn":true}`, "https://vpn.test:443/remote/saml/start?realm=staff"
	if kind == 9 {
		settings, start = `{"Host":"vpn.test","PreSharedKey":"fixture-psk","UserAuth":3,"SamlPort":1001}`, "https://vpn.test:1001/saml?nonce=fresh"
	}
	installSharedTunnelReleaseFixture(t, wire, material, []byte(settings), signing)
	// Sign the selected provider kind. Both metadata and ciphertext use the
	// production verified-release graph; no source/authentication seam is bypassed.
	metadata := wire["metadata"].(map[string]any)
	row := metadata["tunnel"].([]any)
	var record sharedcatalog.TunnelRecord
	if err := json.Unmarshal([]byte(row[4].(string)), &record); err != nil {
		t.Fatal(err)
	}
	record.Metadata.Kind = kind
	seal, err := sharedcatalog.SignSelection(o.Binding.WorkspaceID, uuid.MustParse(row[5].(string)), record, 1, material.Binding.Signing, signing)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(record)
	row[4], row[11] = string(body), hex.EncodeToString(seal.Signature)
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: anchor.FileID, vaultID: anchor.VaultID}}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	q := localvault.TunnelPlanRequest{NodeID: node.String(), RequestID: uuid.NewString(), SessionID: uuid.NewString(), Epoch: 3}
	binding, err := c.PlanConnectionTunnel(context.Background(), q, anchor.FileID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"request": map[string]any{"nodeId": q.NodeID, "credentialOverride": "", "requestId": q.RequestID, "sessionId": q.SessionID, "epoch": "3"}, "binding": binding, "challengeId": uuid.NewString(), "profileId": uuid.NewString(), "startURL": start, "ignoreCertificateErrors": false, "restorePublicKey": key.PublicKey().Bytes(), "custody": map[string]any{"workspaceId": anchor.VaultID, "fileId": anchor.FileID}, "fixturePrivate": key.Bytes()}
	return h, p, request, wire
}

func TestSharedVPNSSODenialsReleasePersonalCustody(t *testing.T) {
	for _, mode := range []string{"custody", "provider", "row-floor", "configuration", "origin", "tls", "missing-device", "missing-anchor", "override", "missing-transfer", "profile-change"} {
		t.Run(mode, func(t *testing.T) {
			h, _, request, _ := sharedSSOFixture(t, 2)
			delete(request, "fixturePrivate")
			c := h.shared.controller
			switch mode {
			case "custody":
				request["custody"] = map[string]any{"workspaceId": uuid.NewString(), "fileId": h.shared.fileID}
			case "provider", "row-floor", "configuration":
				b := request["binding"].(vault.TunnelBundleBinding)
				if mode == "provider" {
					b.Kind = 9
				} else {
					b.RowVersion++
					if mode == "configuration" {
						b.ConfigurationVersion++
					}
				}
				request["binding"] = b
			case "origin":
				request["startURL"] = "https://other.test:443/remote/saml/start?realm=staff"
			case "tls":
				request["ignoreCertificateErrors"] = true
			case "missing-device":
				if err := os.Remove(sharedDeviceEnrollmentPath(c.trustPath)); err != nil {
					t.Fatal(err)
				}
			case "missing-anchor":
				if err := os.Remove(sharedStartupAnchorPath(c.trustPath)); err != nil {
					t.Fatal(err)
				}
			case "override":
				request["request"].(map[string]any)["credentialOverride"] = uuid.NewString()
			case "profile-change":
				c.runtimeProfile = vault.Standard
			case "missing-transfer":
				if _, _, err := c.lookupVPNSSOSource(context.Background(), uuid.NewString()); err == nil {
					t.Fatal("missing transfer accepted")
				}
				return
			}
			if raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request)); err == nil || len(raw) != 0 {
				t.Fatal("invalid source released an offer", err)
			}
			// An override is refused before requesting a Source Use. All other
			// admitted failures retire the shared and personal native keys together.
			if mode != "override" && (c.Unlocked() || c.vpnSSO != nil) {
				t.Fatal("admitted failure retained custody")
			}
		})
	}
}

func TestSharedVPNSSONativeReceiptsNeverEscapeAdmission(t *testing.T) {
	p, other := &sharedVPNSSOStorage{}, &sharedVPNSSOStorage{}
	b := localvault.VPNSSOBinding{WorkspaceID: uuid.NewString()}
	r := &sharedVPNSSOReceipt{storage: p, binding: b, security: localvault.SecurityProfile{Sequence: 4, Effective: vault.Standard}, active: true}
	ctx := context.WithValue(context.Background(), sharedVPNSSOReceiptKey{}, r)
	if _, err := p.security(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.checkSource(b)(ctx); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), sharedVPNSSOReceiptKey{}, &sharedVPNSSOReceipt{storage: other, active: true})} {
		if _, err := p.security(invalid); err == nil {
			t.Fatal("foreign receipt policy")
		}
		if err := p.checkSource(b)(invalid); err == nil {
			t.Fatal("foreign receipt source")
		}
	}
	if err := p.checkSource(localvault.VPNSSOBinding{})(ctx); err == nil {
		t.Fatal("foreign source binding")
	}
	r.active = false
	if _, err := p.security(ctx); err == nil {
		t.Fatal("retained receipt policy")
	}
	if err := p.checkSource(b)(ctx); err == nil {
		t.Fatal("retained receipt source")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	c := &sharedAdmissionController{gate: make(chan struct{}, 1)}
	if _, _, err := c.lookupVPNSSOSource(cancelled, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := c.lookupVPNSSOSource(context.Background(), ""); err == nil {
		t.Fatal("absent personal owner")
	}
	if err := c.checkpointVPNSSOLocked(context.Background()); err == nil {
		t.Fatal("checkpoint without owner")
	}
	if err := c.adoptVPNSSOStorage(context.Background(), nil, startupTestProtection()); err == nil {
		t.Fatal("adoption without account")
	}
}

func TestSharedVPNSSOExpiryCancellationAndMalformedActions(t *testing.T) {
	h, _, request, _ := sharedSSOFixture(t, 2)
	delete(request, "fixturePrivate")
	c := h.shared.controller
	for _, operation := range []string{"vpn-sso-begin", "vpn-sso-push", "vpn-sso-take", "vpn-sso-restore-ack", "vpn-sso-commit", "vpn-sso-cancel", "unknown"} {
		if raw, err := c.runVPNSSO(context.Background(), operation, []byte(`{"unexpected":true}`)); err == nil || len(raw) != 0 {
			t.Fatal("malformed action", operation)
		}
	}
	var first, second localvault.VPNSSOTransferOffer
	raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request))
	if err != nil || json.Unmarshal(raw, &first) != nil {
		t.Fatal(err)
	}
	entry := c.vpnSSO.transfers[first.Context.TransferID]
	entry.expires = time.Now().Add(-time.Minute)
	c.vpnSSO.transfers[first.Context.TransferID] = entry
	request["profileId"], request["challengeId"] = uuid.NewString(), uuid.NewString()
	raw, err = h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request))
	if err != nil || json.Unmarshal(raw, &second) != nil || len(c.vpnSSO.transfers) != 1 {
		t.Fatal("expired reservation not cleaned", err)
	}
	for range 2 {
		if _, err := h.Handle(context.Background(), "vpn-sso-cancel", vaultInput(t, map[string]any{"context": second.Context})); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.vpnSSO.transfers) != 0 {
		t.Fatal("cancel retained source metadata")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.runVPNSSO(cancelled, "vpn-sso-cancel", vaultInput(t, map[string]any{"context": second.Context})); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSharedVPNSSOCheckpointFailureNeverReleasesPreparedOffer(t *testing.T) {
	for _, mode := range []string{"protection", "anchor-sync", "slot-floor"} {
		t.Run(mode, func(t *testing.T) {
			h, _, request, _ := sharedSSOFixture(t, 2)
			delete(request, "fixturePrivate")
			c := h.shared.controller
			originalSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = originalSync })
			if mode == "slot-floor" {
				anchor, err := readSharedStartupAnchor(c.trustPath, startupTestProtection())
				if err != nil {
					t.Fatal(err)
				}
				anchor.MinimumSequence += 10
				raw, _ := json.Marshal(anchor)
				protected, err := startupTestProtection().protect(sharedStartupAnchorPath(c.trustPath), raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := persistSharedTransitionBytes(sharedStartupAnchorPath(c.trustPath), protected); err != nil {
					t.Fatal(err)
				}
			} else {
				protect := c.vpnSSO.protection.protect
				c.vpnSSO.protection.protect = func(path string, raw []byte) ([]byte, error) {
					if mode == "protection" {
						return nil, os.ErrPermission
					}
					out, err := protect(path, raw)
					privateFileDirectorySync = func(string) error { return os.ErrPermission }
					return out, err
				}
			}
			if raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request)); err == nil || len(raw) != 0 || c.Unlocked() || c.vpnSSO != nil {
				t.Fatal("uncheckpointed offer escaped", err)
			}
		})
	}
}

func TestSharedVPNSSOAdoptionRefusesInvalidNativeStorage(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "closed", "duplicate", "missing-anchor", "missing-device", "changed-device", "cache-directory", "invalid-protection"} {
		t.Run(mode, func(t *testing.T) {
			f, previous, _, slot := selectedDeviceFixture(t)
			if err := previous.Close(); err != nil {
				t.Fatal(err)
			}
			selected, err := unlockSharedSelectedDevice(context.Background(), f.o, slot, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, startupTestProtection())
			if err != nil {
				t.Fatal(err)
			}
			defer selected.Close()
			c, _ := selectedDeviceController(t, f)
			if err := selected.Open(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			ctx, protection := context.Background(), startupTestProtection()
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				if err := c.Close(ctx); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				if err := c.adoptVPNSSOStorage(ctx, selected.account, protection); err != nil {
					t.Fatal(err)
				}
			case "missing-anchor":
				if err := os.Remove(sharedStartupAnchorPath(c.trustPath)); err != nil {
					t.Fatal(err)
				}
			case "missing-device":
				if err := os.Remove(sharedDeviceEnrollmentPath(c.trustPath)); err != nil {
					t.Fatal(err)
				}
			case "changed-device":
				if err := os.WriteFile(sharedDeviceEnrollmentPath(c.trustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cache-directory":
				if err := os.Mkdir(sharedVPNSSOPath(c.trustPath), 0700); err != nil {
					t.Fatal(err)
				}
			case "invalid-protection":
				protection.protect = nil
			}
			if err := c.adoptVPNSSOStorage(ctx, selected.account, protection); err == nil {
				t.Fatal("invalid native storage adopted")
			}
			if mode != "duplicate" && c.vpnSSO != nil {
				t.Fatal("failed adoption retained personal owner")
			}
		})
	}
}

func TestSharedVPNSSONativeCustodyRoundtripAndRevocation(t *testing.T) {
	for _, kind := range []int{2, 9} {
		t.Run(map[int]string{2: "ssl", 9: "ipsec"}[kind], func(t *testing.T) {
			h, probe, request, _ := sharedSSOFixture(t, kind)
			private := request["fixturePrivate"].([]byte)
			defer vault.Wipe(private)
			delete(request, "fixturePrivate")
			calls := 0
			beginUse := probe.begin
			probe.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
				calls++
				return beginUse(ctx, id, source)
			}
			raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request))
			var offer localvault.VPNSSOTransferOffer
			if err != nil || json.Unmarshal(raw, &offer) != nil {
				t.Fatal("shared begin", err)
			}
			if offer.Context.WorkspaceID != h.shared.vaultID || offer.Context.WorkspaceID == h.shared.controller.trustBinding.WorkspaceID.String() {
				t.Fatal("shared state not in personal custody")
			}
			if _, err := h.Handle(context.Background(), "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": offer.Context, "manifest": offer.Manifest})); err != nil {
				t.Fatal("restore ack", err)
			}
			archive := []byte("shared-account-personal-sso-storage")
			manifest, chunks, err := vault.SealVPNSSOTransferArchive(offer.Context, "capture", archive)
			if err != nil {
				t.Fatal(err)
			}
			for i, bundle := range chunks {
				encoded, err := json.Marshal(vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: manifest, Index: i, Bundle: bundle})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.Handle(context.Background(), "vpn-sso-push", encoded); err != nil {
					t.Fatal("capture", err)
				}
				vault.Wipe(bundle.Ciphertext)
			}
			if _, err := h.Handle(context.Background(), "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
				t.Fatal("commit", err)
			}
			anchor, err := readSharedStartupAnchor(h.shared.controller.trustPath, startupTestProtection())
			if err != nil {
				t.Fatal(err)
			}
			slots, _, err := readSharedDeviceEnrollment(h.shared.controller.trustPath)
			if err != nil || len(slots.VPNSSO) != 1 || slots.VPNSSO[0].Revision != 1 || slots.Sequence != anchor.MinimumSequence {
				t.Fatal("response preceded durable personal checkpoint", err)
			}
			request["profileId"], request["challengeId"] = uuid.NewString(), uuid.NewString()
			raw, err = h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, request))
			if err != nil || json.Unmarshal(raw, &offer) != nil || offer.Context.SourceRevision != "1" {
				t.Fatal("second begin", err)
			}
			raw, err = h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": offer.Context, "index": 0}))
			var packet vault.VPNSSOTransferPacket
			if err != nil || json.Unmarshal(raw, &packet) != nil {
				t.Fatal("restore", err)
			}
			decoded, err := vault.OpenVPNSSOTransferArchive(private, offer.Context, "restore", offer.Manifest, []vault.SealedBundle{packet.Bundle})
			defer vault.Wipe(decoded)
			if err != nil || !bytes.Equal(decoded, archive) || calls != 6 {
				t.Fatal("audited source actions/restore", err, calls)
			}
			cache, err := os.ReadFile(sharedVPNSSOPath(h.shared.controller.trustPath))
			if err != nil || bytes.Contains(cache, archive) {
				t.Fatal("plaintext personal state", err)
			}
			probe.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) { return nil, vault.ErrPolicy }
			if raw, err := h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": offer.Context, "index": 0})); err == nil || len(raw) != 0 || h.shared.controller.vpnSSO != nil || h.shared.controller.Unlocked() {
				t.Fatal("revocation retained personal root or returned data", err)
			}
			if _, err := h.Handle(context.Background(), "vpn-sso-cancel", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
				t.Fatal("revocation blocked cleanup", err)
			}
		})
	}
}
