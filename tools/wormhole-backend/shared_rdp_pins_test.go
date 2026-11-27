package main

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSharedImportedRDPNativeBundlesKeepGatewaySelection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		manual        bool
		gatewayPinned bool
	}{
		{"saved", false, true},
		{"manual with independent gateway", true, true},
		{"manual with gateway credential reuse", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, probe, owner, _, account, _, node, primary := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, owner.Binding.WorkspaceID, account.Binding.Signing, primary, func(n *vaultstore.NodeMetadata, cr *sharedcatalog.CredentialRecord) {
				rdp, enabled, same, host := 1, 1, true, "gateway.example"
				n.Protocol, n.RDPGatewayUsageMethod, n.RDPGatewayUseSameCreds, n.RDPGatewayHostname = &rdp, &enabled, &same, &host
				cr.Metadata.Protocol = "rdp"
			})
			mainMetadata := primary["metadata"].(map[string]any)
			base := mainMetadata["plan"].(resolver.Plan)
			mainPin := resolver.EffectiveCredentialSnapshot{NodeID: node.String(), ProtocolPath: "rdp", SourceKind: "saved",
				CredentialID: base.Credential.ID, Username: "original-desktop", Domain: "DESKTOP"}
			gatewayPin := mainPin
			gatewayPin.ProtocolPath, gatewayPin.Username, gatewayPin.Domain = "rdp-gateway", "original-gateway", "GATEWAY"
			pins := []resolver.EffectiveCredentialSnapshot{mainPin}
			if tc.gatewayPinned {
				pins = append(pins, gatewayPin)
			}
			addSharedPathProjection(primary, "rdp", signSharedPathFixture(t, owner.Binding.WorkspaceID, account.Binding.Signing, primary, pins))
			gateway, gateMetadata := maps.Clone(primary), maps.Clone(mainMetadata)
			gateway["metadata"] = gateMetadata
			gateMetadata["path"] = "rdp-gateway"
			if tc.gatewayPinned {
				gateMetadata["plan"] = resolver.ApplyRetainedAccount(base, gatewayPin)
			}
			mainMetadata["plan"] = resolver.ApplyRetainedAccount(base, mainPin)
			oldPlan, oldBegin := probe.plan, probe.begin
			probe.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
				return nil, sharedpg.ErrImportedConnectionPins
			}
			probe.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("pinned RDP attempted a legacy release")
				return nil, nil
			}
			begins := 0
			c.session = &sharedPathProbe{credentialReleaseProbe: probe, capability: func() (bool, error) { return true, nil },
				planPath: func(ctx context.Context, n uuid.UUID, path string) (*sharedpg.UnverifiedConnectionPlan, error) {
					if path != sharedpg.DefaultConnectionPath {
						t.Fatal("unexpected account path in RDP plan")
					}
					return oldPlan(ctx, n)
				},
				beginPath: func(ctx context.Context, id uuid.UUID, src, path string) (*sharedpg.UseIntent, error) {
					if path != "rdp" {
						t.Fatal("gateway release requested a different ticket")
					}
					begins++
					intent, err := oldBegin(ctx, id, src)
					intent.Path = path
					return intent, err
				},
			}
			probe.fetch = func(_ context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				raw := vaultInput(t, map[string]any{"formatVersion": 6, "primary": primary, "gateway": gateway})
				return sharedpg.DecodeCredentialRelease(raw, owner.Request, intent.Node, intent.Epoch, intent.ChangeSeq)
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			q, recipient := sharedSSHRequest(node)
			defer vault.Wipe(recipient)
			ctx := context.Background()
			request := sharedPlanPayload(q)
			operation := "rdp-bundle"
			if tc.manual {
				operation = "rdp-manual-bundle"
				raw, err := h.Handle(ctx, "rdp-plan", vaultInput(t, request))
				var planned struct {
					Binding vault.BundleBinding `json:"binding"`
				}
				if err != nil || json.Unmarshal(raw, &planned) != nil || begins != 0 {
					t.Fatal("manual RDP planning opened a ticket", err)
				}
				manual, err := vault.SealManualRDPCredentials(q.PublicKey, planned.Binding, nil, "", vault.RDPManualCredentials{Username: "manual", Password: []byte("one-use-primary")})
				if err != nil {
					t.Fatal(err)
				}
				request["binding"], request["manual"] = planned.Binding, manual
				if !tc.gatewayPinned {
					if err := c.privateKeys.With(func(private []byte) error { vault.Wipe(private); return nil }); err != nil {
						t.Fatal(err)
					}
				}
			}
			request["publicKey"] = q.PublicKey
			raw, err := h.Handle(ctx, operation, vaultInput(t, request))
			var bundle localvault.RDPConnectionBundle
			if err != nil || json.Unmarshal(raw, &bundle) != nil || begins != 1 || bytes.Contains(raw, []byte("native-connection-secret")) {
				t.Fatal("RDP did not seal one audited account pair", err)
			}
			plaintext, err := vault.OpenBundle(recipient, bundle.Binding, bundle.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plaintext)
			var payload vault.RDPBundlePayload
			if tc.manual {
				payload, _, err = vault.DecodeRDPManualAuthorization(plaintext)
				if payload.Username != "" || payload.Settings.Domain != "" || payload.PasswordProvided {
					t.Fatal("manual RDP opened saved desktop credentials", err)
				}
			} else {
				payload, err = vault.DecodeRDPBundle(plaintext)
				if payload.Username != mainPin.Username || payload.Settings.Domain != mainPin.Domain || !payload.PasswordProvided {
					t.Fatal("desktop pin was lost", err)
				}
			}
			if err != nil || payload.Settings.GatewayUseSameCreds != !tc.gatewayPinned {
				t.Fatal("wrong credential reuse decision", err)
			}
			if tc.gatewayPinned && (payload.GatewayUsername != gatewayPin.Username || payload.GatewayDomain != gatewayPin.Domain ||
				!payload.GatewayPasswordProvided || !bytes.Equal(payload.GatewayPassword, []byte("native-connection-secret"))) {
				t.Fatal("native handoff lost the independent gateway pin")
			}
		})
	}
}
