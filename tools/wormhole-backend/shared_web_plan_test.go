package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedWebPlanUsesSignedMetadataAndKeepsTunnelAuthority(t *testing.T) {
	for _, mode := range []string{"http", "https", "routed", "missing-tunnel", "wrong-file", "non-web", "invalid-signature", "credential-override"} {
		t.Run(mode, func(t *testing.T) {
			c, p, options, root, keys, _, node, wire := credentialControllerFixture(t)
			if mode != "non-web" {
				editSharedConnectionFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire,
					func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
						protocol, port, noAccount, ignore, path := 4, 8443, 1, true, "/tools%2Fconsole?ignored=yes"
						if mode == "http" {
							protocol = 3
						}
						n.Protocol, n.Port, n.HTTPPath, n.HTTPIgnoreCertErrors = &protocol, &port, &path, &ignore
						n.CredentialID, n.CredentialMode = nil, &noAccount
						if mode == "routed" || mode == "missing-tunnel" || mode == "wrong-file" {
							enabled, id := true, uuid.NewString()
							n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
						}
					})
				metadata := wire["metadata"].(map[string]any)
				metadata["credential"] = nil
				if mode == "routed" || mode == "wrong-file" {
					installSharedTunnelPlanFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire)
				}
				if mode == "invalid-signature" {
					row := metadata["chain"].([]any)[0].([]any)
					row[11] = "00"
				}
			}
			p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("web metadata issued a credential ticket")
				return nil, nil
			}
			p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				t.Fatal("web metadata requested secret values")
				return nil, nil
			}
			fileID := uuid.NewString()
			if mode == "wrong-file" {
				fileID = "invalid"
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: fileID}}
			q, _ := sharedSSHRequest(node)
			payload := sharedPlanPayload(q)
			if mode == "credential-override" {
				payload["credentialOverride"] = uuid.NewString()
			}
			raw, err := h.Handle(context.Background(), "web-plan", vaultInput(t, payload))
			switch mode {
			case "missing-tunnel", "invalid-signature", "wrong-file":
				if len(raw) != 0 || !errors.Is(err, vaultwire.ErrRetired) {
					t.Fatalf("bad authority did not fail closed: %v", err)
				}
				return
			case "non-web", "credential-override":
				if len(raw) != 0 || !errors.Is(err, vault.ErrPolicy) || h.closed {
					t.Fatalf("invalid web request changed owner or returned a plan: %v", err)
				}
				return
			}
			var plan vaultWebPlan
			if err != nil || json.Unmarshal(raw, &plan) != nil {
				t.Fatalf("signed web plan denied: %v", err)
			}
			protocol := "https"
			if mode == "http" {
				protocol = "http"
			}
			if plan.Target.URL != protocol+"://server.example:8443/tools%2Fconsole" ||
				plan.Target.IgnoreCertErrors != (mode != "http") || plan.Binding.Protocol != protocol ||
				plan.Binding.WorkspaceID != options.Binding.WorkspaceID.String() || plan.Binding.NodeID != q.NodeID ||
				plan.Binding.RequestID != q.RequestID || plan.Binding.SessionID != q.SessionID || plan.Binding.Epoch != q.Epoch || plan.Temporary {
				t.Fatal("plan lost the signed endpoint or native request scope")
			}
			if mode == "routed" {
				if plan.Route == nil || plan.Route.BundleBinding != plan.Binding || plan.Route.FileID != fileID ||
					plan.Route.TunnelConfigID == "" || plan.Route.TunnelConfigID != plan.Target.TunnelConfigID {
					t.Fatal("web plan dropped authenticated tunnel authority")
				}
			} else if plan.Route != nil || plan.Binding.TunnelConfigID != "" {
				t.Fatal("direct web plan unexpectedly returned route data")
			}
			trust, err := readSharedTrustFile(options.TrustPath, root, options.Binding, c.trustRevision)
			if err != nil || trust.Catalog["node/"+node.String()].Revision < 2 {
				t.Fatalf("web plan became available before the signed state was durable: %v", err)
			}
		})
	}
}
