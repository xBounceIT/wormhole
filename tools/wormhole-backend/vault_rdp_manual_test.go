package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

func TestVaultRDPManualBoundary(t *testing.T) {
	for _, routed := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "route"}[routed], func(t *testing.T) {
			ctx := context.Background()
			h := vaultCredentialFixture(t)
			protocol, port, host := 1, 3389, "rdp.example"
			metadata := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Temporary RDP", Kind: 1, Protocol: &protocol, Host: &host, Port: &port}
			if routed {
				tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte("not-the-primary-account"), 0)
				if err != nil {
					t.Fatal(err)
				}
				yes := true
				metadata.TunnelEnabled, metadata.TunnelConfigID = &yes, &tunnel.ID
			}
			node, err := h.owner.PutNode(ctx, metadata, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			private := key.Bytes()
			defer vault.Wipe(private)
			q := localvault.TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
			request := map[string]any{"nodeId": q.NodeID, "credentialOverride": "", "sessionId": q.SessionID, "requestId": q.RequestID, "epoch": "1"}
			var binding vault.BundleBinding
			var route *vault.TunnelBundleBinding
			endpoint := ""
			if routed {
				route, err = h.owner.ResolveConnectionRoute(ctx, q)
				if err != nil || route == nil {
					t.Fatal(err)
				}
				binding, endpoint = route.BundleBinding, "127.0.0.1:2345"
			} else {
				raw, err := h.Handle(ctx, "rdp-plan", vaultInput(t, request))
				var result struct {
					Binding vault.BundleBinding `json:"binding"`
				}
				if err != nil || json.Unmarshal(raw, &result) != nil {
					t.Fatal("plan", err)
				}
				binding = result.Binding
			}
			inner, err := vault.SealManualRDPCredentials(key.PublicKey().Bytes(), binding, route, endpoint, vault.RDPManualCredentials{Username: "manual-only", Domain: "ONE-USE", Password: []byte{}})
			if err != nil {
				t.Fatal(err)
			}
			request["publicKey"], request["manual"] = key.PublicKey().Bytes(), inner
			operation := "rdp-manual-bundle"
			if routed {
				operation = "rdp-manual-route-bundle"
				request["route"], request["endpoint"] = route, endpoint
			} else {
				request["binding"] = binding
			}
			raw, err := h.Handle(ctx, operation, vaultInput(t, request))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("manual-only")) || bytes.Contains(raw, []byte("ONE-USE")) {
				t.Fatal("identity exposed")
			}
			var result localvault.RoutedRDPConnectionBundle
			if err = json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			var outer []byte
			if routed {
				outer, err = vault.OpenRoutedBundle(private, *route, endpoint, result.Bundle)
			} else {
				outer, err = vault.OpenBundle(private, binding, result.Bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(outer)
			base, opaque, err := vault.DecodeRDPManualAuthorization(outer)
			if err != nil || base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" {
				t.Fatal("primary fallback", err)
			}
			plain, err := vault.OpenManualRDPCredentials(private, binding, route, endpoint, opaque)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plain)
			account, err := vault.DecodeRDPManualCredentials(plain)
			if err != nil || account.Username != "manual-only" || account.Domain != "ONE-USE" || len(account.Password) != 0 {
				t.Fatal("explicit empty primary changed", err)
			}
		})
	}
}
