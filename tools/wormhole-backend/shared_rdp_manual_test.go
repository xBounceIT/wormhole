package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

func TestSharedRDPManualSelectsPrimaryEnvelopeAndIndependentGateway(t *testing.T) {
	for _, mode := range []string{"direct", "empty", "same", "gateway", "saved-azuread"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, cr *sharedcatalog.CredentialRecord) {
				v := 1
				n.Protocol = &v
				cr.Metadata.Protocol = "rdp"
				if mode == "saved-azuread" {
					cr.Metadata.Username = "AzureAD\\old"
					cr.Metadata.Domain = "AzureAD"
				}
				if mode == "same" {
					yes, method, host := true, 1, "gateway.example"
					n.RDPGatewayUseSameCreds = &yes
					n.RDPGatewayUsageMethod = &method
					n.RDPGatewayHostname = &host
				}
			})
			if mode == "gateway" {
				installSharedRDPGatewayFixture(t, wire, account)
			} else {
				if err := c.privateKeys.With(func(k []byte) error { vault.Wipe(k); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			begins, fetches := 0, 0
			begin, fetch := p.begin, p.fetch
			p.begin = func(ctx context.Context, id uuid.UUID, s string) (*sharedpg.UseIntent, error) {
				begins++
				return begin(ctx, id, s)
			}
			p.fetch = func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				fetches++
				return fetch(ctx, i)
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			q, key := sharedSSHRequest(node)
			plan := sharedPlanPayload(q)
			raw, err := h.Handle(context.Background(), "rdp-plan", vaultInput(t, plan))
			var planned struct {
				Binding vault.BundleBinding `json:"binding"`
			}
			if err != nil || json.Unmarshal(raw, &planned) != nil || begins != 0 || fetches != 0 {
				t.Fatal("plan released ciphertext", err)
			}
			password := []byte("one-use-shared")
			if mode == "empty" {
				password = nil
			}
			inner, err := vault.SealManualRDPCredentials(q.PublicKey, planned.Binding, nil, "", vault.RDPManualCredentials{Username: "manual-user", Domain: "MANUAL", Password: password})
			if err != nil {
				t.Fatal(err)
			}
			request := cloneSFTPPacket(plan)
			request["publicKey"], request["binding"], request["manual"] = q.PublicKey, planned.Binding, inner
			raw, err = h.Handle(context.Background(), "rdp-manual-bundle", vaultInput(t, request))
			var result localvault.RDPConnectionBundle
			if err != nil || json.Unmarshal(raw, &result) != nil || begins != 1 || fetches != 1 {
				t.Fatal("manual release not audited", err)
			}
			if bytes.Contains(raw, password) && len(password) > 0 || bytes.Contains(raw, []byte("native-connection-secret")) || bytes.Contains(raw, []byte("independent-gateway-secret")) {
				t.Fatal("plaintext relay")
			}
			outer, err := vault.OpenBundle(key, planned.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(outer)
			base, envelope, err := vault.DecodeRDPManualAuthorization(outer)
			if err != nil || base.Username != "" || base.Settings.Domain != "" || base.PasswordProvided {
				t.Fatal("saved fallback", err)
			}
			if mode == "gateway" && (string(base.GatewayPassword) != "independent-gateway-secret" || base.GatewayUsername != "gateway-user" || base.GatewayDomain != "EDGE") {
				t.Fatal("gateway lost")
			}
			if mode != "gateway" && base.GatewayPasswordProvided {
				t.Fatal("unselected gateway")
			}
			plain, err := vault.OpenManualRDPCredentials(key, planned.Binding, nil, "", envelope)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plain)
			accountInput, err := vault.DecodeRDPManualCredentials(plain)
			if err != nil || accountInput.Username != "manual-user" || accountInput.Domain != "MANUAL" || !bytes.Equal(accountInput.Password, password) {
				t.Fatal("manual account lost", err)
			}
		})
	}
}
func TestSharedRDPManualRoutedAndRefusals(t *testing.T) {
	for _, mode := range []string{"valid", "revision", "endpoint", "binding", "override", "inner", "source", "cancel", "fetch", "private"} {
		t.Run(mode, func(t *testing.T) {
			c, p, h, ssh, key, _ := sharedRoutedFixture(t, 1)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			route, err := c.ResolveConnectionRoute(ctx, q.Plan(), h.shared.fileID)
			if err != nil || route == nil {
				t.Fatal(err)
			}
			endpoint := "127.0.0.1:2345"
			inner, err := vault.SealManualRDPCredentials(q.PublicKey, route.BundleBinding, route, endpoint, vault.RDPManualCredentials{Username: "manual", Password: []byte{}})
			if err != nil {
				t.Fatal(err)
			}
			source := "ui"
			bad := *route
			switch mode {
			case "revision":
				bad.ConfigurationVersion++
			case "endpoint":
				endpoint = "remote:2345"
			case "binding":
				bad.Host = "changed.example"
			case "override":
				q.CredentialOverride = uuid.NewString()
			case "inner":
				inner.Ciphertext = nil
			case "source":
				source = "other"
			case "cancel":
				cancel()
			case "fetch":
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, sharedpg.ErrConfiguration
				}
			case "private":
				_ = c.privateKeys.With(func(k []byte) error { vault.Wipe(k); return nil })
			}
			result, err := c.SealRoutedManualRDPConnection(ctx, q, bad, endpoint, h.shared.fileID, inner, source)
			if mode != "valid" && mode != "private" {
				if err == nil {
					t.Fatal("invalid manual authority", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			outer, err := vault.OpenRoutedBundle(key, *route, endpoint, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(outer)
			if _, _, err = vault.DecodeRDPManualAuthorization(outer); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRDPManualHandlerRejectsMalformedAndUnownedRequests(t *testing.T) {
	if _, err := (&vaultFoundationHandler{}).rdpManual(context.Background(), "rdp-plan", nil); err == nil {
		t.Fatal("unowned manual API")
	}
	for _, mode := range []string{"operation", "large", "nil-context", "missing", "extra", "epoch", "null-inner", "inner-shape", "binding", "route-shape", "invalid-plan", "override", "plan-override", "bad-protocol", "private-gateway"} {
		t.Run(mode, func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, cr *sharedcatalog.CredentialRecord) {
				v := 1
				n.Protocol = &v
				cr.Metadata.Protocol = "rdp"
			})
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			ssh, _ := sharedSSHRequest(node)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			binding, err := c.PlanRDPConnection(context.Background(), q.Plan())
			if err != nil {
				t.Fatal(err)
			}
			inner, _ := vault.SealManualRDPCredentials(q.PublicKey, binding, nil, "", vault.RDPManualCredentials{Username: "manual"})
			request := sharedPlanPayload(ssh)
			request["publicKey"], request["binding"], request["manual"] = q.PublicKey, binding, inner
			operation := "rdp-manual-bundle"
			ctx := context.Background()
			switch mode {
			case "operation":
				operation = "other"
			case "large":
				if _, err = h.rdpManual(ctx, operation, make([]byte, 32769)); err == nil {
					t.Fatal("large frame")
				}
				return
			case "nil-context":
				ctx = nil
			case "missing":
				delete(request, "nodeId")
			case "extra":
				request["password"] = "private-must-not-be-accepted"
			case "epoch":
				request["epoch"] = "01"
			case "null-inner":
				request["manual"] = nil
			case "inner-shape":
				request["manual"] = map[string]any{"formatVersion": 1, "suiteId": 2, "enc": q.PublicKey, "ciphertext": inner.Ciphertext, "extra": true}
			case "binding":
				bad := binding
				bad.Host = "changed.example"
				request["binding"] = bad
			case "route-shape":
				operation = "rdp-manual-route-bundle"
				delete(request, "binding")
				request["route"] = binding
				request["endpoint"] = "127.0.0.1:2345"
			case "invalid-plan":
				operation = "rdp-plan"
				request = sharedPlanPayload(ssh)
				request["epoch"] = "0"
			case "plan-override":
				operation = "rdp-plan"
				request = sharedPlanPayload(ssh)
				request["credentialOverride"] = uuid.NewString()
			case "override":
				request["credentialOverride"] = uuid.NewString()
			case "bad-protocol":
				editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, cr *sharedcatalog.CredentialRecord) {
					v := 6
					n.Protocol = &v
					cr.Metadata.Protocol = "vnc"
				})
			case "private-gateway":
				installSharedRDPGatewayFixture(t, wire, account)
				_ = c.privateKeys.With(func(k []byte) error { vault.Wipe(k); return nil })
			}
			if result, err := h.rdpManual(ctx, operation, vaultInput(t, request)); err == nil || len(result) != 0 {
				t.Fatal("invalid manual request released output", mode, err)
			}
		})
	}
	c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
	defer c.Close(context.Background())
	editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, cr *sharedcatalog.CredentialRecord) {
		v := 1
		n.Protocol = &v
		cr.Metadata.Protocol = "rdp"
	})
	ssh, _ := sharedSSHRequest(node)
	q := localvault.TunnelPlanRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch}
	if _, err := c.PlanRDPConnection(nil, q); err == nil {
		t.Fatal("nil plan context")
	}
	bad := q
	bad.CredentialOverride = uuid.NewString()
	if _, err := c.PlanRDPConnection(context.Background(), bad); err == nil {
		t.Fatal("plan override")
	}
	if _, err := c.SealManualRDPConnection(nil, localvault.TunnelBundleRequest{}, vault.BundleBinding{}, vault.SealedBundle{}, "ui"); err == nil {
		t.Fatal("invalid manual bundle")
	}
}
