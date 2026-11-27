package localvault

import (
	"bytes"
	"context"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type manualRDPSelectedStore struct {
	*vaultstore.SQLite
	primary             string
	reads               *[]vaultstore.SecretRef
	failGateway         bool
	allowPrimaryGateway bool
}

func (s manualRDPSelectedStore) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	*s.reads = append(*s.reads, ref)
	if ref.OwnerKind == "node" || (ref.OwnerID == s.primary && !s.allowPrimaryGateway) || s.failGateway {
		return vaultstore.Secret{}, vaultstore.ErrStorage
	}
	return s.SQLite.ReadSecret(ctx, ref)
}
func TestManualRDPBorrowsOnlyIndependentGateway(t *testing.T) {
	for _, mode := range []string{"independent", "alias", "saved-azuread", "same", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			o, n, parent, c, q, key := rdpBundleFixture(t)
			ctx := context.Background()
			if mode == "saved-azuread" {
				metadata := c.CredentialMetadata
				metadata.Username = `AzureAD\old`
				metadata.Domain = "AzureAD"
				if _, err := o.PutCredential(ctx, metadata, nil, c.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			m := parent.NodeMetadata
			if mode == "alias" {
				m.RDPGatewayCredentialID = &c.ID
			}
			if mode == "same" {
				m.RDPGatewayUseSameCreds = nodePtr(true)
			}
			if mode == "disabled" {
				m.RDPGatewayUsageMethod = nodePtr(0)
			}
			if _, err := o.PutNode(ctx, m, nil, parent.RowVersion); err != nil {
				t.Fatal(err)
			}
			original := o.store.(*vaultstore.SQLite)
			var reads []vaultstore.SecretRef
			o.store = manualRDPSelectedStore{SQLite: original, primary: c.ID, reads: &reads, allowPrimaryGateway: mode == "alias"}
			binding, err := o.PlanRDPConnection(ctx, q.Plan())
			if err != nil || len(reads) != 0 {
				t.Fatal("plan borrowed secrets", err)
			}
			for _, password := range [][]byte{nil, []byte("manual-account-secret")} {
				inner, err := vault.SealManualRDPCredentials(q.PublicKey, binding, nil, "", vault.RDPManualCredentials{Username: "new-user", Domain: "MANUAL", Password: password})
				if err != nil {
					t.Fatal(err)
				}
				result, err := o.SealManualRDPConnection(ctx, q, binding, nil, "", inner)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := vault.OpenBundle(key, binding, result.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				base, envelope, err := vault.DecodeRDPManualAuthorization(raw)
				if err != nil || base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" {
					t.Fatal("saved primary fallback", err)
				}
				if (mode == "independent" || mode == "saved-azuread") && (string(base.GatewayPassword) != "rdp-gateway" || base.GatewayUsername != "EDGE\\gateway-user") {
					t.Fatal("independent gateway lost")
				}
				if mode == "alias" && (string(base.GatewayPassword) != "rdp-primary" || base.GatewayUsername != c.Domain+`\`+c.Username || base.GatewayDomain != "") {
					t.Fatal("explicit gateway alias lost")
				}
				if mode != "independent" && mode != "saved-azuread" && mode != "alias" && (base.GatewayPasswordProvided || len(base.GatewayPassword) != 0) {
					t.Fatal("unselected gateway read")
				}
				plain, err := vault.OpenManualRDPCredentials(key, binding, nil, "", envelope)
				if err != nil {
					t.Fatal(err)
				}
				selected, err := vault.DecodeRDPManualCredentials(plain)
				if err != nil || selected.Username != "new-user" || selected.Domain != "MANUAL" || !bytes.Equal(selected.Password, password) {
					t.Fatal("manual primary changed", err)
				}
				vault.Wipe(plain)
				vault.Wipe(raw)
			}
			expected := 0
			if mode == "independent" || mode == "alias" || mode == "saved-azuread" {
				expected = 2
			}
			if len(reads) != expected {
				t.Fatal("wrong secret selection", len(reads))
			}
			if _, err = o.SealRDPConnection(ctx, q); err == nil && mode != "alias" {
				t.Fatal("denial store failed to detect saved borrowing")
			}
			o.store = original
			changed := n.NodeMetadata
			changed.Host = nodePtr("changed.example")
			if _, err = o.PutNode(ctx, changed, nil, n.RowVersion); err != nil {
				t.Fatal(err)
			}
			inner, _ := vault.SealManualRDPCredentials(q.PublicKey, binding, nil, "", vault.RDPManualCredentials{Username: "u"})
			if _, err = o.SealManualRDPConnection(ctx, q, binding, nil, "", inner); err == nil {
				t.Fatal("stale target")
			}
		})
	}
}
func TestManualRDPRoutesAndInvalidAuthority(t *testing.T) {
	o, n, parent, c, q, key := rdpBundleFixture(t)
	ctx := context.Background()
	metadata := c.CredentialMetadata
	metadata.Domain = "AzureAD"
	if _, err := o.PutCredential(ctx, metadata, nil, c.RowVersion); err != nil {
		t.Fatal(err)
	}
	binding, err := o.PlanRDPConnection(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := vault.SealManualRDPCredentials(q.PublicKey, binding, nil, "", vault.RDPManualCredentials{Username: "u"})
	for _, bad := range []TunnelBundleRequest{{}, func() TunnelBundleRequest { v := q; v.PublicKey = nil; return v }(), func() TunnelBundleRequest { v := q; v.CredentialOverride = uuid.NewString(); return v }(), func() TunnelBundleRequest { v := q; v.NodeID = uuid.NewString(); return v }()} {
		if _, err = o.SealManualRDPConnection(ctx, bad, binding, nil, "", inner); err == nil {
			t.Fatal("invalid request")
		}
	}
	for _, plan := range []TunnelPlanRequest{{}, func() TunnelPlanRequest { v := q.Plan(); v.CredentialOverride = uuid.NewString(); return v }()} {
		if _, err = o.PlanRDPConnection(ctx, plan); err == nil {
			t.Fatal("bad plan")
		}
	}
	if _, err = o.PlanRDPConnection(nil, q.Plan()); err == nil {
		t.Fatal("nil context")
	}
	if _, err = o.SealManualRDPConnection(nil, q, binding, nil, "", inner); err == nil {
		t.Fatal("nil context")
	}
	if _, err = o.SealManualRDPConnection(ctx, q, binding, nil, "127.0.0.1:1", inner); err == nil {
		t.Fatal("unexpected endpoint")
	}
	if _, err = o.SealManualRDPConnection(ctx, q, binding, nil, "", vault.SealedBundle{}); err == nil {
		t.Fatal("invalid envelope")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = o.SealManualRDPConnection(cancelCtx, q, binding, nil, "", inner); err == nil {
		t.Fatal("cancel ignored")
	}
	config, err := o.PutTunnel(ctx, tunnelDraft(), []byte("settings"), 0)
	if err != nil {
		t.Fatal(err)
	}
	m := parent.NodeMetadata
	m.TunnelEnabled = nodePtr(true)
	m.TunnelConfigID = &config.ID
	m.RDPGatewayUsageMethod = nodePtr(0)
	if _, err = o.PutNode(ctx, m, nil, parent.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = o.PlanRDPConnection(ctx, q.Plan()); err == nil {
		t.Fatal("route became direct plan")
	}
	route, err := o.ResolveConnectionRoute(ctx, q.Plan())
	if err != nil || route == nil {
		t.Fatal(err)
	}
	endpoint := "127.0.0.1:19050"
	// Only Windows delegates this saved AzureAD identity to its system client.
	if _, err := o.SealConnectionTunnel(ctx, q); err != nil {
		t.Fatal("route rejected by unselected identity", err)
	}
	var wantSaved error
	if runtime.GOOS == "windows" {
		wantSaved = vault.ErrPolicy
	}
	if _, err := o.SealRoutedRDPConnection(ctx, q, *route, endpoint); err != wantSaved {
		t.Fatalf("saved routed AzureAD identity: got %v, want %v", err, wantSaved)
	}

	inner, _ = vault.SealManualRDPCredentials(q.PublicKey, route.BundleBinding, route, endpoint, vault.RDPManualCredentials{Username: "routed", Password: []byte("temporary")})
	result, err := o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, endpoint, inner)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenRoutedBundle(key, *route, endpoint, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	_, envelope, err := vault.DecodeRDPManualAuthorization(raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenManualRDPCredentials(key, route.BundleBinding, route, endpoint, envelope)
	if err != nil {
		t.Fatal(err)
	}
	vault.Wipe(plain)
	bad := *route
	bad.ConfigurationVersion++
	if _, err = o.SealManualRDPConnection(ctx, q, bad.BundleBinding, &bad, endpoint, inner); err == nil {
		t.Fatal("route revision swap")
	}
	if _, err = o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, "remote:19050", inner); err == nil {
		t.Fatal("nonloopback")
	}
	leaf := n.NodeMetadata
	leaf.RDPServerAuthentication = nodePtr(1)
	if _, err = o.PutNode(ctx, leaf, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, endpoint, inner); err == nil {
		t.Fatal("mandatory certificate weakened")
	}
	current, err := o.ReadNode(ctx, n.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf = current.NodeMetadata
	leaf.RDPServerAuthentication = nil
	leaf.RDPUseExternalClient = nodePtr(true)
	if _, err = o.PutNode(ctx, leaf, nil, current.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ResolveConnectionRoute(ctx, q.Plan()); err == nil {
		t.Fatal("explicit external route policy ignored")
	}
	if _, err = o.PlanRDPConnection(ctx, q.Plan()); err == nil {
		t.Fatal("explicit external plan ignored")
	}
	if _, err = o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, endpoint, inner); err == nil {
		t.Fatal("explicit external release ignored")
	}
}
