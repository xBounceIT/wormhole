package localvault

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestRoutedSSHConnectionChecksCurrentLeaseBeforeReadingCredentials(t *testing.T) {
	o, n, q, key := sshBundleFixture(t)
	ctx := context.Background()
	planRequest := TunnelPlanRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch}
	if direct, err := o.ResolveConnectionRoute(ctx, planRequest); err != nil || direct != nil {
		t.Fatal("not direct", err)
	}
	m := n.NodeMetadata
	m.TunnelEnabled = nodePtr(true)
	n, err := o.PutNode(ctx, m, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	route, err := o.PlanConnectionTunnel(ctx, planRequest)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "127.0.0.1:12345"
	sealed, err := o.SealRoutedSSHConnection(ctx, q, route, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenRoutedBundle(key, sealed.Binding, sealed.Endpoint, sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := vault.DecodeSSHBundle(plain)
	if err != nil || !bytes.Equal(payload.Password, []byte("selected-password")) {
		t.Fatal("credential drift", err)
	}
	vault.Wipe(plain)
	if _, err := o.SealSSHConnection(ctx, q); err != vault.ErrPolicy {
		t.Fatal("direct fallback", err)
	}
	base := o.store.(integrityStore)
	reads := 0
	o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) { reads++; return s, nil }}
	for _, mutate := range []func(*vault.TunnelBundleBinding){func(b *vault.TunnelBundleBinding) { b.Host = "changed" }, func(b *vault.TunnelBundleBinding) { b.RowVersion++ }, func(b *vault.TunnelBundleBinding) { b.ConfigurationVersion++ }, func(b *vault.TunnelBundleBinding) { b.RequestID = uuid.NewString() }, func(b *vault.TunnelBundleBinding) { b.FileID = uuid.NewString() }} {
		bad := route
		mutate(&bad)
		if _, err := o.SealRoutedSSHConnection(ctx, q, bad, endpoint); err == nil {
			t.Fatal("stale lease")
		}
	}
	if _, err := o.SealRoutedSSHConnection(ctx, q, route, "remote:22"); err == nil {
		t.Fatal("nonloopback")
	}
	if reads != 0 {
		t.Fatal("credentials borrowed before lease authorization")
	}
	o.store = base
	m = n.NodeMetadata
	m.TunnelEnabled = nodePtr(false)
	if _, err := o.PutNode(ctx, m, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealRoutedSSHConnection(ctx, q, route, endpoint); err == nil {
		t.Fatal("disabled route accepted")
	}
	if _, err := o.SealSSHConnection(ctx, q); err != nil {
		t.Fatal("native direct decision unavailable", err)
	}
}
