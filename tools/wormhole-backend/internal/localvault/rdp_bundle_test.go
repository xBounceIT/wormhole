package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func rdpBundleFixture(t *testing.T) (*Owner, vaultstore.Node, vaultstore.Node, vaultstore.Credential, TunnelBundleRequest, []byte) {
	t.Helper()
	o, _, _, _ := owner(t)
	ctx := context.Background()
	d := draft()
	d.Protocol = "rdp"
	d.Domain = "PRIMARY"
	c, err := o.PutCredential(ctx, d, []SecretChange{{Field: "password", Value: []byte("rdp-primary")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d = draft()
	d.Protocol = "rdp"
	d.Username = "gateway-user"
	d.Domain = "EDGE"
	g, err := o.PutCredential(ctx, d, []SecretChange{{Field: "password", Value: []byte("rdp-gateway")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := nodeDraft()
	root.Kind = 0
	root.Protocol = nodePtr(1)
	root.CredentialID = &c.ID
	root.RDPScreenSize = nodePtr("1280x720")
	root.RDPGatewayUsageMethod = nodePtr(1)
	root.RDPGatewayHostname = nodePtr("gateway.example")
	root.RDPGatewayCredentialID = &g.ID
	parent, err := o.PutNode(ctx, root, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.ParentID = &parent.ID
	m.Protocol = nil
	m.Host = nil
	m.RDPRedirectClipboard = nodePtr(false)
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := key.Bytes()
	t.Cleanup(func() { vault.Wipe(private) })
	return o, n, parent, c, TunnelBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}, private
}
func TestRDPConnectionBundlesResolveBothAccountsAndSettings(t *testing.T) {
	for _, mode := range []string{"saved", "inline", "override", "none", "empty", "absent", "same"} {
		t.Run(mode, func(t *testing.T) {
			o, n, _, c, q, key := rdpBundleFixture(t)
			ctx := context.Background()
			m := n.NodeMetadata
			var changes []SecretChange
			want := "rdp-primary"
			provided := true
			switch mode {
			case "inline":
				m.UseInlinePassword = nodePtr(true)
				m.Username = nodePtr("inline-user")
				m.RDPDomain = nodePtr("INLINE")
				changes = []SecretChange{{Field: "inlinePassword", Value: []byte("inline-secret")}}
				want = "inline-secret"
			case "override":
				d := draft()
				d.Protocol = "rdp"
				d.Username = "override-user"
				c, err := o.PutCredential(ctx, d, []SecretChange{{Field: "password", Value: []byte("override-secret")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				q.CredentialOverride = c.ID
				want = "override-secret"
			case "none":
				m.CredentialMode = nodePtr(1)
				m.CredentialID = nil
				want = ""
				provided = false
			case "empty":
				if _, err := o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte{}}}, 1); err != nil {
					t.Fatal(err)
				}
				want = ""
			case "absent":
				if _, err := o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "password", Remove: true}}, 1); err != nil {
					t.Fatal(err)
				}
				want = ""
				provided = false
			case "same":
				m.RDPGatewayUseSameCreds = nodePtr(true)
			}
			if _, err := o.PutNode(ctx, m, changes, n.RowVersion); err != nil {
				t.Fatal(err)
			}
			result, err := o.SealRDPConnection(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(raw)
			payload, err := vault.DecodeRDPBundle(raw)
			if err != nil || !bytes.Equal(payload.Password, []byte(want)) || payload.PasswordProvided != provided {
				t.Fatal("wrong primary presence", mode, err)
			}
			if payload.Settings.ScreenSize != "1280x720" || payload.Settings.RedirectClipboard || result.Binding.Protocol != "rdp" || result.Binding.Port != 3389 {
				t.Fatal("RDP settings/binding changed")
			}
			if mode == "same" {
				if payload.GatewayPasswordProvided || len(payload.GatewayPassword) != 0 || !payload.Settings.GatewayUseSameCreds {
					t.Fatal("same credentials opened gateway")
				}
			} else if !bytes.Equal(payload.GatewayPassword, []byte("rdp-gateway")) || !payload.GatewayPasswordProvided || payload.GatewayUsername != "EDGE\\gateway-user" || payload.GatewayDomain != "" {
				t.Fatal("independent gateway lost")
			}
			if mode == "saved" && payload.Settings.Domain != "PRIMARY" {
				t.Fatal("credential domain lost")
			}
		})
	}
}
func TestRDPRoutedBundleBindsCurrentRouteAndDoesNotFallBack(t *testing.T) {
	o, n, parent, _, q, key := rdpBundleFixture(t)
	ctx := context.Background()
	config, err := o.PutTunnel(ctx, tunnelDraft(), []byte("route-settings"), 0)
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
	if _, err = o.SealRDPConnection(ctx, q); err != vault.ErrPolicy {
		t.Fatal("tunnel fell back to direct", err)
	}
	route, err := o.ResolveConnectionRoute(ctx, q.Plan())
	if err != nil || route == nil {
		t.Fatal(err)
	}
	endpoint := "127.0.0.1:19050"
	result, err := o.SealRoutedRDPConnection(ctx, q, *route, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenRoutedBundle(key, *route, endpoint, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	if _, err = vault.DecodeRDPBundle(raw); err != nil {
		t.Fatal(err)
	}
	changed := *route
	changed.ConfigurationVersion++
	if _, err = o.SealRoutedRDPConnection(ctx, q, changed, endpoint); err != vault.ErrPolicy {
		t.Fatal("stale configuration accepted", err)
	}
	if _, err = o.SealRoutedRDPConnection(ctx, q, *route, "example.com:19050"); err == nil {
		t.Fatal("remote proxy accepted")
	}
	leaf := n.NodeMetadata
	leaf.RDPServerAuthentication = nodePtr(1)
	if _, err = o.PutNode(ctx, leaf, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealRoutedRDPConnection(ctx, q, *route, endpoint); err != vault.ErrPolicy {
		t.Fatal("mandatory certificate policy weakened", err)
	}
}
func TestRDPBundlesRejectInvalidRequestsAndUnsafeMetadata(t *testing.T) {
	o, n, _, _, q, _ := rdpBundleFixture(t)
	ctx := context.Background()
	if _, err := o.SealRDPConnection(nil, q); err == nil {
		t.Fatal("nil context accepted")
	}
	for _, mutate := range []func(*TunnelBundleRequest){func(q *TunnelBundleRequest) { q.NodeID = "bad" }, func(q *TunnelBundleRequest) { q.PublicKey = nil }, func(q *TunnelBundleRequest) { q.Epoch = 0 }, func(q *TunnelBundleRequest) { q.CredentialOverride = uuid.NewString() }} {
		bad := q
		mutate(&bad)
		if _, err := o.SealRDPConnection(ctx, bad); err == nil {
			t.Fatal("bad request accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.SealRDPConnection(cancelled, q); err == nil {
		t.Fatal("cancel ignored")
	}
	for _, mutate := range []func(*vaultstore.NodeMetadata){func(n *vaultstore.NodeMetadata) { n.RDPScreenSize = nodePtr("invalid") }, func(n *vaultstore.NodeMetadata) { n.Host = nodePtr("bad host") }} {
		m := n.NodeMetadata
		mutate(&m)
		written, err := o.PutNode(ctx, m, nil, n.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		n.RowVersion = written.RowVersion
		if _, err = o.SealRDPConnection(ctx, q); err == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
}

func TestRDPExternalPreferenceKeepsNonWindowsNativeAdapter(t *testing.T) {
	o, n, _, _, q, key := rdpBundleFixture(t)
	m := n.NodeMetadata
	m.RDPUseExternalClient = nodePtr(true)
	if _, err := o.PutNode(context.Background(), m, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	result, err := o.SealRDPConnection(context.Background(), q)
	if runtime.GOOS == "windows" {
		if err != vault.ErrPolicy {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	p, err := vault.DecodeRDPBundle(raw)
	if err != nil || p.Settings.UseExternalClient {
		t.Fatal("Windows-only preference disabled FreeRDP", err)
	}
}
