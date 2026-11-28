package localvault

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestConnectionPlansRecheckAuthenticatedSecurityProfile(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := nodeDraft()
	m.Protocol = nodePtr(4)
	node, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 2}
	if _, err := o.PlanWebConnection(ctx, q); err != nil {
		t.Fatal(err)
	}
	p, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	previous := p.Policy.Sequence
	p.Policy.Sequence++
	p.Policy.KDF = vault.KDFV2
	if _, err := o.PutLocalPolicy(ctx, p.Policy, vault.Hardened, previous); err != nil {
		t.Fatal(err)
	}
	if plan, err := o.PlanWebConnection(ctx, q); !errors.Is(err, vault.ErrPolicy) || plan.Binding.NodeID != "" {
		t.Fatalf("web plan survived a profile change: %#v, %v", plan, err)
	}
	if route, err := o.ResolveConnectionRoute(ctx, q); !errors.Is(err, vault.ErrPolicy) || route != nil {
		t.Fatalf("direct route survived a profile change: %#v, %v", route, err)
	}
}

func TestWebPlanAuthenticatesInheritedMetadataWithoutSecretReads(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	parent := nodeDraft()
	parent.Kind = 0
	parent.Protocol = nodePtr(4)
	parent.Host = nodePtr("web.example")
	parent.Port = nodePtr(8443)
	parent.HTTPPath = nodePtr("/inherited?view=1#page")
	parent.HTTPIgnoreCertErrors = nodePtr(true)
	folder, err := o.PutNode(ctx, parent, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := vaultstore.NodeMetadata{ID: uuid.NewString(), ParentID: &folder.ID, Name: "Web", Kind: 1, HTTPIgnoreCertErrors: nodePtr(false)}
	node, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 2}
	original := o.store.(*vaultstore.SQLite)
	reads := 0
	o.store = manualVNCNoSecretStore{original, &reads}
	plan, err := o.PlanWebConnection(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	b := plan.Binding
	if b.NodeID != node.ID || b.WorkspaceID != original.Identity().WorkspaceID || b.SessionID != q.SessionID || b.RequestID != q.RequestID || b.Epoch != 2 || b.Host != "web.example" || b.Port != 8443 || b.Protocol != "https" || plan.HTTPPath != "/inherited?view=1#page" || plan.IgnoreCertificateErrors || plan.Route != nil {
		t.Fatal("wrong inherited target", plan)
	}
	o.store = original
	tunnel, err := o.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Web VPN", Kind: 6}, []byte("must-not-be-read"), 0)
	if err != nil {
		t.Fatal(err)
	}
	m = node.NodeMetadata
	m.TunnelEnabled = nodePtr(true)
	m.TunnelConfigID = &tunnel.ID
	m.HTTPIgnoreCertErrors = nodePtr(true)
	node, err = o.PutNode(ctx, m, nil, node.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	o.store = manualVNCNoSecretStore{original, &reads}
	plan, err = o.PlanWebConnection(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.IgnoreCertificateErrors || plan.Route == nil || plan.Route.BundleBinding != plan.Binding || plan.Route.FileID != original.Identity().FileID || plan.Route.TunnelConfigID != tunnel.ID || plan.Route.RowVersion != tunnel.RowVersion || plan.Route.ConfigurationVersion != tunnel.ConfigurationVersion {
		t.Fatal("wrong route snapshot")
	}
	if reads != 0 {
		t.Fatal("planning read a secret")
	}
	o.store = original
	m = node.NodeMetadata
	m.Protocol = nodePtr(3)
	m.TunnelEnabled = nodePtr(false)
	node, err = o.PutNode(ctx, m, nil, node.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = o.PlanWebConnection(ctx, q)
	if err != nil || plan.Binding.Protocol != "http" || plan.Binding.Port != 80 || plan.IgnoreCertificateErrors || plan.Route != nil {
		t.Fatal("HTTP port/certificate context", plan, err)
	}
}
func TestWebPlanRejectsInvalidStaleOrUnavailableMetadata(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := nodeDraft()
	m.Protocol = nodePtr(4)
	m.Port = nodePtr(443)
	node, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	for _, delta := range []func(*TunnelPlanRequest){func(v *TunnelPlanRequest) { v.Epoch = 0 }, func(v *TunnelPlanRequest) { v.CredentialOverride = uuid.NewString() }, func(v *TunnelPlanRequest) { v.NodeID = "bad" }} {
		bad := q
		delta(&bad)
		if _, err := o.PlanWebConnection(ctx, bad); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PlanWebConnection(cancelled, q); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, protocol := range []int{0, 1, 5, 6, 7} {
		m = node.NodeMetadata
		m.Protocol = &protocol
		m.Port = nil
		node, err = o.PutNode(ctx, m, nil, node.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = o.PlanWebConnection(ctx, q); err == nil {
			t.Fatal("non-web protocol accepted")
		}
	}
	// Raw, even correctly re-authenticated, invalid metadata must fail at use.
	for _, host := range []string{"", "bad host", "a\nb", string(make([]byte, 1025))} {
		m = node.NodeMetadata
		m.Protocol = nodePtr(4)
		m.Host = &host
		// Storage rejects some of these before a plan can observe them.
		if updated, e := o.PutNode(ctx, m, nil, node.RowVersion); e == nil {
			node = updated
			if _, e = o.PlanWebConnection(ctx, q); e == nil {
				t.Fatal("invalid target accepted")
			}
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanWebConnection(ctx, q); err == nil {
		t.Fatal("closed owner planned target")
	}
}

type webPlanTamperStore struct {
	*vaultstore.SQLite
	mutate func(*vaultstore.Node)
}

func (s webPlanTamperStore) ReadNode(ctx context.Context, id string) (vaultstore.Node, error) {
	n, err := s.SQLite.ReadNode(ctx, id)
	if err == nil {
		s.mutate(&n)
	}
	return n, err
}

func TestWebPlanRejectsChangedRoutingFieldsAtTheSameRevision(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := nodeDraft()
	m.Protocol = nodePtr(4)
	m.HTTPPath = nodePtr("/original")
	m.HTTPIgnoreCertErrors = nodePtr(true)
	node, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	original := o.store.(*vaultstore.SQLite)
	for _, mutate := range []func(*vaultstore.Node){
		func(n *vaultstore.Node) { n.Host = nodePtr("redirect.example") },
		func(n *vaultstore.Node) { n.HTTPPath = nodePtr("/redirect") },
		func(n *vaultstore.Node) { n.HTTPIgnoreCertErrors = nodePtr(false) },
		func(n *vaultstore.Node) {
			n.TunnelEnabled = nodePtr(true)
			n.TunnelConfigID = nodePtr(uuid.NewString())
		},
	} {
		o.store = webPlanTamperStore{original, mutate}
		if _, err := o.PlanWebConnection(ctx, q); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("tampered target authenticated", err)
		}
	}
	o.store = original
}
