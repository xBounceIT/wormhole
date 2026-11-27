package localvault

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func hostFingerprint(value byte) string {
	raw := make([]byte, 32)
	raw[0] = value
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw)
}

func TestSSHHostPlanAndTrustDoNotBorrowCredentials(t *testing.T) {
	ctx := context.Background()
	o, n, request, key := sshBundleFixture(t)
	q := TunnelPlanRequest{request.NodeID, request.CredentialOverride, request.SessionID, request.RequestID, request.Epoch}
	m := n.NodeMetadata
	m.SshKnownHostFingerprint = nil
	n, err := o.PutNode(ctx, m, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	base := o.store.(integrityStore)
	reads := 0
	o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) { reads++; return s, nil }}
	p, err := o.PlanSSHHost(ctx, q, nil)
	if err != nil || p.Fingerprint != "" || len(p.Revision) != 64 || p.FileID == "" {
		t.Fatal(p, err)
	}
	// No caller may persist a different destination or reuse a stale plan.
	for _, mutate := range []func(*SSHHostPlan){
		func(p *SSHHostPlan) { p.Binding.Host = "other.example" },
		func(p *SSHHostPlan) { p.Binding.RequestID = uuid.NewString() },
		func(p *SSHHostPlan) { p.FileID = uuid.NewString() },
		func(p *SSHHostPlan) { p.Revision = "bad" },
		func(p *SSHHostPlan) { p.Fingerprint = hostFingerprint(2) },
	} {
		bad := p
		mutate(&bad)
		if _, err := o.TrustSSHHost(ctx, q, nil, bad, hostFingerprint(1)); err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"", "MD5:bad", hostFingerprint(1) + "=", "SHA256:bad"} {
		if _, err := o.TrustSSHHost(ctx, q, nil, p, bad); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	saved, err := o.TrustSSHHost(ctx, q, nil, p, hostFingerprint(1))
	if err != nil || saved.RowVersion != n.RowVersion+1 || *saved.SshKnownHostFingerprint != hostFingerprint(1) {
		t.Fatal(saved, err)
	}
	if _, err := o.TrustSSHHost(ctx, q, nil, p, hostFingerprint(1)); err != vaultstore.ErrConflict {
		t.Fatal("replay", err)
	}
	current, err := o.PlanSSHHost(ctx, q, nil)
	if err != nil || current.Fingerprint != hostFingerprint(1) || current.Revision == p.Revision {
		t.Fatal(current, err)
	}
	if _, err := o.TrustSSHHost(ctx, q, nil, current, current.Fingerprint); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if reads != 0 {
		t.Fatal("host trust borrowed a credential", reads)
	}
	o.store = base
	sealed, err := o.SealSSHConnection(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenBundle(key, sealed.Binding, sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	payload, err := vault.DecodeSSHBundle(raw)
	if err != nil || payload.Fingerprint != current.Fingerprint {
		t.Fatal("trust not used by connection", err)
	}
}

func TestSSHHostTrustRejectsConcurrentResolutionChanges(t *testing.T) {
	for _, change := range []string{"leaf", "parent", "credential", "tunnel", "closed", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			o, _, _, _ := owner(t)
			n, parent, credential, tunnel := resolutionFixture(t, o)
			q := TunnelPlanRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
			route, err := o.PlanConnectionTunnel(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			p, err := o.PlanSSHHost(ctx, q, &route)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "leaf":
				m := n.NodeMetadata
				m.Name = "new leaf"
				_, err = o.PutNode(ctx, m, nil, n.RowVersion)
			case "parent":
				m := parent.NodeMetadata
				m.Host = nodePtr("new.example")
				_, err = o.PutNode(ctx, m, nil, parent.RowVersion)
			case "credential":
				m := credential.CredentialMetadata
				m.Name = "changed credential"
				_, err = o.PutCredential(ctx, m, nil, credential.RowVersion)
			case "tunnel":
				m := tunnel.TunnelMetadata
				m.Name = "changed tunnel"
				_, err = o.PutTunnel(ctx, m, nil, tunnel.RowVersion)
			case "closed":
				err = o.Close()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := o.TrustSSHHost(ctx, q, &route, p, hostFingerprint(1)); err == nil {
				t.Fatal("stale confirmation committed")
			}
		})
	}
}

func TestSSHHostPlanRouteAndRequestAdmission(t *testing.T) {
	ctx := context.Background()
	o, n, request, _ := sshBundleFixture(t)
	q := TunnelPlanRequest{request.NodeID, request.CredentialOverride, request.SessionID, request.RequestID, request.Epoch}
	bad := q
	bad.NodeID = "bad"
	if _, err := o.PlanSSHHost(ctx, bad, nil); err == nil {
		t.Fatal("invalid request")
	}
	if _, err := o.PlanSSHHost(ctx, q, &vault.TunnelBundleBinding{}); err == nil {
		t.Fatal("direct route supplied")
	}
	m := n.NodeMetadata
	m.TunnelEnabled = nodePtr(true)
	n, err := o.PutNode(ctx, m, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanSSHHost(ctx, q, nil); err == nil {
		t.Fatal("VPN bypassed")
	}
	route, err := o.PlanConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.PlanSSHHost(ctx, q, &route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.TrustSSHHost(ctx, q, &route, p, hostFingerprint(1)); err != nil {
		t.Fatal(err)
	}
	// Parent pins are inherited for comparison but acceptance writes only the leaf.
	parent, err := o.ReadNode(ctx, *n.ParentID, 0)
	if err != nil || parent.SshKnownHostFingerprint != nil {
		t.Fatal("parent mutated", err)
	}
	m = n.NodeMetadata
	m.Protocol = nodePtr(6)
	if _, err := o.PutNode(ctx, m, nil, n.RowVersion+1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanSSHHost(ctx, q, &route); err == nil {
		t.Fatal("non-SSH host probe")
	}
}

func TestSSHHostInheritedPinOnlyUpdatesSelectedLeaf(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, parent, _, _ := resolutionFixture(t, o)
	m := parent.NodeMetadata
	m.SshKnownHostFingerprint = nodePtr(hostFingerprint(1))
	parent, err := o.PutNode(ctx, m, nil, parent.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	sibling := n.NodeMetadata
	sibling.ID = uuid.NewString()
	if _, err := o.PutNode(ctx, sibling, nil, 0); err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	route, err := o.PlanConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.PlanSSHHost(ctx, q, &route)
	if err != nil || p.Fingerprint != hostFingerprint(1) {
		t.Fatal(p, err)
	}
	if _, err := o.TrustSSHHost(ctx, q, &route, p, hostFingerprint(2)); err != nil {
		t.Fatal(err)
	}
	savedParent, err := o.ReadNode(ctx, parent.ID, 0)
	if err != nil || savedParent.RowVersion != parent.RowVersion || *savedParent.SshKnownHostFingerprint != hostFingerprint(1) {
		t.Fatal("parent trust changed", err)
	}
	for id, want := range map[string]string{n.ID: hostFingerprint(2), sibling.ID: hostFingerprint(1)} {
		r, err := o.ResolveConnectionPath(ctx, id, "", "ssh")
		if err != nil || r.Plan.HostKeyFingerprint != want {
			t.Fatal("leaf trust isolation", err)
		}
	}
}
