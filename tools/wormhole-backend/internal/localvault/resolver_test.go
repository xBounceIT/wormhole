package localvault

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func resolutionFixture(t *testing.T, o *Owner) (vaultstore.Node, vaultstore.Node, vaultstore.Credential, vaultstore.Tunnel) {
	t.Helper()
	ctx := context.Background()
	c, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("selected-password")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := o.PutTunnel(ctx, tunnelDraft(), []byte("private-tunnel-configuration"), 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := nodeDraft()
	parent.Kind = 0
	parent.CredentialID = &c.ID
	parent.TunnelConfigID = &tunnel.ID
	parent.TunnelEnabled = nodePtr(true)
	folder, err := o.PutNode(ctx, parent, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	child := nodeDraft()
	child.ParentID = &folder.ID
	child.Protocol = nil
	child.Host = nil
	leaf, err := o.PutNode(ctx, child, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, folder, c, tunnel
}

func TestConnectionResolutionAndBorrowedRelease(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, parent, c, tunnel := resolutionFixture(t, o)
	r, err := o.ResolveConnection(ctx, n.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity != o.store.Identity() || r.Plan.Username != "user" || r.Plan.Port != 22 || r.Plan.Credential.ID != c.ID || r.Plan.TunnelID != tunnel.ID || len(r.Nodes) != 2 || r.Nodes[0] != (ResolutionRevision{n.ID, 1}) || r.Nodes[1] != (ResolutionRevision{parent.ID, 1}) {
		t.Fatal("incorrect authenticated resolution")
	}
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		var borrowed []byte
		sentinel := errors.New("consumer failed")
		err := o.WithConnectionSecret(ctx, n.ID, "", path, "password", func(got Resolution, value []byte) error {
			if got.Plan.Credential.ID != c.ID || !bytes.Equal(value, []byte("selected-password")) {
				t.Fatal("wrong resolved secret")
			}
			borrowed = value
			return sentinel
		})
		if err != sentinel || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("borrowed secret retained", err)
		}
	}
	if err := o.WithConnectionTunnel(ctx, n.ID, func(got Resolution, value []byte) error {
		if got.Plan.TunnelID != tunnel.ID || !bytes.Equal(value, []byte("private-tunnel-configuration")) {
			t.Fatal("wrong tunnel")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A returned plan is not a capability. A changed route is re-read next time.
	r.Plan.Host = "untrusted-plan.example"
	next := parent.NodeMetadata
	next.Host = nodePtr("new.example")
	if _, err := o.PutNode(ctx, next, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(got Resolution, value []byte) error {
		if got.Plan.Host != "new.example" || got.Nodes[1].Version != 2 {
			t.Fatal("stale route was reused")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionResolutionOverrideAndInline(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, _, _, _ := resolutionFixture(t, o)
	other := draft()
	other.Username = "other-user"
	other.Domain = "OTHER"
	c, err := o.PutCredential(ctx, other, []SecretChange{{Field: "password", Value: []byte("override-password")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := n.NodeMetadata
	m.UseInlinePassword = nodePtr(true)
	m.Username = nodePtr("inline-user")
	if _, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("inline-password")}}, 1); err != nil {
		t.Fatal(err)
	}
	for _, override := range []string{"", c.ID} {
		wantUser, wantSecret := "inline-user", "inline-password"
		if override != "" {
			wantUser, wantSecret = "other-user", "override-password"
		}
		if err := o.WithConnectionSecret(ctx, n.ID, override, "ssh", "password", func(r Resolution, value []byte) error {
			if r.Plan.Username != wantUser || !bytes.Equal(value, []byte(wantSecret)) {
				t.Fatal("identity mixed across override")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "privateKey", func(Resolution, []byte) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}

func TestConnectionRDPGatewayAndExternalPolicy(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	makeCredential := func(username, password string) vaultstore.Credential {
		m := draft()
		m.Protocol = "rdp"
		m.Username = username
		c, err := o.PutCredential(ctx, m, []SecretChange{{Field: "password", Value: []byte(password)}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeCredential("desktop-user", "desktop-password")
	gateway := makeCredential("gateway-user", "gateway-password")
	m := nodeDraft()
	m.Protocol = nodePtr(1)
	m.CredentialID = &c.ID
	m.RDPGatewayUsageMethod = nodePtr(1)
	m.RDPGatewayHostname = nodePtr("gateway.example")
	m.RDPGatewayCredentialID = &gateway.ID
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"rdp", "rdp-gateway"} {
		want := "desktop-password"
		if path == "rdp-gateway" {
			want = "gateway-password"
		}
		if err := o.WithConnectionSecret(ctx, n.ID, "", path, "password", func(r Resolution, value []byte) error {
			if !bytes.Equal(value, []byte(want)) || r.GatewayCredential.ID != gateway.ID {
				t.Fatal("gateway credential choice")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	m.RDPGatewayCredentialID = &c.ID
	if _, err := o.PutNode(ctx, m, nil, 1); err != nil {
		t.Fatal(err)
	}
	if r, err := o.ResolveConnection(ctx, n.ID, ""); err != nil || r.GatewayCredential.ID != c.ID {
		t.Fatal(err)
	}
	m.RDPGatewayUseSameCreds = nodePtr(true)
	if _, err := o.PutNode(ctx, m, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "rdp-gateway", "password", func(r Resolution, value []byte) error {
		if r.GatewayCredential != nil || !bytes.Equal(value, []byte("desktop-password")) {
			t.Fatal("same credentials ignored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m.RDPUseExternalClient = nodePtr(true)
	if _, err := o.PutNode(ctx, m, nil, 3); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"rdp", "rdp-gateway"} {
		want := error(nil)
		if runtime.GOOS == "windows" {
			want = vault.ErrPolicy
		}
		if err := o.WithConnectionSecret(ctx, n.ID, "", path, "password", func(Resolution, []byte) error {
			if runtime.GOOS == "windows" {
				t.Fatal("external client secret release")
			}
			return nil
		}); err != want {
			t.Fatal(err)
		}
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "reveal", "password", func(Resolution, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m.RDPUseExternalClient = nil
	m.RDPGatewayUsageMethod = nodePtr(0)
	if _, err := o.PutNode(ctx, m, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "rdp-gateway", "password", func(Resolution, []byte) error { return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestConnectionResolutionRejectsTamperingBeforeDecrypt(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, parent, _, _ := resolutionFixture(t, o)
	real := o.store.(completeNodeStore)
	for _, attack := range []string{"parent-mac", "node-id", "credential-mac", "credential-id", "tunnel-mac", "tunnel-id", "secret-substitution"} {
		t.Run(attack, func(t *testing.T) {
			f := nodeFilter{completeNodeStore: real}
			f.read = func(v vaultstore.Node) (vaultstore.Node, error) {
				if attack == "parent-mac" && v.ID == parent.ID {
					v.Name = "forged"
				}
				if attack == "node-id" {
					v.ID = uuid.NewString()
				}
				return v, nil
			}
			f.credential = func(v vaultstore.Credential) (vaultstore.Credential, error) {
				if attack == "credential-mac" {
					v.Username = "forged"
				}
				if attack == "credential-id" {
					v.ID = uuid.NewString()
				}
				return v, nil
			}
			f.tunnel = func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) {
				if attack == "tunnel-mac" {
					v.Kind++
				}
				if attack == "tunnel-id" {
					v.ID = uuid.NewString()
				}
				return v, nil
			}
			f.secret = func(v vaultstore.Secret) (vaultstore.Secret, error) {
				if attack == "secret-substitution" {
					v.Ref.OwnerID = uuid.NewString()
				}
				return v, nil
			}
			o.store = f
			err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(Resolution, []byte) error { t.Fatal("unverified release"); return nil })
			o.store = real
			if err != vault.ErrAuthentication {
				t.Fatal("attack not rejected", err)
			}
		})
	}
}

func TestConnectionResolutionAuthenticatedNodeFloor(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	n, parent, _, _ := resolutionFixture(t, o)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	opts.Slots.Nodes = []vault.NodeHighWater{{NodeID: parent.ID, Revision: 2}}
	raw, err := vault.EncodeSlotFile(key, opts.Slots)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// Caller mutations of its old slot document cannot lower the copied floor.
	opts.Slots.Nodes[0].Revision = 1
	if err := reopened.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(Resolution, []byte) error { t.Fatal("rolled back ancestor released secret"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
}

func TestConnectionResolutionFailureAndAbsentChoices(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, parent, c, _ := resolutionFixture(t, o)
	consumer := func(Resolution, []byte) error { t.Fatal("unexpected release"); return nil }
	for _, path := range []string{"unknown", "rdp", "rdp-gateway", "vnc"} {
		if err := o.WithConnectionSecret(ctx, n.ID, "", path, "password", consumer); err != vault.ErrPolicy {
			t.Fatal(err)
		}
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "notes", consumer); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithConnectionTunnel(ctx, n.ID, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "privateKey", consumer); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ResolveConnection(cancelled, n.ID, ""); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := o.ResolveConnection(ctx, uuid.NewString(), ""); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if _, err := o.ResolveConnection(ctx, parent.ID, ""); err != resolver.ErrChain {
		t.Fatal(err)
	}
	m := n.NodeMetadata
	m.CredentialMode = nodePtr(1)
	m.TunnelEnabled = nodePtr(false)
	if _, err := o.PutNode(ctx, m, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", consumer); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithConnectionTunnel(ctx, n.ID, consumer); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	// A provider-backed record cannot fall back to cached local plaintext.
	provider := c.CredentialMetadata
	provider.Provider = "bitwarden"
	provider.BitwardenItemID = "item"
	if _, err := o.PutCredential(ctx, provider, []SecretChange{{Field: "password", Remove: true}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, c.ID, "ssh", "password", consumer); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ResolveConnection(ctx, n.ID, ""); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestConnectionResolutionSignedInvalidGraphAndProtocol(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, parent, _, _ := resolutionFixture(t, o)
	real := o.store.(completeNodeStore)
	for _, attack := range []string{"cycle", "deleted-node", "credential-protocol", "deleted-credential", "deleted-tunnel", "slot"} {
		t.Run(attack, func(t *testing.T) {
			f := nodeFilter{completeNodeStore: real}
			f.read = func(v vaultstore.Node) (vaultstore.Node, error) {
				if attack == "cycle" && v.ID == parent.ID {
					v.ParentID = &n.ID
				}
				if attack == "deleted-node" {
					v.Deleted = true
				}
				if attack == "slot" && v.ID == n.ID {
					v.CredentialMode = nodePtr(3)
					v.CredentialSlotID = nodePtr(uuid.NewString())
				}
				err := o.root.With(func(key []byte) error { var err error; v.Seal, err = nodeMAC(key, real.Identity(), v); return err })
				return v, err
			}
			f.credential = func(v vaultstore.Credential) (vaultstore.Credential, error) {
				if attack == "credential-protocol" {
					v.Protocol = "rdp"
				}
				if attack == "deleted-credential" {
					v.Deleted = true
					v.Fields = nil
				}
				err := o.root.With(func(key []byte) error {
					var err error
					v.Seal, err = credentialMAC(key, real.Identity(), v)
					return err
				})
				return v, err
			}
			f.tunnel = func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) {
				if attack == "deleted-tunnel" {
					v.Deleted = true
				}
				err := o.root.With(func(key []byte) error { var err error; v.Seal, err = tunnelMAC(key, real.Identity(), v); return err })
				return v, err
			}
			o.store = f
			_, err := o.ResolveConnection(ctx, n.ID, "")
			o.store = real
			want := map[string]error{"cycle": resolver.ErrChain, "deleted-node": vaultstore.ErrMissing, "credential-protocol": resolver.ErrCredential, "deleted-credential": vaultstore.ErrMissing, "deleted-tunnel": vaultstore.ErrMissing, "slot": vault.ErrPolicy}[attack]
			if !reflect.DeepEqual(err, want) {
				t.Fatal(err, want)
			}
		})
	}
}

func TestConnectionReleaseSerializesWithRouteEdits(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, parent, _, _ := resolutionFixture(t, o)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(r Resolution, value []byte) error {
			if r.Plan.Host != "host.example" || !bytes.Equal(value, []byte("selected-password")) {
				return errors.New("mixed snapshot")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("release did not start")
	}
	edited := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		metadata := parent.NodeMetadata
		metadata.Host = nodePtr("updated.example")
		_, err := o.PutNode(ctx, metadata, nil, 1)
		edited <- err
	}()
	<-started
	select {
	case err := <-edited:
		close(release)
		t.Fatal("route changed during secret callback", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-edited; err != nil {
		t.Fatal(err)
	}
	if r, err := o.ResolveConnection(ctx, n.ID, ""); err != nil || r.Plan.Host != "updated.example" {
		t.Fatal("new resolution missed committed edit", err)
	}
}

func TestConnectionVNCAndAzureADCredentialPolicy(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	for _, protocol := range []int{1, 6} {
		m := draft()
		m.Protocol = resolver.CredentialProtocol(protocol)
		m.Domain = "AzureAD"
		c, err := o.PutCredential(ctx, m, []SecretChange{{Field: "password", Value: []byte("account-password")}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		node := nodeDraft()
		node.Protocol = nodePtr(protocol)
		node.CredentialID = &c.ID
		n, err := o.PutNode(ctx, node, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		path := "vnc"
		if protocol == 1 {
			path = "rdp"
		}
		want := error(nil)
		if protocol == 1 && runtime.GOOS == "windows" {
			want = vault.ErrPolicy
		}
		called := false
		err = o.WithConnectionSecret(ctx, n.ID, "", path, "password", func(Resolution, []byte) error { called = true; return nil })
		if err != want || called != (want == nil) {
			t.Fatal("AzureAD/system-client policy", err, called)
		}
	}
}

func TestConnectionInlineGatewayAndPinnedFieldRevision(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := nodeDraft()
	m.Protocol = nodePtr(1)
	m.UseInlinePassword = nodePtr(true)
	m.RDPGatewayUsageMethod = nodePtr(2)
	m.RDPGatewayUseSameCreds = nodePtr(true)
	n, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("inline-gateway")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "rdp-gateway", "password", func(r Resolution, value []byte) error {
		if r.Plan.Credential.Kind != "inline" || !bytes.Equal(value, []byte("inline-gateway")) {
			t.Fatal("gateway ignored inline choice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A valid old metadata record cannot select a newer encrypted field version.
	if _, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("new-password")}}, 1); err != nil {
		t.Fatal(err)
	}
	real := o.store.(completeNodeStore)
	o.store = nodeFilter{completeNodeStore: real, read: func(vaultstore.Node) (vaultstore.Node, error) { return n, nil }}
	err = o.WithConnectionSecret(ctx, n.ID, "", "rdp", "password", func(Resolution, []byte) error { t.Fatal("mixed revisions released"); return nil })
	if err != vault.ErrRollback {
		t.Fatal("committed node floor ignored", err)
	}
	// Without a resident checkpoint (as in a fresh process), the independent
	// field-version binding must still reject this mixed metadata/secret pair.
	delete(o.nodeFloors, n.ID)
	err = o.WithConnectionSecret(ctx, n.ID, "", "rdp", "password", func(Resolution, []byte) error { t.Fatal("mixed revisions released without checkpoint"); return nil })
	o.store = real
	if err != vault.ErrAuthentication {
		t.Fatal(err)
	}
}
