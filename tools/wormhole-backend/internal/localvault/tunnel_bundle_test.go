package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"sync"
	"testing"
)

func routeBundleFixture(t *testing.T) (*Owner, vaultstore.Node, vaultstore.Tunnel, TunnelBundleRequest, []byte) {
	t.Helper()
	o, _, _, _ := owner(t)
	n, _, _, tunnel := resolutionFixture(t, o)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return o, n, tunnel, TunnelBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}, key.Bytes()
}
func TestTunnelConnectionBundleResolvesAndRebindsCurrentRoute(t *testing.T) {
	o, n, tunnel, q, key := routeBundleFixture(t)
	ctx := context.Background()
	read := func(want string) TunnelConnectionBundle {
		t.Helper()
		got, e := o.SealConnectionTunnel(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		if got.Binding.TunnelConfigID != tunnel.ID || got.Binding.NodeID != n.ID || got.Binding.FileID != o.store.Identity().FileID {
			t.Fatal("wrong route binding")
		}
		plain, e := vault.OpenTunnelBundle(key, got.Binding, got.Bundle)
		if e != nil || !bytes.Equal(plain, []byte(want)) {
			t.Fatal("wrong configuration", e)
		}
		vault.Wipe(plain)
		return got
	}
	first := read("private-tunnel-configuration")
	for kind := 0; kind <= 9; kind++ {
		metadata := tunnel.TunnelMetadata
		metadata.Kind = kind
		var e error
		tunnel, e = o.PutTunnel(ctx, metadata, []byte("new configuration"), tunnel.RowVersion)
		if e != nil {
			t.Fatal(e)
		}
		got := read("new configuration")
		if got.Binding.Kind != uint16(kind) || got.Binding.RowVersion != tunnel.RowVersion || got.Binding.ConfigurationVersion != tunnel.ConfigurationVersion {
			t.Fatal("stale metadata")
		}
	}
	m := n.NodeMetadata
	m.Host = nodePtr("other.example")
	var e error
	n, e = o.PutNode(ctx, m, nil, n.RowVersion)
	if e != nil {
		t.Fatal(e)
	}
	second := read("new configuration")
	if first.Binding.Host == second.Binding.Host {
		t.Fatal("old host reused")
	}
	if _, e := vault.OpenTunnelBundle(key, first.Binding, second.Bundle); e == nil {
		t.Fatal("mixed route/config accepted")
	}
	for _, tc := range []struct {
		code int
		name string
		port int
	}{{0, "ssh", 22}, {7, "sftp", 22}, {1, "rdp", 3389}, {6, "vnc", 5900}, {3, "http", 80}, {4, "https", 443}} {
		m := n.NodeMetadata
		m.Protocol = &tc.code
		m.CredentialMode = nodePtr(1)
		m.CredentialID = nil
		m.Username = nodePtr("user")
		m.Port = &tc.port
		n, e = o.PutNode(ctx, m, nil, n.RowVersion)
		if e != nil {
			t.Fatal(e)
		}
		got := read("new configuration")
		if got.Binding.Protocol != tc.name || got.Binding.Port != uint16(tc.port) {
			t.Fatal("protocol mapping", tc, got.Binding)
		}
	}
	m = n.NodeMetadata
	m.TunnelEnabled = nodePtr(false)
	n, e = o.PutNode(ctx, m, nil, n.RowVersion)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.SealConnectionTunnel(ctx, q); e != vaultstore.ErrMissing {
		t.Fatal("disabled tunnel", e)
	}
}
func TestTunnelConnectionBundleRejectsInvalidAndStaleInputs(t *testing.T) {
	o, n, _, q, _ := routeBundleFixture(t)
	ctx := context.Background()
	for _, change := range []func(*TunnelBundleRequest){func(q *TunnelBundleRequest) { q.NodeID = "bad" }, func(q *TunnelBundleRequest) { q.NodeID = uuid.NewString() }, func(q *TunnelBundleRequest) { q.SessionID = uuid.Nil.String() }, func(q *TunnelBundleRequest) { q.RequestID = "bad" }, func(q *TunnelBundleRequest) { q.Epoch = 0 }, func(q *TunnelBundleRequest) { q.Epoch = 1 << 53 }, func(q *TunnelBundleRequest) { q.PublicKey = nil }, func(q *TunnelBundleRequest) { q.PublicKey = make([]byte, 32) }} {
		bad := q
		change(&bad)
		got, e := o.SealConnectionTunnel(ctx, bad)
		if e == nil || got.Bundle.Ciphertext != nil {
			t.Fatal("bad request")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := o.SealConnectionTunnel(cancelled, q); e != context.Canceled {
		t.Fatal(e)
	}
	for _, host := range []string{"bad host"} {
		m := n.NodeMetadata
		m.Host = &host
		written, e := o.PutNode(ctx, m, nil, n.RowVersion)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = o.SealConnectionTunnel(ctx, q); e == nil {
			t.Fatal("bad destination")
		}
		n, e = o.PutNode(ctx, n.NodeMetadata, nil, written.RowVersion)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := o.SealConnectionTunnel(ctx, q); e != vaultstore.ErrClosed {
		t.Fatal("closed", e)
	}
}
func TestTunnelConnectionBundleBorrowsUnderOwnerLockAndRejectsTamperedSecrets(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "cancel", "observe"} {
		o, _, _, q, _ := routeBundleFixture(t)
		base := o.store.(integrityStore)
		ctx, cancel := context.WithCancel(context.Background())
		o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
			if o.mu.TryLock() {
				o.mu.Unlock()
				t.Fatal("borrow outside lock")
			}
			if mode == "missing" {
				return s, vaultstore.ErrMissing
			}
			if mode == "corrupt" {
				s.Envelope.Ciphertext[0] ^= 1
			}
			if mode == "cancel" {
				cancel()
			}
			return s, nil
		}}
		got, e := o.SealConnectionTunnel(ctx, q)
		cancel()
		o.store = base
		if mode == "observe" {
			if e != nil {
				t.Fatal(e)
			}
		} else if e == nil || got.Bundle.Ciphertext != nil || got.Binding.Host != "" {
			t.Fatal("partial or unauthenticated output", mode, e)
		}
	}
}
func TestTunnelConnectionBundleConcurrentClose(t *testing.T) {
	o, _, _, q, _ := routeBundleFixture(t)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			got, e := o.SealConnectionTunnel(context.Background(), q)
			if e != nil && !errors.Is(e, vaultstore.ErrClosed) {
				t.Error(e)
			}
			vault.Wipe(got.Bundle.Ciphertext)
		})
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	group.Wait()
}

func TestTunnelPlanAuthenticatesMetadataWithoutReadingSecrets(t *testing.T) {
	o, n, tunnel, q, _ := routeBundleFixture(t)
	ctx := context.Background()
	base := o.store.(integrityStore)
	reads := 0
	o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) { reads++; return s, vault.ErrAuthentication }}
	plan, err := o.PlanConnectionTunnel(ctx, q.Plan())
	if err != nil || reads != 0 || plan.TunnelConfigID != tunnel.ID || plan.ConfigurationVersion != tunnel.ConfigurationVersion {
		t.Fatal("planning read secrets", reads, err)
	}
	if _, err := o.SealConnectionTunnel(ctx, q); err == nil || reads == 0 {
		t.Fatal("release bypassed secret authentication")
	}
	o.store = base
	sealed, err := o.SealConnectionTunnel(ctx, q)
	if err != nil || sealed.Binding != plan {
		t.Fatal("plan/release drift", err)
	}
	tunnel, err = o.PutTunnel(ctx, tunnel.TunnelMetadata, []byte("changed-config"), tunnel.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := o.PlanConnectionTunnel(ctx, q.Plan())
	if err != nil || changed.ConfigurationVersion == plan.ConfigurationVersion {
		t.Fatal("stale revision", err)
	}
	bad := q.Plan()
	bad.NodeID = "bad"
	if _, err := o.PlanConnectionTunnel(ctx, bad); err != vault.ErrFormat {
		t.Fatal(err)
	}
	bad.NodeID = uuid.NewString()
	if _, err := o.PlanConnectionTunnel(ctx, bad); err == nil {
		t.Fatal("missing node")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PlanConnectionTunnel(cancelled, q.Plan()); err != context.Canceled {
		t.Fatal(err)
	}
	m := n.NodeMetadata
	m.TunnelEnabled = nodePtr(false)
	if _, err := o.PutNode(ctx, m, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanConnectionTunnel(ctx, q.Plan()); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestTunnelConnectionBundleUsesSelectedCredentialOverride(t *testing.T) {
	o, _, _, q, key := routeBundleFixture(t)
	ctx := context.Background()
	c, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("override-secret")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	q.CredentialOverride = c.ID
	got, err := o.SealConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenTunnelBundle(key, got.Binding, got.Bundle)
	if err != nil || !bytes.Equal(plain, []byte("private-tunnel-configuration")) {
		t.Fatal(err)
	}
	vault.Wipe(plain)
	for _, id := range []string{"bad", uuid.Nil.String(), uuid.NewString()} {
		q.CredentialOverride = id
		if _, err := o.SealConnectionTunnel(ctx, q); err == nil {
			t.Fatal("bad override")
		}
	}
}

func TestTunnelConnectionBundleRejectsExternalRDPWithoutRetiringOwner(t *testing.T) {
	o, n, _, q, _ := routeBundleFixture(t)
	ctx := context.Background()
	m := n.NodeMetadata
	m.Protocol = nodePtr(1)
	m.CredentialMode = nodePtr(1)
	m.CredentialID = nil
	m.Username = nodePtr("user")
	m.RDPUseExternalClient = nodePtr(true)
	written, err := o.PutNode(ctx, m, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealConnectionTunnel(ctx, q); err != vault.ErrPolicy {
		t.Fatal("external client admitted", err)
	}
	if _, err := o.PutNode(ctx, n.NodeMetadata, nil, written.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealConnectionTunnel(ctx, q); err != nil {
		t.Fatal("owner unusable", err)
	}
}
