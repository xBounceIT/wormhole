package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func sshBundleFixture(t *testing.T) (*Owner, vaultstore.Node, SSHBundleRequest, []byte) {
	t.Helper()
	o, _, _, _ := owner(t)
	n, _, _, _ := resolutionFixture(t, o)
	m := n.NodeMetadata
	m.TunnelEnabled = nodePtr(false)
	m.SshKnownHostFingerprint = nodePtr("SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	n, err := o.PutNode(context.Background(), m, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return o, n, SSHBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}, key.Bytes()
}

func TestSSHConnectionBundleAuthenticatedResolution(t *testing.T) {
	o, n, q, key := sshBundleFixture(t)
	ctx := context.Background()
	read := func(want string) SSHConnectionBundle {
		t.Helper()
		sealed, err := o.SealSSHConnection(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if sealed.Binding.NodeID != n.ID || sealed.Binding.Protocol != "ssh" || sealed.Binding.Port != 22 || sealed.Binding.TunnelConfigID != "" {
			t.Fatal("wrong binding")
		}
		raw, err := vault.OpenBundle(key, sealed.Binding, sealed.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(raw)
		p, err := vault.DecodeSSHBundle(raw)
		if err != nil || !bytes.Equal(p.Password, []byte(want)) {
			t.Fatal("wrong credential", err)
		}
		if want == "" && (!bytes.Equal(p.PrivateKey, []byte("private")) || !bytes.Equal(p.Passphrase, []byte("passphrase"))) {
			t.Fatal("private key or passphrase lost in handoff")
		}
		return sealed
	}
	first := read("selected-password")
	m := n.NodeMetadata
	m.UseInlinePassword = nodePtr(true)
	m.Username = nodePtr("inline-user")
	m.Host = nodePtr("changed.example")
	if _, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("inline-password")}}, 2); err != nil {
		t.Fatal(err)
	}
	second := read("inline-password")
	if second.Binding.Host == first.Binding.Host {
		t.Fatal("stale route")
	}
	if _, err := vault.OpenBundle(key, first.Binding, second.Bundle); err == nil {
		t.Fatal("host substitution accepted")
	}
	c := draft()
	c.Kind = "sshKey"
	credential, err := o.PutCredential(ctx, c, []SecretChange{{Field: "privateKey", Value: []byte("private")}, {Field: "passphrase", Value: []byte("passphrase")}, {Field: "certificate", Value: []byte("certificate")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	q.CredentialOverride = credential.ID
	read("")
	if _, err := o.PutCredential(ctx, c, []SecretChange{{Field: "certificate", Remove: true}}, 1); err != nil {
		t.Fatal(err)
	}
	read("")
}

func TestSSHConnectionBundleRefusesUnsafeRequests(t *testing.T) {
	o, n, q, _ := sshBundleFixture(t)
	ctx := context.Background()
	for _, mutate := range []func(*SSHBundleRequest){func(q *SSHBundleRequest) { q.NodeID = "bad" }, func(q *SSHBundleRequest) { q.SessionID = "bad" }, func(q *SSHBundleRequest) { q.RequestID = "bad" }, func(q *SSHBundleRequest) { q.PublicKey = nil }, func(q *SSHBundleRequest) { q.PublicKey = make([]byte, 32) }, func(q *SSHBundleRequest) { q.Epoch = 0 }, func(q *SSHBundleRequest) { q.Epoch = 1 << 53 }, func(q *SSHBundleRequest) { q.CredentialOverride = uuid.NewString() }} {
		bad := q
		mutate(&bad)
		if _, err := o.SealSSHConnection(ctx, bad); err == nil {
			t.Fatal("unsafe request accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.SealSSHConnection(cancelled, q); err == nil {
		t.Fatal("cancellation ignored")
	}
	for _, mutate := range []func(*vaultstore.NodeMetadata){func(m *vaultstore.NodeMetadata) { m.TunnelEnabled = nodePtr(true) }, func(m *vaultstore.NodeMetadata) { m.SshKnownHostFingerprint = nodePtr("") }, func(m *vaultstore.NodeMetadata) { m.Host = nodePtr("bad host") }, func(m *vaultstore.NodeMetadata) { m.CredentialMode = nodePtr(1); m.CredentialID = nil }, func(m *vaultstore.NodeMetadata) { m.Protocol = nodePtr(1) }} {
		m := n.NodeMetadata
		mutate(&m)
		written, err := o.PutNode(ctx, m, nil, n.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.SealSSHConnection(ctx, q); err == nil {
			t.Fatal("unsafe route accepted")
		}
		n, err = o.PutNode(ctx, n.NodeMetadata, nil, written.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealSSHConnection(ctx, q); err == nil {
		t.Fatal("closed owner accepted")
	}
}

func TestSSHConnectionBundleAtomicBorrowFailures(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "inline"}[inline], func(t *testing.T) {
			o, n, q, _ := sshBundleFixture(t)
			if inline {
				m := n.NodeMetadata
				m.UseInlinePassword = nodePtr(true)
				m.Username = nodePtr("inline")
				if _, err := o.PutNode(context.Background(), m, []SecretChange{{Field: "inlinePassword", Value: []byte("inline")}}, n.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			base := o.store.(integrityStore)
			defer func() { o.store = base }()
			for _, mode := range []string{"missing", "corrupt", "cancel"} {
				ctx, cancel := context.WithCancel(context.Background())
				o.store = integrityProbe{integrityStore: base, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
					if o.mu.TryLock() {
						o.mu.Unlock()
						t.Fatal("secret borrow outside owner lock")
					}
					if mode == "missing" {
						return vaultstore.Secret{}, vaultstore.ErrMissing
					}
					if mode == "corrupt" {
						value.Envelope.Ciphertext[0] ^= 1
					} else {
						cancel()
					}
					return value, nil
				}}
				got, err := o.SealSSHConnection(ctx, q)
				cancel()
				if err == nil || got.Bundle.Ciphertext != nil || got.Binding.Host != "" {
					t.Fatal("partial or unauthenticated bundle returned")
				}
			}
		})
	}
}
func TestSFTPConnectionBundleSelectsAuthenticatedProtocolPath(t *testing.T) {
	for _, protocol := range []int{0, 7} {
		for _, routed := range []bool{false, true} {
			t.Run(map[bool]string{false: "direct", true: "routed"}[routed], func(t *testing.T) {
				ctx := context.Background()
				o, n, q, key := sshBundleFixture(t)
				m := n.NodeMetadata
				m.Protocol = nodePtr(protocol)
				q.SFTPOnly = true
				wantProtocol := resolver.DefaultPath(protocol)
				m.SshAutoSudo = nodePtr(true)
				m.TunnelEnabled = nodePtr(routed)
				var err error
				n, err = o.PutNode(ctx, m, nil, n.RowVersion)
				if err != nil {
					t.Fatal(err)
				}
				c, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("sftp-specific-password")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				sshCredential, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("ssh-specific-password")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{
					"ssh":  {SourceKind: "saved", CredentialID: sshCredential.ID, Username: "ssh-specific-user"},
					"sftp": {SourceKind: "saved", CredentialID: c.ID, Username: "sftp-specific-user"},
				})
				planRequest := TunnelPlanRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch}
				route, err := o.ResolveConnectionRoute(ctx, planRequest)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := o.PlanSSHHost(ctx, planRequest, route)
				if err != nil || plan.Binding.Protocol != wantProtocol {
					t.Fatal("wrong host plan", err)
				}
				tampered := plan
				tampered.Binding.Protocol = "rdp"
				if _, err = o.TrustSSHHost(ctx, planRequest, route, tampered, hostFingerprint(8)); err == nil {
					t.Fatal("protocol substitution trusted")
				}
				if _, err = o.TrustSSHHost(ctx, planRequest, route, plan, hostFingerprint(8)); err != nil {
					t.Fatal(err)
				}
				var raw []byte
				if routed {
					if route == nil || route.Protocol != wantProtocol {
						t.Fatal("missing SFTP route")
					}
					sealed, e := o.SealRoutedSSHConnection(ctx, q, *route, "127.0.0.1:4321")
					if e != nil {
						t.Fatal(e)
					}
					raw, err = vault.OpenRoutedBundle(key, *route, sealed.Endpoint, sealed.Bundle)
					bad := *route
					bad.Protocol = "rdp"
					if _, e = o.SealRoutedSSHConnection(ctx, q, bad, sealed.Endpoint); e == nil {
						t.Fatal("route substitution accepted")
					}
				} else {
					sealed, e := o.SealSSHConnection(ctx, q)
					if e != nil || sealed.Binding.Protocol != wantProtocol {
						t.Fatal("wrong bundle", e)
					}
					raw, err = vault.OpenBundle(key, sealed.Binding, sealed.Bundle)
					bad := sealed.Binding
					bad.Protocol = "rdp"
					if _, e = vault.OpenBundle(key, bad, sealed.Bundle); e == nil {
						t.Fatal("protocol not authenticated")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				payload, err := vault.DecodeSSHBundle(raw)
				if err != nil || payload.Username != wantProtocol+"-specific-user" || string(payload.Password) != wantProtocol+"-specific-password" || !payload.SFTPOnly || payload.AutoSudo || payload.Fingerprint != hostFingerprint(8) {
					t.Fatal("SFTP account, pin or shell policy lost", err)
				}
			})
		}
	}
}
