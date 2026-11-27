package localvault

import (
	"bytes"
	"context"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSSHManualOwnerAuthorizesOnlyCurrentSnapshotAndRequiredKey(t *testing.T) {
	for _, mode := range []string{"account", "passphrase"} {
		for _, routed := range []bool{false, true} {
			o, n, q, key := sshBundleFixture(t)
			ctx := context.Background()
			if mode == "passphrase" {
				c := draft()
				c.Kind = "sshKey"
				credential, err := o.PutCredential(ctx, c, []SecretChange{{Field: "privateKey", Value: []byte("saved-private-key")}, {Field: "passphrase", Value: []byte("stored-passphrase-never-read")}, {Field: "certificate", Value: []byte("saved-certificate")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				q.CredentialOverride = credential.ID
			}
			if routed {
				m := n.NodeMetadata
				m.TunnelEnabled = nodePtr(true)
				var err error
				n, err = o.PutNode(ctx, m, nil, n.RowVersion)
				if err != nil {
					t.Fatal(err)
				}
			}
			request := TunnelPlanRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch}
			route, err := o.ResolveConnectionRoute(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := ""
			if routed {
				endpoint = "127.0.0.1:2345"
			}
			plan, err := o.PlanManualSSHConnection(ctx, request, route, mode, q.SFTPOnly)
			if err != nil {
				t.Fatal(err)
			}
			manualContext := vault.SSHManualContext{Binding: plan.Host.Binding, Route: route, Endpoint: endpoint, Mode: mode, FileID: plan.Host.FileID, Revision: plan.Host.Revision, Fingerprint: plan.Host.Fingerprint, AutoSudo: plan.AutoSudo, SFTPOnly: plan.SFTPOnly}
			input := vault.SSHBundlePayload{Username: "temporary-user", Fingerprint: plan.Host.Fingerprint, Password: []byte("temporary-password")}
			if mode == "passphrase" {
				input = vault.SSHBundlePayload{}
			} // explicit empty override
			inner, err := vault.SealManualSSHCredentials(q.PublicKey, manualContext, input)
			if err != nil {
				t.Fatal(err)
			}
			store := o.store.(integrityStore)
			reads := 0
			o.store = integrityProbe{integrityStore: store, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
				reads++
				if o.mu.TryLock() {
					o.mu.Unlock()
					t.Fatal("borrow outside lock")
				}
				if mode == "account" || s.Ref.Field == "passphrase" || s.Ref.Field == "password" {
					t.Fatal("saved fallback borrowed")
				}
				return s, nil
			}}
			sealed, err := o.SealManualSSHConnection(ctx, q, plan, route, endpoint, inner)
			o.store = store
			if err != nil {
				t.Fatal(err)
			}
			if mode == "account" && reads != 0 || mode == "passphrase" && reads != 2 {
				t.Fatal("wrong secret borrows", reads)
			}
			var raw []byte
			if route == nil {
				raw, err = vault.OpenBundle(key, sealed.Binding, sealed.Bundle)
			} else {
				raw, err = vault.OpenRoutedBundle(key, *route, endpoint, sealed.Bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			a, err := vault.DecodeSSHManualAuthorization(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Base.Password)+len(a.Base.Passphrase) != 0 {
				t.Fatal("saved account leaked into manual authority")
			}
			if mode == "passphrase" && (!bytes.Equal(a.Base.PrivateKey, []byte("saved-private-key")) || !bytes.Equal(a.Base.Certificate, []byte("saved-certificate"))) {
				t.Fatal("selected key missing")
			}
			plain, err := vault.OpenManualSSHCredentials(key, manualContext, a.Manual)
			if err != nil {
				t.Fatal(err)
			}
			p, err := vault.DecodeSSHManualCredentials(manualContext, plain)
			if err != nil || !bytes.Equal(p.Passphrase, input.Passphrase) || !bytes.Equal(p.Password, input.Password) {
				t.Fatal("manual input changed", err)
			}
			vault.Wipe(raw)
			vault.Wipe(plain)
			for _, edit := range []func(*SSHManualPlan){func(p *SSHManualPlan) { p.Host.Revision = "stale" }, func(p *SSHManualPlan) { p.Host.Fingerprint = "" }, func(p *SSHManualPlan) { p.AutoSudo = !p.AutoSudo }, func(p *SSHManualPlan) { p.SFTPOnly = !p.SFTPOnly }} {
				bad := plan
				edit(&bad)
				if _, err = o.SealManualSSHConnection(ctx, q, bad, route, endpoint, inner); err == nil {
					t.Fatal("stale authorization")
				}
			}
			if _, err = o.SealManualSSHConnection(ctx, q, plan, route, "remote:22", inner); err == nil {
				t.Fatal("endpoint substitution")
			}
			if _, err = o.SealManualSSHConnection(nil, q, plan, route, endpoint, inner); err == nil {
				t.Fatal("nil context")
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err = o.SealManualSSHConnection(cancelled, q, plan, route, endpoint, inner); err == nil {
				cancel()
				t.Fatal("cancelled request")
			}
			cancel()
			if _, err = o.SealManualSSHConnection(ctx, q, plan, route, endpoint, vault.SealedBundle{}); err == nil {
				t.Fatal("malformed inner")
			}
			if mode == "passphrase" {
				o.store = integrityProbe{integrityStore: store, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
					return vaultstore.Secret{}, vaultstore.ErrMissing
				}}
				if _, err = o.SealManualSSHConnection(ctx, q, plan, route, endpoint, inner); err == nil {
					t.Fatal("failed key borrow accepted")
				}
				o.store = store
			} else {
				bad := q
				bad.CredentialOverride = "invalid"
				if _, err = o.SealManualSSHConnection(ctx, bad, plan, route, endpoint, inner); err == nil {
					t.Fatal("invalid request")
				}
			}
			bad := q
			bad.PublicKey = make([]byte, 32)
			if _, err = o.SealManualSSHConnection(ctx, bad, plan, route, endpoint, inner); err == nil {
				t.Fatal("bad recipient key")
			}
			badPlan := plan
			badPlan.Mode = "invalid"
			if _, err = o.SealManualSSHConnection(ctx, q, badPlan, route, endpoint, inner); err == nil {
				t.Fatal("invalid mode")
			}
		}
	}
}

func TestSSHManualOwnerPlanRefusesUnsafeSourceAndMode(t *testing.T) {
	o, _, q, _ := sshBundleFixture(t)
	ctx := context.Background()
	r := TunnelPlanRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch}
	if _, err := o.PlanManualSSHConnection(ctx, r, nil, "passphrase", false); err == nil {
		t.Fatal("password credential became key")
	}
	if _, err := o.PlanManualSSHConnection(ctx, r, nil, "bad", false); err == nil {
		t.Fatal("invalid mode")
	}
	if _, err := o.PlanManualSSHConnection(nil, r, nil, "account", false); err == nil {
		t.Fatal("nil context")
	}
	r.CredentialOverride = q.NodeID
	if _, err := o.PlanManualSSHConnection(ctx, r, nil, "account", false); err == nil {
		t.Fatal("manual primary saved override")
	}
	r.CredentialOverride = ""
	r.NodeID = "bad"
	if _, err := o.PlanManualSSHConnection(ctx, r, nil, "account", false); err == nil {
		t.Fatal("invalid request")
	}
}
