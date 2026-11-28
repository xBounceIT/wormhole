package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type manualVNCNoSecretStore struct {
	*vaultstore.SQLite
	reads *int
}

func (s manualVNCNoSecretStore) ReadSecret(context.Context, vaultstore.SecretRef) (vaultstore.Secret, error) {
	*s.reads++
	return vaultstore.Secret{}, vaultstore.ErrStorage
}

func TestManualVNCPlanAndSealNeverReadSavedPassword(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	c := draft()
	c.Protocol = "vnc"
	credential, err := o.PutCredential(ctx, c, []SecretChange{{Field: "password", Value: []byte("must-not-be-read")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.Protocol = nodePtr(6)
	m.Port = nodePtr(5900)
	m.CredentialID = &credential.ID
	node, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	q := TunnelBundleRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}
	original := o.store.(*vaultstore.SQLite)
	reads := 0
	o.store = manualVNCNoSecretStore{original, &reads}
	binding, err := o.PlanVNCConnection(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range [][]byte{nil, []byte("one-use")} {
		inner, err := vault.SealManualVNCPassword(q.PublicKey, binding, nil, "", password)
		if err != nil {
			t.Fatal(err)
		}
		result, err := o.SealManualVNCConnection(ctx, q, binding, nil, "", inner)
		if err != nil {
			t.Fatal(err)
		}
		outer, err := vault.OpenBundle(key.Bytes(), binding, result.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := vault.DecodeVNCManualAuthorization(outer)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.OpenManualVNCPassword(key.Bytes(), binding, nil, "", envelope)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := vault.DecodeVNCBundle(raw)
		if err != nil || !payload.PasswordProvided || !bytes.Equal(payload.Password, password) {
			t.Fatal("wrong manual password", err)
		}
		vault.Wipe(raw)
		vault.Wipe(outer)
	}
	if reads != 0 {
		t.Fatal("manual flow read a saved secret")
	}
	if _, err := o.SealVNCConnection(ctx, q); err == nil || reads == 0 {
		t.Fatal("secret-denying store did not detect ordinary saved password borrowing")
	}
	o.store = original
	meta := node.NodeMetadata
	meta.Host = nodePtr("changed.example")
	if _, err := o.PutNode(ctx, meta, nil, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	inner, _ := vault.SealManualVNCPassword(q.PublicKey, binding, nil, "", nil)
	if _, err := o.SealManualVNCConnection(ctx, q, binding, nil, "", inner); err == nil {
		t.Fatal("stale target admitted")
	}
}
func TestManualVNCRouteAndRejections(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := nodeDraft()
	m.Protocol = nodePtr(6)
	m.Port = nodePtr(5900)
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	q := TunnelBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}
	binding, err := o.PlanVNCConnection(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := vault.SealManualVNCPassword(q.PublicKey, binding, nil, "", nil)
	for _, bad := range []TunnelBundleRequest{{}, func() TunnelBundleRequest { bad := q; bad.PublicKey = nil; return bad }(), func() TunnelBundleRequest { bad := q; bad.NodeID = uuid.NewString(); return bad }()} {
		if _, err := o.SealManualVNCConnection(ctx, bad, binding, nil, "", inner); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := o.PlanVNCConnection(ctx, TunnelPlanRequest{}); err == nil {
		t.Fatal("invalid plan accepted")
	}
	bad := binding
	bad.SessionID = uuid.NewString()
	if _, err := o.SealManualVNCConnection(ctx, q, bad, nil, "", inner); err == nil {
		t.Fatal("binding substitution accepted")
	}
	if _, err := o.SealManualVNCConnection(ctx, q, binding, nil, "127.0.0.1:2345", inner); err == nil {
		t.Fatal("direct endpoint accepted")
	}
	if _, err := o.SealManualVNCConnection(ctx, q, binding, nil, "", vault.SealedBundle{}); err == nil {
		t.Fatal("invalid inner accepted")
	}
	zero := q
	zero.PublicKey = make([]byte, 32)
	if _, err := o.SealManualVNCConnection(ctx, zero, binding, nil, "", inner); err == nil {
		t.Fatal("invalid X25519 recipient accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PlanVNCConnection(cancelled, q.Plan()); err == nil {
		t.Fatal("cancelled plan accepted")
	}
	if _, err := o.SealManualVNCConnection(cancelled, q, binding, nil, "", inner); err == nil {
		t.Fatal("cancelled seal accepted")
	}
	tunnel, err := o.PutTunnel(ctx, tunnelDraft(), []byte("native-route"), 0)
	if err != nil {
		t.Fatal(err)
	}
	meta := n.NodeMetadata
	meta.TunnelEnabled = nodePtr(true)
	meta.TunnelConfigID = &tunnel.ID
	n, err = o.PutNode(ctx, meta, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanVNCConnection(ctx, q.Plan()); err == nil {
		t.Fatal("routed manual plan fell back direct")
	}
	route, err := o.PlanConnectionTunnel(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "127.0.0.1:2345"
	inner, err = vault.SealManualVNCPassword(q.PublicKey, route.BundleBinding, &route, endpoint, []byte("route-password"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := o.SealManualVNCConnection(ctx, q, route.BundleBinding, &route, endpoint, inner)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := vault.OpenRoutedBundle(key.Bytes(), route, endpoint, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(outer)
	envelope, err := vault.DecodeVNCManualAuthorization(outer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenManualVNCPassword(key.Bytes(), route.BundleBinding, &route, endpoint, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	if p, _ := vault.DecodeVNCBundle(raw); !bytes.Equal(p.Password, []byte("route-password")) {
		t.Fatal("wrong routed password")
	}
	stale := route
	stale.RowVersion++
	if _, err := o.SealManualVNCConnection(ctx, q, route.BundleBinding, &stale, endpoint, inner); err == nil {
		t.Fatal("route substitution accepted")
	}
	if _, err := o.SealManualVNCConnection(ctx, q, route.BundleBinding, &route, "localhost:2345", inner); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	ssh := nodeDraft()
	other, err := o.PutNode(ctx, ssh, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrong := q
	wrong.NodeID = other.ID
	if _, err := o.PlanVNCConnection(ctx, wrong.Plan()); err == nil {
		t.Fatal("wrong protocol plan accepted")
	}
	if _, err := o.SealManualVNCConnection(ctx, wrong, binding, nil, "", inner); err == nil {
		t.Fatal("wrong protocol seal accepted")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanVNCConnection(ctx, q.Plan()); err == nil {
		t.Fatal("closed plan accepted")
	}
	if _, err := o.SealManualVNCConnection(ctx, q, binding, nil, "", inner); err == nil {
		t.Fatal("closed seal accepted")
	}
}
