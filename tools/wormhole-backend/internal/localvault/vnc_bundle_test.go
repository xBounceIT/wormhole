package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVNCConnectionSealedCredentialAndRoute(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	c := draft()
	c.Protocol = "vnc"
	credential, err := o.PutCredential(ctx, c, []SecretChange{{Field: "password", Value: []byte("native-vnc-password")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.Protocol = nodePtr(6)
	m.Port = nodePtr(5900)
	m.CredentialID = &credential.ID
	m.TunnelEnabled = nodePtr(false)
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}
	read := func(want string, present bool) VNCConnectionBundle {
		t.Helper()
		result, err := o.SealVNCConnection(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if result.Binding.Protocol != "vnc" || result.Binding.NodeID != n.ID || result.Binding.Port != 5900 {
			t.Fatal("wrong target binding")
		}
		raw, err := vault.OpenBundle(key.Bytes(), result.Binding, result.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(raw)
		p, err := vault.DecodeVNCBundle(raw)
		if err != nil || p.PasswordProvided != present || string(p.Password) != want {
			t.Fatal("wrong credential", err)
		}
		return result
	}
	original := read("native-vnc-password", true)
	wrong := original.Binding
	wrong.Host = "different.example"
	if _, err := vault.OpenBundle(key.Bytes(), wrong, original.Bundle); err == nil {
		t.Fatal("destination substitution accepted")
	}
	wrong = original.Binding
	wrong.Protocol = "ssh"
	if _, err := vault.OpenBundle(key.Bytes(), wrong, original.Bundle); err == nil {
		t.Fatal("protocol substitution accepted")
	}
	for _, value := range [][]byte{{}, nil} {
		changes := []SecretChange{{Field: "password", Value: value, Remove: value == nil}}
		credential, err = o.PutCredential(ctx, credential.CredentialMetadata, changes, credential.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		read("", value != nil)
	}
	credential, err = o.PutCredential(ctx, credential.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte("route-password")}}, credential.RowVersion)
	if err != nil {
		t.Fatal(err)
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
	if _, err := o.SealVNCConnection(ctx, q); err == nil {
		t.Fatal("routed node fell back to direct")
	}
	route, err := o.PlanConnectionTunnel(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	routed, err := o.SealRoutedVNCConnection(ctx, q, route, "127.0.0.1:2345")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenRoutedBundle(key.Bytes(), route, routed.Endpoint, routed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	p, err := vault.DecodeVNCBundle(raw)
	if err != nil || !bytes.Equal(p.Password, []byte("route-password")) {
		t.Fatal(err)
	}
	if _, err := vault.OpenRoutedBundle(key.Bytes(), route, "127.0.0.1:2346", routed.Bundle); err == nil {
		t.Fatal("endpoint substitution accepted")
	}
	stale := route
	stale.ConfigurationVersion++
	if _, err := o.SealRoutedVNCConnection(ctx, q, stale, "127.0.0.1:2345"); err == nil {
		t.Fatal("stale configuration accepted")
	}
	if _, err := o.SealRoutedVNCConnection(ctx, q, route, "invalid"); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
	bad := q
	bad.PublicKey = nil
	if _, err := o.SealVNCConnection(ctx, bad); err == nil {
		t.Fatal("invalid recipient accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.SealVNCConnection(cancelled, q); err != context.Canceled {
		t.Fatal(err)
	}
	anonymous := nodeDraft()
	anonymous.Protocol = nodePtr(6)
	anonymous.Port = nodePtr(5900)
	anon, err := o.PutNode(ctx, anonymous, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	anonRequest := q
	anonRequest.NodeID = anon.ID
	anonBundle, err := o.SealVNCConnection(ctx, anonRequest)
	if err != nil {
		t.Fatal(err)
	}
	anonRaw, err := vault.OpenBundle(key.Bytes(), anonBundle.Binding, anonBundle.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(anonRaw)
	if p, err := vault.DecodeVNCBundle(anonRaw); err != nil || p.PasswordProvided || len(p.Password) != 0 {
		t.Fatal("anonymous state changed", err)
	}

	foreign, err := o.PutNode(ctx, nodeDraft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q.NodeID = foreign.ID
	if _, err := o.SealVNCConnection(ctx, q); err == nil {
		t.Fatal("foreign protocol admitted")
	}
}

func TestVNCBundleConcurrentTargetEdit(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	credentials := []string{}
	for _, password := range []string{"secret-a", "secret-b"} {
		c := draft()
		c.Protocol = "vnc"
		created, err := o.PutCredential(ctx, c, []SecretChange{{Field: "password", Value: []byte(password)}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, created.ID)
	}
	m := nodeDraft()
	m.Protocol = nodePtr(6)
	m.Port = nodePtr(5900)
	m.Host = nodePtr("a.example")
	m.CredentialID = &credentials[0]
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelBundleRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1, PublicKey: key.PublicKey().Bytes()}
	var work sync.WaitGroup
	work.Add(1)
	go func() {
		defer work.Done()
		current := n
		for i := 0; i < 30; i++ {
			index := i % 2
			meta := current.NodeMetadata
			meta.Host = nodePtr([]string{"a.example", "b.example"}[index])
			meta.CredentialID = &credentials[index]
			next, err := o.PutNode(ctx, meta, nil, current.RowVersion)
			if err != nil {
				t.Error(err)
				return
			}
			current = next
		}
	}()
	defer work.Wait()
	for i := 0; i < 30; i++ {
		result, err := o.SealVNCConnection(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.OpenBundle(key.Bytes(), result.Binding, result.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		p, err := vault.DecodeVNCBundle(raw)
		want := "secret-a"
		if result.Binding.Host == "b.example" {
			want = "secret-b"
		}
		valid := err == nil && p.PasswordProvided && bytes.Equal(p.Password, []byte(want))
		vault.Wipe(raw)
		if !valid {
			t.Fatal("concurrent edit mixed destination and credential")
		}
	}
}
