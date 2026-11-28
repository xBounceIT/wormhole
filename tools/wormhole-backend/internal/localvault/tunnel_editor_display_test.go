package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestTunnelEditorDisplayOwnsSnapshotAndBuffers(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := tunnelDraft()
	saved, err := o.PutTunnel(ctx, metadata, []byte("native configuration"), 0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request := uuid.NewString()
	var borrowed, projected []byte
	sentinel := errors.New("projection failed")
	for _, fail := range []bool{false, true} {
		result, err := o.SealTunnelEditor(ctx, saved.ID, request, 1, key.PublicKey().Bytes(), func(current vaultstore.Tunnel, configuration []byte) ([]byte, error) {
			if o.mu.TryLock() {
				o.mu.Unlock()
				t.Fatal("projection did not retain ownership")
			}
			if current.RowVersion != 1 || current.Name != metadata.Name || !bytes.Equal(configuration, []byte("native configuration")) {
				t.Fatal("mixed snapshot")
			}
			borrowed = configuration
			projected = []byte("redacted projection")
			if fail {
				return projected, sentinel
			}
			return projected, nil
		})
		if fail {
			if err != sentinel {
				t.Fatal(err)
			}
		} else if err != nil || result.TunnelID != saved.ID || result.RequestID != request || result.RowVersion != "1" || len(result.Bundle.Ciphertext) != len(projected)+16 {
			t.Fatal("display result", err)
		}
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || !bytes.Equal(projected, make([]byte, len(projected))) {
			t.Fatal("display retained buffers")
		}
	}
	project := func(vaultstore.Tunnel, []byte) ([]byte, error) {
		projected = []byte("projection")
		return projected, nil
	}
	if _, err = o.SealTunnelEditor(ctx, saved.ID, request, 1, nil, project); err == nil {
		t.Fatal("invalid key")
	}
	if !bytes.Equal(projected, make([]byte, len(projected))) {
		t.Fatal("failed seal retained plaintext")
	}
	if _, err = o.SealTunnelEditor(ctx, saved.ID, request, 1, key.PublicKey().Bytes(), nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	for _, version := range []uint64{0, 2} {
		if _, err = o.SealTunnelEditor(ctx, saved.ID, request, version, key.PublicKey().Bytes(), project); err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	if _, err = o.SealTunnelEditor(ctx, uuid.NewString(), request, 1, key.PublicKey().Bytes(), project); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err = o.DeleteTunnel(ctx, saved.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealTunnelEditor(ctx, saved.ID, request, 2, key.PublicKey().Bytes(), project); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealTunnelEditor(ctx, saved.ID, request, 2, key.PublicKey().Bytes(), project); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestTunnelEditorDisplayRejectsUnverifiedData(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := tunnelDraft()
	saved, err := o.PutTunnel(ctx, metadata, []byte("private config"), 0)
	if err != nil {
		t.Fatal(err)
	}
	store := o.store.(vaultstore.TunnelStore)
	defer func() { o.store = store }()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	project := func(vaultstore.Tunnel, []byte) ([]byte, error) {
		t.Fatal("unverified configuration released")
		return nil, nil
	}
	for _, mutate := range []func(*vaultstore.Tunnel){func(v *vaultstore.Tunnel) { v.ID = uuid.NewString() }, func(v *vaultstore.Tunnel) { v.Name = "tampered" }, func(v *vaultstore.Tunnel) { v.Seal = nil }} {
		o.store = tunnelFilter{TunnelStore: store, read: func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { mutate(&v); return v, nil }}
		if _, err = o.SealTunnelEditor(ctx, saved.ID, uuid.NewString(), 1, key.PublicKey().Bytes(), project); err == nil {
			t.Fatal("metadata tampering accepted")
		}
	}
	o.store = tunnelFilter{TunnelStore: store, secret: func(v vaultstore.Secret) (vaultstore.Secret, error) { v.Envelope.Ciphertext[0] ^= 1; return v, nil }}
	if _, err = o.SealTunnelEditor(ctx, saved.ID, uuid.NewString(), 1, key.PublicKey().Bytes(), project); err == nil {
		t.Fatal("ciphertext tampering accepted")
	}
}
