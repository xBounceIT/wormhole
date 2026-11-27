package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func tunnelDraft() vaultstore.TunnelMetadata {
	id := uuid.NewString()
	return vaultstore.TunnelMetadata{ID: id, Name: "VPN " + id, Kind: 1}
}

func TestTunnelOwnerConfigurationLifecycle(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	metadata := tunnelDraft()
	plain := []byte(`{"ProfileOvpn":"unique-private-config-not-for-metadata"}`)
	v, err := o.PutTunnel(ctx, metadata, plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.RowVersion != 1 || v.ConfigurationVersion != 1 || v.CreatedAt == "" || v.CreatedAt != v.UpdatedAt {
		t.Fatal("invalid initial state")
	}
	got, err := o.ReadTunnel(ctx, v.ID, 1)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal(err)
	}
	if page, err := o.ListTunnels(ctx, "", 1); err != nil || len(page) != 1 || !reflect.DeepEqual(page[0], v) {
		t.Fatal(err)
	}
	var borrowed []byte
	if err := o.WithTunnelConfiguration(ctx, v.ID, 1, func(value []byte) error {
		borrowed = value
		if !bytes.Equal(value, plain) {
			t.Fatal("configuration mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed configuration not wiped")
	}
	sentinel := errors.New("consumer failed")
	if err := o.WithTunnelConfiguration(ctx, v.ID, 1, func(value []byte) error { borrowed = value; return sentinel }); err != sentinel {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("error callback leaked configuration")
	}
	metadata.Name = "renamed"
	renamed, err := o.PutTunnel(ctx, metadata, nil, 1)
	if err != nil || renamed.ConfigurationVersion != 1 || renamed.CreatedAt != v.CreatedAt {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: v.ID, Field: "settings"}, []byte("bypass"), 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	updated, err := o.PutTunnel(ctx, metadata, []byte("replacement-private-config"), 2)
	if err != nil || updated.ConfigurationVersion != 2 {
		t.Fatal(err)
	}
	if _, err := o.ReadTunnel(ctx, v.ID, 4); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithTunnelConfiguration(ctx, v.ID, 4, func([]byte) error { t.Fatal("rollback release"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(path)
	if err != nil || bytes.Contains(file, plain) || bytes.Contains(file, []byte("replacement-private-config")) {
		t.Fatal("plaintext on disk", err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.WithTunnelConfiguration(ctx, v.ID, 3, func(value []byte) error {
		if string(value) != "replacement-private-config" {
			t.Fatal("lost across reopen")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteTunnel(ctx, v.ID, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ReadTunnel(ctx, v.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := reopened.WithTunnelConfiguration(ctx, v.ID, 0, func([]byte) error { t.Fatal("deleted release"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if values, err := reopened.ListTunnels(ctx, "", 1); err != nil || len(values) != 0 {
		t.Fatal(err)
	}
	if _, err := reopened.PutTunnel(ctx, metadata, plain, 0); err != vaultstore.ErrConflict {
		t.Fatal("reused deleted ID", err)
	}
}

type tunnelFilter struct {
	vaultstore.TunnelStore
	read     func(vaultstore.Tunnel) (vaultstore.Tunnel, error)
	list     func([]vaultstore.Tunnel) ([]vaultstore.Tunnel, error)
	secret   func(vaultstore.Secret) (vaultstore.Secret, error)
	writeErr error
}

func (s tunnelFilter) ReadTunnel(ctx context.Context, id string) (vaultstore.Tunnel, error) {
	v, err := s.TunnelStore.ReadTunnel(ctx, id)
	if err == nil && s.read != nil {
		return s.read(v)
	}
	return v, err
}
func (s tunnelFilter) ListTunnels(ctx context.Context, after string, limit int) ([]vaultstore.Tunnel, error) {
	vs, err := s.TunnelStore.ListTunnels(ctx, after, limit)
	if err == nil && s.list != nil {
		return s.list(vs)
	}
	return vs, err
}
func (s tunnelFilter) WriteTunnel(ctx context.Context, v vaultstore.Tunnel, secret *vaultstore.Secret, expected uint64) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.TunnelStore.WriteTunnel(ctx, v, secret, expected)
}
func (s tunnelFilter) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	v, err := s.TunnelStore.ReadSecret(ctx, ref)
	if err == nil && s.secret != nil {
		return s.secret(v)
	}
	return v, err
}

func TestTunnelOwnerRejectsTamperingAndSubstitution(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := tunnelDraft()
	original, err := o.PutTunnel(ctx, metadata, []byte("secret"), 0)
	if err != nil {
		t.Fatal(err)
	}
	store := o.store.(vaultstore.TunnelStore)
	defer func() { o.store = store }()
	for _, mutate := range []func(*vaultstore.Tunnel){func(v *vaultstore.Tunnel) { v.Name = "redirect" }, func(v *vaultstore.Tunnel) { v.Kind = 2 }, func(v *vaultstore.Tunnel) { v.ID = uuid.NewString() }, func(v *vaultstore.Tunnel) { v.Seal = nil }, func(v *vaultstore.Tunnel) { v.ConfigurationVersion = 0 }, func(v *vaultstore.Tunnel) { v.Deleted = true }, func(v *vaultstore.Tunnel) { v.UpdatedAt = "2026-01-01T00:00:00Z" }} {
		o.store = tunnelFilter{TunnelStore: store, read: func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { mutate(&v); return v, nil }, list: func(vs []vaultstore.Tunnel) ([]vaultstore.Tunnel, error) { mutate(&vs[0]); return vs, nil }}
		if _, err := o.ReadTunnel(ctx, metadata.ID, 0); err == nil {
			t.Fatal("read unverified row")
		}
		if _, err := o.ListTunnels(ctx, "", 1); err == nil {
			t.Fatal("listed unverified row")
		}
		if _, err := o.PutTunnel(ctx, metadata, nil, 1); err == nil {
			t.Fatal("signed unverified row")
		}
		if err := o.WithTunnelConfiguration(ctx, metadata.ID, 0, func([]byte) error { t.Fatal("released unverified row"); return nil }); err == nil {
			t.Fatal("accepted metadata")
		}
	}
	o.store = store
	current, err := o.PutTunnel(ctx, metadata, []byte("updated"), 1)
	if err != nil {
		t.Fatal(err)
	}
	o.store = tunnelFilter{TunnelStore: store, read: func(vaultstore.Tunnel) (vaultstore.Tunnel, error) { return original, nil }}
	if err := o.WithTunnelConfiguration(ctx, metadata.ID, 0, func([]byte) error { t.Fatal("mixed field/metadata revisions"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	o.store = store
	other := tunnelDraft()
	otherTunnel, err := o.PutTunnel(ctx, other, []byte("other"), 0)
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: other.ID, Field: "settings"})
	if err != nil {
		t.Fatal(err)
	}
	o.store = tunnelFilter{TunnelStore: store, read: func(vaultstore.Tunnel) (vaultstore.Tunnel, error) { return otherTunnel, nil }}
	if _, err := o.ReadTunnel(ctx, metadata.ID, 0); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = tunnelFilter{TunnelStore: store, secret: func(vaultstore.Secret) (vaultstore.Secret, error) { return otherSecret, nil }}
	if err := o.WithTunnelConfiguration(ctx, metadata.ID, current.RowVersion, func([]byte) error { t.Fatal("other tunnel released"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, []byte("new"), 2); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = store
	if err := o.DeleteTunnel(ctx, other.ID, 1); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ReadTunnel(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	o.store = tunnelFilter{TunnelStore: store, list: func([]vaultstore.Tunnel) ([]vaultstore.Tunnel, error) { return []vaultstore.Tunnel{deleted}, nil }}
	if _, err := o.ListTunnels(ctx, "", 1); err != vault.ErrAuthentication {
		t.Fatal("listed signed tombstone", err)
	}
}

func TestTunnelOwnerValidationAndFailures(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := tunnelDraft()
	if _, err := o.PutTunnel(ctx, metadata, nil, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, []byte{}, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, make([]byte, vault.MaxSecretBytes+1), 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, []byte("new"), math.MaxInt64); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.DeleteTunnel(ctx, metadata.ID, 0); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, []byte("new"), 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.ReadTunnel(ctx, metadata.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithTunnelConfiguration(ctx, metadata.ID, 0, func([]byte) error { return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithTunnelConfiguration(ctx, metadata.ID, 0, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PutTunnel(cancelled, metadata, []byte("new"), 0); err != context.Canceled {
		t.Fatal(err)
	}
	bad := metadata
	bad.Kind = 10
	if _, err := o.PutTunnel(ctx, bad, []byte("new"), 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, []byte("initial"), 0); err != nil {
		t.Fatal(err)
	}
	bad = metadata
	bad.Kind = 2
	if _, err := o.PutTunnel(ctx, bad, nil, 1); err != vault.ErrFormat {
		t.Fatal("provider switched without configuration", err)
	}
	store := o.store.(vaultstore.TunnelStore)
	o.store = tunnelFilter{TunnelStore: store, writeErr: vaultstore.ErrStorage}
	if _, err := o.PutTunnel(ctx, metadata, []byte("failed update"), 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = tunnelFilter{TunnelStore: store, read: func(vaultstore.Tunnel) (vaultstore.Tunnel, error) { return vaultstore.Tunnel{}, vaultstore.ErrStorage }, list: func([]vaultstore.Tunnel) ([]vaultstore.Tunnel, error) { return nil, vaultstore.ErrStorage }}
	if _, err := o.PutTunnel(ctx, metadata, nil, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.ListTunnels(ctx, "", 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = struct{ vaultstore.Store }{store}
	if _, err := o.ReadTunnel(ctx, metadata.ID, 0); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.ListTunnels(ctx, "", 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, metadata, nil, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if err := o.WithTunnelConfiguration(ctx, metadata.ID, 0, func([]byte) error { return nil }); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = store
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := o.PutTunnel(ctx, metadata, []byte("winner"), 1); results <- err }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal(winners)
	}
	o.Close()
	if _, err := o.ReadTunnel(ctx, metadata.ID, 0); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := tunnelMAC(nil, store.Identity(), vaultstore.Tunnel{}); err == nil {
		t.Fatal("invalid MAC key")
	}
}
