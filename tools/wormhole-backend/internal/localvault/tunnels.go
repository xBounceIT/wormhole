package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func tunnelMAC(key []byte, identity vaultstore.Identity, tunnel vaultstore.Tunnel) ([]byte, error) {
	subkey, err := vault.DeriveKey(key, []byte(identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	tunnel.Seal = nil
	body, err := json.Marshal(struct {
		Identity vaultstore.Identity `json:"identity"`
		Tunnel   vaultstore.Tunnel   `json:"tunnel"`
	}{identity, tunnel})
	if err != nil {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-tunnel\x00"))
	mac.Write(body)
	return mac.Sum(nil), nil
}

func (o *Owner) verifyTunnel(t vaultstore.Tunnel) error {
	if t.Validate() != nil {
		return vault.ErrFormat
	}
	err := o.root.With(func(key []byte) error {
		mac, err := tunnelMAC(key, o.store.Identity(), t)
		if err != nil {
			return err
		}
		if !hmac.Equal(mac, t.Seal) {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return err
	}
	if t.RowVersion < o.tunnelFloors[t.ID] {
		return vault.ErrRollback
	}
	if o.tunnelFloors == nil {
		o.tunnelFloors = make(map[string]uint64)
	}
	o.tunnelFloors[t.ID] = t.RowVersion
	return nil
}

func (o *Owner) tunnelStore() (vaultstore.TunnelStore, error) {
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	s, ok := o.store.(vaultstore.TunnelStore)
	if !ok {
		return nil, vaultstore.ErrStorage
	}
	return s, nil
}

func (o *Owner) ReadTunnel(ctx context.Context, id string, minimum uint64) (vaultstore.Tunnel, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readTunnel(ctx, id, minimum)
}

// Caller holds the owner lock, including when resolving a secondary source.
func (o *Owner) readTunnel(ctx context.Context, id string, minimum uint64) (vaultstore.Tunnel, error) {
	s, err := o.tunnelStore()
	if err != nil {
		return vaultstore.Tunnel{}, err
	}
	t, err := s.ReadTunnel(ctx, id)
	if err != nil {
		return vaultstore.Tunnel{}, err
	}
	if t.ID != id {
		return vaultstore.Tunnel{}, vault.ErrAuthentication
	}
	if err := o.verifyTunnel(t); err != nil {
		return vaultstore.Tunnel{}, err
	}
	if t.RowVersion < minimum {
		return vaultstore.Tunnel{}, vault.ErrRollback
	}
	if t.Deleted {
		return vaultstore.Tunnel{}, vaultstore.ErrMissing
	}
	return t, nil
}

func (o *Owner) ListTunnels(ctx context.Context, after string, limit int) ([]vaultstore.Tunnel, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.tunnelStore()
	if err != nil {
		return nil, err
	}
	values, err := s.ListTunnels(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	for _, t := range values {
		if err := o.verifyTunnel(t); err != nil {
			return nil, err
		}
		if t.Deleted {
			return nil, vault.ErrAuthentication
		}
	}
	return values, nil
}

// A nil configuration preserves the existing value. A non-nil empty value is
// invalid; deletion is explicit. Native callers validate provider settings and
// authorize changes before calling this method, and own/wipe the input buffer.
func (o *Owner) PutTunnel(ctx context.Context, metadata vaultstore.TunnelMetadata, configuration []byte, expected uint64) (vaultstore.Tunnel, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeTunnel(ctx, metadata, configuration, expected, false, nil)
}

// ImportTunnel preserves source times only for a newly created aggregate.
// The native importer validates the provider configuration before this call.
func (o *Owner) ImportTunnel(ctx context.Context, metadata vaultstore.TunnelMetadata, configuration []byte, times ImportTimes) (vaultstore.Tunnel, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeTunnel(ctx, metadata, configuration, 0, false, &times)
}

func (o *Owner) DeleteTunnel(ctx context.Context, id string, expected uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.writeTunnel(ctx, vaultstore.TunnelMetadata{ID: id}, nil, expected, true, nil)
	return err
}

func (o *Owner) writeTunnel(ctx context.Context, metadata vaultstore.TunnelMetadata, configuration []byte, expected uint64, deleted bool, importedTimes *ImportTimes) (vaultstore.Tunnel, error) {
	s, err := o.tunnelStore()
	if err != nil {
		return vaultstore.Tunnel{}, err
	}
	if expected >= math.MaxInt64 || len(configuration) > vault.MaxSecretBytes || (configuration != nil && len(configuration) == 0) {
		return vaultstore.Tunnel{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vaultstore.Tunnel{}, err
	}
	old, err := s.ReadTunnel(ctx, metadata.ID)
	if errors.Is(err, vaultstore.ErrMissing) {
		if expected != 0 || deleted {
			return vaultstore.Tunnel{}, vaultstore.ErrConflict
		}
		if configuration == nil {
			return vaultstore.Tunnel{}, vault.ErrFormat
		}
	} else if err != nil {
		return vaultstore.Tunnel{}, err
	} else {
		if old.ID != metadata.ID {
			return vaultstore.Tunnel{}, vault.ErrAuthentication
		}
		if err := o.verifyTunnel(old); err != nil {
			return vaultstore.Tunnel{}, err
		}
		if old.RowVersion != expected || old.Deleted {
			return vaultstore.Tunnel{}, vaultstore.ErrConflict
		}
		if !deleted && metadata.Kind != old.Kind && configuration == nil {
			return vaultstore.Tunnel{}, vault.ErrFormat
		}
	}
	if deleted {
		metadata = old.TunnelMetadata
		configuration = []byte{}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	value := vaultstore.Tunnel{TunnelMetadata: metadata, CreatedAt: old.CreatedAt, UpdatedAt: now, RowVersion: expected + 1, ConfigurationVersion: old.ConfigurationVersion, Deleted: deleted, Seal: make([]byte, 32)}
	if expected == 0 {
		value.CreatedAt = now
		if importedTimes != nil {
			value.CreatedAt, value.UpdatedAt = importedTimes.CreatedAt, importedTimes.UpdatedAt
		}
	}
	if configuration != nil {
		value.ConfigurationVersion++
	}
	if value.Validate() != nil {
		return vaultstore.Tunnel{}, vault.ErrFormat
	}
	var secret *vaultstore.Secret
	if configuration != nil {
		prepared, err := o.prepareSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: metadata.ID, Field: "settings"}, configuration, old.ConfigurationVersion)
		if err != nil {
			return vaultstore.Tunnel{}, err
		}
		secret = &prepared
	}
	err = o.root.With(func(key []byte) error {
		var err error
		value.Seal, err = tunnelMAC(key, s.Identity(), value)
		return err
	})
	if err != nil {
		return vaultstore.Tunnel{}, err
	}
	if err := s.WriteTunnel(ctx, value, secret, expected); err != nil {
		return vaultstore.Tunnel{}, err
	}
	if o.tunnelFloors == nil {
		o.tunnelFloors = make(map[string]uint64)
	}
	o.tunnelFloors[value.ID] = value.RowVersion
	return value, nil
}

// The caller must first authorize the complete connection and its tunnel route.
// The configuration is never returned over a general-purpose metadata channel.
func (o *Owner) WithTunnelConfiguration(ctx context.Context, id string, minimum uint64, use func([]byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.tunnelStore(); err != nil {
		return err
	}
	if use == nil {
		return vault.ErrFormat
	}
	t, err := o.readTunnel(ctx, id, minimum)
	if err != nil {
		return err
	}
	return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: id, Field: "settings"}, t.ConfigurationVersion, true, use)
}
