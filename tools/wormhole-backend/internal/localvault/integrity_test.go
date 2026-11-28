package localvault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type integrityStore interface {
	catalogStore
	vaultstore.ProfileStore
	vaultstore.LocalStateStore
}
type integrityProbe struct {
	integrityStore
	secret func(vaultstore.Secret) (vaultstore.Secret, error)
	states func(context.Context, string, int) ([]vaultstore.LocalState, error)
}

func (s integrityProbe) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	v, err := s.integrityStore.ReadSecret(ctx, ref)
	if err == nil && s.secret != nil {
		return s.secret(v)
	}
	return v, err
}
func (s integrityProbe) ListLocalStates(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
	if s.states != nil {
		return s.states(ctx, after, limit)
	}
	return s.integrityStore.ListLocalStates(ctx, after, limit)
}

func integrityFixture(t *testing.T) (*Owner, string, OpenOptions, []byte) {
	t.Helper()
	o, path, opts, key := owner(t)
	ctx := context.Background()
	if _, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("credential")}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, nodeDraft(), []SecretChange{{Field: "notes", Value: []byte("note")}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 1}, []byte("configuration"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, bytes.Repeat([]byte{9}, vault.MaxSecretBytes+1), 0); err != nil {
		t.Fatal(err)
	}
	return o, path, opts, key
}

func TestIntegrityReopensAndAuthenticatesEveryPersistedDomain(t *testing.T) {
	o, path, opts, key := integrityFixture(t)
	ctx := context.Background()
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	opened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	base := opened.store.(integrityStore)
	fields := map[string]int{}
	opened.store = integrityProbe{integrityStore: base, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
		if opened.mu.TryLock() {
			opened.mu.Unlock()
			t.Fatal("integrity check released owner mutex")
		}
		fields[value.Ref.OwnerKind]++
		return value, nil
	}}
	got, err := opened.VerifyIntegrity(ctx)
	if err != nil || got != (IntegrityInventory{Credentials: 1, Tunnels: 1, Nodes: 1, LocalStates: 1}) {
		t.Fatal(got, err)
	}
	for kind, want := range map[string]int{"credential": 1, "tunnel": 1, "node": 1, "local-state": 2} {
		if fields[kind] != want {
			t.Fatal("missing persisted secret", kind, fields)
		}
	}
	opened.store = base
	// Shrinking state retains an authenticated, empty retired chunk.
	if _, err := opened.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.VerifyIntegrity(ctx); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.VerifyIntegrity(ctx); !errors.Is(err, vaultstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestIntegrityRejectsMissingCorruptAndSubstitutedSecretFields(t *testing.T) {
	o, _, opts, key := integrityFixture(t)
	base := o.store.(integrityStore)
	defer func() { o.store = base }()
	for _, kind := range []string{"credential", "node", "tunnel", "local-state"} {
		for _, missing := range []bool{false, true} {
			o.store = integrityProbe{integrityStore: base, secret: func(v vaultstore.Secret) (vaultstore.Secret, error) {
				if v.Ref.OwnerKind == kind {
					if missing {
						return vaultstore.Secret{}, vaultstore.ErrMissing
					}
					v.Envelope.Ciphertext[0] ^= 1
				}
				return v, nil
			}}
			if got, err := o.VerifyIntegrity(context.Background()); err == nil || got != (IntegrityInventory{}) {
				t.Fatal("partial inventory accepted", kind, got, err)
			}
		}
	}
	o.store = base
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.VerifyIntegrity(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// A valid seal cannot excuse a manifest size inconsistent with its chunks.
	o.store = integrityProbe{integrityStore: base, states: func(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
		values, err := base.ListLocalStates(ctx, after, limit)
		if len(values) != 0 {
			values[0].Size++
			values[0].Seal, err = localStateMAC(key, opts.Identity, values[0])
		}
		return values, err
	}}
	if _, err := o.VerifyIntegrity(context.Background()); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal(err)
	}
}

func TestIntegrityLocalInventoryRejectsMalformedPages(t *testing.T) {
	o, _, _, _ := owner(t)
	base := o.store.(integrityStore)
	defer func() { o.store = base }()
	ctx := context.Background()
	for i := 0; i < 129; i++ {
		if _, err := o.PutLocalState(ctx, "azure-refresh", uuid.NewString(), nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := o.VerifyIntegrity(ctx); err != nil || got.LocalStates != 129 {
		t.Fatal(got, err)
	}
	for _, mode := range []string{"error", "oversized", "duplicate", "deleted", "scope", "seal", "cancel"} {
		ctx, cancel := context.WithCancel(context.Background())
		o.store = integrityProbe{integrityStore: base, states: func(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
			values, err := base.ListLocalStates(ctx, after, limit)
			if err != nil {
				return nil, err
			}
			switch mode {
			case "error":
				return nil, vaultstore.ErrStorage
			case "oversized":
				return append(values, values[0]), nil
			case "duplicate":
				values[1] = values[0]
			case "deleted":
				values[0].Deleted = true
			case "scope":
				values[0].ScopeID = "bad"
			case "seal":
				values[0].Seal[0] ^= 1
			case "cancel":
				cancel()
			}
			return values, nil
		}}
		if got, err := o.VerifyIntegrity(ctx); err == nil || got != (IntegrityInventory{}) {
			t.Fatal(mode, got, err)
		}
		cancel()
	}
}
