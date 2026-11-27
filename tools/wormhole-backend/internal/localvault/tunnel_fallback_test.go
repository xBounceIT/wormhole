package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type fallbackFixture struct {
	o                 *Owner
	q                 TunnelPlanRequest
	primary, fallback vaultstore.Tunnel
	binding           vault.TunnelFallbackBinding
	public, private   []byte
	selectFallback    TunnelFallbackSelector
}

func localFallbackFixture(t *testing.T) fallbackFixture {
	t.Helper()
	o, _, primary, q, private := routeBundleFixture(t)
	ctx := context.Background()
	target, err := o.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "SSL fallback", Kind: 2}, []byte("ssl-configuration"), 0)
	if err != nil {
		t.Fatal(err)
	}
	metadata := primary.TunnelMetadata
	metadata.Kind = 9
	settings, _ := json.Marshal(map[string]any{"Host": "vpn.test", "PreSharedKey": "synthetic-key", "UserAuth": 0, "FallbackTunnelId": target.ID})
	primary, err = o.PutTunnel(ctx, metadata, settings, primary.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	selectFallback := func(raw []byte) (string, error) {
		if o.mu.TryLock() {
			o.mu.Unlock()
			t.Error("source selection escaped owner lock")
		}
		var settings struct {
			FallbackTunnelID string `json:"FallbackTunnelId"`
		}
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", err
		}
		return settings.FallbackTunnelID, nil
	}
	original, err := o.PlanConnectionTunnel(ctx, q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := o.PlanConnectionFallback(ctx, q.Plan(), original, uuid.NewString(), selectFallback)
	if err != nil {
		t.Fatal(err)
	}
	return fallbackFixture{o: o, q: q.Plan(), primary: primary, fallback: target, binding: binding, public: q.PublicKey, private: private, selectFallback: selectFallback}
}

func TestConnectionFallbackResolvesEncryptedReferenceAndSealsOnlyTarget(t *testing.T) {
	f := localFallbackFixture(t)
	ctx := context.Background()
	base := f.o.store.(integrityStore)
	var reads []string
	var borrowed []byte
	f.o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
		reads = append(reads, s.Ref.OwnerID)
		if f.o.mu.TryLock() {
			f.o.mu.Unlock()
			t.Error("secret read escaped owner lock")
		}
		if s.Ref.OwnerID == f.fallback.ID && !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Error("primary settings retained across target opening")
		}
		return s, nil
	}}
	selectFallback := func(raw []byte) (string, error) {
		borrowed = raw
		return f.selectFallback(raw)
	}
	planned, err := f.o.PlanConnectionFallback(ctx, f.q, f.binding.Primary, f.binding.Fallback.RequestID, selectFallback)
	if err != nil || planned != f.binding || len(reads) != 1 || reads[0] != f.primary.ID || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("planning did not confine primary borrow", reads, err)
	}
	reads = nil
	packet, err := f.o.SealConnectionFallback(ctx, f.q, planned, f.public, selectFallback)
	if err != nil || packet.Binding != planned || len(reads) != 2 || reads[0] != f.primary.ID || reads[1] != f.fallback.ID {
		t.Fatal("fallback source release", reads, err)
	}
	plain, err := vault.OpenTunnelFallback(f.private, packet.Binding, packet.Bundle)
	if err != nil || string(plain) != "ssl-configuration" {
		t.Fatal("wrong secondary configuration", err)
	}
	vault.Wipe(plain)
	if _, err := vault.OpenTunnelBundle(f.private, packet.Binding.Fallback, packet.Bundle); err == nil {
		t.Fatal("fallback lost its independent purpose")
	}
	f.o.store = base
}

func TestConnectionFallbackRejectsChangedContextBeforeTargetOpening(t *testing.T) {
	for _, mode := range []string{"primary-host", "primary-revision", "target-id", "target-revision", "target-configuration", "target-kind", "foreign-file", "same-attempt", "node", "bad-attempt"} {
		t.Run(mode, func(t *testing.T) {
			f := localFallbackFixture(t)
			b, q := f.binding, f.q
			switch mode {
			case "primary-host":
				b.Primary.Host = "changed.example"
			case "primary-revision":
				b.Primary.RowVersion++
			case "target-id":
				b.Fallback.TunnelConfigID = uuid.NewString()
			case "target-revision":
				b.Fallback.RowVersion++
			case "target-configuration":
				b.Fallback.ConfigurationVersion++
			case "target-kind":
				b.Fallback.Kind = 9
			case "foreign-file":
				b.Fallback.FileID = uuid.NewString()
			case "same-attempt":
				b.Fallback.RequestID = q.RequestID
			case "node":
				q.NodeID = uuid.NewString()
			case "bad-attempt":
				b.Fallback.RequestID = "bad"
			}
			base := f.o.store.(integrityStore)
			targetReads := 0
			f.o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
				if s.Ref.OwnerID == f.fallback.ID {
					targetReads++
				}
				return s, nil
			}}
			got, err := f.o.SealConnectionFallback(context.Background(), q, b, f.public, f.selectFallback)
			f.o.store = base
			if err == nil || got.Bundle.Ciphertext != nil || targetReads != 0 || got.Binding.Primary.NodeID != "" {
				t.Fatal("substituted context released target", targetReads, err)
			}
		})
	}
}

func TestConnectionFallbackRejectsMissingInvalidAndForeignReferences(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "nil-id", "noncanonical", "self", "absent", "wrong-kind", "deleted", "selector-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := localFallbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selectFallback := func(raw []byte) (string, error) {
				switch mode {
				case "missing":
					return "", nil
				case "malformed":
					return "bad", nil
				case "nil-id":
					return uuid.Nil.String(), nil
				case "noncanonical":
					return "{" + f.fallback.ID + "}", nil
				case "self":
					return f.primary.ID, nil
				case "absent":
					return uuid.NewString(), nil
				case "selector-error":
					return "", vault.ErrPolicy
				case "cancel":
					cancel()
				}
				return f.selectFallback(raw)
			}
			if mode == "wrong-kind" {
				metadata := f.fallback.TunnelMetadata
				metadata.Kind = 9
				if _, err := f.o.PutTunnel(ctx, metadata, []byte("wrong-provider-configuration"), f.fallback.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "deleted" {
				if err := f.o.DeleteTunnel(ctx, f.fallback.ID, f.fallback.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := f.o.PlanConnectionFallback(ctx, f.q, f.binding.Primary, f.binding.Fallback.RequestID, selectFallback); err == nil || got.Primary.NodeID != "" {
				t.Fatal("invalid configured fallback admitted", err)
			}
		})
	}
}

func TestConnectionFallbackRefusesEditsReplayAndUnauthenticatedSecrets(t *testing.T) {
	for _, mode := range []string{"primary-edit", "target-edit", "primary-secret", "target-secret", "target-missing", "cancel-target"} {
		t.Run(mode, func(t *testing.T) {
			f := localFallbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "primary-edit" || mode == "target-edit" {
				target := f.primary
				if mode == "target-edit" {
					target = f.fallback
				}
				if _, err := f.o.PutTunnel(ctx, target.TunnelMetadata, []byte("changed"), target.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			base := f.o.store.(integrityStore)
			f.o.store = integrityProbe{integrityStore: base, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) {
				if mode == "primary-secret" && s.Ref.OwnerID == f.primary.ID || mode == "target-secret" && s.Ref.OwnerID == f.fallback.ID {
					s.Envelope.Ciphertext = bytes.Clone(s.Envelope.Ciphertext)
					s.Envelope.Ciphertext[0] ^= 1
				}
				if s.Ref.OwnerID == f.fallback.ID {
					if mode == "target-missing" {
						return s, vaultstore.ErrMissing
					}
					if mode == "cancel-target" {
						cancel()
					}
				}
				return s, nil
			}}
			got, err := f.o.SealConnectionFallback(ctx, f.q, f.binding, f.public, f.selectFallback)
			f.o.store = base
			if err == nil || got.Bundle.Ciphertext != nil || got.Binding.Primary.NodeID != "" {
				t.Fatal("stale or unauthenticated fallback released", err)
			}
		})
	}
	f := localFallbackFixture(t)
	ctx := context.Background()
	if _, err := f.o.PlanConnectionFallback(nil, f.q, f.binding.Primary, f.binding.Fallback.RequestID, f.selectFallback); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := f.o.PlanConnectionFallback(ctx, f.q, f.binding.Primary, f.binding.Fallback.RequestID, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := f.o.SealConnectionFallback(ctx, f.q, f.binding, nil, f.selectFallback); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := f.o.SealConnectionFallback(ctx, f.q, f.binding, make([]byte, 32), f.selectFallback); err == nil {
		t.Fatal("invalid recipient accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.o.PlanConnectionFallback(canceled, f.q, f.binding.Primary, f.binding.Fallback.RequestID, f.selectFallback); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := f.o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.o.SealConnectionFallback(ctx, f.q, f.binding, f.public, f.selectFallback); !errors.Is(err, vaultstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestConnectionFallbackPersistsAuthenticatedTargetFloorsAndRejectsReplay(t *testing.T) {
	f := localFallbackFixture(t)
	ctx := context.Background()
	metadata := f.fallback.TunnelMetadata
	metadata.Name = "Renamed SSL"
	newer, err := f.o.PutTunnel(ctx, metadata, nil, f.fallback.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	base := f.o.store.(integrityStore)
	for _, mode := range []string{"replay", "corrupt", "substituted", "cancel-after-metadata"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			targetReads := 0
			f.o.store = nodeFilter{completeNodeStore: base, tunnel: func(value vaultstore.Tunnel) (vaultstore.Tunnel, error) {
				if value.ID != f.fallback.ID {
					return value, nil
				}
				switch mode {
				case "replay":
					return f.fallback, nil
				case "corrupt":
					value.Seal = bytes.Clone(value.Seal)
					value.Seal[0] ^= 1
				case "substituted":
					value.ID = uuid.NewString()
				case "cancel-after-metadata":
					cancel()
				}
				return value, nil
			}, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
				if value.Ref.OwnerID == f.fallback.ID {
					targetReads++
				}
				return value, nil
			}}
			got, err := f.o.SealConnectionFallback(ctx, f.q, f.binding, f.public, f.selectFallback)
			f.o.store = base
			if err == nil || got.Bundle.Ciphertext != nil || targetReads != 0 || f.o.tunnelFloors[f.fallback.ID] != newer.RowVersion {
				t.Fatal("target metadata rejection lost floor or opened settings", err)
			}
			if mode == "replay" && !errors.Is(err, vault.ErrRollback) {
				t.Fatal("old target replay not recognized", err)
			}
			if mode == "cancel-after-metadata" && !errors.Is(err, context.Canceled) {
				t.Fatal("metadata cancellation lost", err)
			}
		})
	}
}

func TestConnectionFallbackRejectsNonIPsecAndUnroutableSources(t *testing.T) {
	for _, mode := range []string{"provider", "disabled", "host"} {
		t.Run(mode, func(t *testing.T) {
			f := localFallbackFixture(t)
			ctx := context.Background()
			original := f.binding.Primary
			if mode == "provider" {
				metadata := f.primary.TunnelMetadata
				metadata.Kind = 2
				if _, err := f.o.PutTunnel(ctx, metadata, []byte("ssl-primary"), f.primary.RowVersion); err != nil {
					t.Fatal(err)
				}
				var err error
				original, err = f.o.PlanConnectionTunnel(ctx, f.q)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				node, err := f.o.ReadNode(ctx, f.q.NodeID, 0)
				if err != nil {
					t.Fatal(err)
				}
				metadata := node.NodeMetadata
				if mode == "disabled" {
					metadata.TunnelEnabled = nodePtr(false)
				} else {
					metadata.Host = nodePtr("bad host")
				}
				if _, err := f.o.PutNode(ctx, metadata, nil, node.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			_, err := f.o.PlanConnectionFallback(ctx, f.q, original, f.binding.Fallback.RequestID, func([]byte) (string, error) { called = true; return f.fallback.ID, nil })
			if err == nil || called {
				t.Fatal("non-IPsec source reached secret selection", err)
			}
		})
	}
}
