package main

import (
	"context"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type sharedFallbackReleaseSession interface {
	BeginFallbackUse(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*sharedpg.FallbackUseIntent, error)
	FetchFallbackSecret(context.Context, sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error)
}

func (c *sharedAdmissionController) withFallbackRelease(ctx context.Context, node, primary, target uuid.UUID, source string, use func(context.Context, sharedpg.TrustState, *sharedpg.VerifiedFallbackRelease) error) error {
	if ctx == nil || node == uuid.Nil || primary == uuid.Nil || target == uuid.Nil || primary == target || (source != "ui" && source != "mcp") || use == nil {
		return sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedFallbackReleaseSession)
	if !ok {
		return sharedpg.ErrConfiguration
	}
	var verified *sharedpg.VerifiedFallbackRelease
	return c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		i, err := session.BeginFallbackUse(ctx, node, primary, target, source)
		if err != nil {
			return err
		}
		if i == nil || i.Node != node || i.PrimaryTunnel != primary || i.FallbackTunnel != target {
			return sharedpg.ErrAdmissionResponse
		}
		graph, err := session.FetchFallbackSecret(ctx, *i)
		if err != nil {
			return err
		}
		if graph == nil {
			return sharedpg.ErrAdmissionResponse
		}
		next, prepared, err := current.VerifyFallbackRelease(ctx, node, graph)
		if next.Revision != 0 {
			*pending = next
		}
		verified = prepared
		return err
	}, func(ctx context.Context, committed sharedpg.TrustState) error { return use(ctx, committed, verified) }, false)
}

// Build a secondary context without mutating the signed original plan.
func sharedFallbackBinding(workspace uuid.UUID, fileID string, q localvault.TunnelPlanRequest, primary vault.TunnelBundleBinding, attempt string, s sharedpg.FallbackSources) (vault.TunnelFallbackBinding, error) {
	secondary := q
	secondary.RequestID = attempt
	if secondary.Validate() != nil || attempt == q.RequestID {
		return vault.TunnelFallbackBinding{}, vault.ErrFormat
	}
	actual, err := sharedTunnelBinding(workspace, fileID, s.Plan, q, &s.Primary)
	if err != nil {
		return vault.TunnelFallbackBinding{}, err
	}
	if actual != primary || actual.Kind != 9 {
		return vault.TunnelFallbackBinding{}, vault.ErrAuthentication
	}
	t := s.Fallback
	if t.Metadata.Validate() != nil || t.Metadata.Kind != 2 || t.Metadata.ID == actual.TunnelConfigID || t.Boundary == uuid.Nil || t.RowVersion == 0 || t.RowVersion > math.MaxInt64 || t.ConfigurationVersion == 0 || t.ConfigurationVersion > t.RowVersion {
		return vault.TunnelFallbackBinding{}, vault.ErrPolicy
	}
	fallback := actual
	fallback.RequestID, fallback.TunnelConfigID, fallback.Kind = attempt, t.Metadata.ID, 2
	fallback.RowVersion, fallback.ConfigurationVersion = t.RowVersion, t.ConfigurationVersion
	return vault.TunnelFallbackBinding{Primary: actual, Fallback: fallback}, nil
}

// Planning discovers the target only through a fresh audited primary opening.
// A second independently audited graph verifies that reference against current
// source/target proofs, after their observations reach native protected custody.
func (c *sharedAdmissionController) PlanConnectionFallback(ctx context.Context, q localvault.TunnelPlanRequest, primary vault.TunnelBundleBinding, attempt, fileID, source string) (vault.TunnelFallbackBinding, error) {
	secondary := q
	secondary.RequestID = attempt
	if ctx == nil || q.Validate() != nil || secondary.Validate() != nil || attempt == q.RequestID {
		return vault.TunnelFallbackBinding{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return vault.TunnelFallbackBinding{}, vault.ErrPolicy
	}
	var target uuid.UUID
	err := c.withConnectionValues(ctx, uuid.MustParse(q.NodeID), source, sharedpg.DefaultConnectionPath, nil, func(v *sharedpg.VerifiedCredentialRelease) error {
		p, err := v.Plan()
		if err != nil {
			return err
		}
		t, err := v.Tunnel()
		if err != nil {
			return err
		}
		actual, err := sharedTunnelBinding(c.trustBinding.WorkspaceID, fileID, p, q, t)
		if err != nil {
			return err
		}
		if actual != primary || actual.Kind != 9 {
			return vault.ErrAuthentication
		}
		return nil
	}, true, func(_ resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil {
			return vault.ErrPolicy
		}
		id, err := selectNativeIPsecFallback(values.Tunnel.Fields["settings"])
		if err != nil {
			return err
		}
		if id == "" {
			return vaultstore.ErrMissing
		}
		target, err = uuid.Parse(id)
		if err != nil || target == uuid.Nil || id == primary.TunnelConfigID {
			return vault.ErrPolicy
		}
		return nil
	})
	if err != nil {
		return vault.TunnelFallbackBinding{}, err
	}
	var result vault.TunnelFallbackBinding
	err = c.withFallbackRelease(ctx, uuid.MustParse(q.NodeID), uuid.MustParse(primary.TunnelConfigID), target, source, func(ctx context.Context, committed sharedpg.TrustState, v *sharedpg.VerifiedFallbackRelease) error {
		sources, err := v.Sources()
		if err != nil {
			return err
		}
		result, err = sharedFallbackBinding(c.trustBinding.WorkspaceID, fileID, q, primary, attempt, sources)
		if err != nil {
			return err
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrTrustState
			}
			_, err := v.ValidateReference(ctx, committed, keys[:32], selectNativeIPsecFallback)
			return err
		})
	})
	if err != nil {
		return vault.TunnelFallbackBinding{}, err
	}
	return result, nil
}

func (c *sharedAdmissionController) SealConnectionFallback(ctx context.Context, q localvault.TunnelPlanRequest, expected vault.TunnelFallbackBinding, public []byte, fileID, source string) (localvault.TunnelFallbackBundle, error) {
	if ctx == nil || q.Validate() != nil || len(public) != 32 {
		return localvault.TunnelFallbackBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.TunnelFallbackBundle{}, vault.ErrPolicy
	}
	primary, e1 := uuid.Parse(expected.Primary.TunnelConfigID)
	target, e2 := uuid.Parse(expected.Fallback.TunnelConfigID)
	if e1 != nil || e2 != nil {
		return localvault.TunnelFallbackBundle{}, vault.ErrFormat
	}
	var result localvault.TunnelFallbackBundle
	err := c.withFallbackRelease(ctx, uuid.MustParse(q.NodeID), primary, target, source, func(ctx context.Context, committed sharedpg.TrustState, v *sharedpg.VerifiedFallbackRelease) error {
		sources, err := v.Sources()
		if err != nil {
			return err
		}
		actual, err := sharedFallbackBinding(c.trustBinding.WorkspaceID, fileID, q, expected.Primary, expected.Fallback.RequestID, sources)
		if err != nil {
			return err
		}
		if actual != expected {
			return vault.ErrAuthentication
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrTrustState
			}
			return v.WithConfiguration(ctx, committed, keys[:32], selectNativeIPsecFallback, func(_ sharedpg.FallbackSources, configuration []byte) error {
				sealed, err := vault.SealTunnelFallback(public, actual, configuration)
				if err != nil {
					return err
				}
				result = localvault.TunnelFallbackBundle{Binding: actual, Bundle: sealed}
				return nil
			})
		})
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.TunnelFallbackBundle{}, err
	}
	return result, nil
}
