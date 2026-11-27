package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedCredentialReleaseSession interface {
	BeginUse(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error)
	FetchSecret(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error)
}

type sharedCredentialPathSession interface {
	ConnectionPathsSupported(context.Context) (bool, error)
	BeginUsePath(context.Context, uuid.UUID, string, string) (*sharedpg.UseIntent, error)
}

type sharedTunnelReleaseSession interface {
	TunnelUseSupported(context.Context) (bool, error)
	BeginTunnelUse(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error)
	FetchTunnelSecret(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error)
}

// WithConnectionCredentials is Go-only. It never returns plaintext to main or
// the renderer: use must encode/seal immediately to the bound protocol process.
// Every call gets a fresh audited ticket. Errors retire the owner, with no retry.
func (c *sharedAdmissionController) WithConnectionCredentials(ctx context.Context, node uuid.UUID, source string, use func(resolver.Plan, sharedpg.CredentialReleaseValues) error) error {
	return c.withConnectionCredentials(ctx, node, source, nil, use)
}

func (c *sharedAdmissionController) withConnectionCredentials(ctx context.Context, node uuid.UUID, source string, check func(resolver.Plan) error, use func(resolver.Plan, sharedpg.CredentialReleaseValues) error) error {
	return c.withConnectionValues(ctx, node, source, "", check, nil, false, use)
}

// Validate authenticated public graph metadata before borrowing any account key.
// Both settings and protocol opening use the same audited publication path.
func (c *sharedAdmissionController) withConnectionValues(ctx context.Context, node uuid.UUID, source, path string, check func(resolver.Plan) error, checkGraph func(*sharedpg.VerifiedCredentialRelease) error, tunnelOnly bool, use func(resolver.Plan, sharedpg.CredentialReleaseValues) error) error {
	if use == nil {
		return sharedpg.ErrConfiguration
	}
	return c.withConnectionReleaseScope(ctx, node, source, path, tunnelOnly, check, func(ctx context.Context, committed sharedpg.TrustState, verified *sharedpg.VerifiedCredentialRelease) error {
		if checkGraph != nil {
			if err := checkGraph(verified); err != nil {
				return err
			}
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrTrustState
			}
			if tunnelOnly {
				return verified.WithTunnelValues(ctx, committed, keys[:32], use)
			}
			return verified.WithValues(ctx, committed, keys[:32], use)
		})
	})
}

// The authorization stage can wrap a user-supplied opaque envelope without
// opening saved credentials. Both consumers share the same audited verification
// and durable trust publication under the admission gate.
func (c *sharedAdmissionController) withConnectionRelease(ctx context.Context, node uuid.UUID, source, path string, check func(resolver.Plan) error, use func(context.Context, sharedpg.TrustState, *sharedpg.VerifiedCredentialRelease) error) error {
	return c.withConnectionReleaseScope(ctx, node, source, path, false, check, use)
}

func (c *sharedAdmissionController) withConnectionReleaseScope(ctx context.Context, node uuid.UUID, source, path string, tunnelOnly bool, check func(resolver.Plan) error, use func(context.Context, sharedpg.TrustState, *sharedpg.VerifiedCredentialRelease) error) error {
	if ctx == nil || node == uuid.Nil || (source != "ui" && source != "mcp") || use == nil {
		return sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedCredentialReleaseSession)
	if !ok {
		return sharedpg.ErrConfiguration
	}
	var verified *sharedpg.VerifiedCredentialRelease
	return c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		var intent *sharedpg.UseIntent
		var e error
		requested := ""
		fetch := session.FetchSecret
		defaultPath := sharedpg.DefaultAuditedPath
		if tunnel, ok := session.(sharedTunnelReleaseSession); ok && tunnelOnly {
			supported, err := tunnel.TunnelUseSupported(ctx)
			if err != nil {
				return err
			}
			if supported {
				requested = sharedpg.DefaultConnectionPath
				intent, e = tunnel.BeginTunnelUse(ctx, node, source)
				fetch = tunnel.FetchTunnelSecret
				defaultPath = sharedpg.DefaultPlanPath
			}
		}
		if scoped, ok := session.(sharedCredentialPathSession); ok && requested == "" && path != "" {
			supported, err := scoped.ConnectionPathsSupported(ctx)
			if err != nil {
				return err
			}
			if supported {
				requested = path
				intent, e = scoped.BeginUsePath(ctx, node, source, path)
			}
		}
		if requested == "" {
			intent, e = session.BeginUse(ctx, node, source)
		}
		if e != nil {
			return e
		}
		if intent == nil || intent.Node != node || (requested != sharedpg.DefaultConnectionPath && intent.Path != requested) {
			return sharedpg.ErrAdmissionResponse
		}
		graph, e := fetch(ctx, *intent)
		if e != nil {
			return e
		}
		if graph == nil {
			return sharedpg.ErrAdmissionResponse
		}
		next, prepared, e := current.VerifyCredentialRelease(ctx, node, graph)
		if next.Revision != 0 {
			*pending = next
		}
		if e != nil {
			return e
		}
		plan, err := prepared.Plan()
		if err != nil {
			return err
		}
		if prepared.ProtocolPath() != intent.Path ||
			(requested == sharedpg.DefaultConnectionPath && intent.Path != defaultPath(plan.Protocol)) {
			return sharedpg.ErrAdmissionResponse
		}
		if plan.TunnelID == "" && !c.runtimeProfile.AllowsDirectRoute() {
			return vault.ErrPolicy
		}
		verified = prepared
		if check != nil {
			return check(plan)
		}
		return nil
	}, func(ctx context.Context, committed sharedpg.TrustState) error {
		return use(ctx, committed, verified)
	}, false)
}
