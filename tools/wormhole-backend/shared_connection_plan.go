package main

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedConnectionPlanSession interface {
	ConnectionPlan(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error)
}

type sharedConnectionPathPlanSession interface {
	ConnectionPlanPath(context.Context, uuid.UUID, string) (*sharedpg.UnverifiedConnectionPlan, error)
}

type sharedWebConnectionPlanSession interface {
	WebConnectionPlanSupported(context.Context) (bool, error)
	WebConnectionPlan(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error)
}

// PlanConnection authenticates and durably publishes public routing/identity
// metadata without requesting ciphertext, opening keys or consuming a ticket.
func (c *sharedAdmissionController) PlanConnection(ctx context.Context, node uuid.UUID) (result sharedpg.ResolvedConnectionPlan, err error) {
	err = c.withConnectionPlan(ctx, node, func(_ context.Context, plan sharedpg.ResolvedConnectionPlan) error {
		result = plan
		return nil
	})
	return result, err
}

// The consumer runs under the admitted lifetime gate after observations commit.
func (c *sharedAdmissionController) withConnectionPlan(ctx context.Context, node uuid.UUID, use func(context.Context, sharedpg.ResolvedConnectionPlan) error) error {
	return c.withConnectionPlanFor(ctx, node, use, false)
}

func (c *sharedAdmissionController) withWebConnectionPlan(ctx context.Context, node uuid.UUID, use func(context.Context, sharedpg.ResolvedConnectionPlan) error) error {
	return c.withConnectionPlanFor(ctx, node, use, true)
}

func (c *sharedAdmissionController) withConnectionPlanFor(ctx context.Context, node uuid.UUID, use func(context.Context, sharedpg.ResolvedConnectionPlan) error, web bool) error {
	if ctx == nil || node == uuid.Nil {
		return sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedConnectionPlanSession)
	if !ok {
		return sharedpg.ErrConfiguration
	}
	var resolved sharedpg.ResolvedConnectionPlan
	var unsupportedWebPlan bool
	err := c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		input, e := session.ConnectionPlan(ctx, node)
		pinned := errors.Is(e, sharedpg.ErrImportedConnectionPins)
		wantPath := ""
		if pinned && web {
			scoped, ok := c.session.(sharedWebConnectionPlanSession)
			if !ok {
				unsupportedWebPlan = true
				return nil
			}
			supported, err := scoped.WebConnectionPlanSupported(ctx)
			if err != nil {
				return err
			}
			if !supported {
				unsupportedWebPlan = true
				return nil
			}
			wantPath = sharedpg.WebConnectionPlanPath
			input, e = scoped.WebConnectionPlan(ctx, node)
		} else if pinned {
			scoped, ok := c.session.(sharedConnectionPathPlanSession)
			if !ok {
				return e
			}
			wantPath = sharedpg.DefaultConnectionPath
			input, e = scoped.ConnectionPlanPath(ctx, node, sharedpg.DefaultConnectionPath)
		}
		if e != nil {
			return e
		}
		if input == nil {
			return sharedpg.ErrAdmissionResponse
		}
		next, plan, e := current.VerifyConnectionPlan(ctx, node, input)
		if next.Revision != 0 {
			*pending = next
		}
		if e == nil {
			if wantPath == sharedpg.DefaultConnectionPath {
				wantPath = sharedpg.DefaultPlanPath(plan.Plan.Protocol)
				if wantPath == "" {
					return sharedpg.ErrAdmissionResponse
				}
			}
			if plan.Path != wantPath {
				return sharedpg.ErrAdmissionResponse
			}
		}
		resolved = plan
		return e
	}, func(ctx context.Context, _ sharedpg.TrustState) error {
		if unsupportedWebPlan {
			return nil
		}
		if resolved.Plan.TunnelID == "" && !c.runtimeProfile.AllowsDirectRoute() {
			return vault.ErrPolicy
		}
		return use(ctx, resolved)
	}, false)
	if err == nil && unsupportedWebPlan {
		return sharedpg.ErrImportedConnectionPins
	}
	return err
}
