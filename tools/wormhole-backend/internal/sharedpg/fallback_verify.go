package sharedpg

import (
	"context"
	"errors"
	"math"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// FallbackSources is authenticated public metadata. The original connection plan
// still selects Primary; Fallback is separate and never retags the signed node.
type FallbackSources struct {
	Plan              resolver.Plan
	Primary, Fallback ResolvedTunnel
}

// The source's existing one-use gate also covers reference validation and target
// opening. No independently reusable target capability is exposed. Verification
// itself neither audits Use nor proves process exit or durable trust publication.
type VerifiedFallbackRelease struct {
	graph  *UnverifiedFallbackRelease
	source *VerifiedCredentialRelease
	trust  TrustState
}

// VerifyFallbackRelease never opens keys. Persist any nonzero returned state,
// including authenticated target observations when another proof fails. Only a
// nil error prepares use, after both source chains and their authors agree.
func (s TrustState) VerifyFallbackRelease(ctx context.Context, node uuid.UUID, graph *UnverifiedFallbackRelease) (observed TrustState, verified *VerifiedFallbackRelease, err error) {
	if ctx == nil || graph == nil || graph.source == nil || graph.source.metadata == nil || node == uuid.Nil {
		return TrustState{}, nil, ErrConfiguration
	}
	target, ok := graph.target.Selection.Record.(sharedcatalog.TunnelRecord)
	if !ok || !target.Deleted && len(graph.values) != 1 {
		return TrustState{}, nil, ErrConfiguration
	}
	if !s.valid() || s.Account == nil || !s.Account.Active || s.Revision == math.MaxUint64 {
		return TrustState{}, nil, ErrTrustState
	}
	observed = cloneTrustState(s)
	changed := false
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
	}
	var source *VerifiedCredentialRelease
	defer func() {
		if changed {
			observed.Revision = s.Revision + 1
		}
		if err == nil {
			// The caller can replace the exported unverified container after this
			// call. Detach it and use the source verifier's frozen inner graph.
			frozen := *graph
			frozen.source = source.graph
			source.trust = cloneTrustState(observed)
			verified = &VerifiedFallbackRelease{graph: &frozen, source: source, trust: cloneTrustState(observed)}
		}
	}()
	next, prepared, sourceErr := observed.VerifyCredentialRelease(ctx, node, graph.source)
	absorb(next)
	source, err = prepared, sourceErr
	if sourceErr == nil {
		primary, e := source.Tunnel()
		if e != nil || primary == nil || primary.Metadata.Kind != 9 {
			err = errors.Join(err, e, vault.ErrPolicy)
		}
	}
	// Independent proofs may contain a revocation or newer manifest even when
	// another source failed. Keep those facts without preparing any key access.
	step := func(run func() (TrustState, error)) bool {
		if canceled := ctx.Err(); canceled != nil {
			err = errors.Join(err, canceled)
			return false
		}
		next, e := run()
		absorb(next)
		err = errors.Join(err, e)
		return true
	}
	verifyTarget := func() bool {
		if !step(func() (TrustState, error) {
			return observed.AdvanceBoundary(graph.target.Selection.Boundary, graph.manifest)
		}) {
			return false
		}
		if !step(func() (TrustState, error) {
			return observed.AdvanceSelection(graph.target.Selection, graph.target.Author)
		}) {
			return false
		}
		if target.Deleted {
			return true
		}
		return step(func() (TrustState, error) { return observed.advanceBoundaryRootCopy(graph.root) }) &&
			step(func() (TrustState, error) {
				return observed.AdvanceKeyCopy(graph.copy.Binding, graph.copy.Copy, graph.copy.Author)
			})
	}
	if !verifyTarget() {
		return observed, nil, err
	}
	if target.Deleted || target.Metadata.Kind != 2 {
		err = errors.Join(err, vault.ErrPolicy)
	}
	if err != nil {
		return observed, nil, err
	}
	// A final author selection or certificate floor can change without a
	// state-sequence change. Reuse complete verification against every fact
	// learned above, including sequence consistency within the original graph.
	stable := cloneTrustState(observed)
	next, source, err = observed.VerifyCredentialRelease(ctx, node, graph.source)
	absorb(next)
	if !verifyTarget() {
		return observed, nil, err
	}
	if err == nil && !reflect.DeepEqual(stable, observed) {
		err = ErrTreeSnapshotChanged
	}
	if canceled := ctx.Err(); canceled != nil {
		err = errors.Join(err, canceled)
	}
	if observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		err = errors.Join(err, vault.ErrAuthentication)
	}
	return observed, nil, err
}

func (v *VerifiedFallbackRelease) Sources() (FallbackSources, error) {
	if v == nil || v.graph == nil || v.source == nil {
		return FallbackSources{}, ErrConfiguration
	}
	p, err := v.source.Plan()
	if err != nil {
		return FallbackSources{}, err
	}
	primary, err := v.source.Tunnel()
	if err != nil || primary == nil {
		return FallbackSources{}, ErrConfiguration
	}
	r := v.graph.target.Selection
	t := r.Record.(sharedcatalog.TunnelRecord)
	return FallbackSources{Plan: p, Primary: *primary, Fallback: ResolvedTunnel{Metadata: t.Metadata, Boundary: r.Boundary, RowVersion: r.Seal.Revision, ConfigurationVersion: t.ConfigurationVersion}}, nil
}
