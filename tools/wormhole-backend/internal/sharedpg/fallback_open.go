package sharedpg

import (
	"context"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ValidateReference consumes this audited graph without opening target settings.
// The native selector validates borrowed IPsec settings and returns their saved
// target ID; it must not retain bytes or reenter its owning operation.
func (v *VerifiedFallbackRelease) ValidateReference(ctx context.Context, committed TrustState, private []byte, selectFallback func([]byte) (string, error)) (FallbackSources, error) {
	if ctx == nil || v == nil || v.graph == nil || v.source == nil || len(private) != 32 || selectFallback == nil {
		return FallbackSources{}, ErrConfiguration
	}
	if !committed.valid() || !reflect.DeepEqual(committed, v.trust) || committed.Account == nil || !committed.Account.Active {
		return FallbackSources{}, ErrTrustState
	}
	sources, err := v.Sources()
	if err != nil {
		return FallbackSources{}, err
	}
	err = v.source.WithTunnelValues(ctx, committed, private, func(_ resolver.Plan, values CredentialReleaseValues) error {
		if values.Tunnel == nil || values.Primary != nil || values.Inline != nil || values.Gateway != nil {
			return ErrAdmissionResponse
		}
		id, err := selectFallback(values.Tunnel.Fields["settings"])
		if err != nil {
			return err
		}
		if id != sources.Fallback.Metadata.ID {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return FallbackSources{}, err
	}
	// WithTunnelValues has now wiped every primary seed and plaintext. A target
	// root is never opened while the primary configuration loan remains live.
	return sources, nil
}

// WithConfiguration requires the exact committed trust and a fresh audited graph.
// It opens only primary settings to check their encrypted reference, then only
// target settings for the owning native sealer. Both loans wipe on every exit.
func (v *VerifiedFallbackRelease) WithConfiguration(ctx context.Context, committed TrustState, private []byte, selectFallback func([]byte) (string, error), use func(FallbackSources, []byte) error) error {
	if use == nil {
		return ErrConfiguration
	}
	sources, err := v.ValidateReference(ctx, committed, private, selectFallback)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pin, err := committed.accountTrust()
	if err != nil {
		return err
	}
	g := v.graph
	issuer := func(copy UnverifiedKeyCopy) vault.KeyCopyTrust {
		public := pin.Organisation
		if copy.Author != nil {
			public = copy.Author.signingPublic()
		}
		return vault.KeyCopyTrust{Issuer: copy.Binding.Issuer, Public: public}
	}
	trust := vault.BoundaryTrust{WorkspaceID: committed.WorkspaceID, BoundaryID: g.manifest.BoundaryID, Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: committed.Catalog["boundary/"+g.manifest.BoundaryID.String()].Revision}
	root, err := openBoundaryReleaseRoot(private, g.root, issuer(g.root), g.manifest, trust, vault.BoundarySecret, committed)
	if err != nil {
		return err
	}
	defer vault.Wipe(root)
	if err := ctx.Err(); err != nil {
		return err
	}
	value := g.values[0]
	plain, err := vault.OpenSharedValue(root, g.copy.Binding.Holder, value.Binding, g.copy.Copy, issuer(g.copy), value.Envelope, g.manifest, trust)
	if err != nil {
		return err
	}
	defer vault.Wipe(plain)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := use(sources, plain); err != nil {
		return err
	}
	return ctx.Err()
}
