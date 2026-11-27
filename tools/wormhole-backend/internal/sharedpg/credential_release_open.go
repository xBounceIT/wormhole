package sharedpg

import (
	"context"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// DecodeCredentialRelease is the native, scope-bound ciphertext codec. Decoding
// grants no permission and authenticates nothing; use VerifyCredentialRelease,
// commit its observations, then open only inside the owning audited operation.
func DecodeCredentialRelease(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedCredentialRelease, error) {
	return parseCredentialRelease(raw, request, node, epoch, sequence)
}

// BorrowedCredential contains native-only temporary bytes for a protocol sealer.
// Fields live only for the callback, must not be retained/copied into strings,
// and are omitted from JSON even if a caller accidentally marshals this type.
type BorrowedCredential struct {
	Metadata vaultstore.CredentialMetadata
	Fields   map[string][]byte `json:"-"`
}

type BorrowedNodeFields struct {
	NodeID string
	Fields map[string][]byte `json:"-"`
}

// BorrowedTunnel is native-only. Settings survive only inside the callback.
type BorrowedTunnel struct {
	Tunnel ResolvedTunnel
	Fields map[string][]byte `json:"-"`
}

type CredentialReleaseValues struct {
	Primary *BorrowedCredential `json:"-"`
	Gateway *BorrowedCredential `json:"-"`
	Inline  *BorrowedNodeFields `json:"-"`
	Tunnel  *BorrowedTunnel     `json:"-"`
}

// Plan returns verified public steering metadata for native protocol validation.
// It confers no release authority; the owner still must commit observations
// before WithValues and must never substitute a previously cached plan.
func (v *VerifiedCredentialRelease) Plan() (resolver.Plan, error) {
	if v == nil || v.graph == nil {
		return resolver.Plan{}, ErrConfiguration
	}
	return v.plan, nil
}

func (v *VerifiedCredentialRelease) ProtocolPath() string {
	if v == nil || v.graph == nil || v.graph.metadata == nil {
		return ""
	}
	return v.graph.metadata.records.Path
}

// Tunnel returns a detached copy of authenticated public route metadata. It
// neither opens settings nor grants release authority; durable trust publication
// must still precede use by the owning operation.
func (v *VerifiedCredentialRelease) Tunnel() (*ResolvedTunnel, error) {
	if v == nil || v.graph == nil || v.graph.metadata == nil {
		return nil, ErrConfiguration
	}
	r := v.graph.metadata.records.Tunnel
	if r == nil {
		return nil, nil
	}
	t := r.Selection.Record.(sharedcatalog.TunnelRecord)
	return &ResolvedTunnel{Metadata: t.Metadata, Boundary: r.Selection.Boundary, RowVersion: r.Selection.Seal.Revision, ConfigurationVersion: t.ConfigurationVersion}, nil
}

// RDPSettings is a detached value projection of the authenticated full chain.
// Like Plan, it grants no permission; call only inside the owning audited gate.
func (v *VerifiedCredentialRelease) RDPSettings() (vault.RDPSettings, error) {
	return v.rdpSettings(false)
}

func (v *VerifiedCredentialRelease) ManualRDPSettings() (vault.RDPSettings, error) {
	return v.rdpSettings(true)
}

func (v *VerifiedCredentialRelease) rdpChain() []vaultstore.NodeMetadata {
	chain := make([]vaultstore.NodeMetadata, 0, len(v.graph.metadata.records.Chain))
	for _, record := range v.graph.metadata.records.Chain {
		chain = append(chain, record.Node.Metadata)
	}
	return chain
}

func (v *VerifiedCredentialRelease) rdpSettings(manual bool) (vault.RDPSettings, error) {
	p, err := v.RDPPlan(manual)
	if err != nil {
		return vault.RDPSettings{}, err
	}
	settings := resolver.ProjectRDPSettings(v.rdpChain())
	settings.Domain = p.Domain
	settings.GatewayUsageMethod = p.GatewayMethod
	settings.GatewayHostname = p.GatewayHost
	settings.GatewayUseSameCreds = p.GatewaySameCredentials
	settings.GatewayCredentialID = p.GatewayCredentialID
	settings.UseExternalClient = p.ExternalRDPClient
	return vault.NormalizeRDPSettings(&settings)
}

// WithValues opens a verified encrypted graph once, only against exactly the
// trust state the owning controller has durably committed. The owner must also
// hold its operation gate and borrow the current account key from securemem.
// This method grants no permission and does not persist or audit by itself.
// It wipes every plaintext/root on all exits, including callback failure/panic.
func (v *VerifiedCredentialRelease) WithValues(ctx context.Context, committed TrustState, private []byte, use func(resolver.Plan, CredentialReleaseValues) error) error {
	if v != nil && v.graph != nil && v.graph.pairedRDP {
		return v.withPairedRDPValues(ctx, committed, private, false, use)
	}
	return v.withValues(ctx, committed, private, false, false, use)
}

// WithTunnelValues opens only the selected tunnel settings, sharing the same
// one-use gate as WithValues. It never opens primary, inline or gateway secrets.
func (v *VerifiedCredentialRelease) WithTunnelValues(ctx context.Context, committed TrustState, private []byte, use func(resolver.Plan, CredentialReleaseValues) error) error {
	if v == nil || v.graph == nil || v.graph.metadata.records.Tunnel == nil {
		return ErrConfiguration
	}
	return v.withValues(ctx, committed, private, true, false, use)
}

// WithGatewayValues shares the one-use gate but opens only the independent
// gateway. Manual primary credentials must never decrypt a saved primary value.
func (v *VerifiedCredentialRelease) WithGatewayValues(ctx context.Context, committed TrustState, private []byte, use func(resolver.Plan, CredentialReleaseValues) error) error {
	if v != nil && v.graph != nil && v.graph.pairedRDP {
		return v.withPairedRDPValues(ctx, committed, private, true, use)
	}
	if v == nil || v.graph == nil || v.graph.metadata.records.Gateway == nil {
		return ErrConfiguration
	}
	return v.withValues(ctx, committed, private, false, true, use)
}

func (v *VerifiedCredentialRelease) withValues(ctx context.Context, committed TrustState, private []byte, tunnelOnly, gatewayOnly bool, use func(resolver.Plan, CredentialReleaseValues) error) error {
	if ctx == nil || v == nil || v.graph == nil || len(private) != 32 || use == nil {
		return ErrConfiguration
	}
	if !tunnelOnly && v.ProtocolPath() == WebConnectionPlanPath {
		return ErrConfiguration
	}
	if !committed.valid() || !reflect.DeepEqual(committed, v.trust) || !committed.Account.Active {
		return ErrTrustState
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if !v.used.CompareAndSwap(false, true) {
		return ErrUseTicket
	}
	pin, e := committed.accountTrust()
	if e != nil {
		return e
	}
	manifests := make(map[uuid.UUID]vault.BoundaryManifest, len(v.graph.metadata.manifests))
	for _, m := range v.graph.metadata.manifests {
		manifests[m.BoundaryID] = m
	}
	copies := make(map[vault.KeyRef]UnverifiedKeyCopy, len(v.graph.roots))
	for _, copy := range v.graph.roots {
		copies[copy.Binding.Key] = copy
	}
	seeds := make(map[vault.KeyRef][]byte)
	// Keep an independent ownership list: the callback may modify/remove map
	// entries, but must never be able to prevent wiping our original buffers.
	var plaintexts [][]byte
	defer func() {
		for _, seed := range seeds {
			vault.Wipe(seed)
		}
		for _, plain := range plaintexts {
			vault.Wipe(plain)
		}
	}()
	issuer := func(copy UnverifiedKeyCopy) vault.KeyCopyTrust {
		public := pin.Organisation
		if copy.Author != nil {
			public = copy.Author.signingPublic() // Verified before preparation.
		}
		return vault.KeyCopyTrust{Issuer: copy.Binding.Issuer, Public: public}
	}
	result := CredentialReleaseValues{}
	for _, account := range v.graph.accounts {
		if gatewayOnly && account.role != "gateway" || !gatewayOnly && (account.role == "tunnel") != tunnelOnly {
			continue
		}
		m := manifests[account.boundary]
		trust := vault.BoundaryTrust{WorkspaceID: committed.WorkspaceID, BoundaryID: account.boundary, Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: committed.Catalog["boundary/"+account.boundary.String()].Revision}
		borrowed := &BorrowedCredential{Fields: make(map[string][]byte, len(account.values))}
		if account.role != "inline" && account.role != "tunnel" {
			profile := v.graph.metadata.records.Credential
			if account.role == "gateway" {
				profile = v.graph.metadata.records.Gateway
			}
			borrowed.Metadata = profile.Credential.Record.Metadata
		}
		for i, value := range account.values {
			if e := ctx.Err(); e != nil {
				return e
			}
			copy := account.copies[i]
			root := copy.Binding.Holder
			seed, ok := seeds[root]
			if !ok {
				rootCopy := copies[root]
				seed, e = openBoundaryReleaseRoot(private, rootCopy, issuer(rootCopy), m, trust, vault.BoundarySecret, committed)
				if e != nil {
					return e
				}
				seeds[root] = seed
			}
			plain, e := vault.OpenSharedValue(seed, root, value.Binding, copy.Copy, issuer(copy), value.Envelope, m, trust)
			if e != nil {
				return e
			}
			plaintexts = append(plaintexts, plain)
			borrowed.Fields[value.Binding.Field] = plain
		}
		if account.role == "primary" {
			result.Primary = borrowed
		} else if account.role == "inline" {
			result.Inline = &BorrowedNodeFields{NodeID: v.plan.Credential.NodeID, Fields: borrowed.Fields}
		} else if account.role == "tunnel" {
			r := v.graph.metadata.records.Tunnel.Selection
			tunnel := r.Record.(sharedcatalog.TunnelRecord)
			result.Tunnel = &BorrowedTunnel{Tunnel: ResolvedTunnel{Metadata: tunnel.Metadata, Boundary: r.Boundary, RowVersion: r.Seal.Revision, ConfigurationVersion: tunnel.ConfigurationVersion}, Fields: borrowed.Fields}
		} else {
			result.Gateway = borrowed
		}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := use(v.plan, result); e != nil {
		return e
	}
	return ctx.Err()
}
