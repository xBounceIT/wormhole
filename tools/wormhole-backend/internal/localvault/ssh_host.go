package localvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// SSHHostPlan is public identity metadata. Revision commits to the authenticated
// resolution inputs; it grants no credential access or permission to change a pin.
type SSHHostPlan struct {
	Binding     vault.BundleBinding `json:"binding"`
	FileID      string              `json:"fileId"`
	Revision    string              `json:"revision"`
	Fingerprint string              `json:"fingerprint"`
}

func (o *Owner) PlanSSHHost(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding) (SSHHostPlan, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	plan, _, err := o.planSSHHost(ctx, q, route)
	return plan, err
}

func (o *Owner) planSSHHost(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding) (SSHHostPlan, Resolution, error) {
	if err := q.Validate(); err != nil {
		return SSHHostPlan{}, Resolution{}, err
	}
	r, err := o.resolveConnectionRequest(ctx, q, false)
	if err != nil {
		return SSHHostPlan{}, Resolution{}, err
	}
	p := r.Plan
	if r.leaf.Kind != 1 || (p.Protocol != 0 && p.Protocol != 7) || p.Port < 1 || p.Port > 65535 || p.Host == "" || len(p.Host) > vault.MaxContextBytes || strings.IndexFunc(p.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 || (p.HostKeyFingerprint != "" && !vault.ValidSSHFingerprint(p.HostKeyFingerprint)) {
		return SSHHostPlan{}, Resolution{}, vault.ErrPolicy
	}
	if r.Tunnel == nil {
		if route != nil {
			return SSHHostPlan{}, Resolution{}, vault.ErrPolicy
		}
	} else {
		current, err := connectionTunnelBinding(r, q)
		if err != nil || route == nil || *route != current {
			return SSHHostPlan{}, Resolution{}, vault.ErrPolicy
		}
	}
	return projectSSHHostPlan(r, q), r, nil
}

func connectionResolutionRevision(r Resolution, q TunnelPlanRequest) string {
	// A change to any parent, selected credential or tunnel invalidates a pending
	// confirmation, even when the visible host and fingerprint happen to match.
	snapshot := struct {
		Nodes                                                  []ResolutionRevision
		Override, CredentialID                                 string
		CredentialVersion, TunnelVersion, ConfigurationVersion uint64
		GatewayID                                              string `json:",omitempty"`
		GatewayVersion                                         uint64 `json:",omitempty"`
	}{Nodes: r.Nodes, Override: q.CredentialOverride}
	if r.Credential != nil {
		snapshot.CredentialID, snapshot.CredentialVersion = r.Credential.ID, r.Credential.RowVersion
	}
	if r.GatewayCredential != nil {
		snapshot.GatewayID, snapshot.GatewayVersion = r.GatewayCredential.ID, r.GatewayCredential.RowVersion
	}
	if r.Tunnel != nil {
		snapshot.TunnelVersion, snapshot.ConfigurationVersion = r.Tunnel.RowVersion, r.Tunnel.ConfigurationVersion
	}
	raw, _ := json.Marshal(snapshot) // fixed, nonrecursive metadata types only
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func projectSSHHostPlan(r Resolution, q TunnelPlanRequest) SSHHostPlan {
	p := r.Plan
	return SSHHostPlan{
		Binding: vault.BundleBinding{WorkspaceID: r.Identity.WorkspaceID, SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: resolver.DefaultPath(p.Protocol), Host: p.Host, Port: uint16(p.Port), TunnelConfigID: p.TunnelID, Epoch: q.Epoch},
		FileID:  r.Identity.FileID, Revision: connectionResolutionRevision(r, q), Fingerprint: p.HostKeyFingerprint,
	}
}

// TrustSSHHost checks exactly what was shown and persists a leaf override in one
// owner critical section. It never rewrites a parent shared by other connections.
// The handler applies profile/fresh-auth admission; shared Write admission must
// precede this local-owner primitive when a shared controller is introduced.
func (o *Owner) TrustSSHHost(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding, expected SSHHostPlan, received string) (vaultstore.Node, error) {
	if !vault.ValidSSHFingerprint(received) || received == expected.Fingerprint {
		return vaultstore.Node{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	current, r, err := o.planSSHHost(ctx, q, route)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if current != expected {
		return vaultstore.Node{}, vaultstore.ErrConflict
	}
	if r.quickID != "" {
		return vaultstore.Node{}, vault.ErrPolicy
	}
	metadata := r.leaf.NodeMetadata
	metadata.SshKnownHostFingerprint = &received
	return o.writeNode(ctx, metadata, nil, r.leaf.RowVersion, false, nil)
}

// TrustQuickSSHHost changes only the current owner's ephemeral pin. It cannot
// persist a node or rewrite a saved host pin; native fresh-action admission is
// still required by the handler, exactly as for the saved trust operation.
func (o *Owner) TrustQuickSSHHost(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding, expected SSHHostPlan, received string) (SSHHostPlan, error) {
	if !vault.ValidSSHFingerprint(received) || received == expected.Fingerprint {
		return SSHHostPlan{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	current, r, err := o.planSSHHost(ctx, q, route)
	if err != nil {
		return SSHHostPlan{}, err
	}
	if r.quickID == "" {
		return SSHHostPlan{}, vault.ErrPolicy
	}
	if current != expected {
		return SSHHostPlan{}, vaultstore.ErrConflict
	}
	stage := o.quickTargets[r.quickID]
	if stage.revision == ^uint64(0) {
		return SSHHostPlan{}, vault.ErrPolicy
	}
	if err = ctx.Err(); err != nil {
		return SSHHostPlan{}, err
	}
	// Prepare the receipt before committing, so cancellation/storage errors
	// cannot leave an acknowledged pin inconsistent with this operation's result.
	r.Nodes = []ResolutionRevision{{ID: stage.ref.ID, Version: stage.revision + 1}}
	r.Plan.HostKeyFingerprint = received
	result := projectSSHHostPlan(r, q)
	stage.fingerprint = received
	stage.revision++
	return result, nil
}
