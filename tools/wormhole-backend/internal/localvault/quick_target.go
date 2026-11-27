package localvault

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// ErrQuickTargetInput identifies rejected caller metadata, not corrupt storage.
var ErrQuickTargetInput = errors.New("vault_quick_target_invalid_input")

const maxQuickTargets = 64
const quickTargetLifetime = 15 * time.Minute

// QuickConnectionTarget contains public target/options and account references
// only. Manual account fields belong to an isolated credential document.
type QuickConnectionTarget struct {
	Protocol                string             `json:"protocol"`
	Host                    string             `json:"host"`
	Port                    int                `json:"port"`
	CredentialID            string             `json:"credentialId"`
	TunnelID                string             `json:"tunnelId"`
	SSHAutoSudo             bool               `json:"sshAutoSudo"`
	HTTPPath                string             `json:"httpPath"`
	IgnoreCertificateErrors bool               `json:"ignoreCertificateErrors"`
	RDP                     *vault.RDPSettings `json:"rdp"`
}

type QuickTargetRequest struct {
	SessionID string
	Epoch     uint64
	Target    QuickConnectionTarget
}

// QuickTargetRef is main/native-only. Its random ID identifies a connection
// admitted by this owner, never a row to insert or a credential-release token.
type QuickTargetRef struct {
	WorkspaceID string `json:"workspaceId"`
	ID          string `json:"id"`
	SessionID   string `json:"sessionId"`
	Epoch       uint64 `json:"epoch"`
}
type quickTargetStage struct {
	ref         QuickTargetRef
	metadata    vaultstore.NodeMetadata
	rdp         vault.RDPSettings
	expires     time.Time
	revision    uint64
	fingerprint string
}

func validQuickScope(session string, epoch uint64) bool {
	id, err := uuid.Parse(session)
	return err == nil && id != uuid.Nil && id.String() == session && epoch > 0 && epoch <= 9007199254740991
}

// RegisterQuickTarget admits a bounded, nonpersistent target. The vault owner
// and main authorization epoch must already be active. Registration borrows no
// secrets; every subsequent release rechecks referenced metadata and its scope.
func (o *Owner) RegisterQuickTarget(ctx context.Context, q QuickTargetRequest) (QuickTargetRef, error) {
	if ctx == nil || !validQuickScope(q.SessionID, q.Epoch) {
		return QuickTargetRef{}, errors.Join(ErrQuickTargetInput, vault.ErrFormat)
	}
	if err := ctx.Err(); err != nil {
		return QuickTargetRef{}, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return QuickTargetRef{}, err
	}
	stage, err := prepareQuickTarget(q, id.String())
	if err != nil {
		return QuickTargetRef{}, errors.Join(ErrQuickTargetInput, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	store, err := o.nodeStore()
	if err != nil {
		return QuickTargetRef{}, err
	}
	now := time.Now()
	for id, current := range o.quickTargets {
		if !now.Before(current.expires) {
			delete(o.quickTargets, id)
		}
	}
	if len(o.quickTargets) >= maxQuickTargets {
		return QuickTargetRef{}, vault.ErrPolicy
	}
	if _, err = store.ReadNode(ctx, id.String()); err == nil {
		return QuickTargetRef{}, vaultstore.ErrConflict
	} else if !errors.Is(err, vaultstore.ErrMissing) {
		return QuickTargetRef{}, err
	}
	// Authenticate every selected reference before committing the in-memory target.
	if _, err = o.quickConnectionCandidate(ctx, stage); err != nil {
		return QuickTargetRef{}, err
	}
	if err = ctx.Err(); err != nil {
		return QuickTargetRef{}, err
	}
	stage.ref.WorkspaceID = store.Identity().WorkspaceID
	stage.expires = now.Add(quickTargetLifetime)
	if o.quickTargets == nil {
		o.quickTargets = make(map[string]*quickTargetStage)
	}
	o.quickTargets[stage.ref.ID] = stage
	return stage.ref, nil
}

func (o *Owner) ReleaseQuickTarget(ctx context.Context, ref QuickTargetRef) error {
	if ctx == nil || !validQuickScope(ref.SessionID, ref.Epoch) {
		return errors.Join(ErrQuickTargetInput, vault.ErrFormat)
	}
	workspace, workspaceErr := uuid.Parse(ref.WorkspaceID)
	if workspaceErr != nil || workspace == uuid.Nil || workspace.String() != ref.WorkspaceID {
		return errors.Join(ErrQuickTargetInput, vault.ErrFormat)
	}
	id, err := uuid.Parse(ref.ID)
	if err != nil || id == uuid.Nil || id.String() != ref.ID {
		return errors.Join(ErrQuickTargetInput, vault.ErrFormat)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return vaultstore.ErrClosed
	}
	if ref.WorkspaceID != o.store.Identity().WorkspaceID {
		return vault.ErrPolicy
	}
	stage := o.quickTargets[ref.ID]
	if stage == nil {
		return nil
	}
	if stage.ref != ref {
		return vault.ErrPolicy
	}
	delete(o.quickTargets, ref.ID)
	return nil
}

func prepareQuickTarget(q QuickTargetRequest, id string) (*quickTargetStage, error) {
	t := q.Target
	protocol := map[string]int{"ssh": 0, "rdp": 1, "http": 3, "https": 4, "vnc": 6, "sftp": 7}
	kind, ok := protocol[t.Protocol]
	if !ok || t.Host == "" || len(t.Host) > 1024 || !utf8.ValidString(t.Host) || strings.ContainsAny(t.Host, "/?#@\\") || strings.IndexFunc(t.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || t.Port < 0 || t.Port > 65535 {
		return nil, vault.ErrFormat
	}
	for _, ref := range []string{t.CredentialID, t.TunnelID} {
		if ref != "" {
			parsed, err := uuid.Parse(ref)
			if err != nil || parsed == uuid.Nil || parsed.String() != ref {
				return nil, vault.ErrFormat
			}
		}
	}
	if kind == 1 && !vault.ValidRDPHost(t.Host) {
		return nil, vault.ErrFormat
	}
	if (kind != 0 && kind != 7 && t.SSHAutoSudo) || (kind != 3 && kind != 4 && t.HTTPPath != "") || (kind != 4 && t.IgnoreCertificateErrors) || (kind != 1 && t.RDP != nil) || ((kind == 3 || kind == 4) && t.CredentialID != "") {
		return nil, vault.ErrPolicy
	}
	mode := 1
	metadata := vaultstore.NodeMetadata{ID: id, Name: "Quick connection", Kind: 1, Protocol: &kind, Host: &t.Host, CredentialMode: &mode, SshAutoSudo: &t.SSHAutoSudo, HTTPPath: &t.HTTPPath, HTTPIgnoreCertErrors: &t.IgnoreCertificateErrors}
	if t.Port != 0 {
		metadata.Port = &t.Port
	}
	if t.CredentialID != "" {
		mode = 2
		metadata.CredentialID = &t.CredentialID
	}
	enabled := t.TunnelID != ""
	metadata.TunnelEnabled = &enabled
	if enabled {
		metadata.TunnelConfigID = &t.TunnelID
	}
	stage := &quickTargetStage{ref: QuickTargetRef{ID: id, SessionID: q.SessionID, Epoch: q.Epoch}, metadata: metadata, revision: 1}
	if kind == 1 {
		if t.RDP != nil && t.RDP.Domain != "" {
			return nil, vault.ErrPolicy
		}
		settings, err := vault.NormalizeRDPSettings(t.RDP)
		if err != nil {
			return nil, vault.ErrFormat
		}
		if err = vault.ValidateRDPRoute(vault.RDPSettingsForPlatform(settings, runtime.GOOS), enabled); err != nil {
			return nil, err
		}
		stage.rdp = settings
		metadata.RDPGatewayUsageMethod = &settings.GatewayUsageMethod
		metadata.RDPGatewayHostname = &settings.GatewayHostname
		if settings.GatewayCredentialID != "" {
			metadata.RDPGatewayCredentialID = &settings.GatewayCredentialID
		}
		metadata.RDPGatewayUseSameCreds = &settings.GatewayUseSameCreds
		metadata.RDPUseExternalClient = &settings.UseExternalClient
		stage.metadata = metadata
	}
	// Reuse the real resolver validation/defaults without inventing any stored row.
	if _, err := resolver.Resolve([]vaultstore.NodeMetadata{stage.metadata}, ""); err != nil {
		return nil, err
	}
	return stage, nil
}

// Scoped protocol APIs can resolve a temporary target; generic metadata/edit
// and per-credential APIs deliberately continue to resolve saved rows only.
func (o *Owner) resolveCandidateRequest(ctx context.Context, q TunnelPlanRequest) (Resolution, error) {
	if ctx == nil {
		return Resolution{}, vault.ErrFormat
	}
	if err := q.Validate(); err != nil {
		return Resolution{}, err
	}
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	if _, err := o.nodeStore(); err != nil {
		return Resolution{}, err
	}
	var r Resolution
	var err error
	if stage := o.quickTargets[q.NodeID]; stage != nil {
		if !time.Now().Before(stage.expires) {
			delete(o.quickTargets, q.NodeID)
			return Resolution{}, vault.ErrPolicy
		}
		if stage.ref.SessionID != q.SessionID || stage.ref.Epoch != q.Epoch || q.CredentialOverride != "" {
			return Resolution{}, vault.ErrPolicy
		}
		r, err = o.quickConnectionCandidate(ctx, stage)
	} else {
		r, err = o.resolveCandidateConnection(ctx, q.NodeID, q.CredentialOverride)
	}
	if err != nil {
		return Resolution{}, err
	}
	if r.Plan.TunnelID != "" {
		return r, nil
	}
	security, err := o.readSecurityProfile(ctx)
	if err != nil {
		return Resolution{}, err
	}
	if !security.Effective.AllowsDirectRoute() {
		return Resolution{}, vault.ErrPolicy
	}
	return r, nil
}

func (o *Owner) quickConnectionCandidate(ctx context.Context, stage *quickTargetStage) (Resolution, error) {
	metadata := stage.metadata
	if stage.fingerprint != "" {
		pin := stage.fingerprint
		metadata.SshKnownHostFingerprint = &pin
	}
	plan, err := resolver.Resolve([]vaultstore.NodeMetadata{metadata}, "")
	if err != nil {
		return Resolution{}, err
	}
	// RowVersion and seals intentionally remain absent: this source is an owner
	// admission, not a fabricated persisted node. Only host-plan snapshots use its
	// explicitly ephemeral revision.
	r := Resolution{Identity: o.store.Identity(), Plan: plan, leaf: vaultstore.Node{NodeMetadata: metadata}, rdpSettings: stage.rdp, quickID: stage.ref.ID, Nodes: []ResolutionRevision{{ID: stage.ref.ID, Version: stage.revision}}}
	return o.completeConnectionCandidate(ctx, r)
}

func (o *Owner) resolveConnectionRequest(ctx context.Context, q TunnelPlanRequest, manualRDP bool) (Resolution, error) {
	r, err := o.resolveCandidateRequest(ctx, q)
	if err != nil {
		return Resolution{}, err
	}
	return o.selectConnectionAccounts(ctx, r, q.CredentialOverride, "", manualRDP)
}
