package localvault

import (
	"context"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// WebConnectionPlan is authenticated public metadata. It is not a credential
// release capability; browser cookies stay in their owning Chromium session.
type WebConnectionPlan struct {
	Binding                 vault.BundleBinding
	FileID                  string
	Route                   *vault.TunnelBundleBinding
	HTTPPath                string
	IgnoreCertificateErrors bool
	Temporary               bool
}

func (o *Owner) PlanWebConnection(ctx context.Context, q TunnelPlanRequest) (WebConnectionPlan, error) {
	if err := q.Validate(); err != nil {
		return WebConnectionPlan{}, err
	}
	if q.CredentialOverride != "" {
		return WebConnectionPlan{}, vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	// HTTP has no saved-account handoff. The candidate resolution authenticates
	// routing metadata without reading migration choices, credentials or settings.
	r, err := o.resolveCandidateRequest(ctx, q)
	if err != nil {
		return WebConnectionPlan{}, err
	}
	result, err := WebConnectionMetadata(r.Identity.WorkspaceID, q, r.Plan)
	if err != nil {
		return WebConnectionPlan{}, err
	}
	result.Temporary = r.quickID != ""
	result.FileID = r.Identity.FileID
	if r.Plan.TunnelID != "" {
		route, err := connectionTunnelBinding(r, q)
		if err != nil {
			return WebConnectionPlan{}, err
		}
		result.Route = &route
	}
	if err := ctx.Err(); err != nil {
		return WebConnectionPlan{}, err
	}
	return result, nil
}

// WebConnectionMetadata projects an authenticated resolver result into the
// common local/shared browser response. The caller retains route authority.
func WebConnectionMetadata(workspace string, q TunnelPlanRequest, p resolver.Plan) (WebConnectionPlan, error) {
	if (p.Protocol != 3 && p.Protocol != 4) || p.Host == "" || len(p.Host) > 1024 ||
		p.NodeID != q.NodeID ||
		strings.IndexFunc(p.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 || p.Port < 1 || p.Port > 65535 {
		return WebConnectionPlan{}, vault.ErrPolicy
	}
	return WebConnectionPlan{Binding: vault.BundleBinding{WorkspaceID: workspace, NodeID: q.NodeID,
		SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, Protocol: resolver.TunnelProtocol(p.Protocol), Host: p.Host, Port: uint16(p.Port), TunnelConfigID: p.TunnelID},
		HTTPPath: p.HTTPPath, IgnoreCertificateErrors: p.Protocol == 4 && p.IgnoreCertificateErrors}, nil
}
