package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultWebPlan struct {
	Binding        vault.BundleBinding        `json:"binding"`
	Route          *vault.TunnelBundleBinding `json:"route"`
	Target         webTargetResponse          `json:"target"`
	Temporary      bool                       `json:"temporary,omitempty"`
	ArchiveBinding string                     `json:"archiveBinding,omitempty"`
	ViewGeneration string                     `json:"viewGeneration,omitempty"`
}

// Main-only metadata API. The ordinary renderer selects a saved node; it cannot
// override its destination, certificate rule or authenticated tunnel revision.
func (h *vaultFoundationHandler) webPlan(ctx context.Context, raw []byte, allowArchive bool) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 2048 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelPlanRequest
	var epoch string
	if decodeVaultObject(raw, map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride,
		"sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch},
		"nodeId", "credentialOverride", "sessionId", "requestId", "epoch") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || q.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	if q.CredentialOverride != "" {
		return nil, vault.ErrPolicy
	}
	var plan localvault.WebConnectionPlan
	var generation uuid.UUID
	if h.shared != nil {
		plan, generation, err = h.sharedWebPlan(ctx, q)
	} else {
		plan, err = h.owner.PlanWebConnection(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	path, err := normalizePersistedWebPath(plan.HTTPPath)
	if plan.Temporary {
		path, err = normalizeWebPath(plan.HTTPPath)
	}
	if err != nil {
		return nil, vault.ErrPolicy
	}
	b := plan.Binding
	uri, err := buildWebURLWithPath(b.Protocol, b.Host, int(b.Port), path)
	if err != nil {
		return nil, vault.ErrPolicy
	}
	result := vaultWebPlan{Binding: b, Route: plan.Route, Temporary: plan.Temporary, Target: webTargetResponse{
		URL: uri, Protocol: b.Protocol, Host: b.Host, Port: int(b.Port), IgnoreCertErrors: plan.IgnoreCertificateErrors,
		TunnelConfigID: b.TunnelConfigID}}
	if allowArchive && !plan.Temporary && (h.shared == nil || generation != uuid.Nil) {
		account := b.WorkspaceID
		if h.shared != nil {
			account = h.shared.controller.trustBinding.UserID.String()
		}
		fingerprint, err := browserArchiveBinding(plan, account, generation).Fingerprint()
		if err != nil {
			return nil, err
		}
		result.ArchiveBinding = hex.EncodeToString(fingerprint[:])
		if generation != uuid.Nil {
			result.ViewGeneration = generation.String()
		}
	}
	return json.Marshal(result)
}

func (h *vaultFoundationHandler) sharedWebPlan(ctx context.Context, q localvault.TunnelPlanRequest) (plan localvault.WebConnectionPlan, generation uuid.UUID, err error) {
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return plan, uuid.Nil, err
	}
	node := uuid.MustParse(q.NodeID)
	var projectionErr error
	err = c.withWebConnectionPlan(ctx, node, func(ctx context.Context, current sharedpg.ResolvedConnectionPlan) error {
		plan, projectionErr = sharedWebConnectionMetadata(c.trustBinding.WorkspaceID, h.shared.fileID, q, current)
		if projectionErr != nil {
			if errors.Is(projectionErr, vault.ErrAuthentication) {
				return projectionErr
			}
			return nil
		}
		cache, owner, e := c.webArchiveOwner()
		if e != nil || cache == nil || !webSessionPersistenceAllowed(c.runtimeProfile) {
			return e
		}
		if owner.FileID.String() != h.shared.fileID {
			return vault.ErrAuthentication
		}
		session, e := c.webViewSession(ctx)
		if e != nil || session == nil {
			return e
		}
		generation, e = session.OpenWebSessionView(ctx, node)
		return e
	})
	if err != nil {
		if errors.Is(err, sharedpg.ErrImportedConnectionPins) && c.Unlocked() {
			return plan, uuid.Nil, err
		}
		return plan, uuid.Nil, h.retire(err)
	}
	return plan, generation, projectionErr
}

func sharedWebConnectionMetadata(workspace uuid.UUID, fileID string, q localvault.TunnelPlanRequest, current sharedpg.ResolvedConnectionPlan) (localvault.WebConnectionPlan, error) {
	plan, err := localvault.WebConnectionMetadata(workspace.String(), q, current.Plan)
	if err != nil {
		return plan, err
	}
	plan.FileID = fileID
	if current.Plan.TunnelID != "" || current.Tunnel != nil {
		route, err := sharedTunnelBinding(workspace, fileID, current.Plan, q, current.Tunnel)
		if err != nil || route.BundleBinding != plan.Binding {
			return localvault.WebConnectionPlan{}, vault.ErrAuthentication
		}
		plan.Route = &route
	}
	return plan, nil
}

func browserArchiveBinding(plan localvault.WebConnectionPlan, account string, generation uuid.UUID) localvault.WebSessionBinding {
	b := plan.Binding
	result := localvault.WebSessionBinding{WorkspaceID: b.WorkspaceID, FileID: plan.FileID, AccountID: account,
		NodeID: b.NodeID, Protocol: b.Protocol, Host: b.Host, Port: b.Port, IgnoreCertificateErrors: plan.IgnoreCertificateErrors, TunnelID: b.TunnelConfigID}
	if plan.Route != nil {
		result.TunnelKind, result.TunnelRevision, result.ConfigurationVersion = plan.Route.Kind, plan.Route.RowVersion, plan.Route.ConfigurationVersion
	}
	if generation != uuid.Nil {
		result.ViewGeneration = generation.String()
	}
	return result
}
