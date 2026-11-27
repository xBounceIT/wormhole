package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type sharedSetupImportReview struct {
	id           uuid.UUID
	target       workspaceimport.Target
	source       localvault.WorkspaceImport
	preview      workspaceimport.Preview
	confirmation uuid.UUID
	prepared     *workspaceimport.Plan
}

type sharedSetupImportPreview struct {
	workspaceimport.Preview
	ReviewID     string `json:"reviewId"`
	Confirmation string `json:"confirmation,omitempty"`
}

func workspaceSetupImportTarget(invitation sharedpg.Invitation) workspaceimport.Target {
	i := invitation.Enrollment.Context
	return workspaceimport.Target{WorkspaceID: i.WorkspaceID, UserID: i.UserID,
		RequestID: uuid.NewSHA1(i.InviteID, []byte("wormhole/v1/setup-workspace-import"))}
}

func (h *vaultFoundationHandler) startSharedSetupImport(ctx context.Context, setup sharedSetupPlan, checkpoint *sharedpg.WorkspaceBootstrapCheckpoint) (json.RawMessage, error) {
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	var target workspaceimport.Target
	if err := checkpoint.BorrowJoin(func(i sharedpg.Invitation, _ []byte) error {
		target = workspaceSetupImportTarget(i)
		return nil
	}); err != nil {
		return nil, err
	}
	source, err := h.owner.CaptureWorkspaceImportWithFallbacks(ctx, workspaceImportFallback)
	if err != nil {
		return nil, err
	}
	preview, plan, err := workspaceimport.Prepare(ctx, source, target, workspaceimport.Selection{})
	if err != nil {
		return nil, err
	}
	review := &sharedSetupImportReview{id: uuid.New(), target: target, source: source, preview: preview}
	if len(preview.Changes) == 0 {
		review.approve(plan)
	}
	reply, err := review.response(setup)
	if err == nil {
		h.setupImport = review
	}
	return reply, err
}

func (r *sharedSetupImportReview) approve(plan *workspaceimport.Plan) {
	r.prepared, r.confirmation = nil, uuid.Nil
	if plan != nil && len(r.preview.Items) != 0 {
		r.prepared, r.confirmation = plan, uuid.New()
	}
}

func (r *sharedSetupImportReview) response(setup sharedSetupPlan) (json.RawMessage, error) {
	summary := sharedSetupImportPreview{Preview: r.preview, ReviewID: r.id.String()}
	if r.confirmation != uuid.Nil {
		summary.Confirmation = r.confirmation.String()
	}
	payload, err := json.Marshal(sharedSetupReply{Plan: &setup.Summary, Import: &summary})
	if err != nil || len(payload) > vaultwire.MaxFrameBytes-65536 {
		return nil, vault.ErrFormat
	}
	return payload, nil
}

func (h *vaultFoundationHandler) reviseSharedSetupImport(ctx context.Context, setup sharedSetupPlan, raw []byte) (json.RawMessage, error) {
	r := h.setupImport
	if h.owner == nil || r == nil || r.target.WorkspaceID.String() != setup.Summary.WorkspaceID {
		return nil, vaultwire.ErrProtocol
	}
	selection, err := decodeSetupImportReview(raw, r)
	if err != nil {
		return nil, err
	}
	preview, plan, err := workspaceimport.Prepare(ctx, r.source, r.target, selection)
	if err != nil {
		return nil, err
	}
	next := *r
	next.preview = preview
	next.approve(plan)
	reply, err := next.response(setup)
	if err == nil {
		h.setupImport = &next
	}
	return reply, err
}

func decodeSetupImportReview(raw []byte, r *sharedSetupImportReview) (workspaceimport.Selection, error) {
	var workspace, review string
	var shared, decisions []json.RawMessage
	if decodeVaultObject(raw, map[string]any{"workspaceId": &workspace, "reviewId": &review, "shared": &shared, "decisions": &decisions},
		"workspaceId", "reviewId", "shared", "decisions") != nil || workspace != r.target.WorkspaceID.String() || review != r.id.String() ||
		len(shared) > len(r.preview.Items) || len(decisions) != len(r.preview.Changes) {
		return workspaceimport.Selection{}, vaultwire.ErrProtocol
	}
	selection := workspaceimport.Selection{Review: &workspaceimport.ResolverReview{Fingerprint: r.preview.ResolverFingerprint}}
	for _, item := range shared {
		var id workspaceimport.ItemID
		if decodeVaultObject(item, map[string]any{"kind": &id.Kind, "id": &id.ID}, "kind", "id") != nil ||
			!vaultCredentialID(id.ID) || (id.Kind != "node" && id.Kind != "credential" && id.Kind != "tunnel") {
			return workspaceimport.Selection{}, vaultwire.ErrProtocol
		}
		selection.Shared = append(selection.Shared, id)
	}
	for _, entry := range decisions {
		var d resolver.MigrationDecision
		if decodeVaultObject(entry, map[string]any{"nodeId": &d.NodeID, "protocolPath": &d.ProtocolPath, "choice": &d.Choice}, "nodeId", "protocolPath", "choice") != nil ||
			!vaultCredentialID(d.NodeID) || len(d.ProtocolPath) > 32 || (d.Choice != "keep" && d.Choice != "new") {
			return workspaceimport.Selection{}, vaultwire.ErrProtocol
		}
		selection.Review.Decisions = append(selection.Review.Decisions, d)
	}
	return selection, nil
}

type sharedSetupImportSession interface {
	sharedRuntimeStateSession
	AccountEnrollmentMaterial(context.Context) (*sharedpg.UnverifiedAccountKeys, error)
	SetupImportSupported(context.Context) (bool, error)
	SetupImportCommitted(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, workspaceimport.Target, [32]byte, *vault.UserKeys) (bool, error)
	WorkspaceImportBoundary(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, workspaceimport.Destination) (sharedpg.TrustState, *vault.BoundaryManifest, error)
	EnsurePersonalImportBoundary(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *vault.UserKeys) (sharedpg.TrustState, *vault.BoundaryManifest, error)
	CommitSetupWorkspaceImport(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, workspaceimport.Target, [32]byte, *vault.UserKeys, *workspaceimport.SealedImport) error
}

func (c *sharedAdmissionController) publishSetupWorkspaceImport(ctx context.Context, source *localvault.Owner, plan *workspaceimport.Plan) error {
	session, ok := c.session.(sharedSetupImportSession)
	if !ok || source == nil || plan == nil {
		return sharedpg.ErrConfiguration
	}
	approval, err := plan.ApprovalDigest()
	if err != nil {
		return err
	}
	return c.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, tls *sharedpg.VerifiedTLSBundle) error {
		if tls == nil || plan.Target.WorkspaceID != trust.WorkspaceID || plan.Target.UserID != trust.UserID {
			return vault.ErrAuthentication
		}
		supported, err := session.SetupImportSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			return sharedpg.ErrWorkspaceImport
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrTrustState
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			committed, err := session.SetupImportCommitted(ctx, trust, tls, plan.Target, approval, keys)
			if err != nil || committed {
				return err
			}
			return c.sealAndCommitSetupImport(ctx, session, trust, tls, source, plan, approval, keys)
		})
	})
}

func (c *sharedAdmissionController) sealAndCommitSetupImport(ctx context.Context, session sharedSetupImportSession, trust sharedpg.TrustState,
	tls *sharedpg.VerifiedTLSBundle, source *localvault.Owner, plan *workspaceimport.Plan, approval [32]byte, keys *vault.UserKeys) error {
	advance := func(next sharedpg.TrustState, err error) error {
		if next.Revision != 0 && next.Revision != trust.Revision {
			if e := c.commitCatalogTrust(trust, next); e != nil {
				return e
			}
			trust = next
		}
		return err
	}
	material, err := session.AccountEnrollmentMaterial(ctx)
	if err != nil {
		return err
	}
	if material == nil || material.EnrollmentCertificate == nil {
		return vault.ErrAuthentication
	}
	if err := advance(trust.AdvanceEnrollment(*material.EnrollmentCertificate, trust.WrappingRevision)); err != nil {
		return err
	}
	anchor, err := trust.AccountTrust()
	if err != nil {
		return err
	}
	profile, err := trust.Policy()
	if err != nil {
		return err
	}
	authority := workspaceimport.Authority{Trust: anchor, Account: *trust.Account, Enrollment: *material.EnrollmentCertificate,
		MinimumEnrollmentRevision: trust.Enrollment.ManifestRevision, EscrowPersonal: profile.OrgEscrow}
	if plan.IncludesDestination(workspaceimport.Personal) {
		next, m, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, keys)
		if err := advance(next, err); err != nil {
			return err
		}
		if m == nil {
			return vault.ErrPolicy
		}
		authority.Personal = &workspaceimport.ImportBoundary{Manifest: *m, MinimumRevision: m.Revision}
	}
	if plan.IncludesDestination(workspaceimport.Shared) {
		next, m, err := session.WorkspaceImportBoundary(ctx, trust, tls, workspaceimport.Shared)
		if err := advance(next, err); err != nil {
			return err
		}
		if m == nil {
			return vault.ErrPolicy
		}
		authority.Shared = &workspaceimport.ImportBoundary{Manifest: *m, MinimumRevision: m.Revision}
	}
	sealed, err := stageVaultWorkspaceImport(ctx, source, plan, authority, keys.SigningSeed)
	if err != nil {
		return err
	}
	return session.CommitSetupWorkspaceImport(ctx, trust, tls, plan.Target, approval, keys, sealed)
}
