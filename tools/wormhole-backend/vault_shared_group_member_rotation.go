package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedGroupMemberRotationSession interface {
	sharedRuntimeStateSession
	GroupMemberAdditionSupported(context.Context) (bool, error)
	PrepareGroupMemberAddition(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupMemberRotationRequest) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, *sharedpg.GroupMemberAdditionPreparation, error)
	CommitPreparedGroupMemberAddition(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupMemberAdditionPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, error)
	GroupMemberReconciliationSupported(context.Context) (bool, error)
	PrepareGroupMemberReconciliation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupMemberRotationRequest) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, *sharedpg.GroupMemberReconciliationPreparation, error)
	CommitPreparedGroupMemberReconciliation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupMemberReconciliationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, error)
	GroupMemberRotationSupported(context.Context) (bool, error)
	PrepareGroupMemberRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupMemberRotationRequest) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, *sharedpg.GroupMemberRotationPreparation, error)
	CommitPreparedGroupMemberRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupMemberRotationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupMemberRotationReply, error)
	ReadGroupMemberRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, uuid.UUID) (*sharedpg.GroupMemberRotationProgress, error)
	PrepareMemberBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.MemberBoundaryRotationRequest) (sharedpg.TrustState, string, *[32]byte, *sharedpg.MemberBoundaryRotationPreparation, error)
	CommitPreparedMemberBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.MemberBoundaryRotationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, error)
}

func decodeSharedMemberRotation(raw []byte) (request sharedpg.GroupMemberRotationRequest, resume bool, err error) {
	var action, group string
	var job, member, login, revision, review *string
	var suspension json.RawMessage
	if len(raw) > 1024 || decodeVaultObject(raw, map[string]any{"action": &action, "groupId": &group, "jobId": &job,
		"memberId": &member, "login": &login, "revision": &revision, "review": &review, "suspension": &suspension}, "action", "groupId") != nil ||
		!vaultCredentialID(group) || (job != nil && !vaultCredentialID(*job)) || (len(suspension) != 0 && action != "remove") {
		return request, false, vaultwire.ErrProtocol
	}
	request.GroupID = uuid.MustParse(group)
	if job != nil {
		request.JobID = uuid.MustParse(*job)
	}
	if action == "resume" {
		if member != nil || revision != nil || review != nil || login != nil {
			return request, false, vaultwire.ErrProtocol
		}
		return request, true, nil
	}
	if request.JobID == uuid.Nil {
		return request, false, vaultwire.ErrProtocol
	}
	if action != "reconcile" {
		if revision == nil {
			return request, false, vaultwire.ErrProtocol
		}
		v, err := vaultCredentialRevision(*revision, false)
		if err != nil || v == math.MaxInt64 {
			return request, false, vaultwire.ErrProtocol
		}
		request.Revision = v
	}
	switch action {
	case "reconcile":
		if member != nil || login != nil || revision != nil {
			return request, false, vaultwire.ErrProtocol
		}
		request.Reconcile = true
	case "remove":
		if member == nil || !vaultCredentialID(*member) || login != nil {
			return request, false, vaultwire.ErrProtocol
		}
		request.MemberID = uuid.MustParse(*member)
		if len(suspension) != 0 {
			var value string
			if json.Unmarshal(suspension, &value) != nil {
				return request, false, vaultwire.ErrProtocol
			}
			scope, err := vaultCredentialRevision(value, false)
			if err != nil {
				return request, false, vaultwire.ErrProtocol
			}
			request.Suspension = scope
		}
	case "add":
		if login == nil || member != nil {
			return request, false, vaultwire.ErrProtocol
		}
		request.Login = *login
		if !request.ValidAddition() {
			return request, false, vaultwire.ErrProtocol
		}
	default:
		return request, false, vaultwire.ErrProtocol
	}
	if review != nil {
		var digest [32]byte
		if len(*review) != 64 {
			return request, false, vaultwire.ErrProtocol
		}
		if _, err := hex.Decode(digest[:], []byte(*review)); err != nil || hex.EncodeToString(digest[:]) != *review {
			return request, false, vaultwire.ErrProtocol
		}
		request.Review = &digest
	}
	return request, false, nil
}

func (h *vaultFoundationHandler) sharedGroupMemberRotation(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, resume, err := decodeSharedMemberRotation(raw)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	reply, err := c.rotateGroupMember(ctx, request, resume)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}

func (c *sharedAdmissionController) rotateGroupMember(ctx context.Context, request sharedpg.GroupMemberRotationRequest, resume bool) (sharedpg.GroupMemberRotationReply, error) {
	session, ok := c.session.(sharedGroupMemberRotationSession)
	if !ok {
		return sharedpg.GroupMemberRotationReply{}, sharedpg.ErrConfiguration
	}
	reply := sharedpg.GroupMemberRotationReply{Status: "unavailable"}
	var bundle *sharedpg.VerifiedTLSBundle
	var member *sharedpg.GroupMemberRotationPreparation
	var addition *sharedpg.GroupMemberAdditionPreparation
	var reconciliation *sharedpg.GroupMemberReconciliationPreparation
	var boundary *sharedpg.MemberBoundaryRotationPreparation
	err := c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		runtime, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !runtime.Administrator {
			return err
		}
		capability := session.GroupMemberRotationSupported
		switch {
		case request.Reconcile:
			capability = session.GroupMemberReconciliationSupported
		case request.Login != "":
			capability = session.GroupMemberAdditionSupported
		}
		supported, err := capability(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		bundle, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		if resume {
			boundary, err = prepareMemberRotationStep(ctx, session, pending, bundle, &request, &reply)
		} else {
			var observed sharedpg.TrustState
			switch {
			case request.Reconcile:
				observed, reply, reconciliation, err = session.PrepareGroupMemberReconciliation(ctx, *pending, bundle, request)
			case request.Login != "":
				observed, reply, addition, err = session.PrepareGroupMemberAddition(ctx, *pending, bundle, request)
			default:
				observed, reply, member, err = session.PrepareGroupMemberRotation(ctx, *pending, bundle, request)
			}
			if observed.Revision != 0 {
				*pending = observed
			}
		}
		if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
			reply = sharedpg.GroupMemberRotationReply{Status: "unavailable"}
			return nil
		}
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if member == nil && boundary == nil && addition == nil && reconciliation == nil {
			return nil
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrAuthentication
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			var next sharedpg.TrustState
			var err error
			switch {
			case reconciliation != nil:
				next, reply, err = session.CommitPreparedGroupMemberReconciliation(ctx, trust, bundle, reconciliation, keys)
			case addition != nil:
				next, reply, err = session.CommitPreparedGroupMemberAddition(ctx, trust, bundle, addition, keys)
			case member != nil:
				next, reply, err = session.CommitPreparedGroupMemberRotation(ctx, trust, bundle, member, keys)
			default:
				var rotated sharedpg.GroupBoundaryGrantReply
				next, rotated, err = session.CommitPreparedMemberBoundaryRotation(ctx, trust, bundle, boundary, keys)
				reply.Status = rotated.Status
			}
			if next.Revision != 0 && next.Revision != trust.Revision {
				if e := c.commitCatalogTrust(trust, next); e != nil {
					return e
				}
			}
			if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
				reply = sharedpg.GroupMemberRotationReply{Status: "unavailable"}
				return nil
			}
			if err != nil || boundary == nil || (reply.Status != "changed" && reply.Status != "unchanged" && reply.Status != "roster-changed") {
				return err
			}
			changed := reply.Status == "roster-changed"
			result, err := session.ReadGroupMemberRotation(ctx, next, bundle, request.GroupID, request.JobID)
			setMemberRotationProgress(&reply, result, request.JobID)
			if changed && reply.Status == "pending" {
				reply.Status = "roster-changed"
			}
			return err
		})
	}, false)
	return reply, err
}

func setMemberRotationProgress(reply *sharedpg.GroupMemberRotationReply, progress *sharedpg.GroupMemberRotationProgress, requestedJob uuid.UUID) {
	if progress == nil {
		*reply = sharedpg.GroupMemberRotationReply{Status: "complete"}
		if requestedJob != uuid.Nil {
			reply.Status = "unavailable"
		}
		return
	}
	reply.Receipt = &sharedpg.GroupMemberRotationReceipt{JobID: progress.JobID, Pending: progress.Pending}
	switch {
	case progress.Pending == 0:
		reply.Status = "complete"
	case progress.Next == uuid.Nil:
		reply.Status = "unavailable"
		reply.Receipt = nil
	default:
		reply.Status = "pending"
	}
}

func prepareMemberRotationStep(ctx context.Context, session sharedGroupMemberRotationSession, pending *sharedpg.TrustState,
	tls *sharedpg.VerifiedTLSBundle, request *sharedpg.GroupMemberRotationRequest, reply *sharedpg.GroupMemberRotationReply) (*sharedpg.MemberBoundaryRotationPreparation, error) {
	progress, err := session.ReadGroupMemberRotation(ctx, *pending, tls, request.GroupID, request.JobID)
	if err != nil {
		return nil, err
	}
	setMemberRotationProgress(reply, progress, request.JobID)
	if reply.Status != "pending" {
		return nil, nil
	}
	request.JobID = progress.JobID
	step := sharedpg.MemberBoundaryRotationRequest{JobID: progress.JobID, GroupID: progress.GroupID, BoundaryID: progress.Next}
	next, status, review, _, err := session.PrepareMemberBoundaryRotation(ctx, *pending, tls, step)
	if next.Revision != 0 {
		*pending = next
	}
	if err == nil && status == "unchanged" {
		progress, err := session.ReadGroupMemberRotation(ctx, *pending, tls, request.GroupID, request.JobID)
		setMemberRotationProgress(reply, progress, request.JobID)
		return nil, err
	}
	if err == nil && status == "roster-changed" {
		reply.Status = status
		return nil, nil
	}
	if err == nil && status == "review" && review == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	if err != nil || status != "review" || review == nil {
		*reply = sharedpg.GroupMemberRotationReply{Status: status}
		return nil, err
	}
	step.Review = review
	next, status, _, plan, err := session.PrepareMemberBoundaryRotation(ctx, *pending, tls, step)
	if next.Revision != 0 {
		*pending = next
	}
	if err == nil && status == "unchanged" {
		progress, err := session.ReadGroupMemberRotation(ctx, *pending, tls, request.GroupID, request.JobID)
		setMemberRotationProgress(reply, progress, request.JobID)
		return nil, err
	}
	if err == nil && status == "roster-changed" {
		reply.Status = status
		return nil, nil
	}
	*reply = sharedpg.GroupMemberRotationReply{Status: status}
	if status == "ready" && plan == nil && err == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	return plan, err
}
