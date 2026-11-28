package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type suspensionInventorySession interface {
	sharedWorkspaceAccessSession
	sharedAccountSuspensionSession
	sharedRuntimeStateSession
}

type sharedSuspensionReceiptSession interface {
	SuspensionReceiptsSupported(context.Context) (bool, error)
	SuspendWithReceipt(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, int64, sharedpg.WorkspaceAccessRequest, *vault.UserKeys) (sharedpg.WorkspaceAccessReply, error)
	ReadSuspensionReceipts(context.Context, vault.UserKeyTrust, int64, uuid.UUID) ([]sharedpg.SuspendedAccount, error)
}

func (c *sharedAdmissionController) wakeSuspensionRotation() {
	if c.rotationPending.Load() {
		select {
		case c.rotationWake <- struct{}{}:
		default:
		}
	}
}

func (c *sharedAdmissionController) monitorSuspensionRotations(session suspensionInventorySession) {
	var turn uint64
	next := make(map[string]int)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	timer.Stop()
	for {
		select {
		case <-c.lifetime.Done():
			return
		case <-c.rotationWake:
		case <-timer.C:
		}
		if !c.Unlocked() || !c.rotationPending.Load() {
			continue
		}
		changed, err := c.advanceSuspensionRotation(c.lifetime, session, next, turn, nil)
		if err != nil {
			_ = c.Close(context.Background())
			return
		}
		turn++
		if c.rotationPending.Load() {
			wait := 30 * time.Second
			if changed {
				wait = 250 * time.Millisecond
			}
			timer.Reset(wait)
		}
	}
}

type suspensionRotationStep struct {
	account   uuid.UUID
	revision  uint64
	workspace uuid.UUID
	entry     sharedpg.AccountSuspensionEntry
	ordinal   int
}

func (c *sharedAdmissionController) advanceSuspensionRotation(ctx context.Context, session suspensionInventorySession, nextIndex map[string]int, turn uint64, receipt *sharedpg.SuspendedAccount) (bool, error) {
	var step *suspensionRotationStep
	var cleared bool
	err := c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		var account string
		var revision uint64
		if receipt != nil {
			account, revision = receipt.ID.String(), receipt.Revision
			if trust.SuspensionRotations[account] >= revision {
				return nil // the local worker already owns this revision
			}
		} else {
			accounts := slices.Sorted(maps.Keys(trust.SuspensionRotations))
			if len(accounts) == 0 {
				return nil
			}
			account = accounts[turn%uint64(len(accounts))]
			revision = trust.SuspensionRotations[account]
		}
		state, err := c.observeRuntime(ctx, session, trust, pending)
		if err != nil || !state.Administrator {
			return err
		}
		// A review on an enabled account cannot disable it. A confirmed
		// operation that never committed must not disable somebody on restart.
		reply, err := session.WorkspaceAccess(ctx, *pending, sharedpg.WorkspaceAccessRequest{Action: "disable-account", TargetID: account})
		if err != nil {
			return err
		}
		var done bool
		switch reply.Status {
		case "review":
			if reply.Review == nil || reply.Review.TargetID != account || reply.Review.Action != "disable-account" || !reply.Review.WorkspaceAccessRequest.Valid() {
				return sharedpg.ErrAdmissionResponse
			}
			current, err := strconv.ParseUint(reply.Review.Revision, 10, 63)
			if err != nil || current < revision-1 {
				return sharedpg.ErrAdmissionResponse
			}
			done = true
		case "unchanged":
			step, done, err = nextSuspensionRotation(ctx, session, *pending, account, revision, nextIndex[account])
			if err != nil {
				return err
			}
		}
		if done && receipt == nil {
			next, err := pending.TrackSuspension(account, revision, true)
			if err != nil {
				return err
			}
			*pending, cleared = next, true
			delete(nextIndex, account)
		}
		return nil
	}, nil, false)
	if err != nil || step == nil {
		return cleared, err
	}
	result, err := step.run(ctx, c.rotateSuspendedRoot, c.rotateGroupMember)
	if err != nil {
		return false, err
	}
	next, progressed := step.nextAttempt(result)
	nextIndex[step.account.String()] = next
	return progressed, nil
}

// A group that just published a key or advanced its queue can retire the
// dependent boundary roots on the next inventory read. A blocked group yields
// its turn so independently authorized roots can still advance.
func (s suspensionRotationStep) nextAttempt(result string) (ordinal int, progressed bool) {
	if s.entry.Kind == "group" && (result == "rotated" || result == "pending" || result == "reconciled") {
		return s.ordinal, true
	}
	return s.ordinal + 1, result == "changed" || result == "complete"
}

func nextSuspensionRotation(ctx context.Context, session sharedAccountSuspensionSession, trust sharedpg.TrustState, account string, revision uint64, target int) (*suspensionRotationStep, bool, error) {
	expected := strconv.FormatUint(revision, 10)
	accountID, err := uuid.Parse(account)
	if err != nil || accountID == uuid.Nil || revision < 2 {
		return nil, false, sharedpg.ErrAdmissionResponse
	}
	var first *suspensionRotationStep
	ordinal := 0
	complete := true
	for _, kind := range []string{"groups", "roots"} {
		request := sharedpg.AccountSuspensionRequest{AccountID: account, Kind: kind}
		for {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			reply, err := session.AccountSuspensionInventory(ctx, trust, request)
			if err == nil && kind == "groups" && reply.Status == "unsupported" {
				break
			}
			if err != nil || reply.Status != "ready" {
				return nil, false, err
			}
			page := reply.Page
			if page == nil || page.AccountID != account || page.Kind != kind {
				return nil, false, sharedpg.ErrAdmissionResponse
			}
			if page.Revision != expected {
				newer, err := strconv.ParseUint(page.Revision, 10, 63)
				return nil, err == nil && newer > revision, err
			}
			for _, entry := range page.Entries {
				switch entry.Status {
				case "retired", "resolved":
				case "active", "needs-removal", "queued":
					if ordinal == 0 || ordinal == target {
						step := &suspensionRotationStep{account: accountID, workspace: trust.WorkspaceID, revision: revision, entry: entry, ordinal: ordinal}
						if ordinal == target {
							return step, false, nil
						}
						first = step
					}
					ordinal++
					complete = false
				default:
					// A restricted or waiting entry needs an authorized holder.
					complete = false
				}
			}
			if page.After == "" {
				break
			}
			request.After, request.Revision = page.After, expected
		}
	}
	return first, complete, nil
}

func rotationReview(encoded string) (*[32]byte, error) {
	var review [32]byte
	if len(encoded) != 64 {
		return nil, sharedpg.ErrAdmissionResponse
	}
	if _, err := hex.Decode(review[:], []byte(encoded)); err != nil || hex.EncodeToString(review[:]) != encoded {
		return nil, sharedpg.ErrAdmissionResponse
	}
	return &review, nil
}

func (s suspensionRotationStep) run(ctx context.Context, rotateRoot func(context.Context, sharedpg.AccountBoundaryRotationRequest) (sharedpg.AccountBoundaryRotationReply, error), rotateGroup func(context.Context, sharedpg.GroupMemberRotationRequest, bool) (sharedpg.GroupMemberRotationReply, error)) (string, error) {
	e := s.entry
	id, err := uuid.Parse(e.ID)
	if err != nil || id == uuid.Nil || s.account == uuid.Nil || s.workspace == uuid.Nil || s.revision < 2 || s.revision > math.MaxInt64 {
		return "", sharedpg.ErrAdmissionResponse
	}
	if e.Kind == "group" {
		// The job ID is stable after a lost response and cannot select another
		// group's work or an earlier suspension of the same user.
		job := uuid.NewHash(sha256.New(), s.workspace, []byte("wormhole/v1/suspension-group/"+s.account.String()+"/"+strconv.FormatUint(s.revision, 10)+"/"+e.ID), 8)
		request := sharedpg.GroupMemberRotationRequest{JobID: job, GroupID: id,
			Automatic: &sharedpg.SuspendedAccount{ID: s.account, Revision: s.revision}}
		if e.Status == "queued" {
			if e.JobID != job.String() {
				return "waiting", nil
			}
			reply, err := rotateGroup(ctx, request, true)
			if err != nil || reply.Status != "roster-changed" {
				return reply.Status, err
			}
			request.Reconcile = true
			reply, err = rotateGroup(ctx, request, false)
			if err != nil || reply.Status != "reconcile-review" {
				return reply.Status, err
			}
			p := reply.Reconciliation
			if p == nil || p.JobID != job || p.GroupID != id {
				return "", sharedpg.ErrAdmissionResponse
			}
			// Changes to another group's certified roster need its own review.
			if p.TargetGroupID != id || includesSuspendedMember(p.Members, s.account) {
				return "waiting", nil
			}
			request.Review, err = rotationReview(p.Review)
			if err != nil {
				return "", err
			}
			reply, err = rotateGroup(ctx, request, false)
			return reply.Status, err
		}
		request.MemberID, request.Suspension = s.account, s.revision
		request.Revision, err = strconv.ParseUint(e.Revision, 10, 63)
		if err != nil || request.Revision == 0 || e.Status != "needs-removal" {
			return "", sharedpg.ErrAdmissionResponse
		}
		if request.Revision == math.MaxInt64 {
			return "waiting", nil
		}
		reply, err := rotateGroup(ctx, request, false)
		if err != nil || reply.Status != "review" {
			return reply.Status, err
		}
		p := reply.Preview
		if p == nil || p.JobID != job || p.GroupID != id || p.MemberID != s.account || p.Revision != e.Revision ||
			p.Suspension != strconv.FormatUint(s.revision, 10) || includesSuspendedMember(p.Remaining, s.account) {
			return "", sharedpg.ErrAdmissionResponse
		}
		request.Review, err = rotationReview(reply.Preview.Review)
		if err != nil {
			return "", err
		}
		reply, err = rotateGroup(ctx, request, false)
		return reply.Status, err
	}
	boundary, err := uuid.Parse(e.BoundaryID)
	version, versionErr := strconv.ParseUint(e.Revision, 10, 31)
	if err != nil || boundary == uuid.Nil || versionErr != nil || version == 0 || (e.Kind != "view" && e.Kind != "secret") || e.Status != "active" {
		return "", sharedpg.ErrAdmissionResponse
	}
	if version == math.MaxInt32 {
		return "waiting", nil
	}
	request := sharedpg.AccountBoundaryRotationRequest{AccountID: s.account, Suspension: s.revision, BoundaryID: boundary, Root: vault.KeyRef{ID: id, Version: uint32(version)}, Affected: permissions.View}
	if e.Kind == "secret" {
		request.Affected = permissions.Use
	}
	reply, err := rotateRoot(ctx, request)
	if err != nil || reply.Status != "review" {
		return reply.Status, err
	}
	request.Review, err = rotationReview(reply.Review)
	if err != nil {
		return "", err
	}
	reply, err = rotateRoot(ctx, request)
	return reply.Status, err
}

func includesSuspendedMember(members []sharedpg.GroupKeyMember, account uuid.UUID) bool {
	return slices.ContainsFunc(members, func(member sharedpg.GroupKeyMember) bool { return member.ID == account })
}
