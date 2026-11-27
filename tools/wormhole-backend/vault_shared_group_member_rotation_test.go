package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestDecodeSharedMemberRotation(t *testing.T) {
	group, job, member := uuid.New(), uuid.New(), uuid.New()
	decode := func(input map[string]any) (sharedpg.GroupMemberRotationRequest, bool, error) {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return decodeSharedMemberRotation(raw)
	}
	resume := map[string]any{"action": "resume", "groupId": group}
	if result, isResume, err := decode(resume); err != nil || !isResume || result.GroupID != group || result.JobID != uuid.Nil {
		t.Fatal("could not discover pending work by group", err)
	}
	for field, value := range map[string]any{"jobId": "", "memberId": "", "revision": "", "review": nil, "recipient": member, "suspension": "1"} {
		resume[field] = value
		if _, _, err := decode(resume); err != vaultwire.ErrProtocol {
			t.Fatal("invalid resume field was accepted", field, err)
		}
		delete(resume, field)
	}
	remove := map[string]any{"action": "remove", "groupId": group, "jobId": job, "memberId": member, "revision": "5", "review": strings.Repeat("a1", 32)}
	if result, isResume, err := decode(remove); err != nil || isResume || result.GroupID != group || result.JobID != job ||
		result.MemberID != member || result.Revision != 5 || result.Review == nil || result.Review[0] != 0xa1 {
		t.Fatal("could not bind removal to the exact confirmation", err)
	}
	for field, value := range map[string]any{"jobId": uuid.Nil, "memberId": nil, "revision": "9223372036854775807", "review": strings.Repeat("A1", 32)} {
		previous := remove[field]
		remove[field] = value
		if _, _, err := decode(remove); err != vaultwire.ErrProtocol {
			t.Fatal("invalid removal field was accepted", field, err)
		}
		remove[field] = previous
	}
	remove["suspension"] = "9223372036854775807"
	if result, _, err := decode(remove); err != nil || result.Suspension != 1<<63-1 {
		t.Fatal("could not decode a canonical suspension revision", err)
	}
	for _, invalid := range []any{0, nil, "0", "04", "9223372036854775808"} {
		remove["suspension"] = invalid
		if _, _, err := decode(remove); err != vaultwire.ErrProtocol {
			t.Fatal("invalid suspension revision reached removal", invalid, err)
		}
	}
	add := map[string]any{"action": "add", "groupId": group, "jobId": job, "login": "alice", "revision": "5"}
	if result, isResume, err := decode(add); err != nil || isResume || result.GroupID != group || result.JobID != job ||
		result.Login != "alice" || result.MemberID != uuid.Nil || result.Revision != 5 || result.Review != nil {
		t.Fatal("could not decode the exact add selection", err)
	}
	for field, value := range map[string]any{"memberId": member, "login": "ali\nce", "action": "other", "suspension": "2"} {
		previous, existed := add[field]
		add[field] = value
		if _, _, err := decode(add); err != vaultwire.ErrProtocol {
			t.Fatal("addition accepted an invalid field", field, err)
		}
		if existed {
			add[field] = previous
		} else {
			delete(add, field)
		}
	}
	reconcile := map[string]any{"action": "reconcile", "groupId": group, "jobId": job, "review": strings.Repeat("a1", 32)}
	if result, isResume, err := decode(reconcile); err != nil || isResume || !result.Reconcile || result.GroupID != group || result.JobID != job ||
		result.Review == nil || result.Review[0] != 0xa1 {
		t.Fatal("could not bind reconciliation to the original job and review", err)
	}
	for field, value := range map[string]any{"memberId": member, "revision": "5", "login": "alice", "targetGroupId": uuid.New(), "suspension": "2"} {
		reconcile[field] = value
		if _, _, err := decode(reconcile); err != vaultwire.ErrProtocol {
			t.Fatal("reconciliation accepted an extra selection", field, err)
		}
		delete(reconcile, field)
	}
}

type memberRotationStepProbe struct {
	sharedGroupMemberRotationSession
	read    func(uuid.UUID, uuid.UUID) *sharedpg.GroupMemberRotationProgress
	prepare func(sharedpg.MemberBoundaryRotationRequest) (string, *[32]byte)
}

func (p memberRotationStepProbe) ReadGroupMemberRotation(_ context.Context, _ sharedpg.TrustState, _ *sharedpg.VerifiedTLSBundle, group, job uuid.UUID) (*sharedpg.GroupMemberRotationProgress, error) {
	return p.read(group, job), nil
}

func (p memberRotationStepProbe) PrepareMemberBoundaryRotation(_ context.Context, trust sharedpg.TrustState, _ *sharedpg.VerifiedTLSBundle, request sharedpg.MemberBoundaryRotationRequest) (sharedpg.TrustState, string, *[32]byte, *sharedpg.MemberBoundaryRotationPreparation, error) {
	status, review := p.prepare(request)
	return trust, status, review, nil, nil
}

func TestMemberRotationOnlyConfirmsAnIdentifiedJob(t *testing.T) {
	job := uuid.New()
	for _, test := range []struct {
		name     string
		job      uuid.UUID
		progress *sharedpg.GroupMemberRotationProgress
		status   string
		receipt  bool
	}{
		{"nothing to discover", uuid.Nil, nil, "complete", false},
		{"unknown job", job, nil, "unavailable", false},
		{"known completed job", job, &sharedpg.GroupMemberRotationProgress{JobID: job}, "complete", true},
		{"no accessible boundary", job, &sharedpg.GroupMemberRotationProgress{JobID: job, Pending: 1}, "unavailable", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := memberRotationStepProbe{read: func(_, _ uuid.UUID) *sharedpg.GroupMemberRotationProgress { return test.progress }}
			request := sharedpg.GroupMemberRotationRequest{GroupID: uuid.New(), JobID: test.job}
			var trust sharedpg.TrustState
			var reply sharedpg.GroupMemberRotationReply
			plan, err := prepareMemberRotationStep(context.Background(), session, &trust, nil, &request, &reply)
			if err != nil || plan != nil || reply.Status != test.status || (reply.Receipt != nil) != test.receipt ||
				(reply.Receipt != nil && (reply.Receipt.JobID != test.job || reply.Receipt.Pending != 0)) {
				t.Fatal("resume misreported the requested job", reply, err)
			}
		})
	}
}

func TestMemberRotationReturnsItsJobWhenRecipientsChange(t *testing.T) {
	group, job, boundary := uuid.New(), uuid.New(), uuid.New()
	for _, duringConfirmation := range []bool{false, true} {
		requested := sharedpg.GroupMemberRotationRequest{GroupID: group}
		var trust sharedpg.TrustState
		var result sharedpg.GroupMemberRotationReply
		var calls int
		session := memberRotationStepProbe{
			read: func(groupID, jobID uuid.UUID) *sharedpg.GroupMemberRotationProgress {
				if groupID != group || jobID != uuid.Nil {
					t.Fatal("resume did not discover the original pending job")
				}
				return &sharedpg.GroupMemberRotationProgress{GroupID: group, JobID: job, Next: boundary, Pending: 1}
			},
			prepare: func(step sharedpg.MemberBoundaryRotationRequest) (string, *[32]byte) {
				calls++
				if step.GroupID != group || step.JobID != job || step.BoundaryID != boundary {
					t.Fatal("resume selected an unrelated job")
				}
				if duringConfirmation && step.Review == nil {
					return "review", &[32]byte{7}
				}
				return "roster-changed", nil
			},
		}
		prepared, err := prepareMemberRotationStep(context.Background(), session, &trust, nil, &requested, &result)
		if err != nil || prepared != nil || result.Status != "roster-changed" || result.Receipt == nil || result.Receipt.JobID != job ||
			result.Receipt.Pending != 1 || (calls == 2) != duringConfirmation {
			t.Fatal("resume did not return the original job for confirmation of changed recipients", result, err)
		}
	}
}

func TestMemberRotationResumesAfterAnotherCustodianFinishesStep(t *testing.T) {
	group, job, first, second := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, phase := range []string{"preview", "confirmation"} {
		t.Run(phase, func(t *testing.T) {
			var reads, preparations int
			digest := [32]byte{5}
			session := memberRotationStepProbe{
				read: func(target, requested uuid.UUID) *sharedpg.GroupMemberRotationProgress {
					reads++
					if target != group || (reads == 1 && requested != uuid.Nil) || (reads == 2 && requested != job) {
						t.Fatal("resume changed groups or rediscovered the job during a race")
					}
					if reads == 1 {
						return &sharedpg.GroupMemberRotationProgress{GroupID: group, JobID: job, Pending: 2, Next: first}
					}
					return &sharedpg.GroupMemberRotationProgress{GroupID: group, JobID: job, Pending: 1, Next: second}
				},
				prepare: func(step sharedpg.MemberBoundaryRotationRequest) (string, *[32]byte) {
					preparations++
					if step.GroupID != group || step.JobID != job || step.BoundaryID != first {
						t.Fatal("resume changed the scope of a boundary review")
					}
					if phase == "confirmation" && preparations == 1 {
						return "review", &digest
					}
					if phase == "confirmation" && (step.Review == nil || *step.Review != digest) {
						t.Fatal("the worker confirmation was not bound to its review")
					}
					return "unchanged", nil
				},
			}
			request := sharedpg.GroupMemberRotationRequest{GroupID: group}
			var trust sharedpg.TrustState
			var reply sharedpg.GroupMemberRotationReply
			plan, err := prepareMemberRotationStep(context.Background(), session, &trust, nil, &request, &reply)
			if err != nil || reads != 2 || plan != nil || reply.Status != "pending" || reply.Receipt == nil || reply.Receipt.Pending != 1 || reply.Receipt.JobID != job {
				t.Fatal("resume did not reconcile progress before attempting a different boundary", reply.Status, err)
			}
		})
	}
}
