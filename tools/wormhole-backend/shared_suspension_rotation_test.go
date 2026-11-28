package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

type suspensionPages struct {
	sharedAccountSuspensionSession
	read func(sharedpg.AccountSuspensionRequest) (sharedpg.AccountSuspensionReply, error)
}

func (p suspensionPages) AccountSuspensionInventory(_ context.Context, _ sharedpg.TrustState, r sharedpg.AccountSuspensionRequest) (sharedpg.AccountSuspensionReply, error) {
	return p.read(r)
}

func TestSuspensionRotationInventory(t *testing.T) {
	account := uuid.NewString()
	trust := sharedpg.TrustState{WorkspaceID: uuid.New()}
	group := sharedpg.AccountSuspensionEntry{Kind: "group", Status: "needs-removal", ID: uuid.NewString()}
	root := sharedpg.AccountSuspensionEntry{Kind: "view", Status: "active", ID: uuid.NewString()}
	var firstStatus, rootsRevision string
	var roots []sharedpg.AccountSuspensionEntry
	probe := suspensionPages{read: func(r sharedpg.AccountSuspensionRequest) (sharedpg.AccountSuspensionReply, error) {
		if r.AccountID != account || !r.Valid() {
			t.Fatalf("invalid inventory request %+v", r)
		}
		p := &sharedpg.AccountSuspensionPage{AccountID: account, Kind: r.Kind, Revision: "3"}
		if r.Kind == "groups" {
			if firstStatus != "" {
				return sharedpg.AccountSuspensionReply{Status: firstStatus}, nil
			}
			if r.After == "" {
				p.Entries = []sharedpg.AccountSuspensionEntry{{Status: "resolved"}}
				p.After = "1"
			} else if r.After == "1" && r.Revision == "3" {
				p.Entries = []sharedpg.AccountSuspensionEntry{group}
			} else {
				t.Fatalf("wrong continuation %+v", r)
			}
		} else {
			p.Entries, p.Revision = roots, rootsRevision
		}
		return sharedpg.AccountSuspensionReply{Status: "ready", Page: p}, nil
	}}
	rootsRevision, roots = "3", []sharedpg.AccountSuspensionEntry{root}
	for index, want := range []string{group.ID, root.ID, group.ID} {
		step, done, err := nextSuspensionRotation(t.Context(), probe, trust, account, 3, index)
		if err != nil || done || step == nil || step.entry.ID != want || step.account.String() != account || step.workspace != trust.WorkspaceID || step.revision != 3 {
			t.Fatal(index, step, done, err)
		}
	}
	firstStatus = "unsupported"
	for _, test := range []struct {
		revision, status string
		done             bool
	}{
		{"4", "active", true}, {"2", "retired", false}, {"3", "retired", true}, {"3", "rotating", false}, {"3", "", false},
	} {
		rootsRevision, roots = test.revision, []sharedpg.AccountSuspensionEntry{{Status: test.status}}
		step, done, err := nextSuspensionRotation(t.Context(), probe, trust, account, 3, 0)
		if err != nil || step != nil || done != test.done {
			t.Fatal(test, done, err)
		}
	}
	firstStatus = "busy"
	if step, done, err := nextSuspensionRotation(t.Context(), probe, trust, account, 3, 0); err != nil || done || step != nil {
		t.Fatal(step, done, err)
	}
	probe.read = func(sharedpg.AccountSuspensionRequest) (sharedpg.AccountSuspensionReply, error) {
		return sharedpg.AccountSuspensionReply{Status: "ready"}, nil
	}
	if _, _, err := nextSuspensionRotation(t.Context(), probe, trust, account, 3, 0); !errors.Is(err, sharedpg.ErrAdmissionResponse) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := nextSuspensionRotation(ctx, probe, trust, account, 3, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSuspensionRotationRootConfirmsExactKey(t *testing.T) {
	step := suspensionRotationStep{account: uuid.New(), workspace: uuid.New(), revision: 7,
		entry: sharedpg.AccountSuspensionEntry{ID: uuid.NewString(), BoundaryID: uuid.NewString(), Status: "active", Revision: "42"}}
	for kind, purpose := range map[string]permissions.Mask{"view": permissions.View, "secret": permissions.Use} {
		step.entry.Kind = kind
		for _, test := range []struct {
			preview, digest, result string
			calls                   int
			invalid                 bool
		}{
			{"review", strings.Repeat("aa", 32), "changed", 2, false}, {"unavailable", "", "unavailable", 1, false},
			{"review", strings.Repeat("A0", 32), "", 1, true}, {"review", "short", "", 1, true},
		} {
			calls := 0
			result, err := step.run(t.Context(), func(_ context.Context, r sharedpg.AccountBoundaryRotationRequest) (sharedpg.AccountBoundaryRotationReply, error) {
				calls++
				if !r.Valid() || r.AccountID != step.account || r.Suspension != 7 || r.BoundaryID.String() != step.entry.BoundaryID ||
					r.Root.ID.String() != step.entry.ID || r.Root.Version != 42 || r.Affected != purpose {
					t.Fatalf("wrong key scope %+v", r)
				}
				if calls == 1 && r.Review == nil {
					return sharedpg.AccountBoundaryRotationReply{Status: test.preview, Review: test.digest}, nil
				}
				if calls != 2 || r.Review == nil || string(r.Review[:]) != strings.Repeat("\xaa", 32) {
					t.Fatal("wrong review")
				}
				return sharedpg.AccountBoundaryRotationReply{Status: "changed"}, nil
			}, nil)
			if result != test.result || calls != test.calls || errors.Is(err, sharedpg.ErrAdmissionResponse) != test.invalid {
				t.Fatal(test, result, err, calls)
			}
		}
	}
	step.entry.Revision = "2147483647"
	if status, err := step.run(t.Context(), nil, nil); err != nil || status != "waiting" {
		t.Fatal(status, err)
	}
	step.entry.ID = ""
	if _, err := step.run(t.Context(), nil, nil); !errors.Is(err, sharedpg.ErrAdmissionResponse) {
		t.Fatal(err)
	}
}

func TestSuspensionRotationNextAttempt(t *testing.T) {
	for _, tc := range []struct {
		kind, status string
		next         int
		progressed   bool
	}{
		{"group", "rotated", 2, true}, {"group", "pending", 2, true}, {"group", "reconciled", 2, true},
		{"group", "complete", 3, true}, {"group", "waiting", 3, false}, {"group", "busy", 3, false},
		{"secret", "group-rotation-required", 3, false}, {"view", "changed", 3, true},
	} {
		step := suspensionRotationStep{ordinal: 2, entry: sharedpg.AccountSuspensionEntry{Kind: tc.kind}}
		if n, progressed := step.nextAttempt(tc.status); n != tc.next || progressed != tc.progressed {
			t.Errorf("%s %s: next=%d progressed=%t", tc.kind, tc.status, n, progressed)
		}
	}
}

func TestSuspensionRotationGroupResumesOnlyConfirmedJob(t *testing.T) {
	group, remaining := uuid.New(), uuid.New()
	s := suspensionRotationStep{account: uuid.New(), workspace: uuid.New(), revision: 5,
		entry: sharedpg.AccountSuspensionEntry{ID: group.String(), Kind: "group", Status: "needs-removal", Revision: "12"}}
	digest := strings.Repeat("1f", 32)
	var job uuid.UUID
	checkAuthority := func(t *testing.T, r sharedpg.GroupMemberRotationRequest) {
		t.Helper()
		if r.Automatic == nil || r.Automatic.ID != s.account || r.Automatic.Revision != s.revision {
			t.Fatalf("group rotation lost its suspension authority: %+v", r.Automatic)
		}
	}
	for _, wrong := range []bool{false, true} {
		calls := 0
		status, err := s.run(t.Context(), nil, func(_ context.Context, r sharedpg.GroupMemberRotationRequest, resume bool) (sharedpg.GroupMemberRotationReply, error) {
			calls++
			checkAuthority(t, r)
			if resume || r.Reconcile || r.GroupID != group || r.MemberID != s.account || r.Revision != 12 || r.Suspension != 5 || r.JobID == uuid.Nil || (job != uuid.Nil && r.JobID != job) {
				t.Fatalf("wrong scope %+v", r)
			}
			job = r.JobID
			if r.Review != nil {
				return sharedpg.GroupMemberRotationReply{Status: "rotated"}, nil
			}
			p := &sharedpg.GroupMemberRotationPreview{JobID: job, GroupID: group, MemberID: s.account, Revision: "12", Suspension: "5", Review: digest, Remaining: []sharedpg.GroupKeyMember{{ID: remaining}}}
			if wrong {
				p.MemberID = remaining
			}
			return sharedpg.GroupMemberRotationReply{Status: "review", Preview: p}, nil
		})
		if wrong && (err != sharedpg.ErrAdmissionResponse || calls != 1) || !wrong && (err != nil || status != "rotated" || calls != 2) {
			t.Fatal(status, err, calls)
		}
	}
	s.entry.Status = "queued"
	s.entry.JobID = uuid.NewString()
	if result, err := s.run(t.Context(), nil, nil); err != nil || result != "waiting" {
		t.Fatal(result, err)
	}
	s.entry.JobID = job.String()
	for _, mode := range []string{"complete", "reconcile", "overlap", "suspended-member", "wrong-job", "busy"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			status, err := s.run(t.Context(), nil, func(_ context.Context, r sharedpg.GroupMemberRotationRequest, resume bool) (sharedpg.GroupMemberRotationReply, error) {
				calls++
				checkAuthority(t, r)
				if r.JobID != job || r.GroupID != group || r.MemberID != uuid.Nil {
					t.Fatal("unexpected job", r)
				}
				if resume {
					if calls != 1 || r.Review != nil || r.Reconcile {
						t.Fatal(r)
					}
					if mode == "complete" {
						return sharedpg.GroupMemberRotationReply{Status: "complete"}, nil
					}
					return sharedpg.GroupMemberRotationReply{Status: "roster-changed"}, nil
				}
				if !r.Reconcile {
					t.Fatal("not a roster reconciliation")
				}
				if r.Review != nil {
					if calls != 3 || string(r.Review[:]) != strings.Repeat("\x1f", 32) {
						t.Fatal("unreviewed reconciliation")
					}
					return sharedpg.GroupMemberRotationReply{Status: "reconciled"}, nil
				}
				p := &sharedpg.GroupMemberReconciliationPreview{JobID: job, GroupID: group, TargetGroupID: group, Members: []sharedpg.GroupKeyMember{{ID: remaining}}, Review: digest}
				switch mode {
				case "overlap":
					p.TargetGroupID = uuid.New()
				case "suspended-member":
					p.Members[0].ID = s.account
				case "wrong-job":
					p.JobID = uuid.New()
				case "busy":
					return sharedpg.GroupMemberRotationReply{Status: "busy"}, nil
				}
				return sharedpg.GroupMemberRotationReply{Status: "reconcile-review", Reconciliation: p}, nil
			})
			want := map[string]string{"complete": "complete", "reconcile": "reconciled", "overlap": "waiting", "suspended-member": "waiting", "wrong-job": "", "busy": "busy"}[mode]
			if status != want || (err == sharedpg.ErrAdmissionResponse) != (mode == "wrong-job") || (calls == 3) != (mode == "reconcile") {
				t.Fatal(status, err, calls)
			}
		})
	}
	s.revision++
	if result, err := s.run(t.Context(), nil, nil); err != nil || result != "waiting" {
		t.Fatal("prior suspension reused", strconv.FormatUint(s.revision, 10), result, err)
	}
}
