package sharedpg

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGroupBoundaryGrantRejectsUnboundRequests(t *testing.T) {
	valid := GroupBoundaryGrantRequest{NodeID: uuid.NewString(), NodeRevision: "1", BoundaryID: uuid.NewString(),
		GroupID: uuid.NewString(), GroupRevision: "1", Mask: 1}
	for _, modify := range []func(*GroupBoundaryGrantRequest){
		func(r *GroupBoundaryGrantRequest) { r.BoundaryID = uuid.Nil.String() },
		func(r *GroupBoundaryGrantRequest) { r.GroupRevision = "01" },
		func(r *GroupBoundaryGrantRequest) { r.Mask = 4 },
		func(r *GroupBoundaryGrantRequest) { r.Review = strings.Repeat("AB", 32) },
	} {
		invalid := valid
		modify(&invalid)
		if invalid.Valid() {
			t.Fatal("invalid selection entered the boundary custody workflow")
		}
	}
	if !valid.Valid() {
		t.Fatal("valid View selection did not pass validation")
	}
	session := new(Session)
	if _, reply, plan, err := session.PrepareGroupBoundaryGrant(context.Background(), TrustState{}, nil, GroupBoundaryGrantRequest{}); err != ErrConfiguration || reply.Status != "" || plan != nil {
		t.Fatal("unscoped request entered the boundary custody workflow", err)
	}
	for _, response := range []string{`{}`, `{"nodeId":"unexpected"}`, strings.Repeat(" ", 32769)} {
		if _, plan, preview, err := verifyGroupBoundaryGrantSnapshot(TrustState{}, valid, []byte(response), nil); err != ErrAdmissionResponse || plan != nil || preview != nil {
			t.Fatal("unbound material produced a review", err)
		}
	}
}
