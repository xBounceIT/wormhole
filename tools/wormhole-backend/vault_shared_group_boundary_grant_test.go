package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type groupBoundaryCustodyProbe struct{ *credentialReleaseProbe }

func (*groupBoundaryCustodyProbe) GroupBoundaryGrantsSupported(context.Context) (bool, error) {
	panic("the account was allowed to enter the boundary custody workflow")
}
func (*groupBoundaryCustodyProbe) PrepareGroupBoundaryGrant(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupBoundaryGrantRequest) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, *sharedpg.GroupBoundaryGrantPreparation, error) {
	panic("the account could read boundary grant material")
}
func (*groupBoundaryCustodyProbe) CommitPreparedGroupBoundaryGrant(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupBoundaryGrantPreparation, *vault.UserKeys) (sharedpg.GroupBoundaryGrantReply, error) {
	panic("the account could publish boundary keys")
}
func (*groupBoundaryCustodyProbe) GroupBoundaryRotationSupported(context.Context) (bool, error) {
	panic("the account was allowed to enter the boundary rotation workflow")
}
func (*groupBoundaryCustodyProbe) PrepareGroupBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupBoundaryGrantRequest) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, *sharedpg.GroupBoundaryRotationPreparation, error) {
	panic("the account could read boundary rotation material")
}
func (*groupBoundaryCustodyProbe) CommitPreparedGroupBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupBoundaryRotationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupBoundaryGrantReply, error) {
	panic("the account could rotate boundary keys")
}

func TestSharedGroupBoundaryGrantRequestAndCustody(t *testing.T) {
	request := sharedpg.GroupBoundaryGrantRequest{NodeID: uuid.NewString(), NodeRevision: "8", BoundaryID: uuid.NewString(),
		GroupID: uuid.NewString(), GroupRevision: "2", Mask: 3, Review: strings.Repeat("ae", 32)}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := decodeSharedGroupBoundarySelection(wire, false); err != nil || parsed != request {
		t.Fatal("could not bind a confirmed grant to both scopes and revisions", err)
	}
	var input map[string]any
	if err := json.Unmarshal(wire, &input); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]any{"nodeId": uuid.Nil.String(), "boundaryId": "personal", "groupRevision": "01",
		"nodeRevision": "9223372036854775808", "mask": 15, "review": "", "copies": []any{}} {
		original, had := input[name]
		input[name] = invalid
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeSharedGroupBoundarySelection(raw, false); err != vaultwire.ErrProtocol {
			t.Fatal("malformed grant request accepted", name, err)
		}
		if had {
			input[name] = original
		} else {
			delete(input, name)
		}
	}
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = &groupBoundaryCustodyProbe{probe}
	handler := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	ctx := context.Background()
	if result, err := handler.Handle(ctx, "shared-admin-group-boundary-grant", []byte(`{}`)); result != nil || err != vaultwire.ErrProtocol {
		t.Fatal("boundary custody accepted an incomplete request", err)
	}
	if result, err := (&vaultFoundationHandler{}).sharedGroupBoundaryChange(ctx, wire, false); result != nil || err != vaultwire.ErrProtocol {
		t.Fatal("boundary custody started without an unlocked shared account", err)
	}
	result, err := handler.Handle(ctx, "shared-admin-group-boundary-grant", wire)
	if err != nil || string(result) != `{"status":"unavailable"}` || !controller.Unlocked() {
		t.Fatal("unverified transport entered the grant custody workflow", err)
	}
	request.Mask = 0
	rotation, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := handler.Handle(ctx, "shared-admin-group-boundary-rotation", rotation); err != nil ||
		string(result) != `{"status":"unavailable"}` || !controller.Unlocked() {
		t.Fatal("unverified transport entered the rotation custody workflow", err)
	}
	controller.session = probe
	if result, err := handler.Handle(ctx, "shared-admin-group-boundary-grant", wire); result != nil ||
		!errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, sharedpg.ErrConfiguration) {
		t.Fatal("boundary custody accepted an unexpected session implementation", err)
	}
}
