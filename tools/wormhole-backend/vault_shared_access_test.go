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

type workspaceAccessProbe struct {
	*credentialReleaseProbe
	supported bool
	probes    int
	requests  int
}

func (p *workspaceAccessProbe) WorkspaceAccessSupported(context.Context) (bool, error) {
	p.probes++
	return p.supported, nil
}

func (p *workspaceAccessProbe) WorkspaceAccess(_ context.Context, trust sharedpg.TrustState, request sharedpg.WorkspaceAccessRequest) (sharedpg.WorkspaceAccessReply, error) {
	p.requests++
	if trust.Account == nil || !trust.Account.Active || request.TargetID != trust.DeviceID.String() {
		return sharedpg.WorkspaceAccessReply{}, sharedpg.ErrConfiguration
	}
	return sharedpg.WorkspaceAccessReply{Status: "review", Review: &sharedpg.WorkspaceAccessReview{CurrentDevice: true}}, nil
}

func TestSharedWorkspaceAccessRequiresVerifiedAdmission(t *testing.T) {
	controller, fixture, opts, _, _, _, _, _ := credentialControllerFixture(t)
	probe := &workspaceAccessProbe{credentialReleaseProbe: fixture}
	controller.session = probe
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	device := opts.Binding.DeviceID.String()
	raw := `{"action":"revoke-device","targetId":"` + device + `"}`
	addRevision := func(revision string) string {
		return strings.TrimSuffix(raw, "}") + `,"revision":` + revision + "}"
	}
	for _, bad := range []string{
		`{}`, `{"action":"unknown","targetId":"` + device + `"}`,
		addRevision("null"), addRevision(`""`), addRevision("1"),
		addRevision(`"1","revision":"2"`), raw + strings.Repeat(" ", 512),
	} {
		if _, err := h.sharedWorkspaceAccess(context.Background(), []byte(bad)); err != vaultwire.ErrProtocol {
			t.Fatal("accepted an invalid access request", err)
		}
	}
	confirm, err := decodeSharedWorkspaceAccess([]byte(addRevision(`"50"`)))
	if err != nil || confirm.Revision != "50" {
		t.Fatal("did not decode the confirmation", err)
	}
	call := func(request, status string) {
		t.Helper()
		value, err := h.Handle(context.Background(), "shared-workspace-access", []byte(request))
		var reply sharedpg.WorkspaceAccessReply
		if err != nil || json.Unmarshal(value, &reply) != nil || reply.Status != status || !controller.Unlocked() {
			t.Fatal("unexpected verified runtime handling", reply.Status, err)
		}
	}
	controller.runtimeTLS = sharedpg.TLSEncrypted
	call(raw, "unavailable")
	controller.runtimeTLS = sharedpg.TLSVerified
	call(strings.Replace(raw, "revoke-device", "disable-account", 1), "unavailable")
	// Confirming this revision would overflow the next signed suspension revision.
	// Refuse it before asking the database to sign or mutate anything.
	call(strings.Replace(addRevision(`"9223372036854775807"`), "revoke-device", "disable-account", 1), "unavailable")
	if probe.probes != 0 {
		t.Fatal("a denied path reached native mutation support")
	}
	call(raw, "unsupported")
	probe.supported = true
	call(raw, "review")
	if probe.probes != 2 || probe.requests != 1 {
		t.Fatal("the verified own-device path did not use the expected capability")
	}
}
