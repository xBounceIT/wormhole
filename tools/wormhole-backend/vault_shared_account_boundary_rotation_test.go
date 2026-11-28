package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type accountBoundaryRotationMemberProbe struct {
	*credentialReleaseProbe
	sharedAccountBoundaryRotationSession
}

func (p accountBoundaryRotationMemberProbe) RuntimeState(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
	return p.credentialReleaseProbe.RuntimeState(ctx)
}

func TestSharedAccountBoundaryRotationValidatesScopeAndAdmission(t *testing.T) {
	account, boundary, root := uuid.NewString(), uuid.NewString(), uuid.NewString()
	raw := `{"accountId":"` + account + `","suspension":"9","boundaryId":"` + boundary + `","purpose":"secret","rootId":"` + root + `","rootVersion":"2"}`
	confirmed := strings.TrimSuffix(raw, "}") + `,"review":"` + strings.Repeat("ab", 32) + `"}`
	request, err := decodeSharedAccountBoundaryRotation([]byte(confirmed))
	if err != nil || request.AccountID.String() != account || request.BoundaryID.String() != boundary ||
		request.Affected != permissions.Use || request.Root.ID.String() != root || request.Root.Version != 2 || request.Review == nil {
		t.Fatal("valid commit request was rejected", err)
	}
	h := &vaultFoundationHandler{}
	for _, invalid := range []string{
		`{}`, strings.Replace(raw, "secret", "write", 1), strings.Replace(raw, root, "invalid", 1),
		strings.Replace(raw, `"9"`, `"09"`, 1), strings.Replace(raw, `"2"`, `"2147483647"`, 1),
		strings.TrimSuffix(raw, "}") + `,"review":null}`, strings.Replace(confirmed, strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1),
		strings.Replace(confirmed, strings.Repeat("ab", 32), strings.Repeat("zx", 32), 1),
	} {
		if _, err := h.sharedAccountBoundaryRotation(context.Background(), []byte(invalid)); err != vaultwire.ErrProtocol {
			t.Fatal("accepted invalid rotation scope", err)
		}
	}
	if _, err := h.sharedAccountBoundaryRotation(context.Background(), []byte(raw)); err != vaultwire.ErrProtocol {
		t.Fatal("closed owner accepted a rotation review", err)
	}
	controller, fixture, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = accountBoundaryRotationMemberProbe{credentialReleaseProbe: fixture}
	controller.runtimeTLS = sharedpg.TLSEncrypted
	h.shared = &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}
	out, err := h.Handle(context.Background(), "shared-account-boundary-rotation", []byte(raw))
	var reply sharedpg.AccountBoundaryRotationReply
	if err != nil || json.Unmarshal(out, &reply) != nil || reply.Status != "unavailable" || !controller.Unlocked() {
		t.Fatal("unverified owner reached rotation custody or was retired on ordinary denial", reply.Status, err)
	}
}
