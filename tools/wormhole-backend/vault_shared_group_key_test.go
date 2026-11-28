package main

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type groupKeyMemberProbe struct{ *credentialReleaseProbe }

func (*groupKeyMemberProbe) GroupKeySupported(context.Context) (bool, error) {
	panic("ordinary account queried group key capabilities")
}
func (*groupKeyMemberProbe) PrepareGroupKey(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupKeyRequest) (sharedpg.TrustState, sharedpg.GroupKeyReply, *sharedpg.GroupKeyPreparation, error) {
	panic("ordinary account read group key material")
}
func (*groupKeyMemberProbe) CommitPreparedGroupKey(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupKeyPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupKeyReply, error) {
	panic("ordinary account issued a group key")
}

func TestSharedGroupKeyRequiresAnExactReviewAndCustody(t *testing.T) {
	id := uuid.New()
	base := `"groupId":"` + id.String() + `","revision":"1"`
	valid := `{` + base + `}`
	digest := strings.Repeat("ab", 32)
	req, err := decodeSharedGroupKey([]byte(`{` + base + `,"review":"` + digest + `"}`))
	if err != nil || req.GroupID != id || req.Revision != 1 || req.Review == nil || req.Review[31] != 0xab {
		t.Fatal("confirmation was not scoped to the reviewed group", err)
	}
	for _, input := range []string{
		`{}`, `{` + base + `,"review":null}`, `{` + base + `,"review":""}`,
		`{` + base + `,"review":"` + strings.ToUpper(digest) + `"}`,
		`{"groupId":"` + id.String() + `","revision":"9223372036854775807"}`,
		`{` + base + `,"extra":"` + strings.Repeat("x", 512) + `"}`,
	} {
		if _, err := decodeSharedGroupKey([]byte(input)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid group key request accepted", err)
		}
	}
	c, p, _, _, _, _, _, _ := credentialControllerFixture(t)
	c.session = &groupKeyMemberProbe{p}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	result, err := h.Handle(context.Background(), "shared-admin-group-key", []byte(valid))
	if err != nil || string(result) != `{"status":"unavailable"}` || !c.Unlocked() {
		t.Fatal("an unverified account was allowed group key custody", err)
	}
}
