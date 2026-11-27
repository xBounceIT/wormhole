package main

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedAdminNodeGrantRequestAndMemberGate(t *testing.T) {
	id := uuid.NewString()
	base := `"nodeId":"` + id + `","nodeRevision":"1","kind":"group"`
	read := `{` + base + `}`
	snapshot := `,"epoch":"1","changeSeq":"0"`
	if _, err := decodeSharedAdminNodeGrant([]byte(read)); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSharedAdminNodeGrant([]byte(`{` + base + snapshot + `,"subjectId":"` + id + `","grantRevision":"0","mask":17}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{}`, `{` + base + `,"mask":null}`, `{` + base + snapshot + `}`,
		`{` + base + snapshot + `,"subjectId":"` + id + `","grantRevision":"0","mask":0}`,
		`{` + base + snapshot + `,"login":"account","grantRevision":"0","mask":17}`,
		`{` + base + `,"token":"` + strings.Repeat("x", 2048) + `"}`,
	} {
		if _, err := decodeSharedAdminNodeGrant([]byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid node grant request accepted", err)
		}
	}
	c, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	c.runtimeTLS = sharedpg.TLSVerified
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	result, err := h.Handle(context.Background(), "shared-admin-node-grant", []byte(read))
	if err != nil || string(result) != `{"status":"unavailable"}` || !c.Unlocked() {
		t.Fatal("a regular account reached the grant API", err)
	}
}
