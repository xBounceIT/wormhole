package sharedpg

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSuspensionRosterOnlyRemovesItsSubject(t *testing.T) {
	a, b, c, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	group := GroupKeyRequest{GroupID: uuid.New(), Revision: 3}
	encode := func(ids ...uuid.UUID) []byte {
		rows := make([][]string, 0, len(ids))
		for _, id := range ids {
			rows = append(rows, []string{id.String(), "key", "1", "state", "certificate"})
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name               string
		before, after      []uuid.UUID
		reconcile, allowed bool
	}{
		{"remove", []uuid.UUID{a, b, c}, []uuid.UUID{a, c}, false, true},
		{"last member", []uuid.UUID{b}, nil, false, true},
		{"add other", []uuid.UUID{a, b, c}, []uuid.UUID{a, c, other}, false, false},
		{"drop other", []uuid.UUID{a, b, c}, []uuid.UUID{a}, false, false},
		{"substitute", []uuid.UUID{a, b, c}, []uuid.UUID{a, other}, false, false},
		{"keep subject", []uuid.UUID{a, b, c}, []uuid.UUID{a, b, c}, false, false},
		{"subject absent", []uuid.UUID{a, c}, []uuid.UUID{a, c}, false, false},
		{"duplicate subject", []uuid.UUID{a, b, b, c}, []uuid.UUID{a, c}, false, false},
		{"reconcile", []uuid.UUID{a, c}, []uuid.UUID{a, c}, true, true},
		{"reconcile other", []uuid.UUID{a, c}, []uuid.UUID{a, other}, true, false},
		{"reconcile disabled", []uuid.UUID{a, b, c}, []uuid.UUID{a, c}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := encode(tc.before...)
			digest := groupKeyReviewDigest(group, prior)
			m := vault.GroupKeyManifest{GroupID: group.GroupID, GroupRevision: group.Revision, RosterDigest: digest[:]}
			var holders []groupKeyHolder
			for _, id := range tc.after {
				holders = append(holders, groupKeyHolder{member: GroupKeyMember{ID: id}})
			}
			if sameSuspensionMembers(prior, m, holders, b, tc.reconcile) != tc.allowed {
				t.Fatal("unexpected automatic membership authorization")
			}
			if sameSuspensionMembers(encode(other), m, holders, b, tc.reconcile) {
				t.Fatal("accepted an uncommitted roster")
			}
		})
	}
}
