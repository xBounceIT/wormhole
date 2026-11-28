package sharedpg

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSelectionTrustPersistenceAndLogicalIdentity(t *testing.T) {
	root, b, s, c, author, _, key := credentialTrustFixture(t)
	id, user := uuid.NewString(), uuid.NewString()
	records := []sharedcatalog.SelectionRecord{
		sharedcatalog.SlotRecord{ID: id, Name: "Account", Protocol: "ssh"},
		sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: id, UserID: user, CredentialID: c.Record.Metadata.ID},
		sharedcatalog.OverrideRecord{NodeID: id, UserID: user, CredentialID: c.Record.Metadata.ID},
	}
	sign := func(r sharedcatalog.SelectionRecord, rev uint64) UnverifiedSelection {
		t.Helper()
		seal, e := sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, r, rev, author.Key, key)
		if e != nil {
			t.Fatal(e)
		}
		return UnverifiedSelection{r, c.Boundary, seal}
	}
	restore := func(s TrustState) TrustState {
		t.Helper()
		raw, e := SealTrustState(root, b, s)
		if e != nil {
			t.Fatal(e)
		}
		restored, e := OpenTrustState(root, b, raw, s.Revision)
		if e != nil || !reflect.DeepEqual(restored, s) {
			t.Fatal("roundtrip", e)
		}
		return restored
	}
	for _, r := range records {
		signed := sign(r, 5)
		next, e := s.AdvanceSelection(signed, author)
		if e != nil || s.ValidateAdvance(next) != nil {
			t.Fatal("advance", e)
		}
		next = restore(next)
		same, e := next.AdvanceSelection(signed, author)
		if e != nil || !reflect.DeepEqual(same, next) {
			t.Fatal("idempotence", e)
		}
		if _, e = next.AdvanceSelection(sign(r, 4), author); e != vault.ErrRollback {
			t.Fatal("rollback", e)
		}
		v := reflect.New(reflect.TypeOf(r)).Elem()
		v.Set(reflect.ValueOf(r))
		switch r.(type) {
		case sharedcatalog.SlotRecord:
			v.FieldByName("Name").SetString("other")
		case sharedcatalog.SlotValueRecord:
			v.FieldByName("ID").SetString(uuid.NewString())
		case sharedcatalog.OverrideRecord:
			v.FieldByName("CredentialID").SetString(uuid.NewString())
		}
		fork := v.Interface().(sharedcatalog.SelectionRecord)
		if _, e = next.AdvanceSelection(sign(fork, 5), author); e != ErrCatalogEquivocation {
			t.Fatal("logical identity fork", e)
		}
		if _, e = next.AdvanceSelection(sign(fork, 4), author); e != vault.ErrRollback {
			t.Fatal("row replacement reset history", e)
		}
		v.FieldByName("Deleted").SetBool(true)
		tomb := sign(v.Interface().(sharedcatalog.SelectionRecord), 6)
		deleted, e := next.AdvanceSelection(tomb, author)
		if e != vaultstore.ErrMissing || next.ValidateAdvance(deleted) != nil {
			t.Fatal("tombstone", e)
		}
		s = restore(deleted)
		if _, e = s.AdvanceSelection(signed, author); e != vault.ErrRollback {
			t.Fatal("tombstone replay", e)
		}
	}
	if len(s.Catalog) != 5 {
		t.Fatal("namespace collision", len(s.Catalog))
	}
	// Composite namespace components must be canonical UUIDs, never versions.
	for _, k := range []string{"slot/" + id + "/" + user, "slot-value/" + id, "slot-value/" + id + "/1", "override/" + id, "override/" + id + "/bad"} {
		if validCatalogFloors(map[string]CatalogFloor{k: {Revision: 1, Digest: make([]byte, 32)}}) {
			t.Fatal("invalid floor key", k)
		}
	}
}

func TestSelectionTrustFailureObservations(t *testing.T) {
	_, b, s, c, author, org, key := credentialTrustFixture(t)
	record := sharedcatalog.SlotRecord{ID: uuid.NewString(), Name: "Account", Protocol: "ssh"}
	seal, e := sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, record, 1, author.Key, key)
	if e != nil {
		t.Fatal(e)
	}
	selection := UnverifiedSelection{record, c.Boundary, seal}
	bad := selection
	bad.Seal.Signature = make([]byte, 64)
	next, e := s.AdvanceSelection(bad, author)
	if e != vault.ErrAuthentication || len(next.Catalog) != 2 || s.ValidateAdvance(next) != nil {
		t.Fatal("lost author observations", e)
	}
	missingCert := author
	missingCert.Certificate = nil
	if next, e = s.AdvanceSelection(selection, missingCert); e == nil || len(next.Catalog) != 1 {
		t.Fatal("missing cert", e)
	}
	revoked := author
	state := *author.State
	state.Sequence++
	state.Active = false
	state, e = vault.SignUserKeyState(state, org)
	if e != nil {
		t.Fatal(e)
	}
	revoked.State = &state
	next, e = s.AdvanceSelection(selection, revoked)
	if e != vault.ErrPolicy || next.Catalog["author/"+state.UserID.String()].Revision != state.Sequence {
		t.Fatal("revocation", e)
	}
	if _, e = next.AdvanceSelection(selection, author); e != vault.ErrRollback {
		t.Fatal("revocation rollback", e)
	}
	invalid := s
	invalid.Revision = 0
	if _, e = invalid.AdvanceSelection(selection, author); e != ErrTrustState {
		t.Fatal(e)
	}
	noAuthor := author
	noAuthor.State = nil
	if _, e = s.AdvanceSelection(selection, noAuthor); e != ErrTrustState {
		t.Fatal(e)
	}
	selection.Record = nil
	if _, e = s.AdvanceSelection(selection, author); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
}
