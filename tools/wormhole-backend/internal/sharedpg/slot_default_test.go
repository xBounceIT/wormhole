package sharedpg

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func checkPostgresSlotDefault(t *testing.T, ctx context.Context, db *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys, slot AdminCredentialSlot, boundary uuid.UUID) {
	t.Helper()
	if ok, err := session.SlotDefaultSupported(ctx); err != nil || !ok {
		t.Fatal("slot default API missing", err)
	}
	query := func(sql string, args ...string) *pgconn.Result {
		t.Helper()
		params := make([][]byte, len(args))
		for i, arg := range args {
			params[i] = []byte(arg)
		}
		r := db.ExecParams(ctx, sql, params, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	signer := trust.Enrollment.Signing
	private := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(private)
	newAccount := func(name, protocol, owner string) string {
		t.Helper()
		id := uuid.NewString()
		meta := vaultstore.CredentialMetadata{ID: id, OwnerUserID: owner, Name: name, Protocol: protocol, Kind: "password", Provider: "local"}
		credential := sharedcatalog.CredentialRecord{Metadata: meta, Fields: []vaultstore.CredentialField{}}
		seal, err := sharedcatalog.SignCredential(trust.WorkspaceID, boundary, credential, 1, signer, private)
		if err != nil {
			t.Fatal(err)
		}
		query(`INSERT INTO wormhole_data.credential_profiles(id,owner_user_id,name,protocol,kind,provider,fields,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
			VALUES($1::uuid,NULLIF($2,'')::uuid,$3,$4,'password','local','[]',$5::uuid,2,$6::uuid,$7::int,decode($8,'hex'))`,
			id, owner, name, protocol, boundary.String(), signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
		t.Cleanup(func() { query("DELETE FROM wormhole_data.credential_profiles WHERE id=$1::uuid", id) })
		return id
	}
	shared := newAccount("Default shell", "ssh", "")
	newAccount("Personal shell", "ssh", trust.UserID.String())
	newAccount("Desktop", "rdp", "")
	read := func(name, status string) *SlotReview {
		t.Helper()
		next, result, got, err := session.ReadSlotDefault(ctx, trust, tls, slot.ID, name)
		if err != nil || got != status || (result != nil) != (got == "review") {
			t.Fatal("default review", name, got, err)
		}
		trust = next
		return result
	}
	commit := func(r *SlotReview, want string) {
		t.Helper()
		next, status, err := session.CommitSlotDefault(ctx, trust, tls, r, keys)
		if err != nil || status != want {
			t.Fatalf("slot commit: got %q, want %q (%v)", status, want, err)
		}
		trust = next
	}
	missing := read("", "review")
	if !missing.Unchanged() || missing.Choice.HasDefault {
		t.Fatal("new slot already assigned")
	}
	commit(missing, "unchanged")
	for _, name := range []string{"Personal shell", "Desktop", "Unknown shell"} {
		read(name, "unavailable")
	}
	r := read("Default shell", "review")
	if r.Unchanged() || r.Choice.CredentialID != shared || r.Choice.SlotName != slot.Name || r.Choice.SlotRevision != "1" || r.Choice.CredentialRevision != "1" {
		t.Fatal("incorrect selected credential")
	}
	query("UPDATE wormhole_data.users SET is_admin=false WHERE id=$1::uuid", trust.UserID.String())
	commit(r, "unavailable")
	read("Default shell", "unavailable")
	query("UPDATE wormhole_data.users SET is_admin=true WHERE id=$1::uuid", trust.UserID.String())
	query("UPDATE wormhole_data.boundary_grants SET permissions=23 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", boundary.String(), trust.UserID.String())
	read("Default shell", "unavailable")
	commit(r, "unavailable")
	query("UPDATE wormhole_data.boundary_grants SET permissions=31 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", boundary.String(), trust.UserID.String())
	commit(r, "saved")
	commit(r, "stale")
	assigned := read("Default shell", "review")
	if !assigned.Unchanged() || !assigned.Choice.HasDefault || assigned.Choice.SlotRevision != "2" {
		t.Fatal("saved slot was not bound to the signed credential")
	}
	commit(assigned, "unchanged")
	clearDefault := read("", "review")
	if clearDefault.Unchanged() || clearDefault.Choice.CredentialID != "" {
		t.Fatal("cannot clear shared slot")
	}
	commit(clearDefault, "saved")
	if next := read("", "review"); !next.Unchanged() || next.Choice.HasDefault || next.Choice.SlotRevision != "3" {
		t.Fatal("slot not cleared")
	}
	if got := query("SELECT count(*)::text FROM wormhole_data.audit_log WHERE user_id=$1::uuid AND action='set_slot_default'", trust.UserID.String()); string(got.Rows[0][0]) != "2" {
		t.Fatal("unexpected number of slot changes")
	}
	// An imported slot may have exhausted its revision. Verify its signature
	// and keep its floor without offering a write that cannot advance.
	current := read("", "review").slot
	exhausted, err := sharedcatalog.SignSelection(trust.WorkspaceID, boundary, current.Record, math.MaxInt64, signer, private)
	if err != nil {
		t.Fatal(err)
	}
	const replaceSeal = "UPDATE wormhole_data.credential_slots SET row_version=$2::bigint,seal=decode($3,'hex') WHERE id=$1::uuid"
	query(replaceSeal, slot.ID.String(), strconv.FormatInt(math.MaxInt64, 10), hex.EncodeToString(exhausted.Signature))
	defer query(replaceSeal, slot.ID.String(), strconv.FormatUint(current.Seal.Revision, 10), hex.EncodeToString(current.Seal.Signature))
	read("Default shell", "unavailable")
	if trust.Catalog["slot/"+slot.ID.String()].Revision != math.MaxInt64 {
		t.Fatal("discarded signed exhausted revision")
	}
}

func TestSlotDefaultChecksWireShapeBeforeTrust(t *testing.T) {
	trust := TrustState{Revision: 3}
	id := uuid.New()
	for _, status := range []string{"stale", "unavailable", "busy"} {
		rows := [][][]byte{{[]byte(status), nil, nil, nil, nil}}
		next, review, got, err := verifySlotDefault(rows, trust, id, "", "review")
		if err != nil || got != status || review != nil || next.Revision != trust.Revision {
			t.Fatal("incorrect closed result", status, err)
		}
	}
	for _, row := range [][][]byte{
		nil, {[]byte("busy"), []byte("1"), nil, nil, nil}, {[]byte("unexpected"), nil, nil, nil, nil},
		{[]byte("review"), nil, []byte("0"), nil, nil}, {[]byte("review"), []byte("1"), []byte("-1"), nil, nil},
		{[]byte("review"), []byte("1"), []byte("0"), []byte{255}, nil},
		{[]byte("review"), []byte("1"), []byte("0"), []byte("[]"), []byte("[]")},
		{[]byte("review"), []byte("1"), []byte("0"), []byte("[]"), nil},
	} {
		next, review, _, err := verifySlotDefault([][][]byte{row}, trust, id, "", "review")
		if err == nil || review != nil || next.Revision != trust.Revision {
			t.Fatal("accepted malformed response")
		}
	}
}

func TestSlotDefaultSignedSnapshotUsesOneTrustRevision(t *testing.T) {
	f, wire, _ := snapshotFixture(t, "slot")
	id := uuid.MustParse(f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord).ID)
	credential := f.records.Credential
	rows := func() [][][]byte {
		t.Helper()
		encode := func(key string) []byte {
			// Current projections include an optional enrollment certificate after the signing certificate.
			data, err := json.Marshal(append(wire[key].([]any), nil))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		return [][][]byte{{[]byte("review"), []byte("1"), []byte("7"), encode("slot"), encode("credential")}}
	}
	next, r, _, err := verifySlotDefault(rows(), f.s, id, credential.Credential.Record.Metadata.Name, "review")
	if err != nil || r == nil {
		t.Fatal("valid review", err)
	}
	if next.Revision != f.s.Revision+1 {
		t.Errorf("one snapshot advanced the local checkpoint from %d to %d", f.s.Revision, next.Revision)
	}
	same, _, _, err := verifySlotDefault(rows(), next, id, credential.Credential.Record.Metadata.Name, "review")
	if err != nil || same.Revision != next.Revision {
		t.Fatal("unchanged observation", err)
	}
	state := *credential.Author.State
	state.Sequence++
	state, err = vault.SignUserKeyState(state, f.org)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.EncodeUserKeyState(state)
	if err != nil {
		t.Fatal(err)
	}
	profileRow := wire["credential"].([]any)
	profileRow[15], profileRow[16] = strconv.FormatUint(state.Sequence, 10), hex.EncodeToString(encoded)
	newer, r, _, err := verifySlotDefault(rows(), f.s, id, credential.Credential.Record.Metadata.Name, "review")
	if err == nil || r != nil || newer.Catalog["author/"+state.UserID.String()].Revision != state.Sequence || newer.Revision != f.s.Revision+1 {
		t.Error("inconsistent author snapshots must reject the review and retain the newest signed floor")
	}
}
