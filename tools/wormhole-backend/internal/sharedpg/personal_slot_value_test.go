package sharedpg

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func checkPostgresPersonalSlot(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys, slot AdminCredentialSlot, publicBoundary uuid.UUID) {
	t.Helper()
	trust, personal, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, keys)
	if err != nil || personal == nil {
		t.Fatal("personal credential store", err)
	}
	query := func(sql string, args ...string) *pgconn.Result {
		t.Helper()
		params := make([][]byte, len(args))
		for i, arg := range args {
			params[i] = []byte(arg)
		}
		r := dba.ExecParams(ctx, sql, params, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	key := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(key)
	user := trust.UserID.String()
	signer := trust.Enrollment.Signing
	add := func(provider string) string {
		t.Helper()
		name := "My " + provider + " account"
		meta := vaultstore.CredentialMetadata{ID: uuid.NewString(), OwnerUserID: user, Name: name, Protocol: slot.Protocol, Kind: "password", Provider: provider}
		if provider == "bitwarden" {
			meta.BitwardenItemID = "demo"
			meta.BitwardenItemName = "Account"
			meta.BitwardenFieldPath = "login.password"
		}
		r := sharedcatalog.CredentialRecord{Metadata: meta, Fields: []vaultstore.CredentialField{}}
		seal, err := sharedcatalog.SignCredential(trust.WorkspaceID, personal.BoundaryID, r, 1, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		query(`INSERT INTO wormhole_data.credential_profiles(id,owner_user_id,name,protocol,kind,provider,bitwarden_item_id,bitwarden_item_name,bitwarden_field_path,fields,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
			VALUES($1::uuid,$2::uuid,$3,$4,'password',$5,$6,$7,$8,'[]',$9::uuid,2,$10::uuid,$11::int,decode($12,'hex'))`, meta.ID, user, name, slot.Protocol, provider, meta.BitwardenItemID, meta.BitwardenItemName, meta.BitwardenFieldPath, personal.BoundaryID.String(), signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
		t.Cleanup(func() { query("DELETE FROM wormhole_data.credential_profiles WHERE id=$1::uuid", meta.ID) })
		return name
	}
	local, bw := add("local"), add("bitwarden")
	query("UPDATE wormhole_data.users SET is_admin=false WHERE id=$1::uuid", user)
	t.Cleanup(func() { query("UPDATE wormhole_data.users SET is_admin=true WHERE id=$1::uuid", user) })
	t.Cleanup(func() {
		query("DELETE FROM wormhole_data.credential_slot_values WHERE slot_id=$1::uuid AND user_id=$2::uuid", slot.ID.String(), user)
	})
	page := func(after uuid.UUID, visible bool) {
		t.Helper()
		next, p, err := session.PersonalCredentialSlots(ctx, trust, after)
		if err != nil || p == nil || p.Kind != "my-slots" || p.Next != nil {
			t.Fatalf("invalid personal slot inventory: %v", err)
		}
		if visible {
			if len(p.Entries) != 1 || p.Entries[0] != slot {
				t.Fatal("expected the signed self-service slot")
			}
		} else if len(p.Entries) != 0 {
			t.Fatal("member inventory exposed a hidden slot")
		}
		trust = next
	}
	page(uuid.Nil, true)
	page(slot.ID, false)
	read := func(name, want string) *SlotReview {
		t.Helper()
		next, r, status, err := session.ReadPersonalSlot(ctx, trust, tls, slot.ID, name)
		if err != nil || status != want || (r == nil) != (want != "review") {
			t.Fatalf("read %s: %s (%v)", name, status, err)
		}
		trust = next
		return r
	}
	commit := func(r *SlotReview, want string) {
		t.Helper()
		next, status, err := session.CommitPersonalSlot(ctx, trust, tls, r, keys)
		if err != nil || status != want {
			t.Fatalf("commit: got %q want %q (%v)", status, want, err)
		}
		trust = next
	}
	first := read(local, "review")
	if first.Choice.ValueRevision != "0" || first.Choice.HasAssignment || first.Choice.Provider != "local" {
		t.Fatal("incorrect initial selection")
	}
	read("Unknown", "unavailable")
	query("UPDATE wormhole_data.boundary_grants SET permissions=1 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", publicBoundary.String(), user)
	page(uuid.Nil, false)
	commit(first, "unavailable")
	query("UPDATE wormhole_data.boundary_grants SET permissions=31 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", publicBoundary.String(), user)
	query("UPDATE wormhole_data.credential_slots SET allow_self_service=false WHERE id=$1::uuid", slot.ID.String())
	page(uuid.Nil, false)
	read(local, "unavailable")
	commit(first, "unavailable")
	query("UPDATE wormhole_data.credential_slots SET allow_self_service=true WHERE id=$1::uuid", slot.ID.String())
	commit(first, "saved")
	commit(first, "stale")
	assigned := read(local, "review")
	if !assigned.Unchanged() || !assigned.Choice.HasAssignment || assigned.Choice.ValueRevision != "1" {
		t.Fatal("missing personal assignment")
	}
	commit(assigned, "unchanged")
	replacement := read(bw, "review")
	if replacement.Choice.Provider != "bitwarden" {
		t.Fatal("lost Bitwarden provider")
	}
	commit(replacement, "saved")
	remove := read("", "review")
	if remove.value.Record.(sharedcatalog.SlotValueRecord).CredentialID != replacement.Choice.CredentialID || remove.Choice.ValueRevision != "2" {
		t.Fatal("unexpected replacement")
	}
	commit(remove, "saved")
	empty := read("", "review")
	if !empty.Unchanged() || empty.Choice.HasAssignment || empty.Choice.ValueRevision != "3" {
		t.Fatal("expected signed tombstone")
	}
	commit(read(local, "review"), "saved")
	if n := query("SELECT count(*)::text FROM wormhole_data.audit_log WHERE user_id=$1::uuid AND action='set_personal_slot_value'", user); string(n.Rows[0][0]) != "4" {
		t.Fatal("unexpected audit history")
	}
	// Check an incomplete copy of a genuine snapshot without retiring the
	// PostgreSQL session used by the other permission checks in this fixture.
	args := [][]byte{[]byte(slot.ID.String()), []byte(""), nil, nil, nil, nil, nil, nil, nil}
	err = session.queryServerCA(ctx, trust, personalSlotSQL, args, 3*adminSlotPageMaxBytes, 1, 6, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 6 || rows[0][4] == nil {
			t.Fatal("missing personal slot fixture row")
		}
		row := append([][]byte(nil), rows[0]...)
		row[4] = nil
		next, r, _, err := verifyPersonalSlot([][][]byte{row}, trust, slot.ID, "", "review")
		if !errors.Is(err, ErrAdmissionResponse) || r != nil || next.Catalog["slot-value/"+slot.ID.String()+"/"+user].Revision != 4 {
			t.Fatal("lost the signed personal assignment floor", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
