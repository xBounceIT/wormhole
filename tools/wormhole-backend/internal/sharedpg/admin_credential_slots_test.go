package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkPostgresAdminCredentialSlots(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, keys *vault.UserKeys) uuid.UUID {
	t.Helper()
	if ok, err := session.AdminInventorySupported(ctx, "slots"); err != nil || !ok {
		t.Fatal("missing slot inventory", err)
	}
	if _, err := session.AdminInventory(ctx, AdminInventoryRequest{Kind: "slots"}); err != ErrConfiguration {
		t.Fatal("unsigned inventory accepted slots", err)
	}
	exec := func(query string, params ...[]byte) {
		t.Helper()
		if result := dba.ExecParams(ctx, query, params, nil, nil, nil).Read(); result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	visible, hidden := uuid.New(), uuid.New()
	defer func() {
		for _, boundary := range []uuid.UUID{visible, hidden} {
			id := []byte(boundary.String())
			exec("DELETE FROM wormhole_data.credential_slots WHERE boundary_id=$1::uuid", id)
			exec("DELETE FROM wormhole_data.boundary_grants WHERE boundary_id=$1::uuid", id)
			exec("DELETE FROM wormhole_data.boundaries WHERE id=$1::uuid", id)
		}
	}()
	exec("INSERT INTO wormhole_data.boundaries(id) VALUES ($1::uuid),($2::uuid)", []byte(visible.String()), []byte(hidden.String()))
	exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES ($1::uuid,$2::uuid,1)", []byte(visible.String()), []byte(trust.UserID.String()))
	key := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(key)
	signer := trust.Enrollment.Signing
	var visibleSlots []AdminCredentialSlot
	for i := 1; i <= adminInventoryLimit+3; i++ {
		id, boundary := uuid.UUID{15: byte(i)}, visible
		if i == 2 {
			boundary = hidden
		}
		record := sharedcatalog.SlotRecord{ID: id.String(), Name: "Slot " + strconv.Itoa(i), Protocol: "ssh", AllowSelfService: i%2 == 1, Deleted: i == 3}
		seal, err := sharedcatalog.SignSelection(trust.WorkspaceID, boundary, record, 1, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO wormhole_data.credential_slots(id,name,protocol,allow_self_service,deleted,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
			VALUES ($1::uuid,$2,'ssh',$3::boolean,$4::boolean,$5::uuid,2,$6::uuid,$7::integer,decode($8,'hex'))`,
			[]byte(id.String()), []byte(record.Name), []byte(strconv.FormatBool(record.AllowSelfService)), []byte(strconv.FormatBool(record.Deleted)), []byte(boundary.String()),
			[]byte(signer.ID.String()), []byte(strconv.FormatUint(uint64(signer.Version), 10)), hex.AppendEncode(nil, seal.Signature))
		if boundary == visible && !record.Deleted {
			visibleSlots = append(visibleSlots, AdminCredentialSlot{id, record.Name, record.Protocol, record.AllowSelfService})
		}
	}
	next, page, err := session.AdminCredentialSlots(ctx, trust, uuid.Nil)
	if err != nil || page == nil || len(page.Entries) != adminInventoryLimit || page.Next == nil || page.Next.ID != visibleSlots[adminInventoryLimit-1].ID {
		t.Fatal("invalid first slot page", err, page)
	}
	for i, entry := range page.Entries {
		if entry != visibleSlots[i] || next.Catalog["slot/"+entry.ID.String()].Revision != 1 {
			t.Fatal("unobserved or incorrect slot", i)
		}
	}
	cursor := page.Next.ID
	_, page, err = session.AdminCredentialSlots(ctx, next, cursor)
	if err != nil || page == nil || len(page.Entries) != 1 || page.Entries[0] != visibleSlots[adminInventoryLimit] || page.Next != nil {
		t.Fatal("incorrect second slot page", err, page)
	}
	// Measure SQL pagination independently of signature verification. The
	// opaque size fixture replaces only the public certificate for this read.
	user := []byte(trust.UserID.String())
	const padding = "convert_to(repeat(' ',400000),'UTF8')"
	exec("UPDATE wormhole_data.user_enrollments SET certificate=certificate||"+padding+" WHERE user_id=$1::uuid", user)
	defer exec("UPDATE wormhole_data.user_enrollments SET certificate=substring(certificate from 1 for octet_length(certificate)-400000) WHERE user_id=$1::uuid", user)
	for i, after := range [][]byte{nil, []byte(visibleSlots[0].ID.String())} {
		err := session.queryAdministration(ctx, trust, adminSlotsSQL, [][]byte{after}, adminSlotPageMaxBytes, 4, func(row [][]byte) error {
			projected, err := snapshotRows(row[3], 1, 24)
			if err != nil || len(projected) != 1 || string(row[0]) != "more" || string(projected[0][1]) != visibleSlots[i].ID.String() || len(row[3]) <= adminInventoryMaxBytes {
				t.Fatal("large author proof did not produce one advancing slot", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return cursor
}

func TestAdminSlotPageRequiresVerifiedRows(t *testing.T) {
	rows, request, c, author, trust := credentialProjectionRows(t)
	id := uuid.UUID{15: 1}
	record := sharedcatalog.SlotRecord{ID: id.String(), Name: "Admin SSH", Protocol: "ssh"}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignSelection(request.WorkspaceID, c.Boundary, record, 1, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	row := append(rows[0], nil)
	row[1], row[11] = []byte(id.String()), hex.AppendEncode(nil, seal.Signature)
	row[4], _ = json.Marshal(record)
	cells := make([]*string, len(row))
	for i, v := range row {
		if v != nil {
			s := string(v)
			cells[i] = &s
		}
	}
	wire, _ := json.Marshal([][]*string{cells})
	if _, page, err := verifyAdminSlotPage([][]byte{[]byte("more"), []byte("1"), []byte("7"), wire}, trust, uuid.Nil); err != nil || page == nil || len(page.Entries) != 1 || page.Next == nil || page.Next.ID != id {
		t.Fatal("short verified page lost its continuation", err)
	}
	for _, suffix := range []string{"," + string(wire[1:]), ",[]]", "] {}", ""} {
		payload := append(bytes.Clone(wire[:len(wire)-1]), suffix...)
		observed, page, err := verifyAdminSlotPage([][]byte{[]byte("ready"), []byte("1"), []byte("7"), payload}, trust, uuid.Nil)
		if err == nil || page != nil || observed.Catalog["slot/"+id.String()].Revision != 1 {
			t.Fatal("invalid later row lost verified observation or released partial inventory", err)
		}
	}
	record.Name = "Changed"
	altered, _ := json.Marshal(record)
	label := string(altered)
	cells[4] = &label
	wire, _ = json.Marshal([][]*string{cells})
	if _, page, err := verifyAdminSlotPage([][]byte{[]byte("ready"), []byte("1"), []byte("7"), wire}, trust, uuid.Nil); err == nil || page != nil {
		t.Fatal("uncertified slot name reached the page")
	}
	for _, row := range [][][]byte{
		nil, {[]byte("unavailable"), nil, nil, []byte("[]")},
		{[]byte("more"), []byte("1"), []byte("7"), []byte("[]")},
		{[]byte("ready"), []byte("0"), []byte("7"), []byte("[]")},
		{[]byte("ready"), []byte("1"), []byte("7"), []byte("null")},
		{[]byte("ready"), []byte("1"), []byte("7"), []byte("[[]]")},
	} {
		if _, page, err := verifyAdminSlotPage(row, trust, uuid.Nil); err == nil || page != nil {
			t.Fatal("accepted invalid slot reply")
		}
	}
}
