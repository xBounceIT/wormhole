package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func checkPostgresCreateCredentialSlot(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) {
	t.Helper()
	if ok, err := session.CreateCredentialSlotSupported(ctx); err != nil || !ok {
		t.Fatal("missing credential slot creation", err)
	}
	pinned, boundary, err := session.WorkspaceImportBoundary(ctx, trust, tls, workspaceimport.Shared)
	if err != nil || boundary == nil {
		t.Fatal("shared slot boundary", err)
	}
	slot := AdminCredentialSlot{ID: uuid.New(), Name: "Admin <&> \"è\"\u2028VPN", Protocol: "ssh", AllowSelfService: true}
	other := pinned
	other.DeviceID = uuid.New()
	if _, status, err := session.CreateCredentialSlot(ctx, other, tls, *boundary, slot, keys); err != ErrAuthentication || status != "" {
		t.Fatal("one device used another device's session", err)
	}
	for _, invalid := range []struct {
		tls      *VerifiedTLSBundle
		manifest vault.BoundaryManifest
		keys     *vault.UserKeys
	}{
		{nil, *boundary, keys},
		{tls, vault.BoundaryManifest{}, keys},
		{tls, *boundary, nil},
		{tls, *boundary, &vault.UserKeys{}},
		{tls, *boundary, &vault.UserKeys{EncryptionPrivate: keys.EncryptionPrivate, SigningSeed: make([]byte, 32)}},
	} {
		if _, status, err := session.CreateCredentialSlot(ctx, pinned, invalid.tls, invalid.manifest, slot, invalid.keys); err == nil || status != "" {
			t.Fatal("invalid slot signing context accepted")
		}
	}
	update := func(sql string, args ...[]byte) {
		t.Helper()
		if r := dba.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	user, target := []byte(trust.UserID.String()), []byte(boundary.BoundaryID.String())
	create := func(input AdminCredentialSlot, expected string) TrustState {
		t.Helper()
		next, status, err := session.CreateCredentialSlot(ctx, pinned, tls, *boundary, input, keys)
		if err != nil || status != expected {
			t.Fatal("create slot", status, expected, err)
		}
		return next
	}
	pinned = create(slot, "saved")
	defer update("DELETE FROM wormhole_data.credential_slots WHERE id=$1::uuid", []byte(slot.ID.String()))
	stored := dba.ExecParams(ctx, "SELECT encode(seal,'hex') FROM wormhole_data.credential_slots WHERE id=$1::uuid", [][]byte{[]byte(slot.ID.String())}, nil, nil, nil).Read()
	if stored.Err != nil || len(stored.Rows) != 1 {
		t.Fatal("missing signed slot", stored.Err)
	}
	manifestBytes, err := vault.EncodeBoundaryManifest(*boundary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestBytes)
	for _, tc := range []struct {
		index       int
		replacement []byte
		status      string
	}{
		{1, []byte("Other name"), "unavailable"},
		{3, []byte("false"), "unavailable"},
		{5, []byte(hex.EncodeToString(make([]byte, 32))), "stale"},
		{6, []byte(hex.EncodeToString(make([]byte, 64))), "unavailable"},
	} {
		args := [][]byte{[]byte(slot.ID.String()), []byte(slot.Name), []byte(slot.Protocol), []byte("true"), target, hex.AppendEncode(nil, digest[:]), stored.Rows[0][0]}
		args[tc.index] = tc.replacement
		err := session.queryServerCA(ctx, pinned, createSlotSQL, args, 512, 1, 4, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 4 || string(rows[0][0]) != tc.status || rows[0][1] != nil || rows[0][2] != nil || rows[0][3] != nil {
				return ErrAdmissionResponse
			}
			return nil
		})
		if err != nil {
			t.Fatalf("invalid slot input %d: %v", tc.index, err)
		}
	}
	if pinned.Catalog["slot/"+slot.ID.String()].Revision != 1 || create(slot, "saved").Revision != pinned.Revision {
		t.Fatal("retry changed the signed slot")
	}
	mismatch := slot
	mismatch.Protocol = "rdp"
	create(mismatch, "stale")
	if got := dba.ExecParams(ctx, "SELECT count(*)::text FROM wormhole_data.audit_log WHERE action='create_credential_slot' AND user_id=$1::uuid", [][]byte{user}, nil, nil, nil).Read(); got.Err != nil || len(got.Rows) != 1 || string(got.Rows[0][0]) != "1" {
		t.Fatal("retries must create exactly one audit event", got.Err)
	}
	_, page, err := session.AdminCredentialSlots(ctx, pinned, uuid.Nil)
	if err != nil || page == nil || len(page.Entries) != 1 || page.Entries[0] != slot {
		t.Fatal("signed slot not visible in inventory", err)
	}
	update("UPDATE wormhole_data.users SET is_admin=false WHERE id=$1::uuid", user)
	create(slot, "unavailable")
	update("UPDATE wormhole_data.users SET is_admin=true WHERE id=$1::uuid", user)
	update("UPDATE wormhole_data.boundary_grants SET permissions=5 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", target, user)
	create(slot, "unavailable")
	update("UPDATE wormhole_data.boundary_grants SET permissions=31 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", target, user)
	update("BEGIN")
	update("SELECT 1 FROM wormhole_data.workspace_meta FOR UPDATE")
	create(slot, "busy")
	update("ROLLBACK")
}
