package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkPostgresGroupKeyProvisioning(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) vault.GroupKeyManifest {
	t.Helper()
	group := uuid.New()
	edit := func(r AdminGroupRequest) {
		t.Helper()
		if reply, err := session.AdminGroups(ctx, trust, r); err != nil || reply.Status != "changed" {
			t.Fatal("group setup failed", reply.Status, err)
		}
	}
	edit(AdminGroupRequest{Action: "create", GroupID: group.String(), Name: "Certified group"})
	read := func(request GroupKeyRequest, status string) (GroupKeyReply, *GroupKeyPreparation) {
		t.Helper()
		state, reply, plan, err := session.PrepareGroupKey(ctx, trust, tls, request)
		if err != nil || reply.Status != status {
			t.Fatal("unexpected group key preparation", reply.Status, status, err)
		}
		trust = state
		return reply, plan
	}
	if supported, err := session.GroupKeySupported(ctx); err != nil || !supported {
		t.Fatal("group key capability unavailable", err)
	}
	read(GroupKeyRequest{GroupID: group, Revision: 1}, "no-members")
	edit(AdminGroupRequest{Action: "add-member", GroupID: group.String(), Revision: "1", Login: "first-admin"})
	read(GroupKeyRequest{GroupID: group, Revision: 1}, "stale")
	request := GroupKeyRequest{GroupID: group, Revision: 2}
	reply, plan := read(request, "review")
	if plan != nil || reply.Preview == nil || len(reply.Preview.Members) != 1 ||
		reply.Preview.Members[0] != (GroupKeyMember{trust.UserID, "first-admin"}) {
		t.Fatal("review did not show the certified recipient", reply)
	}
	wrong := sha256.Sum256([]byte("wrong reviewed recipients"))
	request.Review = &wrong
	read(request, "stale")
	var review [32]byte
	if _, err := hex.Decode(review[:], []byte(reply.Preview.Review)); err != nil {
		t.Fatal(err)
	}
	request.Review = &review
	if _, plan = read(request, "ready"); plan == nil {
		t.Fatal("confirmed review did not prepare key issuance")
	}
	edit(AdminGroupRequest{Action: "rename", GroupID: group.String(), Revision: "2", Name: "Reviewed certified group"})
	if _, reply, err := session.CommitPreparedGroupKey(ctx, trust, tls, plan, keys); err != nil || reply.Status != "stale" {
		t.Fatal("a changed group accepted the previously reviewed key", reply.Status, err)
	}
	request.Revision = 3
	read(request, "stale")
	request.Review = nil
	refreshed, _ := read(request, "review")
	if _, err := hex.Decode(review[:], []byte(refreshed.Preview.Review)); err != nil {
		t.Fatal(err)
	}
	request.Review = &review
	if _, plan = read(request, "ready"); plan == nil {
		t.Fatal("current group revision could not prepare issuance")
	}
	observed, committed, err := session.CommitPreparedGroupKey(ctx, trust, tls, plan, keys)
	if err != nil || committed.Status != "issued" || observed.Catalog["group-key/"+group.String()].Revision != 1 {
		t.Fatal("group key issuance did not persist an authenticated manifest", committed.Status, err)
	}
	trust = observed
	read(request, "provisioned")
	if _, reply, err := session.CommitPreparedGroupKey(ctx, trust, tls, plan, keys); err != nil || reply.Status != "provisioned" {
		t.Fatal("group key retry generated another key", reply.Status, err)
	}
	query := func(sql string) [][]byte {
		t.Helper()
		result := dba.ExecParams(ctx, sql, [][]byte{[]byte(group.String()), []byte(trust.Enrollment.Encryption.ID.String())}, nil, nil, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 {
			t.Fatal("group custody fixture query", result.Err)
		}
		return result.Rows[0]
	}
	row := query(`SELECT convert_from(g.key_manifest,'UTF8'),encode(c.enc,'hex'),encode(c.ciphertext,'hex'),encode(c.signature,'hex')
		FROM wormhole_data.groups g JOIN wormhole_data.keys k ON k.owner_id=g.id AND k.kind='group'
		JOIN wormhole_data.key_copies c USING(key_id,key_version) WHERE g.id=$1::uuid AND c.holder_key_id=$2::uuid`)
	manifest, err := vault.DecodeGroupKeyManifest(row[0])
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := hex.DecodeString(string(row[1]))
	ciphertext, _ := hex.DecodeString(string(row[2]))
	proof, _ := hex.DecodeString(string(row[3]))
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := vault.OpenGroupKeyCopy(manifest, trust.WorkspaceID, group, pin.Signer, pin.Organisation, 1, trust.Enrollment.Encryption,
		keys.EncryptionPrivate, vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: enc, Ciphertext: ciphertext}, Signature: proof})
	defer vault.Wipe(opened)
	if err != nil || len(opened) != 32 || bytes.Contains(row[0], opened) {
		t.Fatal("a real enrolled member could not open the signed group recipient", err)
	}
	state := query(`SELECT (wormhole_data.group_keys_recoverable(m.workspace_id)
		AND EXISTS(SELECT FROM wormhole_data.groups g WHERE g.id=$1::uuid AND g.row_version=4)
		AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='group_key_provision' AND admin_group_id=$1::uuid)=1
		AND EXISTS(SELECT FROM wormhole_data.user_enrollments e WHERE e.encryption_key_id=$2::uuid))::text FROM wormhole_data.workspace_meta m`)
	if len(state) != 1 || string(state[0]) != "true" {
		t.Fatal("group issuance lacked recovery custody or a single audit record")
	}
	remove := AdminGroupRequest{Action: "remove-member", GroupID: group.String(), Revision: "4", MemberID: trust.UserID.String()}
	if reply, err := session.AdminGroups(ctx, trust, remove); err != nil || reply.Status != "key-change-required" {
		t.Fatal("unkeyed membership deletion remained available after issuance", reply.Status, err)
	}
	return manifest
}
