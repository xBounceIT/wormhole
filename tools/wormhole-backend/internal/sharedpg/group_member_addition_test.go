package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestMemberAdditionOnlyExpandsTheSignedRosterByOne(t *testing.T) {
	previous := vault.GroupKeyManifest{GroupID: uuid.New(), GroupRevision: 9}
	existing, added, other := uuid.New(), uuid.New(), uuid.New()
	row := func(member uuid.UUID, proof string) []string {
		return []string{member.String(), "key", "1", "state", proof}
	}
	prior, _ := json.Marshal([][]string{row(existing, "original")})
	digest := groupKeyReviewDigest(GroupKeyRequest{GroupID: previous.GroupID, Revision: previous.GroupRevision}, prior)
	previous.RosterDigest = digest[:]
	wire := func(rows ...[]string) []byte { encoded, _ := json.Marshal(rows); return encoded }
	valid := wire(row(added, "new"), row(existing, "original"))
	if err := validateMemberAdditionRoster(previous, added, prior, valid); err != nil {
		t.Fatal("the verified recipient was rejected", err)
	}
	for name, test := range map[string]struct{ before, after []byte }{
		"missing signed roster":            {nil, valid},
		"different signed roster":          {wire(row(existing, "new proof")), valid},
		"additional undisclosed recipient": {prior, wire(row(added, "new"), row(existing, "original"), row(other, "new"))},
		"substituted existing proof":       {prior, wire(row(added, "new"), row(existing, "different"))},
		"missing selected recipient":       {prior, wire(row(other, "new"), row(existing, "original"))},
	} {
		if err := validateMemberAdditionRoster(previous, added, test.before, test.after); err == nil {
			t.Fatal("a changed recipient proof was accepted", name)
		}
	}
}

func checkKeyedMemberAddition(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, actor *vault.UserKeys, group uuid.UUID) TrustState {
	t.Helper()
	if supported, err := session.GroupMemberAdditionSupported(ctx); err != nil || !supported {
		t.Fatal("keyed addition is unavailable", err)
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT row_version::text FROM wormhole_data.groups WHERE id=$1::uuid`, [][]byte{[]byte(group.String())}, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := strconv.ParseUint(string(row[0]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(request GroupMemberRotationRequest, status string) (GroupMemberRotationReply, *GroupMemberAdditionPreparation) {
		t.Helper()
		next, reply, plan, err := session.PrepareGroupMemberAddition(ctx, trust, tls, request)
		if err != nil || reply.Status != status {
			t.Fatal("unexpected keyed addition status", status, reply.Status, err)
		}
		trust = next
		return reply, plan
	}
	nobody := GroupMemberRotationRequest{JobID: uuid.New(), GroupID: group, Revision: revision, Login: "nonexistent-account"}
	prepare(nobody, "account-unavailable")
	for i, login := range []string{"first-admin", "restored-admin"} {
		request := GroupMemberRotationRequest{JobID: uuid.New(), GroupID: group, Revision: revision + uint64(i), Login: login}
		reply, previewPlan := prepare(request, "review-add")
		if previewPlan != nil || reply.Addition == nil || reply.Addition.Member.Login != login || reply.Addition.Boundaries != 2 {
			t.Fatal("review omitted the certified member or affected boundaries")
		}
		if i == 1 {
			checkAdditionReviewEncoding(t, ctx, session, trust, request)
		}
		member := reply.Addition.Member.ID
		row, err := readAccountResetRow(ctx, dba, `SELECT (NOT EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=$1::uuid AND user_id=$2::uuid))::text`,
			[][]byte{[]byte(group.String()), []byte(member.String())}, 1, 8)
		if err != nil || string(row[0]) != "true" {
			t.Fatal("preview wrote membership", err)
		}
		stale := request
		stale.Review = &[32]byte{1}
		prepare(stale, "stale")
		var digest [32]byte
		if _, err := hex.Decode(digest[:], []byte(reply.Addition.Review)); err != nil {
			t.Fatal(err)
		}
		request.Review = &digest
		_, plan := prepare(request, "ready")
		if plan == nil || len(plan.roots) != 3 || len(plan.key.holders) != i+1 {
			t.Fatal("verified proposal did not bind all group copies and root wraps")
		}
		if i == 1 {
			if _, _, err := session.CommitPreparedGroupMemberAddition(ctx, trust, tls, nil, actor); err != ErrConfiguration {
				t.Fatal("member addition reached custody without its confirmed preparation", err)
			}
			other := cloneTrustState(trust)
			delete(other.Catalog, "group-key/"+group.String())
			if _, _, err := session.CommitPreparedGroupMemberAddition(ctx, other, tls, plan, actor); err != ErrTrustState {
				t.Fatal("member addition opened custody without committing the observed trust", err)
			}
			wrong := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{0x73}, 32), SigningSeed: actor.SigningSeed}
			defer vault.Wipe(wrong.EncryptionPrivate)
			if _, _, err := session.CommitPreparedGroupMemberAddition(ctx, trust, tls, plan, wrong); !errors.Is(err, vault.ErrAuthentication) {
				t.Fatal("a different private key opened organisation custody", err)
			}
			checkAdditionPublicationRollback(t, ctx, dba, session, trust, plan, actor, member)
		}
		preparedTrust := trust
		next, result, err := session.CommitPreparedGroupMemberAddition(ctx, trust, tls, plan, actor)
		if err != nil || result.Status != "added" || result.Receipt == nil || result.Receipt.JobID != request.JobID || result.Receipt.Pending != 0 {
			t.Fatal("member and copies did not publish atomically", result.Status, err)
		}
		trust = next
		if i == 1 {
			checkNewMemberBoundaryCopies(t, ctx, dba, trust, actor, plan)
		}
		if _, replay, err := session.CommitPreparedGroupMemberAddition(ctx, preparedTrust, tls, plan, actor); err != nil || replay.Receipt == nil || *replay.Receipt != *result.Receipt {
			t.Fatal("an uncertain commit did not reconcile the same receipt", err)
		}
		prepare(request, "added")
		prepare(stale, "stale")
	}
	row, err = readAccountResetRow(ctx, dba, `SELECT (
        (SELECT count(*) FROM wormhole_data.group_members WHERE group_id=$1::uuid)=2
        AND (SELECT count(*) FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
            WHERE k.kind='group' AND k.owner_id=$1::uuid AND k.status='active')=3
        AND (SELECT count(*) FROM wormhole_data.key_copies c JOIN wormhole_data.keys k
            ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
            WHERE k.kind='group' AND k.owner_id=$1::uuid AND k.status='active')=3
        AND (SELECT count(*) FROM wormhole_data.audit_log WHERE admin_group_id=$1::uuid AND action='group_keyed_member_addition')=2
        AND wormhole_data.group_rotation_queue_recoverable())::text`, [][]byte{[]byte(group.String())}, 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("addition omitted a copy, retained a retired wrap or duplicated the audit", err)
	}
	return trust
}

func checkNewMemberBoundaryCopies(t *testing.T, ctx context.Context, dba *pgconn.PgConn, trust TrustState, member *vault.UserKeys, plan *GroupMemberAdditionPreparation) {
	t.Helper()
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	group := plan.request.GroupID
	row, err := readAccountResetRow(ctx, dba, `SELECT convert_from(key_manifest,'UTF8') FROM wormhole_data.groups WHERE id=$1::uuid`,
		[][]byte{[]byte(group.String())}, 1, 4096)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.DecodeGroupKeyManifest(row[0])
	if err != nil {
		t.Fatal(err)
	}
	readCopy := func(key, holder vault.KeyRef) vault.SignedKeyCopy {
		t.Helper()
		row, err := readAccountResetRow(ctx, dba, `SELECT key_id::text,key_version::text,encode(enc,'hex'),encode(ciphertext,'hex'),encode(signature,'hex')
            FROM wormhole_data.key_copies WHERE (key_id,key_version,holder_key_id,holder_key_version,issuer_key_id,issuer_key_version)=
            ($1::uuid,$2::integer,$3::uuid,$4::integer,$5::uuid,$6::integer)`,
			append(append(keyCopyFixtureRef(key), keyCopyFixtureRef(holder)...), keyCopyFixtureRef(pin.Signer)...), 5, 8192)
		if err != nil {
			t.Fatal(err)
		}
		_, copy, err := parseServerCAOrgCopy(row)
		if err != nil {
			t.Fatal(err)
		}
		return copy
	}
	private, err := vault.OpenGroupKeyCopy(manifest, trust.WorkspaceID, group, pin.Signer, pin.Organisation, plan.key.previous.Version+1,
		trust.Enrollment.Encryption, member.EncryptionPrivate, readCopy(manifest.Key.Key, trust.Enrollment.Encryption))
	if err != nil {
		t.Fatal("the new member could not open its certified group key", err)
	}
	defer vault.Wipe(private)
	for _, root := range plan.roots {
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.key, Holder: manifest.Key.Key, Issuer: pin.Signer}
		scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: root.boundary.BoundaryID, Signer: pin.Signer,
			Organisation: pin.Organisation, MinimumRevision: root.boundary.Revision}
		seed, err := vault.OpenBoundaryKeyCopy(private, binding, readCopy(root.key, manifest.Key.Key),
			vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}, root.boundary, scope, root.purpose)
		vault.Wipe(seed)
		if err != nil {
			t.Fatal("the next group key could not open the current verified boundary root", err)
		}
	}
}

func checkAdditionReviewEncoding(t *testing.T, ctx context.Context, session *Session, trust TrustState, request GroupMemberRotationRequest) {
	t.Helper()
	if err := session.queryServerCA(ctx, trust, `SELECT convert_from(snapshot,'UTF8'),convert_from(roster,'UTF8')`+memberAdditionCall,
		request.additionArguments(nil), 1<<20, 1, 2, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 2 {
				return ErrAdmissionResponse
			}
			raw, roster := rows[0][0], rows[0][1]
			input, previous, _, err := decodeMemberAdditionSnapshot(request, raw, roster)
			if err != nil {
				return err
			}
			if _, _, _, err := decodeMemberAdditionSnapshot(request, raw, append(bytes.Clone(roster), ' ')); err != vault.ErrAuthentication {
				t.Fatal("altered roster matched the review", err)
			}
			wrong := request
			wrong.Review = &[32]byte{7}
			if _, _, _, err := decodeMemberAdditionSnapshot(wrong, raw, roster); err != vault.ErrAuthentication {
				t.Fatal("altered confirmation matched the review", err)
			}
			wrong = request
			wrong.JobID = uuid.New()
			if _, _, _, err := decodeMemberAdditionSnapshot(wrong, raw, roster); err != ErrAdmissionResponse {
				t.Fatal("another request was able to confirm the review", err)
			}
			input.Boundaries[0].Keys[0].ID = uuid.New()
			plan := &GroupMemberAdditionPreparation{}
			if _, err := plan.observeBoundaries(trust, input.Boundaries, previous.Signer); err != ErrAdmissionResponse {
				t.Fatal("a root outside the signed boundary was accepted", err)
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}

func checkAdditionPublicationRollback(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	plan *GroupMemberAdditionPreparation, actor *vault.UserKeys, member uuid.UUID) {
	t.Helper()
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := plan.wrap(ctx, trust, pin, actor)
	if err != nil {
		t.Fatal(err)
	}
	var publication struct {
		Manifest string               `json:"manifest"`
		Copies   json.RawMessage      `json:"copies"`
		Roots    []personalImportCopy `json:"roots"`
	}
	if err := json.Unmarshal(raw, &publication); err != nil {
		t.Fatal(err)
	}
	publication.Roots[len(publication.Roots)-1].Binding.Key.ID = uuid.New()
	bad, err := json.Marshal(publication)
	if err != nil {
		t.Fatal(err)
	}
	err = session.queryServerCA(ctx, trust, memberAdditionResultSQL, plan.request.additionArguments(bad), 8192, 1, 2,
		func([][][]byte) error { t.Error("unexpected receipt for substituted root"); return nil })
	if !errors.Is(err, ErrQuery) {
		t.Fatal("publication did not reject the substituted root", err)
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT (
        NOT EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=$1::uuid AND user_id=$2::uuid)
        AND NOT EXISTS(SELECT FROM wormhole_data.group_member_additions WHERE id=$3::uuid)
        AND EXISTS(SELECT FROM wormhole_data.keys WHERE (key_id,key_version)=($4::uuid,$5::integer) AND status='active')
        AND NOT EXISTS(SELECT FROM wormhole_data.keys WHERE (key_id,key_version)=($4::uuid,($5::integer)+1)))::text`,
		append([][]byte{[]byte(plan.request.GroupID.String()), []byte(member.String()), []byte(plan.request.JobID.String())}, keyCopyFixtureRef(plan.key.previous)...), 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("a rejected publication left a partial member or generation", err)
	}
}
