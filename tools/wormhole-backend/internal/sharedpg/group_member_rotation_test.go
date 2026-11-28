package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestMemberRotationRequiresAuthenticatedScope(t *testing.T) {
	var session *Session
	ctx := context.Background()
	request := GroupMemberRotationRequest{JobID: uuid.New(), GroupID: uuid.New(), MemberID: uuid.New(), Revision: 3}
	if _, _, plan, err := session.PrepareGroupMemberRotation(nil, TrustState{}, nil, request); err != ErrConfiguration || plan != nil {
		t.Fatal("removal accepted a missing operation context", err)
	}
	if _, _, plan, err := session.PrepareGroupMemberRotation(ctx, TrustState{}, nil, request); err == nil || plan != nil {
		t.Fatal("removal accepted an unverified account and transport", err)
	}
	step := MemberBoundaryRotationRequest{JobID: request.JobID, GroupID: request.GroupID, BoundaryID: uuid.New()}
	if _, _, _, plan, err := session.PrepareMemberBoundaryRotation(ctx, TrustState{}, nil, step); err == nil || plan != nil {
		t.Fatal("worker accepted an unverified account and transport", err)
	}
	if progress, err := session.ReadGroupMemberRotation(ctx, TrustState{}, nil, request.GroupID, uuid.Nil); err == nil || progress != nil {
		t.Fatal("progress was disclosed without an authenticated account and transport", err)
	}
}

type restoredAdministratorFixture struct {
	join     func(*testing.T, WorkspaceRecoveryTarget, *pgconn.PgConn, []byte, string, joinedAdministratorCheck)
	appOffer func(*testing.T, WorkspaceRecoveryTarget, []byte, string) (document, code, ask []byte)
}

func checkGroupMemberRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle,
	actor *vault.UserKeys, group, boundary, connection uuid.UUID, recover restoredAdministratorFixture) {
	t.Helper()
	if supported, err := session.GroupMemberRotationSupported(ctx); err != nil || !supported {
		t.Fatal("member rotation capability unavailable", err)
	}
	additional := createAdditionalMemberRotationBoundary(t, ctx, dba, trust, actor, group)
	request := GroupMemberRotationRequest{JobID: uuid.New(), GroupID: group, MemberID: trust.UserID, Revision: 3}
	prepare := func(r GroupMemberRotationRequest, status string) (GroupMemberRotationReply, *GroupMemberRotationPreparation) {
		t.Helper()
		next, reply, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, r)
		if err != nil || reply.Status != status {
			t.Fatal("unexpected member rotation preparation", reply.Status, status, err)
		}
		trust = next
		return reply, plan
	}
	reply, plan := prepare(request, "review")
	if plan != nil || reply.Preview == nil || reply.Preview.Remaining == nil || len(reply.Preview.Remaining) != 0 || reply.Preview.Boundaries != 2 {
		t.Fatal("review did not exclude the member and identify its exact boundary scope")
	}
	checkMemberRotationReviewEncoding(t, ctx, session, trust, request)
	var wrong [32]byte
	bad := request
	bad.Review = &wrong
	prepare(bad, "stale")
	var review [32]byte
	if _, err := hex.Decode(review[:], []byte(reply.Preview.Review)); err != nil {
		t.Fatal(err)
	}
	request.Review = &review
	_, plan = prepare(request, "ready")
	if plan == nil {
		t.Fatal("confirmed member review did not prepare a replacement")
	}
	preparedTrust := trust
	if _, _, err := session.CommitPreparedGroupMemberRotation(ctx, trust, tls, nil, actor); err != ErrConfiguration {
		t.Fatal("member rotation accessed custody without a prepared review", err)
	}
	otherTrust := cloneTrustState(trust)
	delete(otherTrust.Catalog, "group-key/"+group.String())
	if _, _, err := session.CommitPreparedGroupMemberRotation(ctx, otherTrust, tls, plan, actor); err != ErrTrustState {
		t.Fatal("member rotation accepted a changed trust floor", err)
	}
	otherKeys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{0x72}, 32), SigningSeed: actor.SigningSeed}
	defer vault.Wipe(otherKeys.EncryptionPrivate)
	if _, _, err := session.CommitPreparedGroupMemberRotation(ctx, trust, tls, plan, otherKeys); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("a different account opened organisation custody for group rotation", err)
	}
	next, rotated, err := session.CommitPreparedGroupMemberRotation(ctx, trust, tls, plan, actor)
	if err != nil || rotated.Status != "rotated" || rotated.Receipt == nil || rotated.Receipt.JobID != request.JobID || rotated.Receipt.Pending != 2 ||
		next.Catalog["group-key/"+group.String()].Revision != 2 {
		t.Fatal("group replacement did not publish membership, generation and pending work together", rotated.Status, err)
	}
	trust = next
	if _, repeated, err := session.CommitPreparedGroupMemberRotation(ctx, preparedTrust, tls, plan, actor); err != nil || repeated.Status != "rotated" ||
		repeated.Receipt == nil || *repeated.Receipt != *rotated.Receipt {
		t.Fatal("retrying a prepared commit changed its result", repeated.Status, err)
	}
	again, _ := prepare(request, "rotated")
	if again.Receipt == nil || *again.Receipt != *rotated.Receipt {
		t.Fatal("retry lost the original job identity")
	}
	bad = request
	bad.Review = &wrong
	prepare(bad, "stale")
	bad = request
	bad.JobID = uuid.New()
	bad.Revision++
	prepare(bad, "rotation-pending")
	addition := GroupMemberRotationRequest{JobID: uuid.New(), GroupID: group, Revision: bad.Revision, Login: "first-admin"}
	if _, reply, plan, err := session.PrepareGroupMemberAddition(ctx, trust, tls, addition); err != nil || reply.Status != "rotation-pending" || plan != nil {
		t.Fatal("a group awaiting rotation accepted a new recipient", reply.Status, err)
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT (wormhole_data.group_rotation_queue_recoverable()
	    AND NOT EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=$1::uuid)
	    AND NOT EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
	        WHERE k.kind='group' AND k.owner_id=$1::uuid AND c.holder_key_id=$2::uuid)
	    AND (SELECT count(*) FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=$3::uuid)=3)::text`,
		[][]byte{[]byte(group.String()), []byte(trust.Enrollment.Encryption.ID.String()), []byte(request.JobID.String())}, 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("removed member retained a group copy or the revocation backlog was not durable", err)
	}
	assertPendingMemberRotationGuards(t, ctx, dba, request.JobID)
	snapshot, err := session.ReadWorkspaceRecoverySnapshot(ctx, trust, tls, actor.EncryptionPrivate, actor.SigningSeed)
	if err != nil {
		t.Fatal("pending member rotation could not be backed up", err)
	}
	defer snapshot.Close()
	var jobs, roots int
	for _, row := range snapshot.Records {
		if row.Relation == "group_member_rotation_jobs" && bytes.Contains(row.Body, []byte(request.JobID.String())) {
			jobs++
		}
		if row.Relation == "group_boundary_rotation_queue" && bytes.Contains(row.Body, []byte(request.JobID.String())) {
			roots++
		}
	}
	if jobs != 1 || roots != 3 {
		t.Fatal("backup omitted the pending work", jobs, roots)
	}
	if !t.Run("RestorePendingRotation", func(t *testing.T) {
		archive, err := json.Marshal(archiveBeforeRosterReconciliation(t, snapshot))
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(archive)
		target, restored, deployerFactor := restoreWorkspaceRecoveryArchive(t, ctx, dba, archive, trust.UserID, plan.key.custody.recipient.Encryption.ID, workspaceImportFixtureNodeCount)
		assertPendingMemberRotationGuards(t, ctx, restored, request.JobID)
		recover.join(t, target, restored, deployerFactor, "restored-admin", func(session *Session, trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys) {
			row, err := readAccountResetRow(ctx, restored, `SELECT (count(*)=3)::text FROM wormhole_data.group_boundary_rotation_queue q
                JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(q.root_id,q.root_version)
                WHERE q.job_id=$1::uuid AND c.holder_key_id=$2::uuid`,
				[][]byte{[]byte(request.JobID.String()), []byte(trust.Enrollment.Encryption.ID.String())}, 1, 8)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("certified Join lost custody of one or more queued roots", err)
			}
			assertPendingMemberRotationGuards(t, ctx, restored, request.JobID)
			trust = finishMemberRotation(t, ctx, session, trust, tls, actor, group, request.JobID, boundary, additional)
			checkRecoveredBoundaryKeys(t, ctx, restored, trust, actor, boundary, additional)
			row, err = readAccountResetRow(ctx, restored, `SELECT (count(DISTINCT admin_boundary_id)=2)::text FROM wormhole_data.audit_log
                WHERE action='member_boundary_rotation' AND outcome='success' AND user_id=$1::uuid AND admin_group_id=$2::uuid
                AND admin_boundary_id IN ($3::uuid,$4::uuid)`,
				[][]byte{[]byte(trust.UserID.String()), []byte(group.String()), []byte(boundary.String()), []byte(additional.String())}, 1, 8)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("recovered administrator's boundary rotations were not audited", err)
			}
			checkImportedQueryDenied(t, ctx, session, beginUsePathSQL, "42501",
				[]byte(connection.String()), []byte("ui"), []byte("ssh"))
			trust = checkKeyedMemberAddition(t, ctx, restored, session, trust, tls, actor, group)
			checkPendingRosterReconciliation(t, ctx, restored, session, trust, tls, actor, group, boundary, additional, connection, recover)
		})
	}) {
		t.Fatal("pending member rotation could not be restored")
	}
	trust = finishMemberRotation(t, ctx, session, trust, tls, actor, group, request.JobID, boundary, additional)
	row, err = readAccountResetRow(ctx, dba, `SELECT (
        (SELECT count(*) FROM wormhole_data.boundary_grants WHERE group_id=$1::uuid AND boundary_id IN ($2::uuid,$3::uuid))=2
        AND NOT EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k
            ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
            WHERE k.owner_id=$1::uuid AND k.kind='group')
        AND wormhole_data.group_rotation_queue_recoverable())::text`,
		[][]byte{[]byte(group.String()), []byte(boundary.String()), []byte(additional.String())}, 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("empty group received a boundary copy or lost its configured grants", err)
	}
	checkImportedPathReleases(t, ctx, session, trust, connection, actor.EncryptionPrivate, uuid.Nil)
}

func archiveBeforeRosterReconciliation(t *testing.T, source *WorkspaceRecoverySnapshot) WorkspaceRecoverySnapshot {
	t.Helper()
	archive := *source
	archive.Records = slices.DeleteFunc(slices.Clone(source.Records), func(row WorkspaceRecoveryRecord) bool {
		return strings.HasPrefix(row.Relation, "account_suspension")
	})
	for i, item := range archive.Records {
		switch item.Relation {
		case "workspace_meta", "group_member_rotation_jobs", "group_boundary_rotation_queue":
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(item.Body, &fields); err != nil {
				t.Fatal(err)
			}
			if item.Relation == "workspace_meta" {
				fields["schema_version"] = json.RawMessage("68")
			} else {
				delete(fields, "holder_version")
				delete(fields, "replacement_revision")
				delete(fields, "replacement_version")
			}
			var err error
			archive.Records[i].Body, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return archive
}

func finishMemberRotation(t *testing.T, ctx context.Context, session *Session, trust TrustState, tls *VerifiedTLSBundle,
	actor *vault.UserKeys, group, job uuid.UUID, boundaries ...uuid.UUID) TrustState {
	t.Helper()
	progress, err := session.ReadGroupMemberRotation(ctx, trust, tls, group, uuid.Nil)
	if err != nil || progress == nil || progress.JobID != job || progress.Pending != len(boundaries) ||
		!slices.Contains(boundaries, progress.Next) {
		t.Fatal("a resume without the originating request could not find the pending boundary", err)
	}
	for pending := len(boundaries); pending > 0; pending-- {
		step := MemberBoundaryRotationRequest{JobID: progress.JobID, GroupID: progress.GroupID, BoundaryID: progress.Next}
		if pending == len(boundaries) {
			checkMemberBoundaryReviewEncoding(t, ctx, session, trust, step)
		}
		next, status, digest, work, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls, step)
		if err != nil || status != "review" || digest == nil || work != nil {
			t.Fatal("pending boundary could not be reviewed", status, err)
		}
		trust, step.Review = next, digest
		next, status, _, work, err = session.PrepareMemberBoundaryRotation(ctx, trust, tls, step)
		if err != nil || status != "ready" || work == nil {
			t.Fatal("pending boundary verification did not stage a write", status, err)
		}
		next, result, err := session.CommitPreparedMemberBoundaryRotation(ctx, next, tls, work, actor)
		if err != nil || result.Status != "changed" {
			t.Fatal("confirmed pending boundary did not commit", result.Status, err)
		}
		trust = next
		progress, err = session.ReadGroupMemberRotation(ctx, trust, tls, group, job)
		if err != nil || progress == nil || progress.Pending != pending-1 ||
			(progress.Pending == 0) != (progress.Next == uuid.Nil) || progress.Next == step.BoundaryID ||
			(progress.Pending > 0 && !slices.Contains(boundaries, progress.Next)) {
			t.Fatal("one completed boundary affected another pending step", err)
		}
		if _, status, _, plan, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls, step); err != nil || status != "unchanged" || plan != nil {
			t.Fatal("finished boundary was rotated again", status, err)
		}
	}
	if progress, err := session.ReadGroupMemberRotation(ctx, trust, tls, group, uuid.Nil); err != nil || progress != nil {
		t.Fatal("unscoped resume returned a completed rotation", err)
	}
	return trust
}

func checkRecoveredBoundaryKeys(t *testing.T, ctx context.Context, conn *pgconn.PgConn, trust TrustState, actor *vault.UserKeys, boundaryID, additional uuid.UUID) {
	t.Helper()
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	public, err := actor.Public()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{boundaryID, additional} {
		row, err := readAccountResetRow(ctx, conn, `SELECT convert_from(body,'UTF8') FROM wormhole_data.boundary_manifests WHERE boundary_id=$1::uuid`,
			[][]byte{[]byte(id.String())}, 1, 4096)
		if err != nil {
			t.Fatal(err)
		}
		boundary, err := vault.DecodeBoundaryManifest(row[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			key     vault.KeyRef
			purpose vault.BoundaryPurpose
		}{{boundary.View.Key, vault.BoundaryView}, {boundary.Secret.Key, vault.BoundarySecret}} {
			issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
			// The synthetic boundary's unaffected Secret root keeps the copy
			// signed by the recovered account during certified Join.
			if id == additional && item.purpose == vault.BoundarySecret {
				issuer = vault.KeyCopyTrust{Issuer: trust.Enrollment.Signing, Public: public.Signing}
			}
			row, err := readAccountResetRow(ctx, conn, `SELECT key_id::text,key_version::text,encode(enc,'hex'),encode(ciphertext,'hex'),encode(signature,'hex')
                FROM wormhole_data.key_copies WHERE (key_id,key_version,holder_key_id,holder_key_version,issuer_key_id,issuer_key_version)=
                ($1::uuid,$2::integer,$3::uuid,$4::integer,$5::uuid,$6::integer)`,
				append(append(keyCopyFixtureRef(item.key), keyCopyFixtureRef(trust.Enrollment.Encryption)...), keyCopyFixtureRef(issuer.Issuer)...), 5, 8192)
			if err != nil {
				t.Fatal("new boundary root was not assigned to the recovered custodian", err)
			}
			_, sealed, err := parseServerCAOrgCopy(row)
			if err != nil {
				t.Fatal(err)
			}
			binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: item.key, Holder: trust.Enrollment.Encryption, Issuer: issuer.Issuer}
			boundaryTrust := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: id, Signer: pin.Signer, Organisation: pin.Organisation}
			seed, err := vault.OpenBoundaryKeyCopy(actor.EncryptionPrivate, binding, sealed, issuer, boundary, boundaryTrust, item.purpose)
			vault.Wipe(seed)
			if err != nil {
				t.Fatal("recovered custodian could not open the signed replacement root", err)
			}
		}
	}
}

func checkMemberRotationReviewEncoding(t *testing.T, ctx context.Context, session *Session, trust TrustState, request GroupMemberRotationRequest) {
	t.Helper()
	if err := session.queryServerCA(ctx, trust, `SELECT convert_from(snapshot,'UTF8'),convert_from(roster,'UTF8')`+memberRotationCall, request.arguments(nil), 1<<20, 1, 2, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 2 {
			return ErrAdmissionResponse
		}
		raw, roster := rows[0][0], rows[0][1]
		snapshot, manifest, _, _, err := decodeMemberRotationSnapshot(request, raw, roster)
		if err != nil || len(snapshot.Roots) != 3 {
			t.Fatal("rotation input omitted its signed group or boundary roots", err)
		}
		if _, _, _, _, err := decodeMemberRotationSnapshot(request, nil, roster); err != ErrAdmissionResponse {
			t.Fatal("an empty rotation review was accepted", err)
		}
		if _, _, _, _, err := decodeMemberRotationSnapshot(request, raw, []byte("[ ]")); err != vault.ErrAuthentication {
			t.Fatal("an altered roster matched the snapshot", err)
		}
		mismatched := request
		mismatched.Review = &[sha256.Size]byte{1}
		if _, _, _, _, err := decodeMemberRotationSnapshot(mismatched, raw, roster); err != vault.ErrAuthentication {
			t.Fatal("an altered confirmation matched its snapshot", err)
		}
		for name, edit := range map[string]func(*memberRotationSnapshot){
			"scope":              func(doc *memberRotationSnapshot) { doc.JobID = uuid.New() },
			"malformed manifest": func(doc *memberRotationSnapshot) { doc.Manifest = "z" },
			"duplicate root":     func(doc *memberRotationSnapshot) { doc.Roots = append(slices.Clone(doc.Roots), doc.Roots[0]) },
		} {
			bad := snapshot
			edit(&bad)
			encoded, err := json.Marshal(bad)
			if err != nil {
				return err
			}
			if _, _, _, _, err := decodeMemberRotationSnapshot(request, encoded, roster); err != ErrAdmissionResponse {
				t.Fatal("an invalid rotation review was accepted", name, err)
			}
		}
		body, err := vault.EncodeGroupKeyManifest(manifest)
		if err != nil {
			return err
		}
		reply := GroupMemberRotationReply{Status: "rotated"}
		if err := acceptMemberRotationResult(&trust, request, &reply, body, []byte("2")); err != ErrAdmissionResponse || reply.Receipt != nil {
			t.Fatal("the previous group generation was accepted as a receipt", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func checkMemberBoundaryReviewEncoding(t *testing.T, ctx context.Context, session *Session, trust TrustState, request MemberBoundaryRotationRequest) {
	t.Helper()
	if err := session.queryServerCA(ctx, trust, `SELECT convert_from(snapshot,'UTF8')`+memberBoundaryRotationCall, request.arguments(nil), 32768, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 {
			return ErrAdmissionResponse
		}
		raw := rows[0][0]
		if _, _, _, _, err := verifyMemberBoundarySnapshot(request, raw); err != nil {
			return err
		}
		other := request
		other.BoundaryID = uuid.New()
		if _, _, _, _, err := verifyMemberBoundarySnapshot(other, raw); err != ErrAdmissionResponse {
			t.Fatal("accepted the review of a different boundary", err)
		}
		request.Review = &[sha256.Size]byte{1}
		if _, _, _, _, err := verifyMemberBoundarySnapshot(request, raw); err != vault.ErrAuthentication {
			t.Fatal("accepted an altered boundary confirmation", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertPendingMemberRotationGuards(t *testing.T, ctx context.Context, conn *pgconn.PgConn, job uuid.UUID) {
	t.Helper()
	args := [][]byte{[]byte(job.String())}
	for name, query := range map[string]string{
		"envelope": `UPDATE wormhole_data.secret_values v SET envelope=v.envelope WHERE EXISTS(
            SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.group_boundary_rotation_queue q
              ON (c.holder_key_id,c.holder_key_version)=(q.root_id,q.root_version)
            WHERE (c.key_id,c.key_version)=(v.dek_id,v.dek_version) AND q.job_id=$1::uuid)`,
		"key copy": `UPDATE wormhole_data.key_copies c SET enc=c.enc WHERE EXISTS(
            SELECT FROM wormhole_data.group_boundary_rotation_queue q
            WHERE (c.key_id,c.key_version)=(q.root_id,q.root_version) AND q.job_id=$1::uuid)`,
		"new key copy": `INSERT INTO wormhole_data.key_copies SELECT c.* FROM wormhole_data.key_copies c
            JOIN wormhole_data.group_boundary_rotation_queue q ON (c.key_id,c.key_version)=(q.root_id,q.root_version)
            WHERE q.job_id=$1::uuid LIMIT 1 ON CONFLICT DO NOTHING`,
	} {
		blocked := conn.ExecParams(ctx, query, args, nil, nil, nil).Read()
		var refusal *pgconn.PgError
		if !errors.As(blocked.Err, &refusal) || refusal.Code != "WH020" {
			t.Fatal("a pending root accepted a write", name, blocked.Err)
		}
	}
}

// A second independently signed boundary exercises the durable multi-boundary
// job. The first boundary's imported secrets exercise actual rewrapping.
func createAdditionalMemberRotationBoundary(t *testing.T, ctx context.Context, dba *pgconn.PgConn, trust TrustState,
	actor *vault.UserKeys, groupID uuid.UUID) uuid.UUID {
	t.Helper()
	query := func(sql string, args [][]byte, count int) [][]byte {
		t.Helper()
		row, err := readAccountResetRow(ctx, dba, sql, args, count, 8192)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	groupRow := query(`SELECT convert_from(key_manifest,'UTF8') FROM wormhole_data.groups WHERE id=$1::uuid`, [][]byte{[]byte(groupID.String())}, 1)
	group, err := vault.DecodeGroupKeyManifest(groupRow[0])
	if err != nil {
		t.Fatal(err)
	}
	borrow := func(ref vault.KeyRef) []byte {
		t.Helper()
		row := query(`SELECT key_id::text,key_version::text,encode(enc,'hex'),encode(ciphertext,'hex'),encode(signature,'hex')
            FROM wormhole_data.key_copies WHERE (key_id,key_version,holder_key_id,holder_key_version)=($1::uuid,$2::integer,$3::uuid,$4::integer)`,
			append(keyCopyFixtureRef(ref), keyCopyFixtureRef(trust.Enrollment.Encryption)...), 5)
		key, sealed, err := parseServerCAOrgCopy(row)
		if err != nil || key != ref {
			t.Fatal("could not open test custodian key", err)
		}
		seed, err := openServerCAOrgCopy(trust, key, sealed, actor.EncryptionPrivate, actor.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		return seed
	}
	org := &vault.UserKeys{SigningSeed: borrow(group.Signer), EncryptionPrivate: borrow(group.Recovery)}
	defer org.Wipe()
	public, err := org.Public()
	if err != nil {
		t.Fatal(err)
	}
	actorPublic, err := actor.Public()
	if err != nil {
		t.Fatal(err)
	}
	viewSeed, secretSeed := make([]byte, 32), make([]byte, 32)
	defer vault.Wipe(viewSeed)
	defer vault.Wipe(secretSeed)
	view, err := newBoundaryRoot(viewSeed)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := newBoundaryRoot(secretSeed)
	if err != nil {
		t.Fatal(err)
	}
	boundary := uuid.New()
	signer := ed25519.NewKeyFromSeed(org.SigningSeed)
	defer vault.Wipe(signer)
	manifest, err := vault.SignBoundaryManifest(vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: trust.WorkspaceID, BoundaryID: boundary,
		Revision: 1, Active: true, OrgEscrow: true, Signer: group.Signer, View: view, Secret: secret}, signer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := vault.EncodeBoundaryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	arg := []byte(boundary.String())
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)`, arg)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.boundary_manifests(boundary_id,body,signer_key_id,signer_key_version,signature)
        VALUES($1::uuid,convert_to($2,'UTF8'),$3::uuid,$4::integer,decode($5,'hex'))`,
		append(append([][]byte{arg, body}, keyCopyFixtureRef(group.Signer)...), hex.AppendEncode(nil, manifest.Signature))...)
	for _, root := range []struct {
		kind      string
		key       vault.BoundaryKey
		seed      []byte
		groupView bool
	}{{"boundary-view", view, viewSeed, true}, {"boundary-secret", secret, secretSeed, false}} {
		groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
            VALUES($1::uuid,$2::integer,$3,$4::uuid,2,decode($5,'hex'))`,
			append(keyCopyFixtureRef(root.key.Key), []byte(root.kind), arg, hex.AppendEncode(nil, root.key.Public))...)
		holders := []vault.BoundaryKey{{Key: group.Recovery, Public: public.Encryption}, {Key: trust.Enrollment.Encryption, Public: actorPublic.Encryption}}
		if root.groupView {
			holders = append(holders, group.Key)
		}
		for _, holder := range holders {
			sealed, err := vault.SealKeyCopy(root.seed,
				vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.key.Key, Holder: holder.Key, Issuer: group.Signer}, holder.Public, org.SigningSeed)
			if err != nil {
				t.Fatal(err)
			}
			refs := append(append(keyCopyFixtureRef(root.key.Key), keyCopyFixtureRef(holder.Key)...), keyCopyFixtureRef(group.Signer)...)
			groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,issuer_key_id,issuer_key_version,suite,enc,ciphertext,signature)
                VALUES($1::uuid,$2::integer,$3::uuid,$4::integer,$5::uuid,$6::integer,2,decode($7,'hex'),decode($8,'hex'),decode($9,'hex'))`,
				append(refs, hex.AppendEncode(nil, sealed.Envelope.Enc), hex.AppendEncode(nil, sealed.Envelope.Ciphertext), hex.AppendEncode(nil, sealed.Signature))...)
		}
	}
	groupBoundaryFixtureSQL(t, ctx, dba, 2, `INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,group_id,permissions)
        VALUES($1::uuid,$2::uuid,NULL,$4::integer),($1::uuid,NULL,$3::uuid,$5::integer)`,
		arg, []byte(trust.UserID.String()), []byte(groupID.String()), []byte("31"), []byte("1"))
	seedAccountRotationPassword(t, ctx, dba, trust.WorkspaceID, boundary, manifest.Secret, group.Signer, org.SigningSeed)
	return boundary
}
