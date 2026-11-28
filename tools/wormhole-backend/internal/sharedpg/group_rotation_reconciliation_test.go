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

func checkPendingRosterReconciliation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, actor *vault.UserKeys, group, boundary, additional, connection uuid.UUID, recover restoredAdministratorFixture) {
	t.Helper()
	if supported, err := session.GroupMemberReconciliationSupported(ctx); err != nil || !supported {
		t.Fatal("schema 69 did not announce rotation reconciliation", err)
	}
	query := func(sql string, args ...string) string {
		t.Helper()
		values := make([][]byte, len(args))
		for i, arg := range args {
			values[i] = []byte(arg)
		}
		row, err := readAccountResetRow(ctx, dba, sql, values, 1, 4096)
		if err != nil {
			t.Fatal(err)
		}
		return string(row[0])
	}
	first := uuid.MustParse(query(`SELECT id::text FROM wormhole_data.users WHERE login_name='first-admin'`))
	// Give this test custodian node Manage to publish a second group grant. The
	// first group will have finished this boundary when the second job starts.
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,31)`,
		[]byte(connection.String()), []byte(trust.UserID.String()))
	other := publishGroupForRotation(t, ctx, session, trust, tls, actor, GroupBoundaryGrantRequest{
		NodeID: connection.String(), NodeRevision: query(`SELECT row_version::text FROM wormhole_data.nodes WHERE id=$1::uuid`, connection.String()),
		BoundaryID: boundary.String(),
	}, "Overlapping rotation group")
	removal := func(group, member uuid.UUID, suspension uint64) GroupMemberRotationRequest {
		t.Helper()
		revision, err := strconv.ParseUint(query(`SELECT row_version::text FROM wormhole_data.groups WHERE id=$1::uuid`, group.String()), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return GroupMemberRotationRequest{JobID: uuid.New(), GroupID: group, MemberID: member, Revision: revision, Suspension: suspension}
	}
	reviewRemoval := func(request GroupMemberRotationRequest, want int) GroupMemberRotationRequest {
		t.Helper()
		next, preview, _, err := session.PrepareGroupMemberRotation(ctx, trust, tls, request)
		if err != nil || preview.Preview == nil || preview.Preview.Boundaries != want {
			t.Fatal("could not start a removal with the exact boundary scope", preview.Status, err)
		}
		if request.Suspension != 0 && preview.Preview.Suspension != strconv.FormatUint(request.Suspension, 10) {
			t.Fatal("review lost its suspension scope")
		}
		var digest [32]byte
		if _, err := hex.Decode(digest[:], []byte(preview.Preview.Review)); err != nil {
			t.Fatal(err)
		}
		request.Review = &digest
		trust = next
		return request
	}
	prepareRemoval := func(request GroupMemberRotationRequest) *GroupMemberRotationPreparation {
		t.Helper()
		next, prepared, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, request)
		if err != nil || prepared.Status != "ready" || plan == nil {
			t.Fatal("could not stage removal", prepared.Status, err)
		}
		trust = next
		return plan
	}
	start := func(request GroupMemberRotationRequest, want int) uuid.UUID {
		t.Helper()
		request = reviewRemoval(request, want)
		plan := prepareRemoval(request)
		next, published, err := session.CommitPreparedGroupMemberRotation(ctx, trust, tls, plan, actor)
		if err != nil || published.Status != "rotated" || published.Receipt == nil || published.Receipt.Pending != want {
			t.Fatal("could not publish removal", published.Status, err)
		}
		trust = next
		if request.Suspension != 0 {
			_, retry, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, request)
			if err != nil || retry.Status != "rotated" || retry.Receipt == nil || retry.Receipt.JobID != request.JobID || plan != nil {
				t.Fatal("exact scoped retry lost the committed job", retry.Status, err)
			}
			otherScope := request
			otherScope.Suspension++
			withoutReview := request
			withoutReview.Review = nil
			for _, bad := range []GroupMemberRotationRequest{otherScope, withoutReview} {
				if _, reply, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, bad); err != nil || reply.Status != "stale" || plan != nil {
					t.Fatal("a different request received a committed scoped job", reply.Status, err)
				}
			}
		}
		return request.JobID
	}
	job := start(removal(group, trust.UserID, 0), 2)
	step := MemberBoundaryRotationRequest{JobID: job, GroupID: group, BoundaryID: boundary}
	next, status, digest, _, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls, step)
	if err != nil || status != "review" || digest == nil {
		t.Fatal("could not review the first boundary", status, err)
	}
	step.Review = digest
	next, status, _, stepPlan, err := session.PrepareMemberBoundaryRotation(ctx, next, tls, step)
	if err != nil || status != "ready" || stepPlan == nil {
		t.Fatal("could not prepare the first boundary", status, err)
	}
	next, rotated, err := session.CommitPreparedMemberBoundaryRotation(ctx, next, tls, stepPlan, actor)
	if err != nil || rotated.Status != "changed" {
		t.Fatal("could not rotate the first boundary", rotated.Status, err)
	}
	trust = next
	otherJob := start(removal(other, first, 0), 1)
	changeFirstAccountAccess := func(action string) {
		t.Helper()
		review, err := session.WorkspaceAccess(ctx, trust, WorkspaceAccessRequest{Action: action, TargetID: first.String()})
		if err != nil || review.Status != "review" || review.Review == nil {
			t.Fatal("could not review the account's workspace access", review.Status, err)
		}
		changed, err := session.WorkspaceAccess(ctx, trust, review.Review.WorkspaceAccessRequest)
		if err != nil || changed.Status != "changed" {
			t.Fatal("could not change the account's workspace access", changed.Status, err)
		}
	}
	changeFirstAccountAccess("disable-account")
	readGroups := func() *AccountSuspensionPage {
		t.Helper()
		reply, err := session.AccountSuspensionInventory(ctx, trust, AccountSuspensionRequest{AccountID: first.String(), Kind: "groups"})
		if err != nil || reply.Status != "ready" || reply.Page == nil {
			t.Fatal("could not read captured groups", reply.Status, err)
		}
		return reply.Page
	}
	requireGroup := func(page *AccountSuspensionPage, target uuid.UUID, status, job string) string {
		t.Helper()
		for _, entry := range page.Entries {
			if entry.ID == target.String() {
				if entry.Kind != "group" || entry.Status != status || entry.JobID != job || entry.Name == "" || entry.Revision == "" {
					t.Fatal("unexpected group status or job", status, entry)
				}
				return entry.Position
			}
		}
		t.Fatal("missing captured group", target, status)
		return ""
	}
	initialGroups := readGroups()
	requireGroup(initialGroups, group, "waiting", "")
	requireGroup(initialGroups, other, "queued", otherJob.String())
	exposure := AccountSuspensionRequest{AccountID: first.String(), Kind: "roots"}
	inventory, err := session.AccountSuspensionInventory(ctx, trust, exposure)
	if err != nil || inventory.Page == nil || inventory.Status != "ready" {
		t.Fatal("suspension did not record accessible boundary roots", inventory.Status, err)
	}
	primarySecret := ""
	for _, entry := range inventory.Page.Entries {
		if entry.BoundaryID == boundary.String() && entry.Kind == "secret" && entry.Status == "active" &&
			entry.GroupCount != "0" && entry.Direct != nil && *entry.Direct {
			primarySecret = entry.Position
		}
	}
	if primarySecret == "" {
		t.Fatal("active root did not retain its direct and group exposure routes", inventory.Page.Entries)
	}
	passwordRequest := AccountSuspensionRequest{AccountID: first.String(), Kind: "passwords"}
	passwords, err := session.AccountSuspensionInventory(ctx, trust, passwordRequest)
	if err != nil || passwords.Page == nil || len(passwords.Page.Entries) == 0 {
		t.Fatal("suspension did not collect wrapped password references", passwords.Status, err)
	}
	permissions := query(`SELECT permissions::text FROM wormhole_data.boundary_grants WHERE boundary_id=$1::uuid AND user_id=$2::uuid`,
		boundary.String(), trust.UserID.String())
	setPermissions := func(mask string) {
		t.Helper()
		groupBoundaryFixtureSQL(t, ctx, dba, 1, `UPDATE wormhole_data.boundary_grants SET permissions=$3::integer
            WHERE boundary_id=$1::uuid AND user_id=$2::uuid`, []byte(boundary.String()), []byte(trust.UserID.String()), []byte(mask))
	}
	setPermissions("15")
	masked, err := session.AccountSuspensionInventory(ctx, trust, exposure)
	setPermissions(permissions)
	if err != nil || masked.Page == nil {
		t.Fatal("administrator without boundary Manage could not load redacted inventory", err)
	}
	for _, entry := range masked.Page.Entries {
		if entry.Position == primarySecret && entry != (AccountSuspensionEntry{Position: primarySecret}) {
			t.Fatal("inventory exposed root coordinates without boundary Manage")
		}
	}
	exposure.Revision, exposure.After = "9223372036854775807", "1"
	if stale, err := session.AccountSuspensionInventory(ctx, trust, exposure); err != nil || stale.Status != "stale" {
		t.Fatal("inventory accepted a cursor from another suspension", stale.Status, err)
	}
	trust = checkAccountBoundaryRotation(t, ctx, dba, session, trust, tls, actor, first, additional, boundary, inventory.Page)
	review := func(selection, requestedJob uuid.UUID, wantMembers int) GroupMemberRotationRequest {
		t.Helper()
		request := GroupMemberRotationRequest{GroupID: selection, JobID: requestedJob, Reconcile: true}
		next, reply, plan, err := session.PrepareGroupMemberReconciliation(ctx, trust, tls, request)
		p := reply.Reconciliation
		if err != nil || reply.Status != "reconcile-review" || plan != nil || p == nil || p.GroupID != selection || p.TargetGroupID != group ||
			p.JobID != requestedJob || p.Boundaries != 2 || len(p.Members) != wantMembers || p.Members == nil {
			t.Fatal("review did not bind the changed group, recipients and boundary scope", reply.Status, err)
		}
		if wantMembers > 0 && p.Members[0].ID != first {
			t.Fatal("review selected a different certified recipient")
		}
		var digest [32]byte
		if _, err := hex.Decode(digest[:], []byte(p.Review)); err != nil {
			t.Fatal(err)
		}
		trust, request.Review = next, &digest
		return request
	}
	apply := func(request GroupMemberRotationRequest) {
		t.Helper()
		bad := request
		bad.Review = &[32]byte{3}
		if _, reply, plan, err := session.PrepareGroupMemberReconciliation(ctx, trust, tls, bad); err != nil || reply.Status != "stale" || plan != nil {
			t.Fatal("a different review reached the signing plan", reply.Status, err)
		}
		next, reply, plan, err := session.PrepareGroupMemberReconciliation(ctx, trust, tls, request)
		if err != nil || reply.Status != "ready" || plan == nil {
			t.Fatal("could not prepare a reviewed replacement", reply.Status, err)
		}
		if _, _, err := session.CommitPreparedGroupMemberReconciliation(ctx, next, tls, nil, actor); err != ErrConfiguration {
			t.Fatal("reconciliation opened escrow without a reviewed plan", err)
		}
		wrong := cloneTrustState(next)
		delete(wrong.Catalog, "group-key/"+plan.key.request.GroupID.String())
		if _, _, err := session.CommitPreparedGroupMemberReconciliation(ctx, wrong, tls, plan, actor); err != ErrTrustState {
			t.Fatal("reconciliation accepted a different trust floor", err)
		}
		wrongKeys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{9}, 32), SigningSeed: actor.SigningSeed}
		defer vault.Wipe(wrongKeys.EncryptionPrivate)
		if _, _, err := session.CommitPreparedGroupMemberReconciliation(ctx, next, tls, plan, wrongKeys); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("a different account opened the signing copy", err)
		}
		next, reply, err = session.CommitPreparedGroupMemberReconciliation(ctx, next, tls, plan, actor)
		if err != nil || reply.Status != "reconciled" {
			t.Fatal("could not publish a reviewed replacement", reply.Status, err)
		}
		trust = next
		if _, reply, plan, err := session.PrepareGroupMemberReconciliation(ctx, trust, tls, request); err != nil || reply.Status != "unchanged" || plan != nil {
			t.Fatal("the same request prepared another generation after publication", reply.Status, err)
		}
	}
	if _, status, _, _, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls,
		MemberBoundaryRotationRequest{GroupID: group, JobID: job, BoundaryID: additional}); err != nil || status != "roster-changed" {
		t.Fatal("rotation did not identify a changed certified roster", status, err)
	}
	if _, status, _, _, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls,
		MemberBoundaryRotationRequest{GroupID: other, JobID: otherJob, BoundaryID: boundary}); err != nil || status != "roster-changed" {
		t.Fatal("a related active holder did not surface its pending recipient review", status, err)
	}
	firstReview := review(other, otherJob, 0)
	checkReconciliationReviewEncoding(t, ctx, session, trust, firstReview)
	apply(firstReview)
	if result := query(`SELECT (
        (SELECT count(*) FROM wormhole_data.group_boundary_rotation_queue WHERE job_id=$1::uuid AND holder_version IS NULL)=1
        AND (SELECT count(*) FROM wormhole_data.group_boundary_rotation_queue WHERE job_id=$1::uuid AND holder_version IS NOT NULL)=2
        AND (SELECT count(*) FROM wormhole_data.group_boundary_rotation_queue a JOIN wormhole_data.group_boundary_rotation_queue b
            USING (root_id,root_version) WHERE a.job_id=$1::uuid AND b.job_id=$2::uuid)=2
        AND (SELECT count(*) FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
            WHERE k.kind='group' AND k.status='active' AND k.owner_id=$3::uuid)=1
        AND wormhole_data.group_rotation_queue_recoverable())::text`, job.String(), otherJob.String(), group.String()); result != "true" {
		t.Fatal("reconciliation lost a previous root, copied a key to a disabled member, or omitted an already-rotated boundary")
	}
	assertPendingMemberRotationGuards(t, ctx, dba, job)
	changeFirstAccountAccess("enable-account")
	if enabled, err := session.AccountSuspensionInventory(ctx, trust, passwordRequest); err != nil || enabled.Status != "unavailable" {
		t.Fatal("historical inventory was available on an enabled account", enabled.Status, err)
	}
	if _, status, _, _, err := session.PrepareMemberBoundaryRotation(ctx, trust, tls,
		MemberBoundaryRotationRequest{GroupID: other, JobID: otherJob, BoundaryID: boundary}); err != nil || status != "roster-changed" {
		t.Fatal("overlapping rotation used an earlier roster from the other group", status, err)
	}
	apply(review(other, otherJob, 1))
	snapshot, err := session.ReadWorkspaceRecoverySnapshot(ctx, trust, tls, actor.EncryptionPrivate, actor.SigningSeed)
	if err != nil {
		t.Fatal("could not back up a queue covering multiple retired generations", err)
	}
	defer snapshot.Close()
	archive, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(archive)
	if !t.Run("RestoreReconciledRotation", func(t *testing.T) {
		org := uuid.MustParse(query(`SELECT key_id::text FROM wormhole_data.keys WHERE kind='org-enc' AND status='active'`))
		_, conn, _ := restoreWorkspaceRecoveryArchive(t, ctx, dba, archive, first, org, workspaceImportFixtureNodeCount)
		assertPendingMemberRotationGuards(t, ctx, conn, job)
		if row, err := readDeploymentRow(ctx, conn, `SELECT (EXISTS(SELECT FROM wormhole_data.account_suspension_roots)
            AND EXISTS(SELECT FROM wormhole_data.account_suspension_passwords)
            AND wormhole_data.account_suspensions_recoverable())::text`, 1); err != nil || string(row[0]) != "true" {
			t.Fatal("key and password references were not retained in the restored inventory", err)
		}
	}) {
		t.Fatal("reconciled and overlapping jobs did not survive restore")
	}
	trust = finishMemberRotation(t, ctx, session, trust, tls, actor, group, job, boundary, additional)
	if progress, err := session.ReadGroupMemberRotation(ctx, trust, tls, other, otherJob); err != nil || progress == nil || progress.Pending != 0 {
		t.Fatal("a shared boundary was left pending in the related job", err)
	}
	if result := query(`SELECT (wormhole_data.group_rotation_queue_recoverable()
        AND NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue WHERE job_id IN ($1::uuid,$2::uuid))
        AND (SELECT count(*) FROM wormhole_data.audit_log WHERE admin_group_id=$3::uuid AND action='group_member_reconciliation')=2)::text`,
		job.String(), otherJob.String(), group.String()); result != "true" {
		t.Fatal("reconciled jobs did not finish with a recoverable graph and both audit events")
	}
	if _, ok := trust.Catalog["group-key/"+group.String()]; !ok || len(archive) == 0 || !bytes.Contains(archive, []byte(`"holder_version"`)) {
		t.Fatal("completed rotation did not verify its group generation or archive its prior holders")
	}

	grant := GroupBoundaryGrantRequest{NodeID: connection.String(), BoundaryID: boundary.String(),
		NodeRevision: query(`SELECT row_version::text FROM wormhole_data.nodes WHERE id=$1::uuid`, connection.String())}
	one := publishGroupForRotation(t, ctx, session, trust, tls, actor, grant, "Suspended holder group one")
	two := publishGroupForRotation(t, ctx, session, trust, tls, actor, grant, "Suspended holder group two")
	personal := seedPersonalAccountRotation(t, ctx, dba, trust, actor, first)
	changeFirstAccountAccess("disable-account")
	suspendedGroups := readGroups()
	scope, err := strconv.ParseUint(suspendedGroups.Revision, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	firstGroupPosition := requireGroup(suspendedGroups, one, "needs-removal", "")
	secondGroupPosition := requireGroup(suspendedGroups, two, "needs-removal", "")
	setPermissions("15")
	maskedGroups := readGroups()
	_, maskedRemoval, maskedPlan, maskedErr := session.PrepareGroupMemberRotation(ctx, trust, tls, removal(one, first, scope))
	setPermissions(permissions)
	if maskedErr != nil || maskedRemoval.Status != "stale" || maskedPlan != nil {
		t.Fatal("a removal revealed a group outside the visible suspension", maskedRemoval.Status, maskedErr)
	}
	for _, position := range []string{firstGroupPosition, secondGroupPosition} {
		index, err := strconv.Atoi(position)
		if err != nil || index < 1 || index > len(maskedGroups.Entries) ||
			maskedGroups.Entries[index-1] != (AccountSuspensionEntry{Position: position}) {
			t.Fatal("a group stayed visible without access to its captured boundary")
		}
	}
	staleRequest := reviewRemoval(removal(one, first, scope), 1)
	approved := prepareRemoval(staleRequest)
	if _, err := dba.Exec(ctx, "BEGIN").ReadAll(); err != nil {
		t.Fatal(err)
	}
	locked := dba.ExecParams(ctx, `SELECT id FROM wormhole_data.users WHERE id=$1::uuid FOR UPDATE NOWAIT`,
		[][]byte{[]byte(first.String())}, nil, nil, nil).Read()
	_, busy, pending, busyErr := session.PrepareGroupMemberRotation(ctx, trust, tls, staleRequest)
	if _, err := dba.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	if locked.Err != nil || len(locked.Rows) != 1 || busyErr != nil || busy.Status != "busy" || pending != nil {
		t.Fatal("review borrowed custody without a lock on the target account", locked.Err, busy.Status, busyErr)
	}
	changeFirstAccountAccess("enable-account")
	if _, reply, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, staleRequest); err != nil || reply.Status != "stale" || plan != nil {
		t.Fatal("a review still matched after the account was enabled", reply.Status, err)
	}
	if _, reply, err := session.CommitPreparedGroupMemberRotation(ctx, trust, tls, approved, actor); err != nil || reply.Status != "stale" {
		t.Fatal("a prepared removal could publish after the account was enabled", reply.Status, err)
	}
	changeFirstAccountAccess("disable-account")
	current := readGroups()
	nextScope, err := strconv.ParseUint(current.Revision, 10, 64)
	if err != nil || nextScope <= scope {
		t.Fatal("new suspension did not create a new review scope", current.Revision, err)
	}
	if _, reply, plan, err := session.PrepareGroupMemberRotation(ctx, trust, tls, staleRequest); err != nil || reply.Status != "stale" || plan != nil {
		t.Fatal("a newly suspended account accepted the previous review", reply.Status, err)
	}
	requireGroup(current, one, "needs-removal", "")
	if row := query(`SELECT (NOT EXISTS(SELECT FROM wormhole_data.group_member_rotation_jobs WHERE id=$1::uuid)
        AND EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=$2::uuid AND user_id=$3::uuid)
        AND (SELECT row_version=$4::bigint FROM wormhole_data.groups WHERE id=$2::uuid))::text`,
		staleRequest.JobID.String(), one.String(), first.String(), strconv.FormatUint(staleRequest.Revision, 10)); row != "true" {
		t.Fatal("rejecting an old review changed membership, key revision or job state")
	}
	// Start every group that actually wrapped a root on this boundary for the
	// suspended user. Each group can retire its generation before the first
	// worker rotates the shared root. Without that ordering the first worker
	// refuses the other group's old roster while that group cannot queue work.
	var groups []struct {
		ID         uuid.UUID `json:"id"`
		Boundaries int       `json:"boundaries"`
	}
	rawGroups := query(`SELECT jsonb_agg(jsonb_build_object('id',g.id,'boundaries',(
            SELECT count(DISTINCT k.owner_id) FROM wormhole_data.keys current_key
            JOIN wormhole_data.key_copies c ON (c.holder_key_id,c.holder_key_version)=(current_key.key_id,current_key.key_version)
            JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.key_id,c.key_version)
            WHERE current_key.kind='group' AND current_key.owner_id=g.id AND current_key.status='active' AND k.status='active'
        )) ORDER BY g.id)::text FROM wormhole_data.groups g
        JOIN wormhole_data.group_members m ON m.group_id=g.id AND m.user_id=$1::uuid
        WHERE EXISTS(SELECT FROM wormhole_data.account_suspension_roots r WHERE r.account_id=m.user_id
            AND r.boundary_id=$2::uuid AND g.id=ANY(r.groups))`, first.String(), boundary.String())
	if err := json.Unmarshal([]byte(rawGroups), &groups); err != nil {
		t.Fatal("could not identify actual overlapping holders", err)
	}
	jobs := make(map[uuid.UUID]uuid.UUID, len(groups))
	for _, held := range groups {
		jobs[held.ID] = start(removal(held.ID, first, nextScope), held.Boundaries)
	}
	if jobs[one] == uuid.Nil || jobs[two] == uuid.Nil {
		t.Fatal("both originally overlapping groups must be queued together")
	}
	queuedGroups := readGroups()
	requireGroup(queuedGroups, one, "queued", jobs[one].String())
	requireGroup(queuedGroups, two, "queued", jobs[two].String())
	t.Run("RotatePersonalBoundary", func(t *testing.T) {
		checkPersonalAccountRotation(t, ctx, dba, session, trust, tls, actor, personal, [2]uuid.UUID{jobs[one], jobs[two]}, recover)
	})
	rotatingRoot := query(`SELECT root_version::text FROM wormhole_data.group_boundary_rotation_queue
        WHERE job_id=$1::uuid AND boundary_id=$2::uuid AND purpose=2`, jobs[one].String(), boundary.String())
	trust = finishMemberRotation(t, ctx, session, trust, tls, actor, one, jobs[one], boundary)
	resolvedGroups := readGroups()
	requireGroup(resolvedGroups, one, "resolved", "")
	requireGroup(resolvedGroups, two, "resolved", "")
	for _, team := range []uuid.UUID{one, two} {
		progress, err := session.ReadGroupMemberRotation(ctx, trust, tls, team, jobs[team])
		if err != nil || progress == nil || progress.Pending != 0 {
			t.Fatal("the joint boundary publication did not finish both groups", err)
		}
	}
	if verified := query(`SELECT (
        NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=$1::uuid)
        AND NOT EXISTS(SELECT FROM wormhole_data.keys k WHERE k.status='active' AND k.owner_id=$1::uuid
            AND k.kind='boundary-secret' AND k.key_version<>$2::integer+1)
        AND wormhole_data.group_rotation_queue_recoverable())::text`, boundary.String(), rotatingRoot); verified != "true" {
		t.Fatal("overlapping account jobs did not retire this boundary generation exactly once")
	}
}

func checkReconciliationReviewEncoding(t *testing.T, ctx context.Context, session *Session, trust TrustState, request GroupMemberRotationRequest) {
	t.Helper()
	if err := session.queryServerCA(ctx, trust, `SELECT convert_from(snapshot,'UTF8'),convert_from(roster,'UTF8')`+memberReconciliationCall,
		request.reconciliationArguments(nil), 1<<20, 1, 2, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 2 {
				return ErrAdmissionResponse
			}
			raw, roster := rows[0][0], rows[0][1]
			input, _, _, _, err := decodeMemberReconciliationSnapshot(request, raw, roster)
			if err != nil || len(input.Pending) != 1 || len(input.Additional) != 2 {
				t.Fatal("review did not prove the union of pending and newly affected roots", err)
			}
			if _, _, _, _, err := decodeMemberReconciliationSnapshot(request, raw, nil); err != ErrAdmissionResponse {
				t.Fatal("accepted an omitted certified roster", err)
			}
			if _, _, _, _, err := decodeMemberReconciliationSnapshot(request, raw, append(bytes.Clone(roster), ' ')); err != vault.ErrAuthentication {
				t.Fatal("accepted an altered roster proof", err)
			}
			wrong := request
			wrong.Review = &[32]byte{9}
			if _, _, _, _, err := decodeMemberReconciliationSnapshot(wrong, raw, roster); err != vault.ErrAuthentication {
				t.Fatal("accepted an altered confirmation", err)
			}
			for _, edit := range []func(*memberReconciliationSnapshot){
				func(input *memberReconciliationSnapshot) { input.RequestJobID = uuid.New() },
				func(input *memberReconciliationSnapshot) { input.Revision = "0" },
				func(input *memberReconciliationSnapshot) { input.Boundaries-- },
				func(input *memberReconciliationSnapshot) { input.Pending = []memberRotationRoot{input.Additional[0]} },
			} {
				changed := input
				edit(&changed)
				modified, err := json.Marshal(changed)
				if err != nil {
					return err
				}
				if _, _, _, _, err := decodeMemberReconciliationSnapshot(request, modified, roster); err != ErrAdmissionResponse {
					t.Fatal("accepted a changed reconciliation scope", err)
				}
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}
