package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const importedGroupNote = "synthetic note shared by group"

func keyCopyFixtureRef(key vault.KeyRef) [][]byte {
	return [][]byte{[]byte(key.ID.String()), strconv.AppendUint(nil, uint64(key.Version), 10)}
}

func groupBoundaryFixtureSQL(t *testing.T, ctx context.Context, dba *pgconn.PgConn, count int64, sql string, args ...[]byte) {
	t.Helper()
	result := dba.ExecParams(ctx, sql, args, nil, nil, nil).Read()
	if result.Err != nil || result.CommandTag.RowsAffected() != count {
		t.Fatal("could not update group boundary fixture", result.CommandTag, result.Err)
	}
}

func checkGroupBoundaryRelease(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys,
	group vault.GroupKeyManifest, boundary vault.BoundaryManifest, note, connection, primary, fallback uuid.UUID, recover restoredAdministratorFixture) {
	t.Helper()
	boundaryID, userID := []byte(boundary.BoundaryID.String()), []byte(trust.UserID.String())
	actorGrant := func(mask string) {
		t.Helper()
		groupBoundaryFixtureSQL(t, ctx, dba, 1, `UPDATE wormhole_data.boundary_grants SET permissions=$3::integer WHERE boundary_id=$1::uuid AND user_id=$2::uuid`,
			boundaryID, userID, []byte(mask))
	}
	if supported, err := session.GroupBoundaryGrantsSupported(ctx); err != nil || !supported {
		t.Fatal("schema 64 did not advertise group boundary grants", err)
	}
	version, err := readAccountResetRow(ctx, dba, "SELECT row_version::text FROM wormhole_data.nodes WHERE id=$1::uuid", [][]byte{[]byte(connection.String())}, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	request := GroupBoundaryGrantRequest{NodeID: connection.String(), NodeRevision: string(version[0]), BoundaryID: boundary.BoundaryID.String(),
		GroupID: group.GroupID.String(), GroupRevision: "4", Mask: permissions.View}
	prepare := func(request GroupBoundaryGrantRequest, status string) (GroupBoundaryGrantReply, *GroupBoundaryGrantPreparation) {
		t.Helper()
		next, reply, plan, err := session.PrepareGroupBoundaryGrant(ctx, trust, tls, request)
		if err != nil || reply.Status != status {
			t.Fatal("unexpected boundary grant preparation", status, reply.Status, err)
		}
		trust = next
		return reply, plan
	}
	actorGrant("15")
	prepare(request, "unavailable")
	actorGrant("31")
	wrong := request
	wrong.BoundaryID = uuid.NewString()
	prepare(wrong, "unavailable")
	wrong = request
	wrong.Review = strings.Repeat("0", 64)
	prepare(wrong, "stale")
	groupID := []byte(group.GroupID.String())
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `DELETE FROM wormhole_data.group_members WHERE group_id=$1::uuid AND user_id=$2::uuid`, groupID, userID)
	prepare(request, "rotation-required")
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES($1::uuid,$2::uuid)`, groupID, userID)
	combined := request
	combined.Mask = permissions.View | permissions.Use
	reply, _ := prepare(combined, "review")
	combined.Review = reply.Preview.Review
	_, both := prepare(combined, "ready")
	checkGroupBoundaryGrantAtomicity(t, ctx, dba, session, trust, tls, both, actor)
	publish := func(current, desired permissions.Mask) {
		t.Helper()
		request.Mask, request.Review = desired, ""
		reply, plan := prepare(request, "review")
		if plan != nil || reply.Preview == nil || reply.Preview.PreviousMask != current ||
			len(reply.Preview.Members) != 1 || reply.Preview.Members[0].ID != trust.UserID {
			t.Fatal("the review did not show the grant and its exact certified membership")
		}
		request.Review = reply.Preview.Review
		_, plan = prepare(request, "ready")
		if plan == nil {
			t.Fatal("the confirmed review did not prepare ciphertext publication")
		}
		if result, err := session.CommitPreparedGroupBoundaryGrant(ctx, trust, tls, plan, &vault.UserKeys{}); result.Status != "" || err != ErrConfiguration {
			t.Fatal("publication accepted missing native keys", err)
		}
		reply, err := session.CommitPreparedGroupBoundaryGrant(ctx, trust, tls, plan, actor)
		if err != nil || reply.Status != "changed" {
			t.Fatal("confirmed encrypted group grant did not commit", reply.Status, err)
		}
		prepare(request, "unchanged")
	}
	publish(0, permissions.View)
	groupBoundaryFixtureSQL(t, ctx, dba, 2, `CREATE TEMP TABLE fixture_direct_root_copies AS
        WITH removed AS (DELETE FROM wormhole_data.key_copies WHERE key_id IN ($1::uuid,$2::uuid)
            AND (holder_key_id,holder_key_version)=($3::uuid,$4::integer) RETURNING *) SELECT * FROM removed`,
		append([][]byte{[]byte(boundary.View.Key.ID.String()), []byte(boundary.Secret.Key.ID.String())}, keyCopyFixtureRef(trust.Enrollment.Encryption)...)...)
	actorGrant("28")
	noteTicket, err := session.BeginNoteView(ctx, note, 1)
	if err != nil || noteTicket == nil {
		t.Fatal("the group View grant did not allow the note", err)
	}
	graph, err := session.FetchNote(ctx, noteTicket)
	if err != nil || graph == nil || graph.material == nil {
		t.Fatal("the note graph did not include its View root", err)
	}
	checkFixtureBoundaryRecipient(t, graph.material.root, group.GroupID)
	next, view, err := trust.VerifyNoteView(ctx, note, 1, graph)
	if err != nil || next.Catalog["group-key/"+group.GroupID.String()].Revision != uint64(group.Key.Key.Version) {
		t.Fatal("the note graph did not advance trust for its group key", err)
	}
	trust = next
	called := false
	if err := view.WithValue(ctx, trust, actor.EncryptionPrivate, func(value []byte) error {
		called = true
		if !bytes.Equal(value, []byte(importedGroupNote)) {
			t.Fatal("the group opened the wrong note")
		}
		return nil
	}); err != nil || !called {
		t.Fatal("the note did not open through its group key", err)
	}
	// An independent account Use grant can issue a ticket. It does not make a
	// View-only group a valid recipient for the Secret root.
	actorGrant("30")
	intent, err := session.BeginUsePath(ctx, connection, "ui", "ssh")
	if err != nil || intent == nil {
		t.Fatal("fixture direct Use grant could not issue a ticket", err)
	}
	checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH010",
		[]byte(connection.String()), []byte(intent.Ticket.String()), []byte("ssh"))

	actorGrant("31")
	publish(permissions.View, permissions.View|permissions.Use)
	request.Mask, request.Review = permissions.View, ""
	prepare(request, "rotation-required")
	row, err := readAccountResetRow(ctx, dba, `SELECT (count(*)=2 AND
        count(*) FILTER (WHERE admin_grant_before=0 AND admin_grant_after=1)=1 AND
        count(*) FILTER (WHERE admin_grant_before=1 AND admin_grant_after=3)=1)::text FROM wormhole_data.audit_log
        WHERE action='boundary_group_grant' AND admin_grant_subject_id=$1::uuid AND admin_boundary_id=$2::uuid`,
		[][]byte{groupID, boundaryID}, 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("published grants did not audit the exact boundary, group and changes", err)
	}
	actorGrant("28")
	checkImportedPathReleases(t, ctx, session, trust, connection, actor.EncryptionPrivate, group.GroupID)
	checkImportedFallbackRelease(t, ctx, session, trust, connection, primary, fallback, actor.EncryptionPrivate, group.GroupID)

	groupBoundaryFixtureSQL(t, ctx, dba, 2, `INSERT INTO wormhole_data.key_copies SELECT * FROM pg_temp.fixture_direct_root_copies`)
	actorGrant("31")
	retained := publishGroupForRotation(t, ctx, session, trust, tls, actor, request, "Retained rotation group")
	checkGroupBoundaryRotation(t, ctx, dba, session, trust, tls, actor, request, retained, boundary, note, connection)
	checkGroupMemberRotation(t, ctx, dba, session, trust, tls, actor, retained, boundary.BoundaryID, connection, recover)
}

func publishGroupForRotation(t *testing.T, ctx context.Context, session *Session, trust TrustState, tls *VerifiedTLSBundle,
	actor *vault.UserKeys, boundary GroupBoundaryGrantRequest, name string) uuid.UUID {
	t.Helper()
	group := uuid.New()
	for _, request := range []AdminGroupRequest{
		{Action: "create", GroupID: group.String(), Name: name},
		{Action: "add-member", GroupID: group.String(), Revision: "1", Login: "first-admin"},
	} {
		if result, err := session.AdminGroups(ctx, trust, request); err != nil || result.Status != "changed" {
			t.Fatal("could not administer the retained recipient", result.Status, err)
		}
	}
	keyRequest := GroupKeyRequest{GroupID: group, Revision: 2}
	trust, key, _, err := session.PrepareGroupKey(ctx, trust, tls, keyRequest)
	if err != nil || key.Preview == nil {
		t.Fatal("the retained group did not expose its certified roster", err)
	}
	var proof [32]byte
	if _, err := hex.Decode(proof[:], []byte(key.Preview.Review)); err != nil {
		t.Fatal(err)
	}
	keyRequest.Review = &proof
	trust, ready, plan, err := session.PrepareGroupKey(ctx, trust, tls, keyRequest)
	if err != nil || ready.Status != "ready" || plan == nil {
		t.Fatal("could not prepare retained group issuance", err)
	}
	trust, done, err := session.CommitPreparedGroupKey(ctx, trust, tls, plan, actor)
	if err != nil || done.Status != "issued" {
		t.Fatal("could not issue the retained group key", err)
	}
	boundary.GroupID, boundary.GroupRevision, boundary.Review, boundary.Mask = group.String(), "3", "", permissions.View|permissions.Use
	trust, review, _, err := session.PrepareGroupBoundaryGrant(ctx, trust, tls, boundary)
	if err != nil || review.Preview == nil {
		t.Fatal("could not review the retained boundary grant", err)
	}
	boundary.Review = review.Preview.Review
	trust, reply, confirmed, err := session.PrepareGroupBoundaryGrant(ctx, trust, tls, boundary)
	if err != nil || reply.Status != "ready" || confirmed == nil {
		t.Fatal("could not prepare the retained boundary grant", err)
	}
	if done, err := session.CommitPreparedGroupBoundaryGrant(ctx, trust, tls, confirmed, actor); err != nil || done.Status != "changed" {
		t.Fatal("could not publish the retained boundary grant", err)
	}
	return group
}

func checkGroupBoundaryRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, actor *vault.UserKeys, request GroupBoundaryGrantRequest, retained uuid.UUID,
	before vault.BoundaryManifest, note, connection uuid.UUID) {
	t.Helper()
	if available, err := session.GroupBoundaryRotationSupported(ctx); err != nil || !available {
		t.Fatal("schema 65 did not advertise group boundary rotation", err)
	}
	read := func(query string, args ...[]byte) []byte {
		t.Helper()
		row, err := readAccountResetRow(ctx, dba, query, args, 1, 8192)
		if err != nil {
			t.Fatal(err)
		}
		return row[0]
	}
	const digest = `SELECT encode(sha256(convert_to(jsonb_agg(encode(envelope,'hex') ORDER BY owner_id,field)::text,'UTF8')),'hex')
	    FROM wormhole_data.secret_values`
	envelopes := read(digest)
	prepare := func(req GroupBoundaryGrantRequest, status string) (GroupBoundaryGrantReply, *GroupBoundaryRotationPreparation) {
		t.Helper()
		next, result, plan, err := session.PrepareGroupBoundaryRotation(ctx, trust, tls, req)
		if err != nil || result.Status != status {
			t.Fatal("unexpected boundary rotation preparation", status, result.Status, err)
		}
		trust = next
		return result, plan
	}
	rotate := func(mask, previous permissions.Mask) vault.BoundaryManifest {
		t.Helper()
		request.Mask, request.Review = mask, ""
		reply, plan := prepare(request, "review")
		if plan != nil || reply.Preview == nil || reply.Preview.PreviousMask != previous {
			t.Fatal("rotation review omitted the exact permission reduction")
		}
		bad := request
		bad.Review = strings.Repeat("0", 64)
		prepare(bad, "stale")
		request.Review = reply.Preview.Review
		_, plan = prepare(request, "ready")
		if plan == nil {
			t.Fatal("rotation confirmation did not yield an authenticated preparation")
		}
		if mask != 0 {
			checkRejectedBoundaryRotation(t, ctx, dba, session, trust, tls, plan, actor, before.Secret.Key)
		}
		next, result, err := session.CommitPreparedGroupBoundaryRotation(ctx, trust, tls, plan, actor)
		if err != nil || result.Status != "changed" {
			t.Fatal("group boundary rotation failed to commit", result.Status, err)
		}
		trust = next
		prepare(request, "unchanged")
		raw := read(`SELECT convert_from(body,'UTF8') FROM wormhole_data.boundary_manifests WHERE boundary_id=$1::uuid`, []byte(request.BoundaryID))
		manifest, err := vault.DecodeBoundaryManifest(raw)
		if err != nil || trust.Catalog["boundary/"+request.BoundaryID].Revision != manifest.Revision {
			t.Fatal("the signed replacement did not advance the native floor", err)
		}
		return manifest
	}
	afterSecret := rotate(permissions.View, permissions.View|permissions.Use)
	if afterSecret.Secret.Key.Version != before.Secret.Key.Version+1 || afterSecret.View.Key != before.View.Key ||
		afterSecret.PreviousSecret != nil || bytes.Equal(afterSecret.Secret.Public, before.Secret.Public) {
		t.Fatal("removing Use failed to replace only the Secret root")
	}
	checkImportedPathReleases(t, ctx, session, trust, connection, actor.EncryptionPrivate, uuid.Nil)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `CREATE TEMP TABLE fixture_rotated_account_copy AS
        WITH removed AS (DELETE FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)
            =($1::uuid,$2::integer,$3::uuid,$4::integer) RETURNING *) SELECT * FROM removed`,
		append(keyCopyFixtureRef(afterSecret.Secret.Key), keyCopyFixtureRef(trust.Enrollment.Encryption)...)...)
	checkImportedPathReleases(t, ctx, session, trust, connection, actor.EncryptionPrivate, retained)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.key_copies SELECT * FROM pg_temp.fixture_rotated_account_copy`)
	afterView := rotate(0, permissions.View)
	if afterView.View.Key.Version != before.View.Key.Version+1 || afterView.Secret.Key != afterSecret.Secret.Key || afterView.PreviousView != nil {
		t.Fatal("revoking the remaining grant failed to replace only the View root")
	}
	noteTicket, err := session.BeginNoteView(ctx, note, 1)
	if err != nil || noteTicket == nil {
		t.Fatal("note access was lost by a retained account", err)
	}
	noteGraph, err := session.FetchNote(ctx, noteTicket)
	if err != nil {
		t.Fatal("the note graph lost its rotated root or DEK", err)
	}
	next, view, err := trust.VerifyNoteView(ctx, note, 1, noteGraph)
	if err != nil {
		t.Fatal("rotated note graph did not authenticate", err)
	}
	opened := false
	err = view.WithValue(ctx, next, actor.EncryptionPrivate, func(value []byte) error {
		opened = bytes.Equal(value, []byte(importedGroupNote))
		return nil
	})
	if err != nil || !opened || !bytes.Equal(envelopes, read(digest)) {
		t.Fatal("rotation lost the note or changed a stored secret envelope", err)
	}
	refs := append(keyCopyFixtureRef(before.View.Key), keyCopyFixtureRef(before.Secret.Key)...)
	refs = append(refs, []byte(request.GroupID))
	if string(read(`SELECT (
        NOT EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version) IN (($1::uuid,$2::integer),($3::uuid,$4::integer))
            OR (c.holder_key_id,c.holder_key_version) IN (($1::uuid,$2::integer),($3::uuid,$4::integer)))
        AND (SELECT count(*) FROM wormhole_data.keys k WHERE (k.key_id,k.key_version) IN (($1::uuid,$2::integer),($3::uuid,$4::integer)) AND k.status='retired')=2
        AND NOT EXISTS(SELECT FROM wormhole_data.boundary_grants g WHERE g.group_id=$5::uuid)
        AND (SELECT count(*) FROM wormhole_data.audit_log a WHERE a.action='boundary_group_rotation' AND a.admin_grant_subject_id=$5::uuid)=2
    )::text`, refs...)) != "true" {
		t.Fatal("the revoked roots, grant or audit were not committed together")
	}
}

func checkGroupBoundaryGrantAtomicity(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, plan *GroupBoundaryGrantPreparation, actor *vault.UserKeys) {
	t.Helper()
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := session.CommitPreparedGroupBoundaryGrant(ctx, trust, tls, nil, actor); reply.Status != "" || err != ErrConfiguration {
		t.Fatal("grant was published without preparation", err)
	}
	wrongTrust := cloneTrustState(trust)
	delete(wrongTrust.Catalog, "group-key/"+plan.group.GroupID.String())
	if _, err := session.CommitPreparedGroupBoundaryGrant(ctx, wrongTrust, tls, plan, actor); err != ErrTrustState {
		t.Fatal("grant prepared private keys before committing the group observation", err)
	}
	wrongKeys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{98}, 32), SigningSeed: actor.SigningSeed}
	defer vault.Wipe(wrongKeys.EncryptionPrivate)
	if _, err := plan.wrapRoots(trust, pin, wrongKeys); err != vault.ErrAuthentication {
		t.Fatal("grant used another account's key", err)
	}
	wire, err := plan.wrapRoots(trust, pin, actor)
	if err != nil {
		t.Fatal(err)
	}
	var copies []personalImportCopy
	if json.Unmarshal(wire, &copies) != nil || len(copies) != 2 {
		t.Fatal("initial View and Use grant did not prepare two encrypted roots")
	}
	copies[1].Binding.Holder.ID = uuid.New()
	bad, err := json.Marshal(copies)
	if err != nil {
		t.Fatal(err)
	}
	err = session.queryServerCA(ctx, trust, "SELECT status"+groupBoundaryGrantCall, plan.request.arguments(bad), 64, 1, 1,
		func([][][]byte) error { t.Error("invalid root publication returned a result"); return nil })
	if err == nil {
		t.Fatal("invalid root publication committed")
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT (NOT EXISTS(SELECT FROM wormhole_data.boundary_grants WHERE group_id=$1::uuid)
        AND NOT EXISTS(SELECT FROM wormhole_data.key_copies WHERE holder_key_id=$2::uuid)
        AND NOT EXISTS(SELECT FROM wormhole_data.audit_log WHERE action='boundary_group_grant' AND admin_grant_subject_id=$1::uuid))::text`,
		[][]byte{[]byte(plan.group.GroupID.String()), []byte(plan.group.Key.Key.ID.String())}, 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("part of a rejected grant escaped the transaction", err)
	}
	damaged := *plan
	damaged.escrow = append([]UnverifiedKeyCopy(nil), plan.escrow...)
	damaged.escrow[1].Copy.Signature = bytes.Clone(damaged.escrow[1].Copy.Signature)
	damaged.escrow[1].Copy.Signature[0] ^= 1
	if raw, err := damaged.wrapRoots(trust, pin, actor); raw != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("unsigned escrow produced a publication payload", err)
	}
}

func checkFixtureBoundaryRecipient(t *testing.T, root UnverifiedKeyCopy, want uuid.UUID) {
	t.Helper()
	var group uuid.UUID
	if root.group != nil {
		group = root.group.manifest.GroupID
	}
	if group != want {
		t.Fatal("boundary root resolved to the wrong recipient", group, want)
	}
}
