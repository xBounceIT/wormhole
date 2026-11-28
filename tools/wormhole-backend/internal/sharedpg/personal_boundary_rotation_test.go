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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPersonalRotationHolderRequiresOrganisation(t *testing.T) {
	plan := GroupBoundaryRotationPreparation{boundary: vault.BoundaryManifest{OwnerUserID: uuid.New()}}
	for _, kind := range []string{"user", "group"} {
		_, _, err := plan.verifyHolder(TrustState{}, boundaryRotationHolder{Kind: kind, Subject: uuid.New()})
		if !errors.Is(err, vault.ErrPolicy) {
			t.Fatal("personal rotation accepted an outside recipient", kind, err)
		}
	}
}

func TestPersonalRotationBindsManifestOwner(t *testing.T) {
	master, _, _, manifest, signer := boundaryTrustFixture(t)
	defer vault.Wipe(master)
	defer vault.Wipe(signer)
	owner := uuid.New()
	boundary := personalImportBoundaryID(manifest.WorkspaceID, owner)
	for _, tc := range []struct {
		name      string
		owner     uuid.UUID
		boundary  uuid.UUID
		orgEscrow bool
		want      error
	}{
		{"owner and canonical boundary", owner, boundary, true, nil},
		{"different owner", uuid.New(), boundary, true, ErrAdmissionResponse},
		{"other boundary for the same owner", owner, uuid.New(), true, ErrAdmissionResponse},
		{"owner declined escrow", owner, boundary, false, ErrAdmissionResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := manifest
			current.OwnerUserID, current.BoundaryID, current.OrgEscrow = tc.owner, tc.boundary, tc.orgEscrow
			current, err := vault.SignBoundaryManifest(current, signer)
			if err != nil {
				t.Fatal(err)
			}
			body, err := vault.EncodeBoundaryManifest(current)
			if err != nil {
				t.Fatal(err)
			}
			request := AccountBoundaryRotationRequest{
				AccountID: owner, Suspension: 1, BoundaryID: tc.boundary, Affected: permissions.Use, Root: current.Secret.Key,
			}
			document, err := json.Marshal(accountBoundaryRotationSnapshot{
				AccountID: owner, Suspension: "1", BoundaryID: request.BoundaryID, Affected: request.Affected, Root: request.Root,
				Epoch: "1", ChangeSeq: "0", Boundary: hex.EncodeToString(body), Digest: hex.EncodeToString(make([]byte, 32)),
				Recovery: vault.KeyRef{ID: uuid.New(), Version: 1},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := decodeAccountBoundaryRotationSnapshot(request, document); !errors.Is(err, tc.want) {
				t.Fatal("unexpected result for signed personal manifest", err)
			}
		})
	}
}

func readPersonalRotationValue(t *testing.T, ctx context.Context, dba *pgconn.PgConn, sql string, args ...[]byte) []byte {
	t.Helper()
	row, err := readAccountResetRow(ctx, dba, sql, args, 1, 32768)
	if err != nil {
		t.Fatal(err)
	}
	return row[0]
}

func seedPersonalAccountRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, trust TrustState,
	actor *vault.UserKeys, owner uuid.UUID) vault.BoundaryManifest {
	t.Helper()
	id := personalImportBoundaryID(trust.WorkspaceID, owner)
	manifest, err := vault.DecodeBoundaryManifest(readPersonalRotationValue(t, ctx, dba,
		`SELECT convert_from(body,'UTF8') FROM wormhole_data.boundary_manifests WHERE boundary_id=$1::uuid`, []byte(id.String())))
	if err != nil || manifest.OwnerUserID != owner || !manifest.OrgEscrow {
		t.Fatal("import fixture lacks a signed escrowed personal boundary", err)
	}
	sealed := readRotationFixtureCopy(t, ctx, dba, manifest.Signer, trust.Enrollment.Encryption)
	signing, err := openServerCAOrgCopy(trust, manifest.Signer, sealed, actor.EncryptionPrivate, actor.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(signing)
	seedAccountRotationPassword(t, ctx, dba, trust.WorkspaceID, id, manifest.Secret, manifest.Signer, signing)
	return manifest
}

func checkPersonalAccountRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session,
	trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys, original vault.BoundaryManifest, queuedJobs [2]uuid.UUID, recover restoredAdministratorFixture) {
	t.Helper()
	owner := original.OwnerUserID
	boundary := original.BoundaryID
	read := func(sql string, args ...[]byte) []byte {
		t.Helper()
		return readPersonalRotationValue(t, ctx, dba, sql, args...)
	}
	access := WorkspaceAccessRequest{Action: "enable-account", TargetID: owner.String()}
	enabled, err := session.WorkspaceAccess(ctx, trust, access)
	if err != nil || enabled.Status != "review" || enabled.Review == nil {
		t.Fatal("unrotated personal keys blocked ordinary enable", enabled.Status, err)
	}
	inventory := func(kind string) *AccountSuspensionPage {
		t.Helper()
		reply, err := session.AccountSuspensionInventory(ctx, trust, AccountSuspensionRequest{AccountID: owner.String(), Kind: kind})
		if err != nil || reply.Status != "ready" || reply.Page == nil {
			t.Fatal("inventory unavailable", reply.Status, err)
		}
		return reply.Page
	}
	page := inventory("roots")
	suspension, err := strconv.ParseUint(page.Revision, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	positions := make(map[string]string, 2)
	for _, entry := range page.Entries {
		if entry.BoundaryID == boundary.String() {
			if !entry.Personal || entry.Status != "active" || entry.Direct == nil || !*entry.Direct || entry.GroupCount != "0" {
				t.Fatal("personal root missing its exact suspension scope", entry)
			}
			positions[entry.Kind] = entry.Position
		} else if entry.Personal {
			t.Fatal("an unrelated boundary was marked personal")
		}
	}
	if positions["view"] == "" || positions["secret"] == "" {
		t.Fatal("the custodian could not review both personal roots")
	}
	passwordPosition := string(read(`SELECT position::text FROM wormhole_data.account_suspension_passwords
        WHERE account_id=$1::uuid AND boundary_id=$2::uuid AND owner_kind='tunnel' AND owner_id=$2::uuid`,
		[]byte(owner.String()), []byte(boundary.String())))
	masked := func(page *AccountSuspensionPage, position string) {
		t.Helper()
		for _, entry := range page.Entries {
			if entry.Position == position {
				if entry != (AccountSuspensionEntry{Position: position}) {
					t.Fatal("private inventory coordinates were disclosed")
				}
				return
			}
		}
		t.Fatal("private inventory position was not checked", position)
	}
	masked(inventory("passwords"), passwordPosition)
	request := AccountBoundaryRotationRequest{AccountID: owner, Suspension: suspension, BoundaryID: boundary,
		Affected: permissions.Use, Root: original.Secret.Key}
	// Exercise the same administrator after loss of one of the two custody copies.
	custody := append(keyCopyFixtureRef(original.Signer), keyCopyFixtureRef(trust.Enrollment.Encryption)...)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `CREATE TEMP TABLE removed_org_copy AS
        SELECT * FROM wormhole_data.key_copies
        WHERE (key_id,key_version,holder_key_id,holder_key_version)=($1::uuid,$2::integer,$3::uuid,$4::integer)`, custody...)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `DELETE FROM wormhole_data.key_copies
        WHERE (key_id,key_version,holder_key_id,holder_key_version)=($1::uuid,$2::integer,$3::uuid,$4::integer)`, custody...)
	_, denied, plan, denial := session.PrepareAccountBoundaryRotation(ctx, trust, tls, request)
	maskedPage := inventory("roots")
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.key_copies SELECT * FROM removed_org_copy`)
	if denial != nil || denied.Status != "unavailable" || plan != nil {
		t.Fatal("administrator without complete custody reached personal rotation", denied.Status, denial)
	}
	masked(maskedPage, positions["view"])
	masked(maskedPage, positions["secret"])

	boundaryBytes := []byte(boundary.String())
	const readPassword = `SELECT convert_from(envelope,'UTF8') FROM wormhole_data.secret_values
        WHERE owner_kind='tunnel' AND owner_id=$1::uuid AND field='password'`
	ciphertext := read(readPassword, boundaryBytes)
	const rewrite = `UPDATE wormhole_data.secret_values SET envelope=envelope WHERE owner_kind='tunnel' AND owner_id=$1::uuid`
	blocked := dba.ExecParams(ctx, rewrite, [][]byte{boundaryBytes}, nil, nil, nil).Read()
	if !hasSQLState(blocked.Err, "WH020", 0) {
		t.Fatal("a suspended personal Secret root accepted a value write", blocked.Err)
	}
	blocked = dba.ExecParams(ctx, `UPDATE wormhole_data.key_copies SET signature=signature
        WHERE (holder_key_id,holder_key_version)=($1::uuid,$2::integer)`,
		keyCopyFixtureRef(original.View.Key), nil, nil, nil).Read()
	if !hasSQLState(blocked.Err, "WH020", 0) {
		t.Fatal("a suspended personal View root accepted a new wrap", blocked.Err)
	}
	var recovery vault.KeyRef
	for _, root := range []struct {
		kind     string
		affected permissions.Mask
		key      vault.KeyRef
	}{
		{"view", permissions.View, original.View.Key},
		{"secret", permissions.Use, original.Secret.Key},
	} {
		request.Affected, request.Root = root.affected, root.key
		next, review, plan, err := session.PrepareAccountBoundaryRotation(ctx, trust, tls, request)
		if err != nil || review.Status != "review" || plan != nil {
			t.Fatal("could not review personal root", root.kind, review.Status, err)
		}
		var digest [32]byte
		if _, err := hex.Decode(digest[:], []byte(review.Review)); err != nil {
			t.Fatal(err)
		}
		approved := request
		approved.Review = &digest
		next, ready, plan, err := session.PrepareAccountBoundaryRotation(ctx, next, tls, approved)
		if err != nil || ready.Status != "ready" || plan == nil {
			t.Fatal("could not prepare personal root", root.kind, ready.Status, err)
		}
		recovery = plan.rotation.recipient.Encryption
		next, changed, err := session.CommitPreparedAccountBoundaryRotation(ctx, next, tls, plan, actor)
		if err != nil || changed.Status != "changed" {
			t.Fatal("could not replace personal root", root.kind, changed.Status, err)
		}
		trust = next
	}
	for _, request := range []WorkspaceAccessRequest{access, enabled.Review.WorkspaceAccessRequest} {
		blocked, err := session.WorkspaceAccess(ctx, trust, request)
		if err != nil || blocked.Status != "personal-recovery-required" || blocked.Review != nil {
			t.Fatal("enablement ignored retired personal custody", blocked.Status, err)
		}
	}
	retired := 0
	for _, entry := range inventory("roots").Entries {
		if entry.BoundaryID == boundary.String() {
			if !entry.Personal || entry.Status != "retired" || positions[entry.Kind] != entry.Position {
				t.Fatal("the captured personal root was not reported as retired")
			}
			retired++
		}
	}
	if retired != len(positions) {
		t.Fatal("one or more retired personal roots disappeared from the inventory")
	}
	rotated, err := vault.DecodeBoundaryManifest(read(`SELECT convert_from(body,'UTF8')
        FROM wormhole_data.boundary_manifests WHERE boundary_id=$1::uuid`, boundaryBytes))
	if err != nil || rotated.OwnerUserID != owner || rotated.Revision != original.Revision+2 ||
		rotated.View.Key.Version != original.View.Key.Version+1 || rotated.Secret.Key.Version != original.Secret.Key.Version+1 {
		t.Fatal("personal root identities and manifest did not advance together", err)
	}
	for _, root := range []vault.KeyRef{rotated.View.Key, rotated.Secret.Key} {
		if copies := read(`SELECT (count(*)=1 AND bool_and((holder_key_id,holder_key_version)=($3::uuid,$4::integer)))::text
            FROM wormhole_data.key_copies WHERE (key_id,key_version)=($1::uuid,$2::integer)`,
			append(keyCopyFixtureRef(root), keyCopyFixtureRef(recovery)...)...); string(copies) != "true" {
			t.Fatal("replacement personal root was wrapped outside organisation custody")
		}
	}
	if !bytes.Equal(ciphertext, read(readPassword, boundaryBytes)) {
		t.Fatal("personal rotation changed the stored ciphertext")
	}
	verifyRotatedPersonalValue(t, ctx, dba, trust, actor, rotated, recovery, ciphertext)
	t.Run("RestorePersonalBoundaryAndScopedGroupJobs", func(t *testing.T) {
		snapshot, err := session.ReadWorkspaceRecoverySnapshot(ctx, trust, tls, actor.EncryptionPrivate, actor.SigningSeed)
		if err != nil {
			t.Fatal("rotated personal boundary could not be exported", err)
		}
		defer snapshot.Close()
		// Exercise reconstruction from a schema-76 archive. The surrounding
		// integration test also restores an unmodified current archive.
		legacy := legacyPersonalSuspensionArchive(t, snapshot)
		archive, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(archive)
		target, restored, factor := restoreWorkspaceRecoveryArchive(t, ctx, dba, archive, owner, recovery.ID, workspaceImportFixtureNodeCount)
		pending := readPersonalRotationValue(t, ctx, restored, `SELECT (count(*)=2 AND bool_and(NOT complete)
            AND bool_and(removed_user_id=$3::uuid AND suspension_revision IS NOT DISTINCT FROM $4::bigint))::text
            FROM wormhole_data.group_member_rotation_jobs WHERE id IN ($1::uuid,$2::uuid)`,
			[]byte(queuedJobs[0].String()), []byte(queuedJobs[1].String()), []byte(owner.String()), []byte(page.Revision))
		if string(pending) != "true" {
			t.Fatal("restored jobs lost the recorded suspension and pending state")
		}
		guard := readPersonalRotationValue(t, ctx, restored, `SELECT wormhole_data.personal_account_recovery_required($1::uuid)::text`,
			[]byte(owner.String()))
		if string(guard) != "true" {
			t.Fatal("restore lost the requirement to recover personal access before enablement")
		}
		captured := readPersonalRotationValue(t, ctx, restored, `SELECT (p.state_digest=sha256(s.signed_state)
            AND (p.encryption_key_id,p.signing_key_id)=(e.encryption_key_id,e.signing_key_id))::text
            FROM wormhole_data.account_suspension_enrollments p
            JOIN wormhole_data.user_key_states s ON s.user_id=p.account_id
            JOIN wormhole_data.user_enrollments e ON e.user_id=p.account_id WHERE p.account_id=$1::uuid`, []byte(owner.String()))
		if string(captured) != "true" {
			t.Fatal("schema-76 restore did not reconstruct the suspended enrollment")
		}
		saved := readPersonalRotationValue(t, ctx, restored, readPassword, boundaryBytes)
		if !bytes.Equal(saved, ciphertext) {
			t.Fatal("archive changed rotated personal ciphertext")
		}
		verifyRotatedPersonalValue(t, ctx, restored, trust, actor, rotated, recovery, saved)
		recover.join(t, target, restored, factor, "personal-recovery-admin", func(session *Session, current TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys) {
			suspension, err := strconv.ParseUint(page.Revision, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			var issue func(string) ([]byte, []byte, []byte)
			if recover.appOffer != nil {
				issue = func(login string) ([]byte, []byte, []byte) {
					return recover.appOffer(t, target, factor, login)
				}
			}
			checkFreshPersonalRecoveryEnrollment(t, ctx, restored, session, current, tls, actor, rotated, recovery, suspension, target.Endpoint, issue)
		})
	})
}

func legacyPersonalSuspensionArchive(t *testing.T, source *WorkspaceRecoverySnapshot) WorkspaceRecoverySnapshot {
	t.Helper()
	legacy := *source
	legacy.Records = make([]WorkspaceRecoveryRecord, 0, len(source.Records))
	for _, row := range source.Records {
		switch row.Relation {
		case "account_suspension_enrollments", "account_suspension_web_reports", "account_suspension_web_targets":
			continue
		case "workspace_meta":
			var meta map[string]json.RawMessage
			if err := json.Unmarshal(row.Body, &meta); err != nil {
				t.Fatal(err)
			}
			meta["schema_version"] = json.RawMessage("76")
			var err error
			row.Body, err = json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
		}
		legacy.Records = append(legacy.Records, row)
	}
	return legacy
}

func checkFreshPersonalRecoveryEnrollment(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, actor *vault.UserKeys, rotated vault.BoundaryManifest, recovery vault.KeyRef, suspension uint64, endpoint Endpoint,
	issue func(string) ([]byte, []byte, []byte)) {
	t.Helper()
	owner := []byte(rotated.OwnerUserID.String())
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := dba.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	request := PersonalRootRecoveryRequest{AccountID: rotated.OwnerUserID, Suspension: suspension}
	inventory, err := session.AccountSuspensionInventory(ctx, trust, AccountSuspensionRequest{AccountID: string(owner), Kind: "roots"})
	if err != nil || inventory.Status != "ready" || inventory.Page == nil {
		t.Fatal("restored custodian could not open captured roots", err)
	}
	retired := 0
	for _, entry := range inventory.Page.Entries {
		if entry.Personal && entry.Status == "retired" {
			retired++
		}
	}
	if retired != 2 {
		t.Fatal("both rotated personal roots must appear in the custodian inventory")
	}
	if available, err := session.PersonalRootRecoverySupported(ctx); err != nil || !available {
		t.Fatal("schema 78 did not advertise personal root recovery", err)
	}
	if _, reply, plan, err := session.PreparePersonalRootRecovery(ctx, trust, tls, request); err != nil || reply.Status != "enrollment-required" || plan != nil {
		t.Fatal("recovery should wait for the replacement enrollment", reply.Status, err)
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT encode(e.certificate,'hex'),p.state_sequence::text,u.login_name,encode(state.signed_state,'hex')
        FROM wormhole_data.account_suspension_enrollments p
        JOIN wormhole_data.user_enrollments e ON e.user_id=p.account_id
        JOIN wormhole_data.user_key_states state ON state.user_id=p.account_id
        JOIN wormhole_data.users u ON u.id=p.account_id
        WHERE p.account_id=$1::uuid AND u.disabled AND p.state_digest=sha256(state.signed_state)
			AND (p.encryption_key_id,p.encryption_key_version,p.signing_key_id,p.signing_key_version)=
				(e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version)`, [][]byte{owner}, 4, 32768)
	if err != nil {
		t.Fatal("suspension did not capture the original certified enrollment", err)
	}
	raw, err := hex.AppendDecode(nil, row[0])
	if err != nil {
		t.Fatal(err)
	}
	replacement, activate := checkAccountReenrollmentHandover(t, ctx, dba, session, trust, tls, actor, request, endpoint, issue)
	old, err := vault.DecodeUserEnrollmentCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := strconv.ParseUint(string(row[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	pin.UserID = rotated.OwnerUserID
	openOrgKey := func(ref vault.KeyRef) []byte {
		t.Helper()
		key, err := openServerCAOrgCopy(trust, ref, readRotationFixtureCopy(t, ctx, dba, ref, trust.Enrollment.Encryption),
			actor.EncryptionPrivate, actor.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	orgSigner, orgEncryption := openOrgKey(pin.Signer), openOrgKey(recovery)
	defer vault.Wipe(orgSigner)
	defer vault.Wipe(orgEncryption)
	putCopy := func(root vault.KeyRef, recipient vault.InviteRekeyProof) {
		t.Helper()
		holder := vault.KeyRef{ID: recipient.EncryptionKeyID, Version: recipient.KeyVersion}
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root, Holder: recovery, Issuer: pin.Signer}
		copy, err := vault.RewrapKeyCopy(orgEncryption, binding, readRotationFixtureCopy(t, ctx, dba, root, recovery),
			pin.Organisation, holder, recipient.Public.Encryption, pin.Signer, orgSigner)
		if err != nil {
			t.Fatal(err)
		}
		args := append(append(keyCopyFixtureRef(root), keyCopyFixtureRef(holder)...), keyCopyFixtureRef(pin.Signer)...)
		exec(`INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,issuer_key_id,issuer_key_version,suite,enc,ciphertext,signature)
            VALUES($1::uuid,$2::integer,$3::uuid,$4::integer,$5::uuid,$6::integer,2,decode($7,'hex'),decode($8,'hex'),decode($9,'hex'))`,
			append(args, hex.AppendEncode(nil, copy.Envelope.Enc), hex.AppendEncode(nil, copy.Envelope.Ciphertext), hex.AppendEncode(nil, copy.Signature))...)
	}
	requireRecovery := func(expected string) {
		t.Helper()
		result := readPersonalRotationValue(t, ctx, dba, `SELECT wormhole_data.personal_account_recovery_required($1::uuid)::text`, owner)
		if string(result) != expected {
			t.Fatalf("recovery required = %q, want %s", result, expected)
		}
	}
	registered := readPersonalRotationValue(t, ctx, dba, `SELECT (u.disabled
		AND (SELECT count(*) FROM wormhole_data.keys k WHERE k.owner_id=u.id AND k.kind IN ('user-enc','user-sign') AND k.status='active')=2
		AND EXISTS(SELECT FROM wormhole_data.user_enrollment_history h WHERE h.user_id=u.id AND h.certificate=decode($2,'hex'))
		AND (SELECT count(*) FROM wormhole_data.devices d WHERE d.user_id=u.id AND d.status='active')=1
		AND EXISTS(SELECT FROM wormhole_data.audit_log a WHERE a.user_id=u.id AND a.action='redeem_account_reenrollment' AND a.outcome='success')
		AND EXISTS(SELECT FROM wormhole_data.account_reset_offers o JOIN pg_roles r ON r.oid=o.role_oid
			WHERE o.user_id=u.id AND o.replacement IS NOT NULL AND o.retired_at IS NOT NULL AND o.capsule IS NULL AND NOT r.rolcanlogin))::text
		FROM wormhole_data.users u WHERE u.id=$1::uuid`, owner, row[0])
	if string(registered) != "true" {
		t.Fatal("replacement did not preserve old certification, retire prior keys and devices, or keep the account suspended")
	}
	exec("BEGIN")
	defer func() { _, _ = dba.Exec(ctx, "ROLLBACK").ReadAll() }()
	putCopy(rotated.View.Key, old.Rekey)
	putCopy(rotated.Secret.Key, old.Rekey)
	requireRecovery("true")
	newCert, newState := replacement.Certificate, replacement.State
	if newState.Sequence != sequence+1 || newCert.Manifest.Context.LoginName != string(row[2]) {
		t.Fatal("handover changed the target identity or failed to advance the key state")
	}
	enc := []byte(newCert.Rekey.EncryptionKeyID.String())
	exec("SAVEPOINT verified_sequence")
	putCopy(rotated.View.Key, newCert.Rekey)
	putCopy(rotated.Secret.Key, newCert.Rekey)
	requireRecovery("false")
	exec(`UPDATE wormhole_data.user_key_states SET state_sequence=$2::bigint,signed_state=decode($3,'hex') WHERE user_id=$1::uuid`,
		owner, row[1], row[3])
	requireRecovery("true")
	exec("ROLLBACK TO SAVEPOINT verified_sequence")
	putCopy(rotated.View.Key, newCert.Rekey)
	putCopy(rotated.Secret.Key, newCert.Rekey)
	exec(`DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid AND key_version=$2::integer AND holder_key_id=$3::uuid`,
		append(keyCopyFixtureRef(rotated.Secret.Key), enc)...)
	requireRecovery("true")
	exec("ROLLBACK")
	access := WorkspaceAccessRequest{Action: "enable-account", TargetID: request.AccountID.String()}
	if blocked, err := session.WorkspaceAccess(ctx, trust, access); err != nil || blocked.Status != "personal-recovery-required" {
		t.Fatal("enrollment alone allowed the admin to enable the account", blocked.Status, err)
	}
	exec("BEGIN")
	exec(`SELECT id FROM wormhole_data.users WHERE id=$1::uuid FOR UPDATE`, owner)
	_, busy, busyPlan, busyErr := session.PreparePersonalRootRecovery(ctx, trust, tls, request)
	exec("ROLLBACK")
	if busyErr != nil || busy.Status != "busy" || busyPlan != nil {
		t.Fatal("a concurrent account change did not return a clean retry status", busy.Status, busyErr)
	}

	checkPersonalRootRecoveryDocumentFailures(t, ctx, session, trust, request)
	observed, reviewed, plan, err := session.PreparePersonalRootRecovery(ctx, trust, tls, request)
	if err != nil || reviewed.Status != "review" || reviewed.Enrollment != string(enc) || plan != nil || trust.ValidateAdvance(observed) != nil {
		t.Fatal("custodian could not review the replacement enrollment", reviewed.Status, err)
	}
	var digest [32]byte
	if _, err := hex.Decode(digest[:], []byte(reviewed.Review)); err != nil {
		t.Fatal(err)
	}
	request.Review = &[32]byte{1}
	if _, stale, plan, err := session.PreparePersonalRootRecovery(ctx, observed, tls, request); err != nil || stale.Status != "stale" || plan != nil {
		t.Fatal("a different review reached the organisation material", stale.Status, err)
	}
	request.Review = &digest
	observed, ready, plan, err := session.PreparePersonalRootRecovery(ctx, observed, tls, request)
	if err != nil || ready.Status != "ready" || plan == nil {
		t.Fatal("custodian could not obtain confirmed root custody", ready.Status, err)
	}
	publication, err := plan.wrapForOwner(ctx, observed, pin, actor)
	if err != nil {
		t.Fatal(err)
	}
	var copies [2]workspaceAdminRecoveryCopy
	if err := json.Unmarshal(publication, &copies); err != nil {
		t.Fatal(err)
	}
	copies[1].Signature = nil
	partial, err := json.Marshal(copies)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.queryServerCA(ctx, observed, "SELECT status"+personalRootRecoveryCall, request.arguments(partial), 128, 1, 1,
		func([][][]byte) error { return nil }); !errors.Is(err, ErrQuery) {
		t.Fatal("database accepted a malformed second copy", err)
	}
	count := readPersonalRotationValue(t, ctx, dba, `SELECT count(*)::text FROM wormhole_data.key_copies WHERE holder_key_id=$1::uuid`, enc)
	if string(count) != "0" {
		t.Fatal("invalid second copy left a partial publication", count)
	}
	if changed, err := session.CommitPreparedPersonalRootRecovery(ctx, observed, tls, plan, actor); err != nil || changed.Status != "changed" {
		t.Fatal("the new owner could not recover both roots", changed.Status, err)
	}
	requireRecovery("false")
	if _, retry, plan, err := session.PreparePersonalRootRecovery(ctx, observed, tls, request); err != nil || retry.Status != "unchanged" || plan != nil {
		t.Fatal("successful publication did not reconcile a retry", retry.Status, err)
	}
	holder := vault.KeyRef{ID: newCert.Rekey.EncryptionKeyID, Version: newCert.Rekey.KeyVersion}
	issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
	boundaryTrust := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: rotated.BoundaryID, Signer: pin.Signer, Organisation: pin.Organisation}
	for _, item := range []struct {
		root    vault.KeyRef
		purpose vault.BoundaryPurpose
	}{
		{rotated.View.Key, vault.BoundaryView}, {rotated.Secret.Key, vault.BoundarySecret},
	} {
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: item.root, Holder: holder, Issuer: pin.Signer}
		seed, err := vault.OpenBoundaryKeyCopy(replacement.Keys.EncryptionPrivate, binding, readRotationFixtureCopy(t, ctx, dba, item.root, holder),
			issuer, rotated, boundaryTrust, item.purpose)
		vault.Wipe(seed)
		if err != nil {
			t.Fatal("the fresh owner could not open a published root", err)
		}
	}
	activate(true)
	enable, err := session.WorkspaceAccess(ctx, observed, access)
	if err != nil || enable.Status != "review" || enable.Review == nil {
		t.Fatal("the admin could not review activation after root recovery", enable.Status, err)
	}
	if changed, err := session.WorkspaceAccess(ctx, observed, enable.Review.WorkspaceAccessRequest); err != nil || changed.Status != "changed" {
		t.Fatal("the admin could not enable the recovered account", changed.Status, err)
	}
	activate(false)
}

func verifyRotatedPersonalValue(t *testing.T, ctx context.Context, dba *pgconn.PgConn, trust TrustState,
	actor *vault.UserKeys, rotated vault.BoundaryManifest, recovery vault.KeyRef, ciphertext []byte) {
	t.Helper()
	custody := readRotationFixtureCopy(t, ctx, dba, recovery, trust.Enrollment.Encryption)
	org, err := openServerCAOrgCopy(trust, recovery, custody, actor.EncryptionPrivate, actor.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(org)
	pin, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: rotated.BoundaryID,
		Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: rotated.Revision}
	issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
	root := rotated.Secret.Key
	binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root, Holder: recovery, Issuer: pin.Signer}
	seed, err := vault.OpenBoundaryKeyCopy(org, binding, readRotationFixtureCopy(t, ctx, dba, root, recovery),
		issuer, rotated, scope, vault.BoundarySecret)
	if err != nil {
		t.Fatal("organisation escrow could not open the replacement root", err)
	}
	defer vault.Wipe(seed)
	id := readPersonalRotationValue(t, ctx, dba, `SELECT dek_id::text FROM wormhole_data.secret_values
        WHERE owner_kind='tunnel' AND owner_id=$1::uuid AND field='password'`, []byte(rotated.BoundaryID.String()))
	dek := vault.KeyRef{ID: uuid.MustParse(string(id)), Version: 1}
	var envelope vault.Envelope
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenSharedValue(seed, root, vault.SharedValueBinding{WorkspaceID: trust.WorkspaceID,
		OwnerKind: "tunnel", OwnerID: rotated.BoundaryID, Field: "password", Version: 1, DEK: dek},
		readRotationFixtureCopy(t, ctx, dba, dek, root), issuer, envelope, rotated, scope)
	defer vault.Wipe(plain)
	if err != nil || string(plain) != accountRotationPassword {
		t.Fatal("replacement personal root could not recover the original secret", err)
	}
}
