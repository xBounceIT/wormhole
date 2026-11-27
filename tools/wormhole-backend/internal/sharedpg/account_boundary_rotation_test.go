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

const accountRotationPassword = "synthetic value in a directly held boundary"

func readRotationFixtureCopy(t *testing.T, ctx context.Context, dba *pgconn.PgConn, key, holder vault.KeyRef) vault.SignedKeyCopy {
	t.Helper()
	row, err := readAccountResetRow(ctx, dba, `SELECT key_id::text,key_version::text,encode(enc,'hex'),
        encode(ciphertext,'hex'),encode(signature,'hex') FROM wormhole_data.key_copies
        WHERE (key_id,key_version,holder_key_id,holder_key_version)=($1::uuid,$2::integer,$3::uuid,$4::integer)`,
		append(keyCopyFixtureRef(key), keyCopyFixtureRef(holder)...), 5, 8192)
	if err != nil {
		t.Fatal(err)
	}
	parsed, copy, err := parseServerCAOrgCopy(row)
	if err != nil || parsed != key {
		t.Fatal("missing authenticated fixture wrap", err)
	}
	return copy
}

func seedAccountRotationPassword(t *testing.T, ctx context.Context, dba *pgconn.PgConn, workspace, boundary uuid.UUID,
	root vault.BoundaryKey, signer vault.KeyRef, signing []byte) {
	t.Helper()
	seed := vault.NewRecoveryKey()
	defer vault.Wipe(seed)
	binding := vault.SharedValueBinding{WorkspaceID: workspace, OwnerKind: "tunnel", OwnerID: boundary,
		Field: "password", Version: 1, DEK: vault.KeyRef{ID: uuid.New(), Version: 1}}
	envelope, err := vault.SealSharedValue(seed, binding, []byte(accountRotationPassword))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := vault.SealKeyCopy(seed, vault.KeyCopyBinding{WorkspaceID: workspace, Key: binding.DEK, Holder: root.Key, Issuer: signer},
		root.Public, signing)
	if err != nil {
		t.Fatal(err)
	}
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite)
        VALUES($1::uuid,1,'dek',$2::uuid,2)`, []byte(binding.DEK.ID.String()), []byte(boundary.String()))
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,
        issuer_key_id,issuer_key_version,suite,enc,ciphertext,signature)
        VALUES($1::uuid,1,$2::uuid,$3::integer,$4::uuid,$5::integer,2,decode($6,'hex'),decode($7,'hex'),decode($8,'hex'))`,
		append(append(append([][]byte{[]byte(binding.DEK.ID.String())}, keyCopyFixtureRef(root.Key)...), keyCopyFixtureRef(signer)...),
			hex.AppendEncode(nil, wrap.Envelope.Enc), hex.AppendEncode(nil, wrap.Envelope.Ciphertext), hex.AppendEncode(nil, wrap.Signature))...)
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope)
        VALUES('tunnel',$1::uuid,'password',$2::uuid,1,convert_to($3,'UTF8'))`,
		[]byte(boundary.String()), []byte(binding.DEK.ID.String()), raw)
}

func checkAccountBoundaryRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session,
	trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys, subject, direct, grouped uuid.UUID,
	page *AccountSuspensionPage) TrustState {
	t.Helper()
	if supported, err := session.AccountBoundaryRotationSupported(ctx); err != nil || !supported {
		t.Fatal("account rotation capability unavailable", err)
	}
	suspension, _ := strconv.ParseUint(page.Revision, 10, 64)
	request := func(boundary uuid.UUID) AccountBoundaryRotationRequest {
		t.Helper()
		for _, entry := range page.Entries {
			if entry.BoundaryID == boundary.String() && entry.Kind == "secret" && entry.Status == "active" {
				version, _ := strconv.ParseUint(entry.Revision, 10, 32)
				return AccountBoundaryRotationRequest{AccountID: subject, Suspension: suspension, BoundaryID: boundary,
					Affected: permissions.Use, Root: vault.KeyRef{ID: uuid.MustParse(entry.ID), Version: uint32(version)}}
			}
		}
		t.Fatal("missing captured secret root")
		return AccountBoundaryRotationRequest{}
	}
	groupedRequest := request(grouped)
	if _, reply, plan, err := session.PrepareAccountBoundaryRotation(ctx, trust, tls, groupedRequest); err != nil || plan != nil ||
		reply.Status != "group-rotation-required" {
		t.Fatal("rotation bypassed a pending group job or a retained group that needs rekeying", reply.Status, err)
	}
	directRequest := request(direct)
	for _, update := range []struct {
		statement string
		args      [][]byte
	}{
		{`UPDATE wormhole_data.key_copies SET signature=signature WHERE (holder_key_id,holder_key_version)=($1::uuid,$2::integer)`,
			keyCopyFixtureRef(directRequest.Root)},
		{`UPDATE wormhole_data.secret_values SET envelope=envelope WHERE owner_id=$1::uuid`, [][]byte{[]byte(direct.String())}},
	} {
		if err := dba.ExecParams(ctx, update.statement, update.args, nil, nil, nil).Read().Err; !hasSQLState(err, "WH020", 0) {
			t.Fatal("captured key accepted new encrypted writes", err)
		}
	}
	t.Run("RestoreSuspendedAccountRotation", func(t *testing.T) {
		snapshot, err := session.ReadWorkspaceRecoverySnapshot(ctx, trust, tls, keys.EncryptionPrivate, keys.SigningSeed)
		if err != nil {
			t.Fatal("could not export the pending account root", err)
		}
		defer snapshot.Close()
		archive, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(archive)
		recovery, err := readDeploymentRow(ctx, dba, `SELECT key_id::text FROM wormhole_data.keys WHERE kind='org-enc' AND status='active'`, 1)
		if err != nil {
			t.Fatal(err)
		}
		_, restored, _ := restoreWorkspaceRecoveryArchive(t, ctx, dba, archive, subject, uuid.MustParse(string(recovery[0])), workspaceImportFixtureNodeCount)
		row := restored.ExecParams(ctx, `SELECT wormhole_data.account_rotation_pending($1::uuid,$2::integer)::text`,
			keyCopyFixtureRef(directRequest.Root), nil, nil, nil).Read()
		if row.Err != nil || len(row.Rows) != 1 || string(row.Rows[0][0]) != "true" {
			t.Fatal("restored account root was not marked pending", row.Err)
		}
		blocked := restored.ExecParams(ctx, `UPDATE wormhole_data.secret_values SET envelope=envelope WHERE owner_id=$1::uuid`,
			[][]byte{[]byte(direct.String())}, nil, nil, nil).Read()
		if !hasSQLState(blocked.Err, "WH020", 0) {
			t.Fatal("restored account root accepted a write before its rotation", blocked.Err)
		}
	})
	query := func(statement string, args ...[]byte) []byte {
		t.Helper()
		row, err := readAccountResetRow(ctx, dba, statement, args, 1, 16384)
		if err != nil {
			t.Fatal(err)
		}
		return row[0]
	}
	readCiphertext := func() []byte {
		return query(`SELECT convert_from(envelope,'UTF8') FROM wormhole_data.secret_values WHERE owner_kind='tunnel' AND owner_id=$1::uuid`,
			[]byte(direct.String()))
	}
	ciphertext := readCiphertext()
	digest := [32]byte{1}
	stale := directRequest
	stale.Suspension++
	if _, reply, plan, err := session.PrepareAccountBoundaryRotation(ctx, trust, tls, stale); err != nil || reply.Status != "stale" || plan != nil {
		t.Fatal("wrong suspension reached custody", reply.Status, err)
	}
	stale = directRequest
	stale.Review = &digest
	if _, reply, plan, err := session.PrepareAccountBoundaryRotation(ctx, trust, tls, stale); err != nil || reply.Status != "stale" || plan != nil {
		t.Fatal("wrong review reached custody", reply.Status, err)
	}
	next, preview, plan, err := session.PrepareAccountBoundaryRotation(ctx, trust, tls, directRequest)
	if err != nil || preview.Status != "review" || plan != nil {
		t.Fatal("unconfirmed rotation borrowed custody", preview.Status, err)
	}
	if _, err := hex.Decode(digest[:], []byte(preview.Review)); err != nil {
		t.Fatal(err)
	}
	directRequest.Review = &digest
	next, reply, plan, err := session.PrepareAccountBoundaryRotation(ctx, next, tls, directRequest)
	if err != nil || reply.Status != "ready" || plan == nil {
		t.Fatal("approved rotation did not authenticate the signing and DEK graph", reply.Status, err)
	}
	checkAccountRotationSnapshot(t, directRequest, plan)
	if _, _, err := session.CommitPreparedAccountBoundaryRotation(ctx, next, tls, nil, keys); !errors.Is(err, ErrConfiguration) {
		t.Fatal("accepted missing plan", err)
	}
	next, reply, err = session.CommitPreparedAccountBoundaryRotation(ctx, next, tls, plan, keys)
	if err != nil || reply.Status != "changed" || !bytes.Equal(ciphertext, readCiphertext()) {
		t.Fatal("publication failed or changed the encrypted value", reply.Status, err)
	}
	if _, reply, plan, err := session.PrepareAccountBoundaryRotation(ctx, next, tls, directRequest); err != nil || reply.Status != "unchanged" || plan != nil {
		t.Fatal("replaying the retired root changed it again", reply.Status, err)
	}
	if result := query(`SELECT (NOT wormhole_data.account_rotation_pending($1::uuid,$2::integer)
        AND NOT EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=($1::uuid,$2::integer))
        AND NOT EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
            WHERE (c.key_id,c.key_version)=($1::uuid,$2::integer+1) AND k.owner_id=$3::uuid)
        AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='account_boundary_rotation'
            AND access_account_id=$3::uuid AND admin_boundary_id=$4::uuid)=1)::text`,
		append(keyCopyFixtureRef(directRequest.Root), []byte(subject.String()), []byte(direct.String()))...); string(result) != "true" {
		t.Fatal("retired copy survived, suspended target was rewrapped, or audit was not committed")
	}
	groupBoundaryFixtureSQL(t, ctx, dba, 1, `UPDATE wormhole_data.secret_values SET envelope=envelope WHERE owner_id=$1::uuid`, []byte(direct.String()))

	// The retained custodian can open the original ciphertext under the new
	// signed root. Read the committed copies instead of the preparation buffer.
	manifest, err := vault.DecodeBoundaryManifest(query(`SELECT convert_from(body,'UTF8') FROM wormhole_data.boundary_manifests
        WHERE boundary_id=$1::uuid`, []byte(direct.String())))
	if err != nil || manifest.Secret.Key.ID != directRequest.Root.ID || manifest.Secret.Key.Version != directRequest.Root.Version+1 ||
		manifest.View.Key != plan.rotation.boundary.View.Key {
		t.Fatal("replacement changed the wrong purpose", err)
	}
	binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: manifest.Secret.Key,
		Holder: trust.Enrollment.Encryption, Issuer: manifest.Signer}
	pin, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	reviewed := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: direct, Signer: manifest.Signer,
		Organisation: pin.Organisation, MinimumRevision: manifest.Revision}
	issuer := vault.KeyCopyTrust{Issuer: manifest.Signer, Public: reviewed.Organisation}
	rootSeed, err := vault.OpenBoundaryKeyCopy(keys.EncryptionPrivate, binding, readRotationFixtureCopy(t, ctx, dba, binding.Key, binding.Holder), issuer,
		manifest, reviewed, vault.BoundarySecret)
	if err != nil {
		t.Fatal("remaining custodian could not open the replacement", err)
	}
	defer vault.Wipe(rootSeed)
	dek := vault.KeyRef{ID: uuid.MustParse(string(query(`SELECT dek_id::text FROM wormhole_data.secret_values WHERE owner_id=$1::uuid`, []byte(direct.String())))), Version: 1}
	var envelope vault.Envelope
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		t.Fatal(err)
	}
	plain, err := vault.OpenSharedValue(rootSeed, manifest.Secret.Key, vault.SharedValueBinding{
		WorkspaceID: trust.WorkspaceID, OwnerKind: "tunnel", OwnerID: direct, Field: "password", Version: 1, DEK: dek,
	}, readRotationFixtureCopy(t, ctx, dba, dek, manifest.Secret.Key), issuer, envelope, manifest, reviewed)
	defer vault.Wipe(plain)
	if err != nil || string(plain) != accountRotationPassword {
		t.Fatal("replacement could not authenticate the unchanged ciphertext", err)
	}
	return next
}

func checkAccountRotationSnapshot(t *testing.T, request AccountBoundaryRotationRequest, plan *AccountBoundaryRotationPreparation) {
	t.Helper()
	signed, err := vault.EncodeBoundaryManifest(plan.rotation.boundary)
	if err != nil {
		t.Fatal(err)
	}
	expected := accountBoundaryRotationSnapshot{
		AccountID: request.AccountID, Suspension: strconv.FormatUint(request.Suspension, 10), BoundaryID: request.BoundaryID,
		Root: request.Root, Affected: request.Affected, Epoch: "1", ChangeSeq: "0", Boundary: hex.EncodeToString(signed),
		Recovery: plan.rotation.recipient.Encryption, Digest: hex.EncodeToString(make([]byte, 32)),
	}
	encode := func(snapshot accountBoundaryRotationSnapshot) []byte {
		t.Helper()
		raw, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, _, _, err := decodeAccountBoundaryRotationSnapshot(request, encode(expected)); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("changed snapshot authenticated under the original review", err)
	}
	request.Review = nil
	for _, change := range []func(*accountBoundaryRotationSnapshot){
		func(s *accountBoundaryRotationSnapshot) { s.AccountID = uuid.New() },
		func(s *accountBoundaryRotationSnapshot) { s.Recovery.Version = 0 },
		func(s *accountBoundaryRotationSnapshot) { s.Epoch = "01" },
		func(s *accountBoundaryRotationSnapshot) { s.Digest = "invalid" },
		func(s *accountBoundaryRotationSnapshot) { s.Boundary = "invalid" },
	} {
		changed := expected
		change(&changed)
		if _, _, _, err := decodeAccountBoundaryRotationSnapshot(request, encode(changed)); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("invalid scoped snapshot accepted", err)
		}
	}
	if _, _, _, err := decodeAccountBoundaryRotationSnapshot(request, bytes.Repeat([]byte{'x'}, 32769)); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("oversized scoped snapshot accepted", err)
	}
	if _, _, err := plan.rotation.verifyHolder(TrustState{}, boundaryRotationHolder{Kind: "user", Subject: request.AccountID}); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("suspended recipient accepted in the retained graph", err)
	}
}
