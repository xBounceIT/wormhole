package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testNativeInvitationCopies(t *testing.T, ctx context.Context, admin *pgconn.PgConn, i Invitation, code []byte) {
	t.Helper()
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	b, copies := invitationCopyFixture(t, i, code, 2, time.Now())
	envelope, err := EncodeInvitationBootstrapEnvelope(i, b.Envelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.EncodeInviteManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	id := []byte(i.Enrollment.Context.InviteID.String())
	holder := []byte(i.Enrollment.Context.KeyID.String())
	issuer := []byte(b.Manifest.Issuers[0].Key.ID.String())
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES ($1::uuid,1,'user-sign','pending',1)", issuer)
	exec("UPDATE wormhole_data.invites SET bootstrap_envelope=decode($1,'hex'),manifest=decode($2,'hex') WHERE id=$3::uuid", hex.AppendEncode(nil, envelope), hex.AppendEncode(nil, manifest), id)
	insertCopy := func(n int) {
		v := copies[n]
		binding := b.Manifest.Copies[n]
		exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,1,$2::uuid,1,2,decode($3,'hex'),decode($4,'hex'),$5::uuid,1,decode($6,'hex'))", []byte(binding.Key.ID.String()), holder, hex.AppendEncode(nil, v.Envelope.Enc), hex.AppendEncode(nil, v.Envelope.Ciphertext), issuer, hex.AppendEncode(nil, v.Signature))
	}
	for n, binding := range b.Manifest.Copies {
		exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,1,'dek','pending',1)", []byte(binding.Key.ID.String()))
		insertCopy(n)
	}
	s := NewSession()
	defer s.Close(context.Background())
	if err := s.OpenInvitation(ctx, i, code); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PrepareInvitationJoin(ctx, i, code, 1)
	if err != nil {
		t.Fatal("prepare native join", err)
	}
	defer plan.Wipe()
	if len(plan.Copies) != 2 || plan.SourceManifestRevision != 1 {
		t.Fatal("incomplete join plan")
	}
	for n, row := range plan.Copies {
		key, err := vault.OpenKeyCopy(plan.Keys.EncryptionPrivate, row.Binding, row.Copy, plan.Proof.Public.Signing)
		if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{byte(n + 1)}, 32)) {
			t.Fatal("rewrap changed shared key", err)
		}
		vault.Wipe(key)
	}
	digest := sha256.Sum256(manifest)
	if !bytes.Equal(digest[:], plan.SourceManifestDigest) {
		t.Fatal("unpinned source manifest")
	}
	plan.Wipe()
	acl := admin.ExecParams(ctx, `SELECT (has_function_privilege('wh_testscope_enroll','wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea)','EXECUTE')
AND NOT has_function_privilege('wh_testscope_user','wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea)','EXECUTE')
AND NOT has_function_privilege('wh_testscope_admin','wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`, nil, nil, nil, nil).Read()
	if acl.Err != nil || len(acl.Rows) != 1 || string(acl.Rows[0][0]) != "true" {
		t.Fatal("copy API privileges", acl.Err)
	}
	for _, args := range [][][]byte{{id, []byte("2"), hex.AppendEncode(nil, digest[:])}, {id, []byte("1"), bytes.Repeat([]byte{'0'}, 64)}} {
		if _, err := s.Query(ctx, invitationCopiesSQL, args); err != ErrInvitation {
			t.Fatal("stale manifest accepted", err)
		}
	}
	badCode := bytes.Clone(code)
	badCode[0] ^= 1
	if p, err := s.PrepareInvitationJoin(ctx, i, badCode, 1); p != nil || err != ErrInvitation {
		t.Fatal("incorrect code", err)
	}
	vault.Wipe(badCode)
	first := []byte(b.Manifest.Copies[0].Key.ID.String())
	exec("UPDATE wormhole_data.key_copies SET signature=decode(repeat('00',64),'hex') WHERE key_id=$1::uuid", first)
	if p, err := s.PrepareInvitationJoin(ctx, i, code, 1); p != nil || err != vault.ErrAuthentication {
		t.Fatal("forged copy accepted", err)
	}
	exec("UPDATE wormhole_data.key_copies SET signature=decode($1,'hex'),ciphertext=decode(repeat('00',16),'hex') WHERE key_id=$2::uuid", hex.AppendEncode(nil, copies[0].Signature), first)
	if p, err := s.PrepareInvitationJoin(ctx, i, code, 1); p != nil || err != ErrInvitation {
		t.Fatal("oversized/invalid SQL copy shape", err)
	}
	exec("UPDATE wormhole_data.key_copies SET ciphertext=decode($1,'hex') WHERE key_id=$2::uuid", hex.AppendEncode(nil, copies[0].Envelope.Ciphertext), first)
	// Test SQL's 1024/1025 boundary without trusting synthetic extra signatures.
	marker := []byte(uuid.NewString())
	exec(`WITH added AS (INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite)
SELECT gen_random_uuid(),1,'dek',$1::uuid,'pending',1 FROM generate_series(1,1023) RETURNING key_id)
INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
SELECT key_id,1,$2::uuid,1,2,decode(repeat('00',32),'hex'),decode(repeat('00',48),'hex'),$3::uuid,1,decode(repeat('00',64),'hex') FROM added`, marker, holder, issuer)
	args := [][]byte{id, []byte("1"), hex.AppendEncode(nil, digest[:])}
	if _, err := s.Query(ctx, invitationCopiesSQL, args); err != ErrInvitation {
		t.Fatal("SQL copy limit bypassed", err)
	}
	exec("DELETE FROM wormhole_data.key_copies WHERE key_id=(SELECT key_id FROM wormhole_data.keys WHERE owner_id=$1::uuid LIMIT 1)", marker)
	rows, err := s.Query(ctx, invitationCopiesSQL, args)
	if err != nil || len(rows) != 1024 {
		t.Fatal("SQL copy boundary", len(rows), err)
	}
	wipeQueryRows(rows)
	exec("DELETE FROM wormhole_data.key_copies WHERE key_id IN (SELECT key_id FROM wormhole_data.keys WHERE owner_id=$1::uuid)", marker)
	exec("DELETE FROM wormhole_data.keys WHERE owner_id=$1::uuid", marker)
	exec("DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid", first)
	if p, err := s.PrepareInvitationJoin(ctx, i, code, 1); p != nil || err != ErrAdmissionResponse {
		t.Fatal("incomplete graph accepted", err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("incomplete response did not retire owner")
	}
	insertCopy(0)
}
