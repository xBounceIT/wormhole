package sharedpg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresKeyGraphMigrationIntegration(t *testing.T) {
	s, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(sql, state string) {
		t.Helper()
		_, err := conn.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != state {
			t.Fatalf("expected %s got %v", state, err)
		}
	}
	check := func(sql, want string) {
		t.Helper()
		r, err := conn.Exec(ctx, sql).ReadAll()
		if err != nil || len(r) != 1 || len(r[0].Rows) != 1 || len(r[0].Rows[0]) != 1 || string(r[0].Rows[0][0]) != want {
			t.Fatalf("query mismatch: %v", err)
		}
	}
	initial, _ := deploy.InitialMigration("testscope", testHintID)
	exec(initial)
	migration, _ := deploy.KeyGraphMigration("testscope", testHintID)
	reject(migration, "55000")
	exec("ROLLBACK")
	sessions, _ := deploy.SessionMigration("testscope", testHintID)
	exec(sessions)
	wrong, _ := deploy.KeyGraphMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrong, "55000")
	exec("ROLLBACK")
	check("SELECT (pg_catalog.to_regclass('wormhole_data.keys') IS NULL)::text", "true")
	locker, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(context.Background())
	if _, err := locker.Exec(ctx, "BEGIN; SELECT singleton FROM wormhole_data.workspace_meta FOR UPDATE").ReadAll(); err != nil {
		t.Fatal(err)
	}
	reject(migration, "55P03")
	exec("ROLLBACK")
	if _, err := locker.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	check("SELECT (pg_catalog.to_regclass('wormhole_data.keys') IS NULL AND schema_version=2)::text FROM wormhole_data.workspace_meta", "true")
	// A late DDL collision must roll back all preceding tables and the version.
	exec("CREATE TABLE wormhole_data.invites(collision integer)")
	reject(migration, "42P07")
	exec("ROLLBACK")
	check("SELECT (pg_catalog.to_regclass('wormhole_data.keys') IS NULL AND schema_version=2)::text FROM wormhole_data.workspace_meta", "true")
	exec("DROP TABLE wormhole_data.invites")
	exec(migration)
	check("SELECT schema_version::text FROM wormhole_data.workspace_meta", "3")
	reject(migration, "55000")
	exec("ROLLBACK")
	for _, table := range []string{"keys", "key_copies", "secret_values", "invites"} {
		check("SELECT (NOT pg_catalog.has_table_privilege('wh_testscope_user','wormhole_data."+table+"','SELECT,INSERT,UPDATE,DELETE') AND NOT pg_catalog.has_table_privilege('wh_testscope_admin','wormhole_data."+table+"','SELECT,INSERT,UPDATE,DELETE'))::text", "true")
		exec("SET ROLE wh_testscope_user")
		reject("SELECT * FROM wormhole_data."+table, "42501")
		exec("RESET ROLE")
	}
	const user = "12345678-1234-4234-8234-123456789abc"
	const enc = "22345678-1234-4234-8234-123456789abc"
	const sign = "32345678-1234-4234-8234-123456789abc"
	const dek = "42345678-1234-4234-8234-123456789abc"
	const next = "52345678-1234-4234-8234-123456789abc"
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + user + "','key-graph-test')")
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite) VALUES ('" + enc + "',1,'user-enc','" + user + "',2),('" + sign + "',1,'user-sign','" + user + "',1),('" + dek + "',1,'dek','" + user + "',1)")
	reject("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite) VALUES ('"+next+"',1,'user-enc','"+user+"',2)", "23505")
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite) VALUES ('" + next + "',1,'user-enc','" + user + "','pending',2)")
	reject("UPDATE wormhole_data.keys SET status='active' WHERE key_id='"+next+"'", "23505")
	for _, assignment := range []string{"key_version=0", "row_version=0", "kind='unknown'", "suite=0", "public_key=''::bytea", "public_key=decode(repeat('00',4097),'hex')", "cert_signature=decode(repeat('00',63),'hex')", "cert_signer_key_id='" + sign + "'", "owner_id='00000000-0000-0000-0000-000000000000'"} {
		reject("UPDATE wormhole_data.keys SET "+assignment+" WHERE key_id='"+next+"'", "23514")
	}
	exec("UPDATE wormhole_data.keys SET cert_signer_key_id='" + sign + "',cert_signer_key_version=1,cert_signature=decode(repeat('00',64),'hex') WHERE key_id='" + next + "'")
	exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES ('" + dek + "',1,'" + enc + "',1,2,decode(repeat('00',32),'hex'),decode(repeat('00',48),'hex'),'" + sign + "',1,decode(repeat('00',64),'hex'))")
	for _, assignment := range []string{"holder_key_id=key_id,holder_key_version=key_version", "signature=''::bytea", "ciphertext=''::bytea", "enc=''::bytea", "enc=decode(repeat('00',4097),'hex')", "ciphertext=decode(repeat('00',4194321),'hex')", "suite=0"} {
		reject("UPDATE wormhole_data.key_copies SET "+assignment, "23514")
	}
	reject("UPDATE wormhole_data.key_copies SET issuer_key_version=2", "23503")
	exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope) VALUES ('credential','" + user + "','password','" + dek + "',1,decode(repeat('00',32),'hex'))")
	for _, assignment := range []string{"field=''", "owner_kind='unknown'", "row_version=0", "envelope=''::bytea", "envelope=decode(repeat('00',8388609),'hex')", "field=repeat('x',1025)"} {
		reject("UPDATE wormhole_data.secret_values SET "+assignment, "23514")
	}
	reject("DELETE FROM wormhole_data.keys WHERE key_id='"+dek+"'", "23503")
	exec("INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision) VALUES ('" + next + "','" + user + "','invite',decode(repeat('00',32),'hex'),'" + user + "',clock_timestamp()+interval '1 hour','" + enc + "',1,'" + sign + "',1,decode(repeat('00',97),'hex'),'{}'::bytea,1)")
	for _, assignment := range []string{"manifest=''::bytea", "manifest=decode(repeat('00',1048577),'hex')", "manifest_revision=0", "user_id='00000000-0000-0000-0000-000000000000'", "created_by='00000000-0000-0000-0000-000000000000'", "code_hash=''::bytea", "attempts=-1", "expires_at=created_at", "expires_at='infinity'", "created_at='-infinity'", "used_at=expires_at+interval '1 second'", "used_at=created_at-interval '1 second'", "bootstrap_sign_key_id=bootstrap_enc_key_id", "bootstrap_envelope=''::bytea", "bootstrap_envelope=decode(repeat('00',65537),'hex')", "kind='unknown'"} {
		reject("UPDATE wormhole_data.invites SET "+assignment, "23514")
	}
	reject("UPDATE wormhole_data.invites SET bootstrap_enc_key_version=2", "23503")
	check("SELECT (manifest_digest=pg_catalog.sha256(manifest) AND pg_catalog.octet_length(manifest_digest)=32)::text FROM wormhole_data.invites", "true")
	reject("UPDATE wormhole_data.invites SET manifest_digest=decode(repeat('00',32),'hex')", "428C9")
	exec("UPDATE wormhole_data.invites SET manifest='{ }'::bytea,manifest_revision=2")
	check("SELECT (manifest_digest=pg_catalog.sha256('{ }'::bytea) AND manifest_revision=2)::text FROM wormhole_data.invites", "true")
	exec("UPDATE wormhole_data.invites SET used_at=clock_timestamp(),attempts=1")
	check("SELECT (used_at IS NOT NULL AND attempts=1)::text FROM wormhole_data.invites", "true")
	exec("DELETE FROM wormhole_data.secret_values; DELETE FROM wormhole_data.keys WHERE key_id='" + dek + "'")
	check("SELECT count(*)::text FROM wormhole_data.key_copies", "0")
}
