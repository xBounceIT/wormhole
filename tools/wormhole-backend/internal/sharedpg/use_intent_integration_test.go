package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresUseIntent(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, node uuid.UUID) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("use state", r.Err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatal("migration rejection", err)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.UseIntentsMigration("testscope", testHintID)
	wrong, _ := deploy.UseIntentsMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=19 AND to_regclass('wormhole_data.use_tickets') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text)")
	script(migration)
	reject(migration, "55000")
	check("SELECT (NOT has_table_privilege('wh_testscope_user','wormhole_data.use_tickets','SELECT,INSERT,UPDATE,DELETE') AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.begin_use(bytea,uuid,text)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.begin_use(bytea,uuid,text)'::regprocedure AND a.grantee=0))::text")
	var capability []byte
	if err := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	query := func(id, source []byte) ([][][]byte, error) {
		return native.Query(ctx, beginUseSQL, [][]byte{capability, id, source})
	}
	script("UPDATE wormhole_data.grants SET permissions=1")
	if rows, err := query([]byte(node.String()), []byte("ui")); err == nil {
		wipeQueryRows(rows)
		t.Fatal("View allowed use")
	}
	check("SELECT (count(*)=0)::text FROM wormhole_data.use_tickets")
	script("UPDATE wormhole_data.grants SET permissions=31")
	for _, v := range [][2][]byte{{nil, []byte("ui")}, {[]byte(uuid.Nil.String()), []byte("ui")}, {[]byte(node.String()), nil}, {[]byte(node.String()), []byte("unknown")}, {[]byte(uuid.NewString()), []byte("ui")}} {
		rows, err := query(v[0], v[1])
		wipeQueryRows(rows)
		if err == nil {
			t.Fatal("invalid use accepted")
		}
	}
	// Failed audit must not publish a ticket.
	script("CREATE FUNCTION wormhole_data.reject_use_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='begin_use' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END$$")
	script("CREATE TRIGGER reject_use_audit BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.reject_use_audit()")
	if _, err := query([]byte(node.String()), []byte("ui")); err != ErrAuditUnavailable {
		t.Fatal("audit failure", err)
	}
	check("SELECT (count(*)=0)::text FROM wormhole_data.use_tickets")
	script("DROP TRIGGER reject_use_audit ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.reject_use_audit()")
	// A caller-controlled transaction cannot produce a native committed receipt.
	if _, err := native.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := native.BeginUse(ctx, node, "ui"); err != ErrConfiguration {
		t.Fatal("open transaction", err)
	}
	rows, err := query([]byte(node.String()), []byte("ui"))
	if err != nil {
		t.Fatal(err)
	}
	wipeQueryRows(rows)
	if _, err := native.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	check("SELECT (count(*)=0)::text FROM wormhole_data.use_tickets")
	check("SELECT (count(*)=0)::text FROM wormhole_data.audit_log WHERE action='begin_use'")
	first, err := native.BeginUse(ctx, node, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if first.Node != node || first.ExpiresAt < time.Now().Unix()+20 || first.ExpiresAt > time.Now().Unix()+31 {
		t.Fatal("invalid receipt")
	}
	check("SELECT (count(*)=1)::text FROM wormhole_data.use_tickets t JOIN wormhole_data.audit_log a ON a.ticket_id=t.ticket_id AND a.transaction_id=t.transaction_id WHERE pg_xact_status(t.transaction_id)='committed' AND t.expires_at=t.issued_at+interval '30 seconds' AND a.node_id=t.node_id AND a.source='ui' AND t.capability_hash=(SELECT d.capability_hash FROM wormhole_data.device_admissions d WHERE d.device_id=t.device_id)")
	second, err := native.BeginUse(ctx, node, "mcp")
	if err != nil || first.Ticket == second.Ticket {
		t.Fatal("replacement ticket", err)
	}
	check("SELECT (count(*)=1)::text FROM wormhole_data.use_tickets")
	check("SELECT (count(*)=2)::text FROM wormhole_data.audit_log WHERE action='begin_use'")
	testPostgresUseConsumption(t, ctx, admin, native, node)
	testPostgresResolver(t, ctx, admin)
	testPostgresResolutionChain(t, ctx, admin, native)
	testPostgresSlots(t, ctx, admin)
	testPostgresCredentialCatalog(t, ctx, admin, native)
	testPostgresCredentialProjection(t, ctx, admin, native)
	testPostgresSelectionProjection(t, ctx, admin, native)
	testPostgresConnectionResolution(t, ctx, admin)
	testPostgresBoundaryPermissions(t, ctx, admin, native)
	testPostgresBoundaryManifest(t, ctx, admin, native)
	testPostgresConnectionSnapshot(t, ctx, admin)
	testPostgresCredentialValues(t, ctx, admin, native)
	testPostgresKeyCopyProjection(t, ctx, admin)
	testPostgresCredentialReleaseGraph(t, ctx, admin, native)
}
