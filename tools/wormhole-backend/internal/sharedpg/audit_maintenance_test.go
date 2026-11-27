package sharedpg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresAuditPartitionMaintenance(t *testing.T) {
	settings, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := Connect(ctx, settings, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(db)
	run := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	rejected := func(sql, state string) {
		t.Helper()
		_, err := db.Exec(ctx, sql).ReadAll()
		var e *pgconn.PgError
		if !errors.As(err, &e) || e.Code != state {
			t.Fatalf("expected SQLSTATE %s, got %v", state, err)
		}
	}
	fresh, err := deploy.SchemaScript("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	previous, _, ok := strings.Cut(fresh, "-- Version 85:")
	if !ok {
		t.Fatal("schema upgrade boundary missing")
	}
	run(previous + "COMMIT;")
	upgrade, err := deploy.AuditMaintenanceMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(upgrade)
	rejected(upgrade, "55000")
	run("ROLLBACK")
	liveClients, err := deploy.UnencryptedClientsMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	probe := db.ExecParams(ctx, unencryptedClientsSupportedSQL, nil, nil, nil, nil).Read()
	if probe.Err != nil || len(probe.Rows) != 1 || len(probe.Rows[0]) != 1 || string(probe.Rows[0][0]) != "false" {
		t.Fatal("schema 85 advertised the live client inventory", probe.Err)
	}
	run(`CREATE ROLE inventory_upgrade NOINHERIT;
		GRANT wh_testscope_owner,wh_testscope_observer TO inventory_upgrade WITH INHERIT FALSE, SET TRUE;
		SET SESSION AUTHORIZATION inventory_upgrade`)
	run(liveClients)
	rejected(liveClients, "55000")
	run("ROLLBACK")
	pinMigration, err := deploy.SSHHostPinMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(pinMigration)
	rejected(pinMigration, "55000")
	run("ROLLBACK")
	editMigration, err := deploy.UpdateNodeMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(editMigration)
	rejected(editMigration, "55000")
	run("ROLLBACK")
	moveMigration, err := deploy.MoveNodeMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(moveMigration)
	rejected(moveMigration, "55000")
	run("ROLLBACK")
	receiptMigration, err := deploy.SuspensionRotationReceiptsMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(receiptMigration)
	rejected(receiptMigration, "55000")
	run("ROLLBACK")
	rlsMigration, err := deploy.RowSecurityMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(rlsMigration)
	rejected(rlsMigration, "55000")
	run("ROLLBACK")
	run("RESET SESSION AUTHORIZATION")
	t.Run("edit-seal-verification", func(t *testing.T) { checkPostgresEditSignatures(t, ctx, db) })
	const maintain = "SELECT * FROM wormhole_data.maintain_audit_partitions('" + testHintID + "'"
	check := func(call string, created, dropped, deleted string) {
		t.Helper()
		result := db.ExecParams(ctx, call, nil, nil, nil, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
			t.Fatal("maintenance result", result.Err)
		}
		row := result.Rows[0]
		if string(row[0]) != created || string(row[1]) != dropped || string(row[2]) != deleted {
			t.Fatalf("unexpected maintenance counts: %s", row)
		}
	}
	rejected(maintain+")", "42501")
	for _, role := range []string{"user", "admin", "enroll", "deployer"} {
		run("SET ROLE wh_testscope_" + role)
		rejected(maintain+")", "42501")
		run("RESET ROLE")
	}
	run("SET ROLE wh_testscope_owner")
	rejected("SELECT wormhole_data.maintain_audit_partitions(gen_random_uuid())", "42501")
	rejected(maintain+",NULL)", "22023")
	rejected(maintain+",0)", "22023")
	locker, err := Connect(ctx, settings, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(locker)
	if _, err = locker.Exec(ctx, "BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('wormhole/schema/"+testHintID+"',0))").ReadAll(); err != nil {
		t.Fatal(err)
	}
	rejected(maintain+")", "55P03")
	if _, err = locker.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	run("SET timezone='Pacific/Auckland'")
	check(maintain+")", "1", "0", "0")
	check(maintain+")", "0", "0", "0")

	// Exercise the real default and an operator-selected cutoff in the middle
	// of a month. The boundary fixture is independent of the runner's date.
	run(`SET timezone='UTC';
DO $fixture$
DECLARE stamp timestamptz; start_at timestamptz; label text;
BEGIN
    FOR label,stamp IN SELECT * FROM (VALUES
        ('expired-month',now()-interval '450 days'),
        ('within-default',now()-interval '395 days'),
        ('expired-row',date_trunc('month',now())-interval '12 months'+interval '13 days'),
        ('retained-row',date_trunc('month',now())-interval '12 months'+interval '15 days'),
        ('future',date_trunc('month',now())+interval '2 months')) AS rows(action,at)
    LOOP
        start_at:=date_trunc('month',stamp);
        EXECUTE format('CREATE TABLE IF NOT EXISTS wormhole_data.%I PARTITION OF wormhole_data.audit_log FOR VALUES FROM (%L) TO (%L)',
            'audit_log_'||to_char(start_at,'YYYYMM'),start_at,start_at+interval '1 month');
        INSERT INTO wormhole_data.audit_log(at,user_id,session_id,session_role,source,action,outcome,app_version)
        VALUES(stamp,gen_random_uuid(),gen_random_uuid(),current_user,'ui',label,'success','1.0.0');
    END LOOP;
END $fixture$`)
	check(maintain+")", "0", "1", "0")
	run(`DO $check$ BEGIN
    IF (SELECT count(*) FROM wormhole_data.audit_log)<>4 OR
       NOT EXISTS(SELECT FROM wormhole_data.audit_log WHERE action='within-default') THEN
        RAISE EXCEPTION 'default retention mismatch';
    END IF;
END $check$`)
	// Discard the independent 395-day fixture before measuring a tight cutoff.
	run("DELETE FROM wormhole_data.audit_log WHERE action='within-default'")
	cutoff := maintain + ",current_date-(date_trunc('month',now())-interval '12 months'+interval '14 days')::date)"
	result := db.ExecParams(ctx, cutoff, nil, nil, nil, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][2]) != "1" {
		t.Fatal("cutoff inside retained partition", result.Err)
	}
	run(`DO $check$ BEGIN
    IF (SELECT array_agg(action ORDER BY action) FROM wormhole_data.audit_log)
       IS DISTINCT FROM ARRAY['future','retained-row'] THEN
        RAISE EXCEPTION 'retained audit entries changed';
    END IF;
END $check$`)
	// A differently bounded table carrying a plausible name must never be
	// removed on the authority of its name. An error rolls back the whole call.
	run("CREATE TABLE wormhole_data.audit_log_199901 PARTITION OF wormhole_data.audit_log FOR VALUES FROM ('1999-01-01') TO ('1999-02-01')")
	run("CREATE TABLE wormhole_data.audit_log_200001 PARTITION OF wormhole_data.audit_log FOR VALUES FROM ('2001-01-01') TO ('2001-02-01')")
	rejected(maintain+")", "55000")
	run("SELECT 1 FROM wormhole_data.audit_log_199901")
	run("ALTER TABLE wormhole_data.audit_log_200001 RENAME TO custom_audit_partition")
	rejected(maintain+")", "55000")
}
