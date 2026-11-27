package sharedpg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresDeviceConnectionLimitUpgrade(t *testing.T) {
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
	fresh, err := deploy.SchemaScript("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	previous, _, found := strings.Cut(fresh, "-- Version 92:")
	if !found {
		t.Fatal("schema 91 boundary missing")
	}
	run(previous + "COMMIT;")
	// The tagged owner creates its own device roles as in real enrollment.
	// Cases 2–4 distinguish unconfirmed, explicitly constrained and replaced roles.
	run(`SET ROLE wh_testscope_owner;
		DO $fixture$
		DECLARE seq integer; device uuid; target text;
		BEGIN
			FOR seq IN 1..4 LOOP
				device:=('00000000-0000-4000-8000-00000000000'||seq)::uuid;
				target:='wh_testscope_d_'||device;
				INSERT INTO wormhole_data.users(id,login_name) VALUES(device,'limit-user-'||seq);
				INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES(device,device,target,'active');
				EXECUTE format('CREATE ROLE %I LOGIN NOINHERIT CONNECTION LIMIT %s',target,CASE WHEN seq=3 THEN 1 ELSE 2 END);
				EXECUTE format('GRANT wh_testscope_user TO %I WITH INHERIT TRUE, SET FALSE',target);
				IF seq<>2 THEN
					INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
					SELECT device,CASE WHEN seq=4 THEN 'wh_testscope_owner'::regrole::oid ELSE r.oid END,sha256('fixture'::bytea)
					FROM pg_roles r WHERE r.rolname=target;
				END IF;
			END LOOP;
		END $fixture$;
		RESET ROLE;`)
	migration, err := deploy.NextMigrationScript("testscope", testHintID, 91)
	if err != nil {
		t.Fatal(err)
	}
	run(migration)
	limits, err := readDeploymentRow(ctx, db, `SELECT string_agg(r.rolconnlimit::text,',' ORDER BY d.id)
		FROM wormhole_data.devices d JOIN pg_roles r ON r.rolname=d.role_name`, 1)
	if err != nil || string(limits[0]) != "3,2,1,2" {
		t.Fatal("unexpected upgraded role limits", limits, err)
	}
	if _, err := db.Exec(ctx, migration).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated upgrade", err)
	}
}
