package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresSessionAdmissionIntegration(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) { testPostgresSessionAdmission(t, false) })
	t.Run("verifiedTLS", func(t *testing.T) { testPostgresSessionAdmission(t, true) })
}

func testPostgresSessionAdmission(t *testing.T, enableTLS bool) {
	settings, secret := postgresTestClusterTLS(t, enableTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if enableTLS {
		wrongCA := settings
		wrongCA.CAPEM = testCA(t)
		wrongName := settings
		wrongName.Endpoints = []Endpoint{{Host: "localhost", Port: settings.Endpoints[0].Port}}
		for _, invalid := range []Settings{wrongCA, wrongName} {
			conn, err := Connect(ctx, invalid, secret)
			if conn != nil {
				_ = conn.Close(ctx)
			}
			if err != ErrConnection {
				t.Fatalf("accepted untrusted TLS endpoint: %v", err)
			}
		}
	}
	admin, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	initial, _ := deploy.InitialMigration("testscope", testHintID)
	exec(initial)
	migration, _ := deploy.SessionMigration("testscope", testHintID)
	wrong, _ := deploy.SessionMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	if _, err := admin.Exec(ctx, wrong).ReadAll(); err == nil {
		t.Fatal("accepted wrong workspace")
	}
	exec("ROLLBACK")
	exec(migration)
	if _, err := admin.Exec(ctx, migration).ReadAll(); err == nil {
		t.Fatal("reapplied migration")
	}
	exec("ROLLBACK")
	role := "wh_testscope_d_" + testHintID
	exec("CREATE ROLE \"" + role + "\" LOGIN CONNECTION LIMIT 3 PASSWORD '" + postgresTestVerifier(secret) + "'; GRANT wh_testscope_user TO \"" + role + "\";")
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + testHintID + "','admission-test'); INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES ('" + testHintID + "','" + testHintID + "','" + role + "','active')")
	settings.DeviceRole = role
	device, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close(context.Background())
	call := "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui')"
	rejected := func(sql, state string) {
		t.Helper()
		_, err := device.Exec(ctx, sql).ReadAll()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != state {
			t.Fatalf("expected %s, got %v", state, err)
		}
	}
	rejected(call, "WH002")
	// Synthetic metadata exercises admission only, not profile signature trust.
	exec("UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea")
	if !enableTLS {
		rejected(call, "WH003")
		exec("UPDATE wormhole_data.workspace_meta SET require_tls=false")
	} else {
		plain := settings
		plain.TLS = TLSOff
		plain.CAPEM = nil
		conn, err := Connect(ctx, plain, secret)
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Exec(ctx, call).ReadAll()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "WH003" {
			t.Fatalf("plaintext bypassed TLS policy: %v", err)
		}
		if err := conn.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{
		"SELECT * FROM wormhole_api_v1.session_start(NULL,'1.2.3','ui')",
		"SELECT * FROM wormhole_api_v1.session_start(1,NULL,'ui')",
		"SELECT * FROM wormhole_api_v1.session_start(1,'bad','ui')",
		"SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','invalid')",
		"SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3',NULL)",
	} {
		rejected(sql, "22023")
	}
	rejected("SELECT * FROM wormhole_api_v1.session_start(999,'1.2.3','ui')", "WH004")
	success := func() {
		t.Helper()
		rows, err := device.Exec(ctx, call).ReadAll()
		if err != nil || len(rows) != 1 || len(rows[0].Rows) != 1 {
			t.Fatalf("admission failed: %v", err)
		}
		row := rows[0].Rows[0]
		if string(row[1]) != testHintID || string(row[2]) != testHintID || string(row[3]) != testHintID {
			t.Fatal("wrong admitted identity")
		}
	}
	success()
	// Changing effective role must not change the authenticated identity.
	if _, err := device.Exec(ctx, "SET ROLE wh_testscope_user").ReadAll(); err != nil {
		t.Fatal(err)
	}
	success()
	exec("UPDATE wormhole_data.users SET disabled=true")
	rejected(call, "WH001")
	exec("UPDATE wormhole_data.users SET disabled=false; UPDATE wormhole_data.devices SET status='revoked'")
	rejected(call, "WH001")
	exec("UPDATE wormhole_data.devices SET status='pending'")
	rejected(call, "WH001")
	exec("UPDATE wormhole_data.devices SET status='active'")
	if _, err := device.Exec(ctx, "BEGIN ISOLATION LEVEL REPEATABLE READ").ReadAll(); err != nil {
		t.Fatal(err)
	}
	rejected(call, "WH006")
	if _, err := device.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	rejected("SELECT * FROM wormhole_data.sessions", "42501")
	rejected("SELECT * FROM wormhole_data.current_connection_tls()", "42501")
	rejected("SET ROLE wh_testscope_observer", "42501")
	check := func(sql, want string) {
		t.Helper()
		rs, err := admin.Exec(ctx, sql).ReadAll()
		if err != nil || len(rs) != 1 || len(rs[0].Rows) != 1 || string(rs[0].Rows[0][0]) != want {
			t.Fatalf("unexpected persisted state: %v", err)
		}
	}
	check("SELECT count(*) FROM wormhole_data.sessions", "2")
	check("SELECT pg_catalog.pg_has_role('wh_testscope_owner','pg_read_all_stats','USAGE')::text", "false")
	check("SELECT pg_catalog.pg_has_role('"+role+"','pg_read_all_stats','USAGE')::text", "false")
	check("SELECT pg_catalog.pg_has_role('wh_testscope_observer','pg_read_all_stats','USAGE')::text", "true")
	check("SELECT rolcanlogin::text FROM pg_catalog.pg_roles WHERE rolname='wh_testscope_observer'", "false")
	check("SELECT pg_catalog.has_schema_privilege('wh_testscope_observer','wormhole_data','CREATE')::text", "false")
	check("SELECT pg_catalog.has_function_privilege('"+role+"','wormhole_data.current_connection_tls()','EXECUTE')::text", "false")
	tlsPredicate := "NOT s.ssl AND s.tls_version IS NULL"
	if enableTLS {
		tlsPredicate = "s.ssl AND s.tls_version IN ('TLSv1.2','TLSv1.3')"
	}
	check("SELECT count(*) FROM wormhole_data.audit_log a JOIN wormhole_data.sessions s ON s.id=a.session_id WHERE a.session_role='"+role+"' AND a.source='ui' AND a.action='login' AND a.outcome='success' AND "+tlsPredicate+" AND s.client_addr='127.0.0.1'::inet", "2")
	exec("ALTER TABLE wormhole_data.audit_log RENAME TO unavailable_audit")
	rejected(call, "WH005")
	check("SELECT count(*) FROM wormhole_data.sessions", "2")
	exec("ALTER TABLE wormhole_data.unavailable_audit RENAME TO audit_log")
	success()
	check("SELECT count(*) FROM wormhole_data.audit_log", "3")
	// The typed native entry point uses bound parameters and checks identities.
	native := NewSession()
	defer native.Close(context.Background())
	if err := native.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	request := admissionRequest()
	request.Source = "mcp"
	admitted, err := native.StartSession(ctx, request)
	if err != nil || admitted.WorkspaceID != request.WorkspaceID || string(admitted.SignedProfile) != "test" {
		t.Fatalf("native admission failed: %v", err)
	}
	check("SELECT count(*) FROM wormhole_data.audit_log WHERE source='mcp'", "1")
	profileFixture, _, trust, _ := signedAdmissionFixture(t)
	if _, err := VerifyAdmissionPolicy(admitted, request, trust); err != ErrProfileAuthentication {
		t.Fatal("unsigned database profile accepted")
	}
	updated := admin.ExecParams(ctx, "UPDATE wormhole_data.workspace_meta SET signed_profile=pg_catalog.decode($1::text,'hex'),max_api=2", [][]byte{[]byte(hex.EncodeToString(profileFixture.SignedProfile))}, nil, nil, nil)
	if _, err := updated.Close(); err != nil {
		t.Fatal(err)
	}
	admitted, err = native.StartSession(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := VerifyAdmissionPolicy(admitted, request, trust)
	if err != nil || policy.Sequence != 7 {
		t.Fatalf("database signed profile verification failed: %v", err)
	}
	trust.MinimumSequence = 8
	if _, err := VerifyAdmissionPolicy(admitted, request, trust); err != ErrProfileRollback {
		t.Fatal("database profile rollback accepted")
	}
	exec("UPDATE wormhole_data.users SET disabled=true")
	if result, err := native.StartSession(ctx, request); err != ErrIdentityUnavailable || result != nil {
		t.Fatalf("native revocation failed: %v", err)
	}
	if _, err := native.Query(ctx, "SELECT 1", nil); err != ErrSessionClosed {
		t.Fatal("revoked native owner remained usable")
	}
	if err := native.Close(ctx); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE wormhole_data.users SET disabled=false; UPDATE wormhole_data.workspace_meta SET workspace_id='22345678-1234-4234-8234-123456789abc'")
	mismatched := NewSession()
	defer mismatched.Close(context.Background())
	if err := mismatched.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if result, err := mismatched.StartSession(ctx, request); err != ErrAdmissionResponse || result != nil {
		t.Fatalf("native accepted wrong workspace: %v", err)
	}
	if _, err := mismatched.Query(ctx, "SELECT 1", nil); err != ErrSessionClosed {
		t.Fatal("invalid response left owner usable")
	}
}
