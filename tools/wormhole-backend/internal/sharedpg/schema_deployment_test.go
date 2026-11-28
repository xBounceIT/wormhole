package sharedpg

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestParseSchemaDeployment(t *testing.T) {
	const tag = "testscope"
	for _, tc := range []struct {
		state, tls string
		want       SchemaDeployment
	}{
		{"provisioning", "true", SchemaDeployment{deploy.SchemaVersion, true, true}},
		{"ready", "false", SchemaDeployment{deploy.SchemaVersion, false, false}},
	} {
		row := [][]byte{[]byte(testHintID), []byte(tag), []byte(strconv.Itoa(deploy.SchemaVersion)), []byte(tc.state), []byte(tc.tls)}
		if got, err := parseSchemaDeploymentRow(row, tag, testHintID); err != nil || got != tc.want {
			t.Fatal("valid deployment", got, err)
		}
		for column, invalid := range []string{"other", "wrongtag", "1", "unknown", "1"} {
			altered := append([][]byte(nil), row...)
			altered[column] = []byte(invalid)
			if _, err := parseSchemaDeploymentRow(altered, tag, testHintID); !errors.Is(err, ErrDeploymentMismatch) {
				t.Fatal("accepted inconsistent deployment column", column)
			}
		}
		for _, fields := range [][][]byte{nil, row[:4], append(row, nil)} {
			if _, err := parseSchemaDeploymentRow(fields, tag, testHintID); !errors.Is(err, ErrDeploymentMismatch) {
				t.Fatal("accepted inconsistent deployment rows")
			}
		}
	}
}

func TestSchemaDeploymentRejectsInvalidInputsBeforeConnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DeploySchema(ctx, Settings{}, nil, "invalid", testHintID); !errors.Is(err, deploy.ErrIdentity) {
		t.Fatal(err)
	}
	if _, err := DeploySchema(nil, Settings{}, nil, "testscope", testHintID); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
	if _, err := CheckSchemaDeployment(ctx, Settings{}, nil, "invalid", testHintID); !errors.Is(err, deploy.ErrIdentity) {
		t.Fatal(err)
	}
	if _, err := CheckSchemaDeployment(ctx, Settings{}, nil, "testscope", testHintID); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
}

func TestPostgresAtomicSchemaDeployment(t *testing.T) {
	s, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
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
	if _, err := CheckSchemaDeployment(ctx, s, secret, "testscope", testHintID); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("empty database check", err)
	}
	if _, err := DeploySchema(ctx, s, []byte("incorrect"), "testscope", testHintID); !errors.Is(err, ErrAuthentication) {
		t.Fatal("deployer login", err)
	}
	// This role is first created by migration 2, after migration 1 has created
	// database-local objects and cluster-global roles in the same transaction.
	exec("CREATE ROLE wh_testscope_observer NOLOGIN")
	if _, err := DeploySchema(ctx, s, secret, "testscope", testHintID); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("role collision", err)
	}
	check := admin.ExecParams(ctx, `SELECT (pg_catalog.to_regnamespace('wormhole_data') IS NULL
AND (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname LIKE 'wh_testscope%')=1)::text`, nil, nil, nil, nil).Read()
	if check.Err != nil || len(check.Rows) != 1 || string(check.Rows[0][0]) != "true" {
		t.Fatal("failed deployment left prior migration changes", check.Err)
	}
	exec("DROP ROLE wh_testscope_observer")
	want := SchemaDeployment{deploy.SchemaVersion, true, true}
	got, err := DeploySchema(ctx, s, secret, "testscope", testHintID)
	requireReleasedCatalog(t, ctx, s, secret, "testscope", standardDeploymentCatalog)
	if err != nil || got != want {
		t.Fatal("run now", got, err)
	}
	if got, err := CheckSchemaDeployment(ctx, s, secret, "testscope", testHintID); err != nil || got.SchemaDeployment != want || got.Checks.PlainStartup != "offered" {
		t.Fatal("check deployment", got, err)
	}
	if _, err := CheckSchemaDeployment(ctx, s, secret, "wrongtag", testHintID); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("foreign identity was accepted", err)
	}
	if _, err := DeploySchema(ctx, s, secret, "testscope", testHintID); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("already installed workspace was overwritten", err)
	}
	if got, err := CheckSchemaDeployment(ctx, s, secret, "testscope", testHintID); err != nil || got.SchemaDeployment != want {
		t.Fatal("failed redeployment changed existing workspace", got, err)
	}
	checkCatalogDrift(t, ctx, s, secret, admin)
	checkDeploymentAPIPermissions(t, ctx, admin)
	checkWorkspaceRowSecurity(t, ctx, s, secret, "testscope", standardRLSCatalog)
	t.Run("DBA logging diagnostics", func(t *testing.T) {
		dba := s
		dba.Profile = vault.Standard
		exec("ALTER ROLE wormhole_test_admin SET log_statement='ddl'; ALTER ROLE wormhole_test_admin SET log_parameter_max_length=0; ALTER ROLE wormhole_test_admin SET log_parameter_max_length_on_error=64")
		t.Cleanup(func() {
			exec("ALTER ROLE wormhole_test_admin RESET log_statement; ALTER ROLE wormhole_test_admin RESET log_parameter_max_length; ALTER ROLE wormhole_test_admin RESET log_parameter_max_length_on_error")
		})
		report, err := CheckSchemaDeployment(ctx, dba, secret, "testscope", testHintID)
		if err != nil || !report.Checks.LogsStatements || !report.Checks.LogsParameters || report.SchemaDeployment != want {
			t.Fatal("diagnostic connection did not report DBA logging settings", err, report)
		}
	})
	// A DBA can also run the exported script independently of the app, then
	// reconnect with Check deployment to reconcile that exact identity.
	exec("CREATE DATABASE wormhole_export_test")
	exported := s
	exported.Database = "wormhole_export_test"
	conn, err := Connect(ctx, exported, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	exportID := uuid.NewString()
	script, err := deploy.SchemaScript("password", exportID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, script).ReadAll(); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckSchemaDeployment(ctx, exported, secret, "password", exportID); err != nil || got.SchemaDeployment != want {
		t.Fatal("exported installation could not be reconciled", got, err)
	}
	if _, err := conn.Exec(ctx, "SET ROLE wh_password_owner; SELECT wormhole_data.set_row_security('"+exportID+"',true)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckSchemaDeployment(ctx, exported, secret, "password", exportID); err != nil || got.SchemaDeployment != want {
		t.Fatal("protected exported installation could not be reconciled", got, err)
	}
}

func TestPostgresSchemaDeploymentWithDelegatedDBA(t *testing.T) {
	s, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(admin)
	for _, sql := range []string{
		`CREATE ROLE "Setup-DBA" LOGIN CREATEROLE PASSWORD '` + postgresTestVerifier(secret) + "'",
		`GRANT pg_read_all_stats TO "Setup-DBA" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`,
		`CREATE DATABASE wormhole_delegated_test OWNER "Setup-DBA"`,
	} {
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	s.Database, s.DeviceRole = "wormhole_delegated_test", "Setup-DBA"
	p, err := CheckDeploymentPrerequisites(ctx, s, secret)
	if err != nil || !p.ReadyToDeploy() {
		t.Fatal("delegated DBA did not pass preflight", p, err)
	}
	state, err := DeploySchema(ctx, s, secret, "delegated", testHintID)
	requireReleasedCatalog(t, ctx, s, secret, "delegated", delegatedDeploymentCatalog)
	if err != nil || state.Version != deploy.SchemaVersion || !state.Provisioning {
		t.Fatal("delegated deployment", state, err)
	}
	grants := admin.ExecParams(ctx, `SELECT count(*)::text FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
WHERE m.member='"Setup-DBA"'::regrole AND pg_catalog.starts_with(r.rolname,'wh_delegated_') AND (m.inherit_option OR m.set_option)`, nil, nil, nil, nil).Read()
	if grants.Err != nil || len(grants.Rows) != 1 || string(grants.Rows[0][0]) != "0" {
		t.Fatal("temporary delegated privileges survived deployment", grants.Err)
	}
	if got, err := CheckSchemaDeployment(ctx, s, secret, "delegated", testHintID); err != nil || got.Version != deploy.SchemaVersion || !got.Provisioning {
		t.Fatal("delegated DBA could not reconcile its own installation", got, err)
	}
	delegated, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(delegated)
	for _, query := range []string{`SELECT signed_profile FROM wormhole_data.workspace_meta`, `SELECT id FROM wormhole_data.users`, `UPDATE wormhole_data.workspace_meta SET require_tls=false`} {
		if _, err := delegated.Exec(ctx, query).ReadAll(); !hasSQLState(err, "42501", 0) {
			t.Fatal("delegated reconciliation granted excess privileges", err)
		}
	}
	s.DeviceRole = "wormhole_test_admin"
	if got, err := CheckSchemaDeployment(ctx, s, secret, "delegated", testHintID); err != nil || got.Version != deploy.SchemaVersion || !got.Provisioning {
		t.Fatal("independent DBA could not reconcile delegated installation", got, err)
	}
	s.DeviceRole = "Setup-DBA"
	checkWorkspaceRowSecurity(t, ctx, s, secret, "delegated", delegatedRLSCatalog)
	checkWorkspaceBootstrap(t, ctx, s, secret)
}

func requireReleasedCatalog(t *testing.T, ctx context.Context, s Settings, password []byte, tag, want string) {
	t.Helper()
	c, err := Connect(ctx, s, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(c)
	digest, err := deploymentCatalog(ctx, c, tag, testHintID)
	if err != nil || digest != want {
		t.Fatalf("fresh %s catalog fingerprint %q, expected %q: %v", tag, digest, want, err)
	}
}

func TestPostgresDeploymentRejectsUnexpectedReplies(t *testing.T) {
	s, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, query string
		want        error
	}{
		{"oversized", `SELECT repeat('x', 64)`, ErrDeploymentMismatch},
		{"multiple rows", `SELECT n::text FROM generate_series(1, 2) AS n`, ErrDeploymentMismatch},
		{"extra columns", `SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9`, ErrDeploymentMismatch},
		{"query error", `SELECT 1/0`, ErrQuery},
		{"canceled", `SELECT pg_catalog.pg_sleep(5)`, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := Connect(ctx, s, secret)
			if err != nil {
				t.Fatal(err)
			}
			defer closeDeploymentConnection(conn)
			queryCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tc.want == context.Canceled {
				cancel()
			}
			if row, err := readDeploymentRow(queryCtx, conn, tc.query, 1); row != nil || !errors.Is(err, tc.want) {
				t.Fatal("accepted invalid deployment response", err)
			}
		})
	}
	conn, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	if tag, err := executeDeploymentScript(ctx, conn, `BEGIN; SELECT 1; COMMIT;`); tag != "" || !errors.Is(err, ErrDeploymentUncertain) {
		t.Fatal("accepted a row-returning statement in deployment script", err)
	}
	for _, tc := range []struct {
		query string
		want  error
	}{
		{`SELECT repeat('x', 33)`, ErrAdmissionResponse},
		{`SELECT n::text FROM generate_series(1, 2) AS n`, ErrAdmissionResponse},
		{`SELECT 'first', 'second'`, ErrAdmissionResponse},
		{`SELECT 1 WHERE false`, ErrAdmissionResponse},
		{`SELECT 1/0`, ErrQuery},
	} {
		target, err := Connect(ctx, s, secret)
		if err != nil {
			t.Fatal(err)
		}
		row, err := readAccountResetRow(ctx, target, tc.query, nil, 1, 32)
		closeDeploymentConnection(target)
		if row != nil || !errors.Is(err, tc.want) {
			t.Fatal("reset transport accepted a malformed reply", err)
		}
	}
}

func TestPostgresRecoveryDeploymentRejectsAmbiguousReceipts(t *testing.T) {
	s, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, query string
		want        error
	}{
		{"oversized", `SELECT repeat('x', 37)`, ErrDeploymentUncertain},
		{"multiple rows", `SELECT n::text FROM generate_series(1, 2) AS n`, ErrDeploymentUncertain},
		{"missing value", `SELECT NULL::text`, ErrDeploymentUncertain},
		{"unexpected columns", `SELECT 1, 2`, ErrDeploymentUncertain},
		{"ordinary PostgreSQL rejection", `SELECT 1/0`, ErrDeploymentRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := Connect(ctx, s, secret)
			if err != nil {
				t.Fatal(err)
			}
			defer closeDeploymentConnection(conn)
			if data, err := readDeploymentResponse(ctx, conn, tc.query, nil, 36); data != nil || !errors.Is(err, tc.want) {
				t.Fatal("unexpected recovery receipt disposition", err)
			}
		})
	}
}
