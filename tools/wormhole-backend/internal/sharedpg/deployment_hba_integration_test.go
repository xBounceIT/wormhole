package sharedpg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Install the generated snippet in the fixture's loopback-only cluster,
// retaining the initdb SCRAM rules below it for unrelated roles/databases.
func installFixtureHBARules(t *testing.T, ctx context.Context, admin *pgconn.PgConn, database, tag, rules string) {
	t.Helper()
	data := postgresFixtureDataDirectory(t, ctx, admin)
	file := filepath.Join(data, "pg_hba.conf")
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "workspace-hba.conf"), []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append([]byte("include workspace-hba.conf\n"), original...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "SELECT pg_reload_conf()").ReadAll(); err != nil {
		t.Fatal(err)
	}
	row, err := readDeploymentRow(ctx, admin, `SELECT count(*)::text FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL`, 1)
	if err != nil || string(row[0]) != "0" {
		t.Fatal("PostgreSQL could not parse the generated HBA include", err)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for checkPlainStartup(wait, admin.Conn(), database, tag) != "refused" {
		select {
		case <-wait.Done():
			t.Fatal("PostgreSQL did not refuse the plaintext workspace startup")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestPostgresWorkspaceNetworkRules(t *testing.T) {
	s, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := Connect(ctx, s, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(admin)
	const tag = "testscope"
	const database = "all" // PostgreSQL interprets the quoted HBA token literally.
	s.DeviceRole = "wh_testscope_deployer"
	if _, err := admin.Exec(ctx, `CREATE DATABASE "all"`).ReadAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE wh_testscope_deployer LOGIN PASSWORD '"+postgresTestVerifier(password)+"'").ReadAll(); err != nil {
		t.Fatal("fixture login creation failed")
	}
	rules, err := DeploymentHBARules(database, tag, testHintID, []string{"192.0.2.0/24", "2001:db8::/64"})
	if err != nil {
		t.Fatal(err)
	}
	installFixtureHBARules(t, ctx, admin, database, tag, rules)
	// The same workspace login may still reach the unrelated fixture
	// database under the preexisting SCRAM policy.
	conn, err := Connect(ctx, s, password)
	if err != nil {
		t.Fatal("HBA included a different database", err)
	}
	closeDeploymentConnection(conn)
	s.Database = database
	cfg, err := Config(s)
	if err != nil {
		t.Fatal(err)
	}
	// The explicit reject must precede initdb's broader SCRAM rule even on TLS.
	cfg.Password = string(password)
	if conn, err := pgconn.ConnectConfig(ctx, cfg); err == nil {
		closeDeploymentConnection(conn)
		t.Fatal("TLS allowed from outside the configured client networks")
	} else if !hasSQLState(err, "28000", 0) {
		t.Fatal("expected HBA refusal for the client address")
	}
}
