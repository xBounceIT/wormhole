package sharedpg

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestValidateDeploymentTargetAcceptsOnlyPublicCertificates(t *testing.T) {
	ca := testCA(t)
	invalidCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})
	privateBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")})
	withCA := func(prefix []byte) []byte { return append(bytes.Clone(prefix), ca...) }
	endpoint := Endpoint{Host: "127.0.0.1", Port: 5432}
	for _, tc := range []struct {
		name string
		pem  []byte
		ok   bool
	}{
		{"single", ca, true},
		{"bundle and comment", withCA(withCA([]byte("# Provider CA bundle\r\n\r\n"))), true},
		{"private before public", withCA(privateBlock), false},
		{"private after public", append(bytes.Clone(ca), privateBlock...), false},
		{"malformed before valid", withCA(invalidCertificate), false},
		{"unfinished before valid", withCA([]byte("-----BEGIN CERTIFICATE-----\n")), false},
		{"extraneous content", withCA([]byte("unexpected\n")), false},
		{"comment only", []byte("# No certificate"), false},
		{"empty", nil, false},
		{"oversized", make([]byte, 256*1024+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDeploymentTarget(endpoint, "workspace", tc.pem)
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrConfiguration)) {
				t.Fatalf("unexpected deployment CA validation result: %v", err)
			}
		})
	}
}

func TestDeploymentPreflightDiagnosticShape(t *testing.T) {
	row := [][]byte{[]byte("160015"), []byte("true"), []byte("true"), []byte("true"), []byte("true"), []byte("true"), []byte("false"), []byte("false"), []byte("all"), []byte("120")}
	p, err := parseDeploymentPreflight(row, TLSVerified)
	if err != nil || !p.ReadyToDeploy() || p.MaxConnections != 120 || p.StatementTracking != "all" || p.TLS != TLSVerified {
		t.Fatal(p, err)
	}
	for _, column := range []int{0, 1, 3, 8} {
		bad := append([][]byte(nil), row...)
		bad[column] = []byte("invalid")
		if _, err := parseDeploymentPreflight(bad, TLSOff); !errors.Is(err, ErrDeploymentMismatch) {
			t.Fatal("accepted malformed server field", column)
		}
	}
	if _, err := parseDeploymentPreflight(row[:7], TLSOff); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("accepted partial preflight", err)
	}
	for _, limit := range []string{"", "0", "-1", "1.5", "020", "2147483648"} {
		bad := append([][]byte(nil), row...)
		bad[9] = []byte(limit)
		if _, err := parseDeploymentPreflight(bad, TLSVerified); !errors.Is(err, ErrDeploymentMismatch) {
			t.Fatalf("accepted invalid max_connections %q", limit)
		}
	}
	row[0] = []byte("150002")
	if p, err := parseDeploymentPreflight(row, TLSOff); err != nil || p.ReadyToDeploy() {
		t.Fatal("accepted unsupported server", p, err)
	}
}

func TestPostgresDeploymentPreflight(t *testing.T) {
	s, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := CheckDeploymentPrerequisites(ctx, s, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatal("diagnostic accepted wrong password", err)
	}
	checkStage := func(settings Settings, secret []byte, want DeploymentConnectionStage) {
		t.Helper()
		_, err := CheckDeploymentPrerequisites(ctx, settings, secret)
		var problem *DeploymentConnectionError
		if !errors.As(err, &problem) || problem.Stage != want || err.Error() != "PostgreSQL deployment check failed at "+string(want) {
			t.Fatal("incorrect deployment stage", want, err)
		}
	}
	checkStage(s, []byte("wrong"), DeploymentSCRAM)
	missingDatabase := s
	missingDatabase.Database = "no_such_database"
	checkStage(missingDatabase, password, DeploymentDatabase)
	wrongCA := s
	wrongCA.CAPEM = testCA(t)
	checkStage(wrongCA, password, DeploymentTLS)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	wrongPort := s
	wrongPort.Endpoints = []Endpoint{{Host: "127.0.0.1", Port: uint16(closedPort)}}
	checkStage(wrongPort, password, DeploymentTCP)
	p, err := CheckDeploymentPrerequisites(ctx, s, password)
	if err != nil || !p.ReadyToDeploy() || p.TLS != TLSVerified || p.LogsStatements || p.StatementTracking != "unavailable" {
		t.Fatal("DBA prerequisite check", p, err)
	}
	admin, err := Connect(ctx, s, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(admin)
	capacity, err := readDeploymentRow(ctx, admin, "SHOW max_connections", 1)
	if err != nil || string(capacity[0]) != strconv.Itoa(p.MaxConnections) {
		t.Fatal("preflight did not report the live server connection limit", err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE ROLE wh_probe_readonly LOGIN NOSUPERUSER NOCREATEROLE PASSWORD '" + postgresTestVerifier(password) + "'")
	limited := s
	limited.DeviceRole = "wh_probe_readonly"
	p, err = CheckDeploymentPrerequisites(ctx, limited, password)
	if err != nil || p.ReadyToDeploy() || p.CanCreateRoles || p.OwnsDatabase || p.OwnsPublicSchema || p.CanGrantStatistics {
		t.Fatal("limited role prerequisite check", p, err)
	}
	exec("ALTER ROLE wh_probe_readonly CONNECTION LIMIT 0")
	checkStage(limited, password, DeploymentConnectionLimit)
	exec("ALTER ROLE wormhole_test_admin SET log_statement='ddl'; ALTER ROLE wormhole_test_admin SET log_parameter_max_length=0; ALTER ROLE wormhole_test_admin SET log_parameter_max_length_on_error=0")
	p, err = CheckDeploymentPrerequisites(ctx, s, password)
	if err != nil || !p.LogsStatements || p.LogsParameters {
		t.Fatal("parameter/statement logging diagnosis", p, err)
	}
	if _, err := CheckSchemaDeployment(ctx, s, password, "testscope", testHintID); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("preflight changed schema", err)
	}
	for _, pair := range [][2]string{
		{"CREATE TABLE public.existing(id integer)", "DROP TABLE public.existing"},
		{"CREATE FUNCTION public.existing() RETURNS integer LANGUAGE sql AS 'SELECT 1'", "DROP FUNCTION public.existing()"},
		{"CREATE TYPE public.existing AS ENUM ('a')", "DROP TYPE public.existing"},
		{"CREATE SCHEMA app_example", "DROP SCHEMA app_example"},
	} {
		exec(pair[0])
		p, err = CheckDeploymentPrerequisites(ctx, s, password)
		if err != nil || p.EmptyDatabase || p.ReadyToDeploy() {
			t.Fatal("preflight accepted nonempty database", p, err)
		}
		exec(pair[1])
	}
	exec("ALTER ROLE wormhole_test_admin SET default_transaction_read_only=on")
	checkStage(s, password, DeploymentReadWrite)
}
