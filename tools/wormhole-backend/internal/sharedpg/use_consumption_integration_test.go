package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testPostgresUseConsumption(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, node uuid.UUID) {
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
			t.Fatal("consumption state", r.Err)
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
	migration, _ := deploy.UseConsumptionMigration("testscope", testHintID)
	wrong, _ := deploy.UseConsumptionMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.claim_use(bytea,uuid,uuid) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=20 AND to_regclass('wormhole_data.use_counter_1') IS NULL AND to_regclass('wormhole_data.use_counter_slots') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.claim_use(bytea,uuid,uuid)")
	script(migration)
	reject(migration, "55000")
	check("SELECT (count(*)=1024)::text FROM wormhole_data.use_counter_slots")
	check("SELECT (count(*)=0)::text FROM wormhole_data.use_tickets")
	check("SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_data.claim_use(bytea,uuid,uuid)','EXECUTE') AND NOT has_table_privilege('wh_testscope_user','wormhole_data.use_counter_slots','SELECT,UPDATE') AND NOT has_sequence_privilege('wh_testscope_user','wormhole_data.use_counter_1','USAGE,SELECT,UPDATE'))::text")
	// Test-only stand-in for the future ciphertext release API; it returns no secrets.
	script("CREATE FUNCTION wormhole_api_v1.test_claim(p bytea,n uuid,t uuid) RETURNS TABLE(epoch bigint,change_seq bigint) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT * FROM wormhole_data.claim_use(p,n,t)'; REVOKE ALL ON FUNCTION wormhole_api_v1.test_claim(bytea,uuid,uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION wormhole_api_v1.test_claim(bytea,uuid,uuid) TO wh_testscope_user")
	var capability []byte
	if err := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	command := func(sql string) {
		t.Helper()
		rows, err := native.Query(ctx, sql, nil)
		wipeQueryRows(rows)
		if err != nil {
			t.Fatal(err)
		}
	}
	claim := func(id, ticket uuid.UUID) error {
		rows, err := native.Query(ctx, "SELECT * FROM wormhole_api_v1.test_claim(decode($1,'hex'),$2::uuid,$3::uuid)", [][]byte{capability, []byte(id.String()), []byte(ticket.String())})
		wipeQueryRows(rows)
		return err
	}
	begin := func() *UseIntent {
		t.Helper()
		r, err := native.BeginUse(ctx, node, "ui")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, mode := range []string{"commit", "rollback", "savepoint"} {
		ticket := begin()
		if mode != "commit" {
			command("BEGIN")
		}
		if mode == "savepoint" {
			command("SAVEPOINT consumed")
		}
		if err := claim(node, ticket.Ticket); err != nil {
			t.Fatal("first claim", mode, err)
		}
		if mode == "commit" {
			check("SELECT (count(*)=0)::text FROM wormhole_data.use_counter_slots WHERE expires_at>clock_timestamp()")
		}
		if mode == "rollback" {
			command("ROLLBACK")
		}
		if mode == "savepoint" {
			command("ROLLBACK TO SAVEPOINT consumed")
			command("COMMIT")
		}
		if err := claim(node, ticket.Ticket); err != ErrUseTicket {
			t.Fatal("replay after "+mode, err)
		}
	}
	ticket := begin()
	command("BEGIN")
	if err := claim(node, ticket.Ticket); err != nil {
		t.Fatal(err)
	}
	script("SET SESSION AUTHORIZATION \"wh_testscope_d_" + testHintID + "\"")
	locked := admin.ExecParams(ctx, "SELECT * FROM wormhole_api_v1.test_claim(decode($1,'hex'),$2::uuid,$3::uuid)", [][]byte{capability, []byte(node.String()), []byte(ticket.Ticket.String())}, nil, nil, nil).Read()
	var lockError *pgconn.PgError
	if !errors.As(locked.Err, &lockError) || lockError.Code != "55P03" {
		t.Fatal("concurrent consumption", locked.Err)
	}
	script("RESET SESSION AUTHORIZATION")
	command("ROLLBACK")
	if err := claim(node, ticket.Ticket); err != ErrUseTicket {
		t.Fatal("concurrent rollback replay", err)
	}
	ticket = begin()
	if err := claim(uuid.New(), ticket.Ticket); err != ErrUseTicket {
		t.Fatal("wrong node", err)
	}
	if err := claim(node, uuid.New()); err != ErrUseTicket {
		t.Fatal("wrong ticket", err)
	}
	if err := claim(node, ticket.Ticket); err != nil {
		t.Fatal("invalid request burned legitimate ticket", err)
	}
	for _, mode := range []string{"expired", "restart", "snapshot", "slot-reassigned"} {
		ticket := begin()
		switch mode {
		case "expired":
			script("UPDATE wormhole_data.use_tickets SET issued_at=issued_at-interval '31 seconds',expires_at=expires_at-interval '31 seconds'")
		case "restart":
			script("UPDATE wormhole_data.use_tickets SET server_started_at=server_started_at-interval '1 second'")
		case "snapshot":
			script("UPDATE wormhole_data.nodes SET name=name")
		case "slot-reassigned":
			script("UPDATE wormhole_data.use_counter_slots SET device_id=NULL")
		}
		if err := claim(node, ticket.Ticket); err != ErrUseTicket {
			t.Fatal(mode, err)
		}
	}
	// Issuance inside the caller's transaction is not a committed audit barrier.
	command("BEGIN")
	rows, err := native.Query(ctx, beginUseSQL, [][]byte{capability, []byte(node.String()), []byte("ui")})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := parseUseIntent(rows, native.admission, node)
	wipeQueryRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim(node, pending.Ticket); err != ErrUseTicket {
		t.Fatal("uncommitted intent", err)
	}
	command("ROLLBACK")
	script("UPDATE wormhole_data.use_counter_slots SET device_id=NULL,expires_at=clock_timestamp()+interval '1 minute'")
	rows, err = native.Query(ctx, beginUseSQL, [][]byte{capability, []byte(node.String()), []byte("ui")})
	wipeQueryRows(rows)
	if err != ErrChangeInProgress {
		t.Fatal("pool exhaustion", err)
	}
	script("UPDATE wormhole_data.use_counter_slots SET expires_at='-infinity'")
	ticket = begin()
	if err := claim(node, ticket.Ticket); err != nil {
		t.Fatal("pool recovery", err)
	}
}

// Crashes only the disposable cluster created by postgresTestCluster. Called last
// because all existing test connections are intentionally invalid after restart.
func testPostgresUseRestart(t *testing.T, ctx context.Context, admin *pgconn.PgConn, config Settings, login, material []byte, node uuid.UUID) {
	t.Helper()
	native := NewSession()
	defer native.Close(context.Background())
	if err := native.Open(ctx, config, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := native.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	ticket, err := native.BeginUse(ctx, node, "ui")
	if err != nil {
		t.Fatal(err)
	}
	var capability []byte
	if err := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	query := "SELECT * FROM wormhole_api_v1.test_claim(decode($1,'hex'),$2::uuid,$3::uuid)"
	args := [][]byte{capability, []byte(node.String()), []byte(ticket.Ticket.String())}
	if _, err := native.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	rows, err := native.Query(ctx, query, args)
	wipeQueryRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	r := admin.ExecParams(ctx, "SHOW data_directory", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		t.Fatal("test cluster location", r.Err)
	}
	data := filepath.Clean(string(r.Rows[0][0]))
	scratch := os.Getenv("WORMHOLE_TEST_POSTGRES_SCRATCH")
	rel, err := filepath.Rel(scratch, data)
	if err != nil || !filepath.IsAbs(data) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.Base(data) != "data" || !strings.HasPrefix(filepath.Base(filepath.Dir(data)), "postgres-integration-") {
		t.Fatal("restart target outside disposable test cluster")
	}
	tool := "pg_ctl"
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	tool = filepath.Join(os.Getenv("WORMHOLE_TEST_POSTGRES_BIN"), tool)
	run := func(args ...string) {
		t.Helper()
		operation, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(operation, tool, args...)
		hidePostgresTestProcess(cmd)
		cmd.WaitDelay = 5 * time.Second
		if err := cmd.Run(); err != nil {
			t.Fatal("disposable PostgreSQL restart", err)
		}
	}
	run("-D", data, "-m", "immediate", "-w", "-t", "30", "stop")
	run("-D", data, "-l", filepath.Join(filepath.Dir(data), "server.log"), "-w", "-t", "30", "start")
	if ticket.ExpiresAt <= time.Now().Unix() {
		t.Fatal("restart test exceeded ticket lifetime")
	}
	fresh := NewSession()
	defer fresh.Close(context.Background())
	if err := fresh.Open(ctx, config, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	rows, err = fresh.Query(ctx, query, args)
	wipeQueryRows(rows)
	if err != ErrUseTicket {
		t.Fatal("consumed uncommitted ticket replayed after crash", err)
	}
	if _, err := fresh.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	next, err := fresh.BeginUse(ctx, node, "ui")
	if err != nil {
		t.Fatal("fresh post-restart ticket", err)
	}
	vault.Wipe(capability)
	if err := fresh.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	rows, err = fresh.Query(ctx, query, [][]byte{capability, []byte(node.String()), []byte(next.Ticket.String())})
	wipeQueryRows(rows)
	if err != nil {
		t.Fatal("post-restart consumption", err)
	}
}
