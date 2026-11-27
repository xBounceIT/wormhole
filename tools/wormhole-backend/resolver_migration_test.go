package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

// A driver can complete BEGIN and then report cancellation. modernc's statement
// finalizer explicitly allows this ordering. Inject it after a real SQLite BEGIN
// to verify cleanup without depending on a scheduler race.
type migrationBeginFaultConnector struct {
	driver    driver.Driver
	path      string
	failQuery string
	closed    int
}

func (c *migrationBeginFaultConnector) Driver() driver.Driver { return c.driver }
func (c *migrationBeginFaultConnector) Connect(context.Context) (driver.Conn, error) {
	connection, err := c.driver.Open(c.path)
	if err != nil {
		return nil, err
	}
	return &migrationBeginFaultConn{Conn: connection, connector: c}, nil
}

type migrationBeginFaultConn struct {
	driver.Conn
	connector *migrationBeginFaultConnector
}

func (c *migrationBeginFaultConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}

func (c *migrationBeginFaultConn) Close() error {
	c.connector.closed++
	return c.Conn.Close()
}

func (c *migrationBeginFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err == nil && query == c.connector.failQuery {
		return nil, context.Canceled
	}
	return result, err
}

func TestResolverMigrationDiscardsAmbiguousBegin(t *testing.T) {
	db, path, _, _ := shadowFixture(t)
	connector := &migrationBeginFaultConnector{driver: db.Driver(), path: path}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	defer db.Close()
	workspace := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
	if err != nil {
		t.Fatal(err)
	}
	connector.failQuery = "BEGIN IMMEDIATE;"
	applied := false
	err = withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil })
	if err != errResolverSnapshot || applied {
		t.Fatal("ambiguous BEGIN applied", err)
	}
	if connector.closed != 1 {
		t.Fatal("ambiguous transaction returned to pool", connector.closed)
	}
	connector.failQuery = ""
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil }); err != nil || !applied {
		t.Fatal("fresh connection could not reserve source", err)
	}
}

func TestResolverMigrationCleansUpPolicyFailures(t *testing.T) {
	for _, test := range []struct {
		query     string
		applied   bool
		wantError bool
		closed    int
	}{
		{"PRAGMA busy_timeout=0;", false, true, 1},
		{"PRAGMA busy_timeout=5000;", true, false, 1},
		{"PRAGMA query_only=ON;", false, true, 0},
		{"PRAGMA query_only=0;", true, true, 1},
	} {
		t.Run(test.query, func(t *testing.T) {
			db, path, _, _ := shadowFixture(t)
			connector := &migrationBeginFaultConnector{driver: db.Driver(), path: path}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = sql.OpenDB(connector)
			db.SetMaxOpenConns(1)
			defer db.Close()
			if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
				t.Fatal(err)
			}
			workspace := uuid.NewString()
			plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
			if err != nil {
				t.Fatal(err)
			}
			connector.failQuery = test.query
			applied := false
			err = withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil })
			if applied != test.applied || (test.wantError && err != errResolverSnapshot) || (!test.wantError && err != nil) {
				t.Fatal("incorrect policy-failure outcome", applied, err)
			}
			if connector.closed != test.closed {
				t.Fatal("incorrect connection retirement", connector.closed)
			}
			connector.failQuery = ""
			if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { return nil }); err != nil {
				t.Fatal("failure leaked source transaction/policy", err)
			}
		})
	}
}

func TestResolverMigrationSourceReservationAndReadOnlyCallback(t *testing.T) {
	db, path, _, _ := shadowFixture(t)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		t.Fatal(err)
	}
	workspace := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
	if err != nil || len(plan.Entries) != 0 {
		t.Fatal(plan, err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`PRAGMA busy_timeout=0;`); err != nil {
		t.Fatal(err)
	}
	applied := false
	err = withLegacyResolverMigration(context.Background(), db, workspace, plan, func(reader resolverCaptureReader, baseline legacyResolverBaseline) error {
		applied = true
		if len(baseline.Snapshots) != 3 || len(baseline.Candidates) != 3 {
			t.Fatal("missing source metadata")
		}
		var username string
		if err := reader.QueryRow(`SELECT Username FROM CredentialProfiles;`).Scan(&username); err != nil || username != "private-user" {
			t.Fatal("provided source reader lost snapshot", err)
		}
		if _, err := other.Exec(`UPDATE CredentialProfiles SET Username='concurrent-user';`); err == nil {
			t.Fatal("source changed while applying migration")
		}
		if err := reader.QueryRow(`UPDATE CredentialProfiles SET Username='callback-write' RETURNING Username;`).Scan(&username); err == nil {
			t.Fatal("callback mutated source")
		}
		return nil
	})
	if err != nil || !applied {
		t.Fatal("valid migration callback rejected", err)
	}
	var queryOnly, timeout int
	if err := db.QueryRow(`PRAGMA query_only;`).Scan(&queryOnly); err != nil || queryOnly != 0 {
		t.Fatal("source query policy not restored", err)
	}
	if err := db.QueryRow(`PRAGMA busy_timeout;`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Fatal("source busy policy not restored", timeout, err)
	}
	if _, err := other.Exec(`UPDATE CredentialProfiles SET Username='concurrent-user';`); err != nil {
		t.Fatal("source reservation leaked", err)
	}
	applied = false
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil }); err != resolver.ErrMigrationStale || applied {
		t.Fatal("stale preview applied", err)
	}
}

func TestResolverMigrationFailureCancellationAndClosedSource(t *testing.T) {
	db, _, _, _ := shadowFixture(t)
	workspace := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("synthetic_destination_failure")
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { return failure }); err != failure {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := withLegacyResolverMigration(ctx, db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { cancel(); return nil }); err != errResolverSnapshot {
		t.Fatal("cancellation reported success", err)
	}
	applied := false
	if err := withLegacyResolverMigration(ctx, db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil }); err != errResolverSnapshot || applied {
		t.Fatal(err)
	}
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, nil); err != resolver.ErrMigration {
		t.Fatal(err)
	}
	if err := withLegacyResolverMigration(context.Background(), nil, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { return nil }); err != resolver.ErrMigration {
		t.Fatal(err)
	}
	if err := withLegacyResolverMigration(context.Background(), db, uuid.NewString(), plan, func(resolverCaptureReader, legacyResolverBaseline) error { return nil }); err != resolver.ErrMigration {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Host='new-route.example';`); err != nil {
		t.Fatal("error/cancel retained source transaction", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := prepareLegacyResolverMigration(context.Background(), db, workspace); err != errResolverSnapshot || !reflect.DeepEqual(got, resolver.MigrationPlan{}) {
		t.Fatal(err)
	}
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { return nil }); err != errResolverSnapshot {
		t.Fatal(err)
	}
}

func TestResolverMigrationBusySourceAndInvalidatedCandidate(t *testing.T) {
	db, path, _, _ := shadowFixture(t)
	workspace := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
	if err != nil {
		t.Fatal(err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	connection, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(context.Background(), `BEGIN IMMEDIATE;`); err != nil {
		t.Fatal(err)
	}
	applied := false
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil }); err != errResolverSnapshot || applied {
		t.Fatal("busy source used", err)
	}
	if _, err := connection.ExecContext(context.Background(), `ROLLBACK;`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Name=?;`, "invalid\nname"); err != nil {
		t.Fatal(err)
	}
	if err := withLegacyResolverMigration(context.Background(), db, workspace, plan, func(resolverCaptureReader, legacyResolverBaseline) error { applied = true; return nil }); err != errResolverSnapshot || applied {
		t.Fatal("invalid candidate applied", err)
	}
}

func TestResolverMigrationDetectsBrokenTransactionBeforeSuccess(t *testing.T) {
	db, _, _, _ := shadowFixture(t)
	workspace := uuid.NewString()
	plan, err := prepareLegacyResolverMigration(context.Background(), db, workspace)
	if err != nil {
		t.Fatal(err)
	}
	// Fault injection: a broken native consumer violates the reader-only contract
	// by ending the source transaction. The wrapper must not report success or
	// recycle a connection whose transaction state no longer matches its guard.
	err = withLegacyResolverMigration(context.Background(), db, workspace, plan, func(reader resolverCaptureReader, _ legacyResolverBaseline) error {
		rows, err := reader.Query(`ROLLBACK;`)
		if err != nil {
			return err
		}
		return rows.Close()
	})
	if err != errResolverSnapshot {
		t.Fatal("lost reservation reported as success", err)
	}
	if got := db.Stats().InUse; got != 0 {
		t.Fatal("connection leaked", got)
	}
}
