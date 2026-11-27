package localvault

import (
	"context"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

func TestMigrationReportAuthenticatesAndPinsRevision(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, _, plan := nodeMigrationFixture(t, o)
	empty, err := o.ReadResolverMigrationReport(ctx, n.ID, 1)
	if err != nil || empty.Fingerprint != nil || len(empty.Entries) != 0 {
		t.Fatal(err)
	}
	n, err = o.ImportResolverMigration(ctx, n.ID, plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := o.ReadResolverMigrationReport(ctx, n.ID, 2)
	if err != nil || report.Fingerprint == nil || len(report.Entries) != 3 {
		t.Fatal(err)
	}
	if _, err = o.ReadResolverMigrationReport(ctx, n.ID, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	o.store = nodeFilter{completeNodeStore: store, read: func(n vaultstore.Node) (vaultstore.Node, error) { n.Seal = nil; return n, nil }}
	if _, err = o.ReadResolverMigrationReport(ctx, n.ID, 2); err == nil {
		t.Fatal("unverified report")
	}
	o.store = nodeFilter{completeNodeStore: store, secret: func(secret vaultstore.Secret) (vaultstore.Secret, error) {
		secret.Copy.Signature = nil
		return secret, nil
	}}
	if _, err = o.ReadResolverMigrationReport(ctx, n.ID, 2); err == nil {
		t.Fatal("corrupt plan reported as absent")
	}
	o.store = store
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ReadResolverMigrationReport(ctx, n.ID, 2); err == nil {
		t.Fatal("closed report")
	}
}
