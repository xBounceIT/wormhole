package main

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func TestSharedCatalogAnchorRefresh(t *testing.T) {
	f, owner := sharedStartupFixture(t)
	protection := startupTestProtection()
	ctx := context.Background()
	anchor, err := writeSharedStartupAnchor(ctx, f.o, owner, "Catalog", 0, protection)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	oldRaw, err := os.ReadFile(f.o.TrustPath)
	if err != nil {
		t.Fatal(err)
	}
	next := anchor.Trust
	next.Revision++
	next.Catalog = maps.Clone(anchor.Trust.Catalog)
	if len(next.Catalog) == 0 {
		t.Fatal("enrolled account checkpoint missing")
	}
	nodeKey := "node/" + uuid.NewString()
	next.Catalog[nodeKey] = sharedpg.CatalogFloor{Revision: 3, Digest: bytes.Repeat([]byte{1}, 32)}
	dropped := next
	dropped.Catalog = map[string]sharedpg.CatalogFloor{nodeKey: next.Catalog[nodeKey]}
	if err := writeSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, dropped, anchor.Trust.Revision); err != sharedpg.ErrTrustRollback {
		t.Fatal("enrollment checkpoints discarded", err)
	}
	if err := writeSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, next, anchor.Trust.Revision); err != nil {
		t.Fatal(err)
	}
	updated, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection)
	if err != nil || updated.Revision != anchor.Revision+1 || !reflect.DeepEqual(updated.Trust, next) || updated.MinimumSequence != anchor.MinimumSequence {
		t.Fatal("anchor refresh", err)
	}
	read, err := readSharedStartupAnchor(f.o.TrustPath, protection)
	if err != nil || !reflect.DeepEqual(read, updated) {
		t.Fatal("anchor restart", err)
	}
	repeated, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection)
	if err != nil || !reflect.DeepEqual(repeated, updated) {
		t.Fatal("confirmation changed anchor", err)
	}
	if _, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, anchor.Trust, protection); err != errSharedTrustConflict {
		t.Fatal("stale update", err)
	}
	bad := protection
	bad.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("protection failed") }
	if _, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, bad); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := refreshSharedCatalogAnchor(cancelled, f.o.TrustPath, f.root, f.o.Binding, next, protection); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := refreshSharedCatalogAnchor(nil, f.o.TrustPath, f.root, f.o.Binding, next, protection); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(f.o.TrustPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	_, err = refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection)
	release()
	if err != errSharedTrustConflict {
		t.Fatal("parallel writer", err)
	}
	if _, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, bytes.Repeat([]byte{99}, 32), f.o.Binding, next, protection); err == nil {
		t.Fatal("wrong root accepted")
	}
	for _, pending := range []string{sharedTrustTransitionPath(f.o.TrustPath), sharedPendingEnrollmentPath(f.o.TrustPath)} {
		if err := os.WriteFile(pending, []byte("pending"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection); err == nil {
			t.Fatal("pending transition accepted")
		}
		if err := os.Remove(pending); err != nil {
			t.Fatal(err)
		}
	}
	during, cancelDuring := context.WithCancel(ctx)
	defer cancelDuring()
	interrupting := protection
	interrupting.protect = func(path string, raw []byte) ([]byte, error) {
		result, e := protection.protect(path, raw)
		cancelDuring()
		return result, e
	}
	if _, err := refreshSharedCatalogAnchor(during, f.o.TrustPath, f.root, f.o.Binding, next, interrupting); err != context.Canceled {
		t.Fatal("late cancellation", err)
	}
	oldSync := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = oldSync })
	privateFileDirectorySync = func(string) error { return errors.New("directory sync failed") }
	if _, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection); err != errSharedTrustCommitUncertain {
		t.Fatal("uncertain anchor accepted", err)
	}
	privateFileDirectorySync = oldSync
	confirmed, err := refreshSharedCatalogAnchor(ctx, f.o.TrustPath, f.root, f.o.Binding, next, protection)
	if err != nil || confirmed.Revision != updated.Revision {
		t.Fatal("anchor confirmation", err)
	}
	// Replacing only encrypted trust with an older valid file is detected using
	// the independently protected startup revision after process restart.
	if err := os.WriteFile(f.o.TrustPath, oldRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, read.Trust.Revision); err != sharedpg.ErrTrustRollback {
		t.Fatal("trust rollback bypassed anchor", err)
	}
}
