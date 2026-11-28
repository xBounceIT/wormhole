package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedTLSRetentionPreservesCurrentAndIncoming(t *testing.T) {
	c, _, o, root, _, _, org := sharedPasswordFixture(t)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	base, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := sharedTLSFixture(t, &o, base, org, 1)
	current, err := acceptSharedTLSBundle(o, root, base)
	if err != nil {
		t.Fatal(err)
	}
	orphan := sharedTLSFixture(t, &o, base, org, 2)
	if err := writeSharedTLSCache(o.TrustPath, orphan); err != nil {
		t.Fatal(err)
	}
	third := sharedTLSFixture(t, &o, base, org, 3)
	next, err := acceptSharedTLSBundle(o, root, current)
	if err != nil {
		t.Fatal(err)
	}
	firstPath, _ := sharedTLSCachePath(o.TrustPath, first.Pin().Digest)
	orphanPath, _ := sharedTLSCachePath(o.TrustPath, orphan.Pin().Digest)
	if _, err := os.Stat(firstPath); err != nil {
		t.Fatal("previous committed snapshot deleted before publication", err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan retained", err)
	}
	if _, err := readSharedTLSCache(o.TrustPath, next); err != nil {
		t.Fatal("incoming deleted", err)
	}
	if _, err := acceptSharedTLSBundle(o, root, next); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired snapshot retained", err)
	}
	// Subsequent rotations remain bounded without losing the active snapshot.
	for seq := uint64(4); seq < 8; seq++ {
		sharedTLSFixture(t, &o, base, org, seq)
		next, err = acceptSharedTLSBundle(o, root, next)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(o.TrustPath + ".tls")
		if err != nil || len(entries) != 2 {
			t.Fatal("rotation accumulation", err, len(entries))
		}
	}
	// A stale controller cannot delete cache state based on an older reference.
	o.Settings.TLSBundle = third
	if err := publishSharedTLSCache(o.TrustPath, third, func() error { return pruneSharedTLSCacheLocked(o, root, current, third.Pin().Digest) }, nil); err != errSharedTrustConflict {
		t.Fatal("stale retention", err)
	}
	if err := publishSharedTLSCache(o.TrustPath, third, func() error {
		return pruneSharedTLSCacheLocked(o, bytes.Repeat([]byte{1}, 32), next, third.Pin().Digest)
	}, nil); err == nil {
		t.Fatal("wrong root retention")
	}
	// An uncertain password transition disables pruning, retaining all snapshots.
	if _, err := stageSharedTrustRootTransition(o.TrustPath, root, bytes.Repeat([]byte{99}, 32), o.Binding, next.Revision); err != nil {
		t.Fatal(err)
	}
	if err := publishSharedTLSCache(o.TrustPath, third, func() error { return pruneSharedTLSCacheLocked(o, root, next, third.Pin().Digest) }, nil); err != errSharedTrustTransitionPending {
		t.Fatal("pruned pending recovery", err)
	}
	if _, err := readSharedTLSCache(o.TrustPath, next); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTLSRetentionLeavesUnownedAndInvalidEntries(t *testing.T) {
	c, _, o, root, _, _, org := sharedPasswordFixture(t)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	base, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := sharedTLSFixture(t, &o, base, org, 1)
	current, err := acceptSharedTLSBundle(o, root, base)
	if err != nil {
		t.Fatal(err)
	}
	other, _, foreignOptions, foreignRoot, _, _, foreignOrg := sharedPasswordFixture(t)
	if err := other.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreignState, err := readSharedTrustFile(foreignOptions.TrustPath, foreignRoot, foreignOptions.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreign := sharedTLSFixture(t, &foreignOptions, foreignState, foreignOrg, 2)
	if err := writeSharedTLSCache(o.TrustPath, foreign); err != nil {
		t.Fatal(err)
	}
	malformed := []byte("not a bundle")
	digest := sha256.Sum256(malformed)
	invalidName := hex.EncodeToString(digest[:]) + ".json"
	directory := o.TrustPath + ".tls"
	for name, raw := range map[string][]byte{"notes.txt": []byte("unrelated"), invalidName: malformed, string(bytes.Repeat([]byte{'0'}, 64)) + ".json": v.Encode(), string(bytes.Repeat([]byte{'A'}, 64)) + ".json": nil} {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	child := filepath.Join(directory, string(bytes.Repeat([]byte{'b'}, 64))+".json")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptSharedTLSBundle(o, root, current); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(directory)
	if err != nil || len(before) != len(after) {
		t.Fatal("deleted unrelated content", err)
	}
	// Failed deletion durability must not publish a newer protected floor.
	orphan := sharedTLSFixture(t, &o, base, org, 2)
	if err := writeSharedTLSCache(o.TrustPath, orphan); err != nil {
		t.Fatal(err)
	}
	sharedTLSFixture(t, &o, base, org, 3)
	original := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = original })
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	if _, err := acceptSharedTLSBundle(o, root, current); err != errSharedTrustStorage {
		t.Fatal("unconfirmed cleanup", err)
	}
	saved, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil || saved.TLSSequence != 1 {
		t.Fatal("floor advanced after cleanup failure", err)
	}
}

func TestSharedTLSCacheLockSpansProtectedPublication(t *testing.T) {
	c, _, o, root, _, _, org := sharedPasswordFixture(t)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := sharedTLSFixture(t, &o, state, org, 1)
	marker := errors.New("commit failed")
	err = publishSharedTLSCache(o.TrustPath, v, nil, func() error {
		if err := writeSharedTLSCache(o.TrustPath, v); err != errSharedTrustConflict {
			t.Fatal("cache lock released before commit", err)
		}
		return marker
	})
	if !errors.Is(err, marker) {
		t.Fatal("commit error lost", err)
	}
	if err := writeSharedTLSCache(o.TrustPath, v); err != nil {
		t.Fatal("lock leaked", err)
	}
	if err := publishSharedTLSCache(o.TrustPath, v, func() error { return marker }, func() error { t.Fatal("commit after preflight failure"); return nil }); !errors.Is(err, marker) {
		t.Fatal(err)
	}
	if err := pruneSharedTLSCacheLocked(o, root, state, nil); err == nil {
		t.Fatal("bad digest")
	}
}
