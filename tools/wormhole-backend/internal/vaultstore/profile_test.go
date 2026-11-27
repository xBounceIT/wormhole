package vaultstore

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestProfileSeedUpdateCASAndReopen(t *testing.T) {
	s, path := database(t)
	ctx := context.Background()
	first, second := []byte("first-authenticated-document"), []byte("second-authenticated-document")
	if _, err := s.ReadProfile(ctx); err != ErrMissing {
		t.Fatal(err)
	}
	if err := s.SeedProfile(ctx, first); err != nil {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
	if err := s.ValidateInitialization(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedProfile(ctx, first); err != ErrConflict {
		t.Fatal("seed overwrote policy", err)
	}
	if err := s.WriteProfile(ctx, second, nil); err != ErrConflict {
		t.Fatal(err)
	}
	if err := s.WriteProfile(ctx, second, first); err != nil {
		t.Fatal(err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal("policy edit still pristine", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		wg.Go(func() { results <- s.WriteProfile(ctx, []byte("third"), second) })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if err != ErrConflict {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("CAS", successes)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, path, s.Identity(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ReadProfile(ctx)
	if err != nil || string(got) != "third" {
		t.Fatal(err)
	}
	if _, err := s.ReadProfile(ctx); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteProfile(ctx, second, first); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestProfileRejectsMalformedStorageBoundsAndCancellation(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	for _, value := range []any{"text", []byte{}, bytes.Repeat([]byte{1}, vault.MaxLocalPolicyBytes+1)} {
		exec(t, s, "UPDATE WorkspaceMeta SET SignedProfile=?", value)
		if raw, err := s.ReadProfile(ctx); err != ErrFormat || raw != nil {
			t.Fatal("invalid storage escaped", err)
		}
	}
	for _, inputs := range [][2][]byte{{nil, nil}, {[]byte{}, nil}, {bytes.Repeat([]byte{1}, vault.MaxLocalPolicyBytes+1), nil}, {[]byte("next"), []byte{}}, {[]byte("next"), bytes.Repeat([]byte{1}, vault.MaxLocalPolicyBytes+1)}} {
		if err := s.WriteProfile(ctx, inputs[0], inputs[1]); err != ErrFormat {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ReadProfile(canceled); err != context.Canceled {
		t.Fatal(err)
	}
	if err := s.WriteProfile(canceled, []byte("next"), nil); err != context.Canceled {
		t.Fatal(err)
	}
	exec(t, s, "DROP TABLE WorkspaceMeta")
	if _, err := s.ReadProfile(ctx); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.WriteProfile(ctx, []byte("next"), nil); err != ErrStorage {
		t.Fatal(err)
	}
	if err := s.SeedProfile(ctx, []byte("next")); err != ErrStorage {
		t.Fatal(err)
	}
}

func TestProfileWritesRollbackOnTriggersAndCannotSeedAfterDomainWrites(t *testing.T) {
	ctx := context.Background()
	for _, trigger := range []string{
		`CREATE TRIGGER fail BEFORE UPDATE OF SignedProfile ON WorkspaceMeta BEGIN SELECT RAISE(IGNORE); END`,
		`CREATE TRIGGER fail AFTER UPDATE OF SignedProfile ON WorkspaceMeta BEGIN UPDATE WorkspaceMeta SET SignedProfile=CAST(NEW.SignedProfile AS TEXT); END`,
		`CREATE TRIGGER fail AFTER UPDATE OF SignedProfile ON WorkspaceMeta BEGIN UPDATE WorkspaceMeta SET SignedProfile=zeroblob(17000); END`,
		`CREATE TRIGGER fail BEFORE UPDATE OF ChangeSeq ON WorkspaceMeta BEGIN SELECT RAISE(ABORT,'private'); END`,
		`CREATE TRIGGER fail AFTER UPDATE OF ChangeSeq ON WorkspaceMeta BEGIN UPDATE WorkspaceMeta SET SignedProfile=x'00'; END`,
	} {
		s, _ := database(t)
		first := []byte("first")
		if err := s.SeedProfile(ctx, first); err != nil {
			t.Fatal(err)
		}
		exec(t, s, trigger)
		if err := s.WriteProfile(ctx, []byte("next"), first); err == nil {
			t.Fatal("fault succeeded")
		}
		got, err := s.ReadProfile(ctx)
		if err != nil || !bytes.Equal(got, first) {
			t.Fatal("partial policy write", err)
		}
		count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
	}
	s, _ := database(t)
	if err := s.WriteSecret(ctx, record(s), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedProfile(ctx, []byte("seed")); err != ErrConflict {
		t.Fatal("seed after user writes", err)
	}
	if _, err := s.ReadProfile(ctx); err != ErrMissing {
		t.Fatal(err)
	}
}
