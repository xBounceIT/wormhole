package localvault

import (
	"context"
	"errors"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestBitwardenCleanupRetainsJournalUntilAcknowledged(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	values := []BitwardenInstallation{installationFixture(), installationFixture(), installationFixture()}
	for i := range values {
		values[i].Layout = 1
		if _, err := o.SaveBitwardenInstallation(ctx, values[i], uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	failed := errors.New("synthetic failed removal")
	calls := 0
	_, err := o.CleanupBitwardenInstallations(ctx, 3, func(_ context.Context, id string) error {
		if o.mu.TryLock() {
			o.mu.Unlock()
			t.Fatal("cleanup lost owner exclusion")
		}
		if id != values[calls].InstallationID {
			t.Fatal("unexpected cleanup target", id)
		}
		calls++
		if calls == 2 {
			return failed
		}
		return nil
	})
	if !errors.Is(err, failed) || calls != 2 {
		t.Fatal(calls, err)
	}
	r, revision, err := o.readBitwardenInstallationRecord(ctx, 3)
	if err != nil || revision != 3 || len(r.Retired) != 2 || r.Installation != values[2] {
		t.Fatal(r, revision, err)
	}
	// Retry includes the already removed first ID: the native remover is idempotent.
	calls = 0
	next, err := o.CleanupBitwardenInstallations(ctx, 3, func(_ context.Context, id string) error {
		if id != values[calls].InstallationID {
			t.Fatal(id)
		}
		calls++
		return nil
	})
	if err != nil || next != 4 || calls != 2 {
		t.Fatal(next, calls, err)
	}
	r, revision, err = o.readBitwardenInstallationRecord(ctx, 4)
	if err != nil || revision != 4 || r.Version != 2 || len(r.Retired) != 0 || r.Installation != values[2] {
		t.Fatal(r, revision, err)
	}
	called := false
	if _, err = o.CleanupBitwardenInstallations(ctx, 3, func(context.Context, string) error { called = true; return nil }); !errors.Is(err, vaultstore.ErrConflict) || called {
		t.Fatal(err, called)
	}
	if _, err = o.CleanupBitwardenInstallations(ctx, 4, nil); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	o.bitwardenTransfers = map[string]*bitwardenTransferStage{"pending": {}}
	if _, err = o.CleanupBitwardenInstallations(ctx, 4, func(context.Context, string) error { called = true; return nil }); !errors.Is(err, vault.ErrPolicy) || called {
		t.Fatal(err, called)
	}
	o.bitwardenTransfers = nil
	profileID := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	browserRead(t, o, profileID)
	if _, err = o.CleanupBitwardenInstallations(ctx, 4, func(context.Context, string) error { called = true; return nil }); !errors.Is(err, vault.ErrPolicy) || called {
		t.Fatal(err, called)
	}
	if err = o.CloseBitwardenBrowserProfile(profileID); err != nil {
		t.Fatal(err)
	}
	if next, err = o.CleanupBitwardenInstallations(ctx, 4, func(context.Context, string) error { called = true; return nil }); err != nil || next != 5 || called {
		t.Fatal(next, err, called)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.CleanupBitwardenInstallations(ctx, 5, func(context.Context, string) error { called = true; return nil }); err == nil || called {
		t.Fatal(err, called)
	}
}

func TestBitwardenCleanupCancellationPreservesJournal(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	for i := range 3 {
		value := installationFixture()
		value.Layout = 1
		if _, err := o.SaveBitwardenInstallation(ctx, value, uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, cancelAfterFirst := range []bool{false, true} {
		canceled, cancel := context.WithCancel(ctx)
		calls := 0
		if !cancelAfterFirst {
			cancel()
		}
		_, err := o.CleanupBitwardenInstallations(canceled, 3, func(context.Context, string) error { calls++; cancel(); return nil })
		cancel()
		if !errors.Is(err, context.Canceled) || calls > 1 {
			t.Fatal(calls, err)
		}
		r, revision, err := o.readBitwardenInstallationRecord(ctx, 3)
		if err != nil || revision != 3 || len(r.Retired) != 2 {
			t.Fatal(r, revision, err)
		}
	}
}

func TestBitwardenCleanupCancellationAfterLastRemoval(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	for i := range 2 {
		value := installationFixture()
		value.Layout = 1
		if _, err := o.SaveBitwardenInstallation(ctx, value, uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	defer cancel()
	_, err := o.CleanupBitwardenInstallations(canceled, 2, func(context.Context, string) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, revision, err := o.readBitwardenInstallationRecord(ctx, 2)
	if err != nil || revision != 2 || len(r.Retired) != 1 {
		t.Fatal(r, revision, err)
	}
}
