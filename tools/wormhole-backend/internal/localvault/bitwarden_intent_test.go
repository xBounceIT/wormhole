package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func intentFixture() BitwardenInstallationIntent {
	return BitwardenInstallationIntent{ID: uuid.NewString(), Namespace: strings.Repeat("a", 64), Phase: "prepared"}
}

func TestBitwardenIntentEncryptedRestartAndReferencedResolution(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	intent := intentFixture()
	if revision, err := o.BeginBitwardenInstallationIntent(ctx, intent); err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intentFixture()); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("lost pending intent", err)
	}
	for i, phase := range []string{"created", "published"} {
		intent.Phase = phase
		if revision, err := o.AdvanceBitwardenInstallationIntent(ctx, intent, uint64(i+1)); err != nil || revision != uint64(i+2) {
			t.Fatal(revision, err)
		}
	}
	if value, revision, err := o.ReadBitwardenInstallation(ctx, 0); err != nil || revision != 0 || value != (BitwardenInstallation{}) {
		t.Fatal("intent changed installation revision", value, revision, err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(intent.ID)) || bytes.Contains(disk, []byte(intent.Namespace)) {
		t.Fatal("intent plaintext")
	}
	opts.Create = false
	o, err = Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	r, version, err := o.readBitwardenIntent(ctx)
	if err != nil || version != 3 || r.Intent == nil || *r.Intent != intent {
		t.Fatal(r, version, err)
	}
	active := installationFixture()
	active.Layout = 1
	active.InstallationID = intent.ID
	if _, err = o.SaveBitwardenInstallation(ctx, active, 0); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []bool{false, true} {
		if retired {
			next := installationFixture()
			next.Layout = 1
			if _, err = o.SaveBitwardenInstallation(ctx, next, 1); err != nil {
				t.Fatal(err)
			}
		}
		failed := errors.New("preserve evidence")
		err = o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, func(_ context.Context, got BitwardenInstallationIntent, referenced bool) error {
			if o.mu.TryLock() {
				o.mu.Unlock()
				t.Fatal("unlocked callback")
			}
			if got != intent || !referenced {
				t.Fatal(got, referenced)
			}
			return failed
		})
		if !errors.Is(err, failed) {
			t.Fatal(err)
		}
	}
	if err = o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, func(_ context.Context, got BitwardenInstallationIntent, referenced bool) error {
		if !referenced {
			t.Fatal("retired unprotected")
		}
		got.Phase = "changed copy"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, version, err = o.readBitwardenIntent(ctx)
	if err != nil || version != 4 || r.Intent != nil {
		t.Fatal(r, version, err)
	}
	if err = o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, func(context.Context, BitwardenInstallationIntent, bool) error { t.Fatal("empty callback"); return nil }); err != nil {
		t.Fatal(err)
	}
	intent = intentFixture()
	intent.InstallationRevision = 2
	if revision, err := o.BeginBitwardenInstallationIntent(ctx, intent); err != nil || revision != 5 {
		t.Fatal(revision, err)
	}
}

func TestBitwardenIntentTransitionsAndCancellation(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	intent := intentFixture()
	bad := intent
	bad.Phase = "created"
	if _, err := o.BeginBitwardenInstallationIntent(ctx, bad); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	o.bitwardenTransfers = map[string]*bitwardenTransferStage{"pending": {}}
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal(err)
	}
	o.bitwardenTransfers = nil
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*BitwardenInstallationIntent){func(v *BitwardenInstallationIntent) { v.ID = uuid.NewString() }, func(v *BitwardenInstallationIntent) { v.Namespace = strings.Repeat("b", 64) }, func(v *BitwardenInstallationIntent) { v.InstallationRevision = 1 }, func(v *BitwardenInstallationIntent) { v.Phase = "published" }} {
		bad = intent
		bad.Phase = "created"
		change(&bad)
		if _, err := o.AdvanceBitwardenInstallationIntent(ctx, bad, 1); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal(bad, err)
		}
	}
	bad = intent
	bad.ID = "bad"
	if _, err := o.AdvanceBitwardenInstallationIntent(ctx, bad, 1); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	bad = intent
	bad.Phase = "created"
	if _, err := o.AdvanceBitwardenInstallationIntent(ctx, bad, 0); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal(err)
	}
	if err := o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, nil); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	callback := func(context.Context, BitwardenInstallationIntent, bool) error {
		t.Fatal("unauthorized callback")
		return nil
	}
	if err := o.ResolveBitwardenInstallationIntent(ctx, strings.Repeat("b", 64), callback); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal(err)
	}
	o.bitwardenTransfers = map[string]*bitwardenTransferStage{"pending": {}}
	if err := o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, callback); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal(err)
	}
	o.bitwardenTransfers = nil
	canceled, cancel := context.WithCancel(ctx)
	err := o.ResolveBitwardenInstallationIntent(canceled, intent.Namespace, func(_ context.Context, got BitwardenInstallationIntent, referenced bool) error {
		if got != intent || referenced {
			t.Fatal(got, referenced)
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, revision, err := o.readBitwardenIntent(ctx)
	if err != nil || revision != 1 || r.Intent == nil {
		t.Fatal(r, revision, err)
	}
	if _, err = o.AdvanceBitwardenInstallationIntent(canceled, bad, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.BeginBitwardenInstallationIntent(ctx, intent); err == nil {
		t.Fatal("closed begin")
	}
	if err = o.ResolveBitwardenInstallationIntent(ctx, intent.Namespace, callback); err == nil {
		t.Fatal("closed resolve")
	}
}

func TestBitwardenIntentMalformedRecordsAndScope(t *testing.T) {
	valid := intentFixture()
	canonical, _ := json.Marshal(bitwardenIntentRecord{1, &valid})
	for _, raw := range [][]byte{[]byte("null"), []byte("{"), []byte(`{"version":2,"intent":null}`), []byte(`{"version":1,"intent":{}}`), bytes.Repeat([]byte("x"), 1025), append(bytes.Clone(canonical), ' ')} {
		o, _, opts, _ := owner(t)
		ctx := context.Background()
		if _, err := o.PutLocalState(ctx, bitwardenIntentKind, opts.Identity.WorkspaceID, raw, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.readBitwardenIntent(ctx); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(err)
		}
		if _, err := o.BeginBitwardenInstallationIntent(ctx, valid); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*BitwardenInstallationIntent){func(v *BitwardenInstallationIntent) { v.ID = uuid.Nil.String() }, func(v *BitwardenInstallationIntent) { v.Namespace = strings.Repeat("A", 64) }, func(v *BitwardenInstallationIntent) { v.Namespace = strings.Repeat("g", 64) }, func(v *BitwardenInstallationIntent) { v.Namespace = "short" }, func(v *BitwardenInstallationIntent) { v.Phase = "unknown" }, func(v *BitwardenInstallationIntent) { v.InstallationRevision = 9223372036854775807 }} {
		bad := valid
		change(&bad)
		if bad.valid() {
			t.Fatal(bad)
		}
	}
	o, _, _, _ := owner(t)
	if _, err := o.PutLocalState(context.Background(), bitwardenIntentKind, uuid.NewString(), canonical, 0); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("foreign intent scope", err)
	}
}

func TestBitwardenIntentRejectsObservedRollbackAndInstallationConflicts(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	active := installationFixture()
	active.Layout = 1
	if _, err := o.SaveBitwardenInstallation(ctx, active, 0); err != nil {
		t.Fatal(err)
	}
	intent := intentFixture()
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("stale installation", err)
	}
	intent.InstallationRevision = 1
	intent.ID = active.InstallationID
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("active ID", err)
	}
	next := installationFixture()
	next.Layout = 1
	if _, err := o.SaveBitwardenInstallation(ctx, next, 1); err != nil {
		t.Fatal(err)
	}
	intent.InstallationRevision = 2
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("retired ID", err)
	}
	intent.ID = uuid.NewString()
	if _, err := o.BeginBitwardenInstallationIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	original := o.store.(*vaultstore.SQLite)
	defer func() { o.store = original }()
	old, err := original.ReadLocalState(ctx, bitwardenIntentKind, opts.Identity.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	intent.Phase = "created"
	if _, err = o.AdvanceBitwardenInstallationIntent(ctx, intent, 1); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{false, true} {
		o.store = installationStoreProbe{SQLite: original, change: func(v vaultstore.LocalState) (vaultstore.LocalState, error) {
			if v.Kind == bitwardenIntentKind {
				if missing {
					return vaultstore.LocalState{}, vaultstore.ErrMissing
				}
				return old, nil
			}
			return v, nil
		}}
		if _, _, err = o.readBitwardenIntent(ctx); !errors.Is(err, vault.ErrRollback) {
			t.Fatal("lost intent floor", err)
		}
	}
	o.store = original
	if _, err = o.DeleteLocalState(ctx, bitwardenIntentKind, opts.Identity.WorkspaceID, 2); err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.readBitwardenIntent(ctx); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("tombstone reset", err)
	}
}
