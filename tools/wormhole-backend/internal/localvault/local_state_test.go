package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestLocalStateEncryptedChunksLifecycleAndWipe(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	scope := opts.Identity.WorkspaceID
	payload := bytes.Repeat([]byte("private-browser-state"), vault.MaxSecretBytes/21+1)
	if len(payload) <= vault.MaxSecretBytes {
		t.Fatal("fixture must span two chunks")
	}
	state, err := o.PutLocalState(ctx, "bitwarden-browser", scope, payload, 0)
	if err != nil || state.Size != len(payload) || len(state.Fields) != 2 {
		t.Fatal(state, err)
	}
	if _, err := o.PutLocalState(ctx, "bitwarden-browser", scope, payload, 0); err != vaultstore.ErrConflict {
		t.Fatal("stale insert accepted", err)
	}
	for _, value := range [][]byte{payload, []byte("short"), nil, payload} {
		var err error
		state, err = o.PutLocalState(ctx, state.Kind, scope, value, state.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if state.Fields[1].Present != (len(value) > vault.MaxSecretBytes) {
			t.Fatal("chunk presence lost")
		}
		var borrowed []byte
		if err := o.WithLocalState(ctx, state.Kind, scope, state.RowVersion, func(actual []byte) error {
			if !bytes.Equal(actual, value) {
				t.Fatal("payload changed")
			}
			borrowed = actual
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("callback retained plaintext")
		}
		if !bytes.Equal(payload, bytes.Repeat([]byte("private-browser-state"), vault.MaxSecretBytes/21+1)) {
			t.Fatal("input was modified")
		}
	}
	ref := vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: state.ID, Field: "chunk00"}
	if _, err := o.Put(ctx, ref, []byte("bypass"), state.Fields[0].Version); err != vault.ErrPolicy {
		t.Fatal("raw write bypass", err)
	}
	if err := o.WithSecret(ctx, ref, 0, func([]byte) error { t.Fatal("raw release bypass"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	deleted, err := o.DeleteLocalState(ctx, state.Kind, scope, state.RowVersion)
	if err != nil || !deleted.Deleted {
		t.Fatal(err)
	}
	if err := o.WithLocalState(ctx, state.Kind, scope, 0, func([]byte) error { t.Fatal("deleted release"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if _, err := o.DeleteLocalState(ctx, state.Kind, scope, deleted.RowVersion); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if rows, err := o.ListLocalStates(ctx, "", 128); err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	restored, err := o.PutLocalState(ctx, state.Kind, scope, []byte("restored-state"), deleted.RowVersion)
	if err != nil || restored.ID != state.ID || restored.Fields[0].Version <= state.Fields[0].Version {
		t.Fatal("restore reset identity/version", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("private-browser-state"), []byte("restored-state")} {
		if bytes.Contains(disk, secret) {
			t.Fatal("plaintext persisted")
		}
	}
	opts.Create = false
	opened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	got, err := opened.ReadLocalState(ctx, state.Kind, scope, restored.RowVersion)
	if err != nil || !reflect.DeepEqual(got, restored) {
		t.Fatal("reopen metadata changed", err)
	}
	if err := opened.WithLocalState(ctx, state.Kind, scope, restored.RowVersion, func(v []byte) error {
		if string(v) != "restored-state" {
			t.Fatal("reopen payload changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStateBoundsFailuresAndCancellation(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	scope := opts.Identity.WorkspaceID
	if _, err := o.DeleteLocalState(ctx, "mcp-token", scope, 0); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	for _, args := range []struct{ kind, scope string }{{"unknown", scope}, {"mcp-token", uuid.NewString()}, {"azure-refresh", "invalid"}} {
		if _, err := o.PutLocalState(ctx, args.kind, args.scope, nil, 0); err != vault.ErrFormat {
			t.Fatal(err)
		}
		if _, err := o.ReadLocalState(ctx, args.kind, args.scope, 0); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := o.PutLocalState(ctx, "mcp-token", scope, make([]byte, vaultstore.MaxLocalStateBytes+1), 0); err != vault.ErrFormat {
		t.Fatal("oversized value accepted", err)
	}
	if _, err := o.PutLocalState(ctx, "mcp-token", scope, nil, math.MaxUint64); err != vault.ErrFormat {
		t.Fatal(err)
	}
	state, err := o.PutLocalState(ctx, "mcp-token", scope, []byte("token-fixture"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadLocalState(ctx, state.Kind, scope, 2); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithLocalState(ctx, state.Kind, scope, 2, func([]byte) error { return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithLocalState(ctx, state.Kind, scope, 0, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	failure := errors.New("consumer fixture")
	var borrowed []byte
	if err := o.WithLocalState(ctx, state.Kind, scope, 1, func(v []byte) error { borrowed = v; return failure }); err != failure {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("error retained plaintext")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PutLocalState(canceled, state.Kind, scope, []byte("new"), 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.WithLocalState(canceled, state.Kind, scope, 0, func([]byte) error { t.Fatal("cancelled release"); return nil }); err == nil {
		t.Fatal("cancelled read succeeded")
	}
	if rows, err := o.ListLocalStates(ctx, "", 128); err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if _, err := o.ListLocalStates(ctx, "bad", 1); err != vaultstore.ErrFormat {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadLocalState(ctx, state.Kind, scope, 0); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.PutLocalState(ctx, state.Kind, scope, nil, 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.ListLocalStates(ctx, "", 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

type localStateProbe struct {
	vaultstore.LocalStateStore
	metadata func(vaultstore.LocalState) vaultstore.LocalState
	secret   func(vaultstore.Secret) (vaultstore.Secret, error)
}

func (p localStateProbe) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	v, err := p.LocalStateStore.ReadLocalState(ctx, kind, scope)
	if err == nil && p.metadata != nil {
		v = p.metadata(v)
	}
	return v, err
}
func (p localStateProbe) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	v, err := p.LocalStateStore.ReadSecret(ctx, ref)
	if err == nil && p.secret != nil {
		return p.secret(v)
	}
	return v, err
}

func TestLocalStateTamperingAndPartialReadNeverRelease(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	scope := opts.Identity.WorkspaceID
	state, err := o.PutLocalState(ctx, "bitwarden-browser", scope, bytes.Repeat([]byte{7}, vault.MaxSecretBytes+1), 0)
	if err != nil {
		t.Fatal(err)
	}
	store := o.store.(vaultstore.LocalStateStore)
	for _, change := range []func(vaultstore.LocalState) vaultstore.LocalState{
		func(v vaultstore.LocalState) vaultstore.LocalState { v.Kind = "mcp-token"; return v },
		func(v vaultstore.LocalState) vaultstore.LocalState { v.ScopeID = uuid.NewString(); return v },
		func(v vaultstore.LocalState) vaultstore.LocalState { v.Size--; return v },
		func(v vaultstore.LocalState) vaultstore.LocalState { v.Seal[0] ^= 1; return v },
		func(v vaultstore.LocalState) vaultstore.LocalState { v.Fields = nil; return v },
	} {
		o.store = localStateProbe{LocalStateStore: store, metadata: change}
		if err := o.WithLocalState(ctx, state.Kind, scope, 0, func([]byte) error { t.Fatal("tampered metadata released"); return nil }); err == nil {
			t.Fatal("tampering accepted")
		}
		if _, err := o.PutLocalState(ctx, state.Kind, scope, nil, 1); err == nil {
			t.Fatal("tampered metadata overwritten")
		}
	}
	for _, change := range []func(vaultstore.Secret) (vaultstore.Secret, error){
		func(v vaultstore.Secret) (vaultstore.Secret, error) {
			if v.Ref.Field == "chunk01" {
				v.Envelope.Ciphertext[0] ^= 1
			}
			return v, nil
		},
		func(v vaultstore.Secret) (vaultstore.Secret, error) {
			if v.Ref.Field == "chunk01" {
				return vaultstore.Secret{}, vaultstore.ErrMissing
			}
			return v, nil
		},
	} {
		o.store = localStateProbe{LocalStateStore: store, secret: change}
		if err := o.WithLocalState(ctx, state.Kind, scope, 0, func([]byte) error { t.Fatal("partial state released"); return nil }); err == nil {
			t.Fatal("partial corruption accepted")
		}
	}
	o.store = store
}

func TestLocalStateConcurrentCASAndMaximumPayload(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	scope := opts.Identity.WorkspaceID
	state, err := o.PutLocalState(ctx, "mcp-token", scope, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := o.PutLocalState(ctx, state.Kind, scope, []byte("new token"), 1)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if err == vaultstore.ErrConflict {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal(wins, conflicts)
	}
	large := make([]byte, vaultstore.MaxLocalStateBytes)
	for i := range large {
		large[i] = byte(i % 251)
	}
	maximum, err := o.PutLocalState(ctx, "bitwarden-browser", scope, large, 0)
	if err != nil || len(maximum.Fields) != vaultstore.MaxLocalStateChunks {
		t.Fatal("maximum failed", err)
	}
	if err := o.WithLocalState(ctx, maximum.Kind, scope, 1, func(actual []byte) error {
		if !bytes.Equal(actual, large) {
			t.Fatal("maximum payload changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationSourceInventoryIsWorkspaceScoped(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	scope := opts.Identity.WorkspaceID
	payload := []byte("native-only-source-inventory")
	record, err := o.PutLocalState(ctx, "migration-source-inventory", scope, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WithLocalState(ctx, record.Kind, scope, record.RowVersion, func(actual []byte) error {
		if !bytes.Equal(actual, payload) {
			t.Fatal("inventory changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := uuid.NewString()
	if _, err := o.PutLocalState(ctx, record.Kind, other, payload, 0); err != vault.ErrFormat {
		t.Fatal("cross-workspace inventory accepted", err)
	}
	if err := o.WithLocalState(ctx, record.Kind, other, 0, func([]byte) error { t.Fatal("cross-workspace inventory released"); return nil }); err != vault.ErrFormat {
		t.Fatal(err)
	}
}
