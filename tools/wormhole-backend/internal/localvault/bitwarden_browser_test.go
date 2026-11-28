package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type browserTestSnapshot struct {
	revision, profile uint64
	restore           bool
	local, session    string
}

func browserBorrow(t *testing.T, run func(func(BitwardenBrowserSnapshot) error) error) browserTestSnapshot {
	t.Helper()
	var got browserTestSnapshot
	var borrowed [][]byte
	if err := run(func(s BitwardenBrowserSnapshot) error {
		got = browserTestSnapshot{s.Revision, s.ProfileRevision, s.Restore, string(s.LocalJSON), string(s.SessionJSON)}
		borrowed = [][]byte{s.LocalJSON, s.SessionJSON}
		if _, err := json.Marshal(s); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal("snapshot can cross ordinary IPC", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, b := range borrowed {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("borrow retained plaintext")
		}
	}
	return got
}
func browserRead(t *testing.T, o *Owner, id string) browserTestSnapshot {
	t.Helper()
	got := browserBorrow(t, func(use func(BitwardenBrowserSnapshot) error) error {
		return o.ReadBitwardenBrowserState(context.Background(), id, []byte("{}"), []byte("{}"), use)
	})
	browserCapture(t, o, id, got.profile, got.local, got.session)
	return got
}
func browserCapture(t *testing.T, o *Owner, id string, revision uint64, local, session string) browserTestSnapshot {
	t.Helper()
	a, b := []byte(local), []byte(session)
	result := browserBorrow(t, func(use func(BitwardenBrowserSnapshot) error) error {
		return o.CaptureBitwardenBrowserState(context.Background(), id, revision, a, b, use)
	})
	if result.profile != result.revision {
		t.Fatal("successful capture reported an obsolete merge-base revision")
	}
	for _, raw := range [][]byte{a, b} {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("capture retained plaintext")
		}
	}
	return result
}
func TestBitwardenBrowserNativeEncryptedLifecycle(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	id := uuid.NewString()
	o.CloseBitwardenBrowserProfile(uuid.NewString())
	first := browserRead(t, o, id)
	if first.revision != 0 || first.local != "{}" || first.session != "{}" {
		t.Fatal(first)
	}
	saved := browserCapture(t, o, id, 0, `{"account":"vault-browser-saved-token"}`, `{"unlock":"runtime-browser-secret"}`)
	if saved.revision != 1 || saved.restore {
		t.Fatal(saved)
	}
	same := browserCapture(t, o, id, 1, `{ "account" : "vault-browser-saved-token" }`, `{ "unlock" : "runtime-browser-secret" }`)
	if same.revision != 1 {
		t.Fatal(same)
	}
	metadata, err := o.ReadLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 1)
	if err != nil || metadata.RowVersion != 1 {
		t.Fatal(metadata, err)
	}
	if err := o.WithLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 1, func(raw []byte) error {
		if bytes.Contains(raw, []byte("runtime-browser-secret")) || bytes.Contains(raw, []byte("Session")) {
			t.Fatal("session persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cache := o.bitwarden.Profiles[id]
	global := o.bitwarden.Session
	if bytes.Contains(cache.Local.Chunks[0].Ciphertext, []byte("vault-browser-saved-token")) || bytes.Contains(global.Chunks[0].Ciphertext, []byte("runtime-browser-secret")) {
		t.Fatal("plaintext runtime cache")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if o.bitwarden != nil {
		t.Fatal("runtime owner survived close")
	}
	for _, state := range []browserSealedState{cache.Local, cache.Session, global} {
		for _, chunk := range state.Chunks {
			if !bytes.Equal(chunk.Ciphertext, make([]byte, len(chunk.Ciphertext))) {
				t.Fatal("retired cache retained")
			}
		}
	}
	database, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"vault-browser-saved-token", "runtime-browser-secret"} {
		if bytes.Contains(database, []byte(secret)) {
			t.Fatal("plaintext on disk")
		}
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	cold := browserRead(t, reopened, uuid.NewString())
	if cold.revision != 1 || cold.local != saved.local || cold.session != "{}" {
		t.Fatal(cold)
	}
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}
func TestBitwardenBrowserNativeMergeRefreshAndLogout(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := uuid.NewString(), uuid.NewString()
	browserRead(t, o, a)
	browserCapture(t, o, a, 0, `{"account":"old","setting":1}`, `{"key":"old"}`)
	browserRead(t, o, b)
	browserCapture(t, o, a, 1, `{"account":"refreshed","setting":1}`, `{"key":"fresh"}`)
	stale := browserCapture(t, o, b, 1, `{"account":"old","setting":2}`, `{"key":"old"}`)
	if stale.revision != 3 || stale.local != `{"account":"refreshed","setting":2}` || stale.session != `{"key":"fresh"}` || !stale.restore {
		t.Fatal(stale)
	}
	browserCapture(t, o, b, 3, stale.local, stale.session)
	logout := browserCapture(t, o, b, 3, `{"setting":2}`, `{}`)
	if logout.revision != 4 {
		t.Fatal(logout)
	}
	late := browserCapture(t, o, a, 2, `{"account":"stale-refresh","setting":1}`, `{"key":"stale-key"}`)
	if late.revision != 4 || late.local != `{"setting":2}` || late.session != "{}" || !late.restore {
		t.Fatal(late)
	}
	old := o.bitwarden.Profiles[a]
	o.CloseBitwardenBrowserProfile(a)
	if _, exists := o.bitwarden.Profiles[a]; exists {
		t.Fatal("profile retained")
	}
	for _, chunk := range old.Local.Chunks {
		if !bytes.Equal(chunk.Ciphertext, make([]byte, len(chunk.Ciphertext))) {
			t.Fatal("closed profile retained")
		}
	}
	o.CloseBitwardenBrowserProfile(a)
}
func TestBitwardenBrowserNativeConcurrentProfilesAndCapacity(t *testing.T) {
	o, _, _, _ := owner(t)
	ids := make([]string, 32)
	for i := range ids {
		ids[i] = uuid.NewString()
		browserRead(t, o, ids[i])
	}
	if err := o.ReadBitwardenBrowserState(context.Background(), uuid.NewString(), []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	failures := make(chan error, len(ids))
	for i, id := range ids {
		group.Add(1)
		go func(i int, id string) {
			defer group.Done()
			failures <- o.CaptureBitwardenBrowserState(context.Background(), id, 0, []byte(fmt.Sprintf(`{"key%d":%d}`, i, i)), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil })
		}(i, id)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot := browserRead(t, o, ids[0])
	fields, err := browserObject([]byte(snapshot.local))
	if err != nil || len(fields) != 32 || snapshot.revision != 32 {
		t.Fatal("concurrent edits lost", err, len(fields), snapshot.revision)
	}
	o.CloseBitwardenBrowserProfile(ids[0])
	browserRead(t, o, uuid.NewString())
}
func TestBitwardenBrowserNativeRejectsMalformedAuthorityAndWipes(t *testing.T) {
	o, _, _, _ := owner(t)
	id := uuid.NewString()
	browserRead(t, o, id)
	ctx := context.Background()
	for _, bad := range []string{"", uuid.Nil.String(), strings.ToUpper(id), "not-id"} {
		if err := o.ReadBitwardenBrowserState(ctx, bad, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	cases := []struct {
		id             string
		rev            uint64
		local, session []byte
		use            func(BitwardenBrowserSnapshot) error
	}{
		{id, 0, []byte(`{"x":1,"x":2}`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte(`{"a":1,"\u0061":2}`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte(`{"private":"value",`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte(`{"x":1} {}`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte(`{"x":`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte(`[]`), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte("{}"), []byte(`null`), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte{0xff, '{', '}'}, []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, bytes.Repeat([]byte{'x'}, MaxBitwardenBrowserJSON+1), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{uuid.NewString(), 0, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 1, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, math.MaxUint64, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }},
		{id, 0, []byte("{}"), []byte("{}"), nil},
	}
	for i, q := range cases {
		if err := o.CaptureBitwardenBrowserState(ctx, q.id, q.rev, q.local, q.session, q.use); err == nil {
			t.Fatal("invalid capture accepted", i)
		}
		for _, raw := range [][]byte{q.local, q.session} {
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("failed capture retained", i)
			}
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.ReadBitwardenBrowserState(cancelled, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.CaptureBitwardenBrowserState(cancelled, id, 0, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != context.Canceled {
		t.Fatal(err)
	}
}
func TestBitwardenBrowserNativeDeliveryFailureIsRetryable(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	id := uuid.NewString()
	failed := errors.New("synthetic recipient failure")
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return failed }); err != failed || len(o.bitwarden.Profiles) != 0 {
		t.Fatal(err)
	}
	browserRead(t, o, id)
	if err := o.CaptureBitwardenBrowserState(ctx, id, 0, []byte(`{"account":"saved"}`), []byte(`{"key":"runtime"}`), func(BitwardenBrowserSnapshot) error { return failed }); err != failed {
		t.Fatal(err)
	}
	if o.bitwarden.Profiles[id].Revision != 0 {
		t.Fatal("unacknowledged base advanced")
	}
	other := browserRead(t, o, uuid.NewString())
	if other.revision != 1 || other.session != `{"key":"runtime"}` {
		t.Fatal(other)
	}
	retried := browserCapture(t, o, id, 0, `{"account":"saved"}`, `{"key":"runtime"}`)
	if retried.revision != 1 || retried.restore {
		t.Fatal(retried)
	}
	cancelled, cancel := context.WithCancel(ctx)
	if err := o.ReadBitwardenBrowserState(cancelled, uuid.NewString(), []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { cancel(); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	cancelled, cancel = context.WithCancel(ctx)
	if err := o.CaptureBitwardenBrowserState(cancelled, id, 1, []byte(`{"account":"next"}`), []byte(`{}`), func(BitwardenBrowserSnapshot) error { cancel(); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	if o.bitwarden.Revision != 2 || o.bitwarden.Profiles[id].Revision != 1 {
		t.Fatal("uncertain delivery corrupted ownership")
	}
	browserCapture(t, o, id, 1, `{"account":"next"}`, `{}`)
}
func TestBitwardenBrowserNativeMigratedRecordsAndRollback(t *testing.T) {
	for _, raw := range []string{`{}`, `{"SchemaVersion":2,"Revision":1,"LocalJson":"{}"}`, `{"SchemaVersion":1,"Revision":0,"LocalJson":"{}"}`, `{"SchemaVersion":1,"Revision":1,"LocalJson":"[]"}`, `{"SchemaVersion":1,"Revision":1,"LocalJson":"{}","SessionJSON":"secret"}`, `{"SchemaVersion":1,"Revision":1,"Revision":2,"LocalJson":"{}"}`, `{"SchemaVersion":1,"Revision":9223372036854775808,"LocalJson":"{}"}`, `{"SchemaVersion":1,"Revision":1,"LocalJson":null}`} {
		t.Run(raw, func(t *testing.T) {
			o, _, opts, _ := owner(t)
			if _, err := o.PutLocalState(context.Background(), "bitwarden-browser", opts.Identity.WorkspaceID, []byte(raw), 0); err != nil {
				t.Fatal(err)
			}
			if err := o.ReadBitwardenBrowserState(context.Background(), uuid.NewString(), []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err == nil {
				t.Fatal("invalid migrated record accepted")
			}
		})
	}
	for _, kind := range []string{"logical-regression", "same-revision-redirect", "unexpected-write", "tombstone"} {
		t.Run(kind, func(t *testing.T) {
			o, _, opts, _ := owner(t)
			ctx := context.Background()
			id := uuid.NewString()
			raw := []byte(`{"SchemaVersion":1,"Revision":9,"LocalJson":"{\"account\":\"saved\"}"}`)
			if _, err := o.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, raw, 0); err != nil {
				t.Fatal(err)
			}
			s := browserRead(t, o, id)
			if s.revision != 9 || s.local != `{"account":"saved"}` {
				t.Fatal(s)
			}
			if kind == "tombstone" {
				if _, err := o.DeleteLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				rev, value := 8, "saved"
				if kind == "same-revision-redirect" {
					rev, value = 9, "redirected"
				}
				if kind == "unexpected-write" {
					rev = 10
				}
				replacement, _ := json.Marshal(bitwardenBrowserRecord{1, uint64(rev), fmt.Sprintf(`{"account":%q}`, value)})
				if _, err := o.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, replacement, 1); err != nil {
					t.Fatal(err)
				}
			}
			err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil })
			if kind == "unexpected-write" {
				if err != vaultstore.ErrConflict {
					t.Fatal(err)
				}
			} else if err != vault.ErrRollback {
				t.Fatal(err)
			}
		})
	}
}
func TestBitwardenBrowserNativeCacheBindingsAndTamper(t *testing.T) {
	o, _, opts, _ := owner(t)
	id, other := uuid.NewString(), uuid.NewString()
	browserRead(t, o, id)
	browserCapture(t, o, id, 0, `{"saved":"local"}`, `{"key":"session"}`)
	profile := o.bitwarden.Profiles[id]
	for _, q := range []struct {
		state       browserSealedState
		scope, area string
	}{
		{profile.Local, other, "local-base"}, {profile.Local, id, "session-base"}, {profile.Session, opts.Identity.WorkspaceID, "shared-session"},
	} {
		if _, err := o.openBrowserState(q.state, q.scope, q.area); err == nil {
			t.Fatal("cache substitution accepted")
		}
	}
	for _, state := range []browserSealedState{{Size: 1}, {ID: "bad", Size: 2}, {ID: id, Size: 1}, {ID: id, Size: MaxBitwardenBrowserJSON + 1}, {ID: id, Size: 2}} {
		if _, err := o.openBrowserState(state, id, "local-base"); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	saved := bytes.Clone(profile.Local.Chunks[0].Ciphertext)
	profile.Local.Chunks[0].Ciphertext[0] ^= 1
	if err := o.CaptureBitwardenBrowserState(context.Background(), id, 1, []byte(`{}`), []byte(`{}`), func(BitwardenBrowserSnapshot) error { return nil }); err == nil {
		t.Fatal("cache tamper accepted")
	}
	copy(profile.Local.Chunks[0].Ciphertext, saved)
	vault.Wipe(saved)
	global := o.bitwarden.Session.Chunks[0].Ciphertext
	global[0] ^= 1
	if err := o.ReadBitwardenBrowserState(context.Background(), other, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err == nil {
		t.Fatal("session cache tamper accepted")
	}
	global[0] ^= 1
	browserRead(t, o, other)
}
func TestBitwardenBrowserNativeLargeChunksAndMemoryBudget(t *testing.T) {
	o, _, _, _ := owner(t)
	id := uuid.NewString()
	reserved := uuid.NewString()
	browserRead(t, o, reserved)
	browserRead(t, o, id)
	large := `{"v":"` + strings.Repeat("x", MaxBitwardenBrowserJSON-8) + `"}`
	if len(large) != MaxBitwardenBrowserJSON {
		t.Fatal("bad fixture size")
	}
	got := browserCapture(t, o, id, 0, large, large)
	if got.revision != 1 {
		t.Fatal(got.revision)
	}
	if len(o.bitwarden.Profiles[id].Local.Chunks) != 2 {
		t.Fatal("large snapshot not chunked")
	}
	for i := 0; i < 2; i++ {
		browserRead(t, o, uuid.NewString())
	}
	if o.browserCacheBytes() > maxBitwardenBrowserCache {
		t.Fatal("cache exceeded budget")
	}
	if err := o.ReadBitwardenBrowserState(context.Background(), uuid.NewString(), []byte(large), []byte(large), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.CaptureBitwardenBrowserState(context.Background(), reserved, 0, []byte(large), []byte(large), func(BitwardenBrowserSnapshot) error { t.Fatal("over-budget capture delivered"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if o.bitwarden.Revision != 1 || o.bitwarden.Profiles[reserved].Revision != 0 {
		t.Fatal("over-budget capture mutated state")
	}
	o.CloseBitwardenBrowserProfile(id)
	browserRead(t, o, id)
	if len(o.bitwarden.Profiles) != 4 {
		t.Fatal("capacity did not recover after close")
	}

}

type browserStateProbe struct {
	vaultstore.Store
	local                          vaultstore.LocalStateStore
	policy                         vaultstore.ProfileStore
	missing, corrupt, writeFailure bool
}

func (p *browserStateProbe) ReadProfile(ctx context.Context) ([]byte, error) {
	return p.policy.ReadProfile(ctx)
}
func (p *browserStateProbe) WriteProfile(ctx context.Context, a, b []byte) error {
	return p.policy.WriteProfile(ctx, a, b)
}
func (p *browserStateProbe) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	if p.missing {
		return vaultstore.LocalState{}, vaultstore.ErrMissing
	}
	state, err := p.local.ReadLocalState(ctx, kind, scope)
	if p.corrupt && err == nil {
		state.Seal = bytes.Repeat([]byte{0}, 32)
	}
	return state, err
}
func (p *browserStateProbe) ListLocalStates(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
	return p.local.ListLocalStates(ctx, after, limit)
}
func (p *browserStateProbe) WriteLocalState(ctx context.Context, state vaultstore.LocalState, secrets []vaultstore.Secret, revision uint64) error {
	if p.writeFailure {
		return vaultstore.ErrStorage
	}
	return p.local.WriteLocalState(ctx, state, secrets, revision)
}
func TestBitwardenBrowserNativePersistenceFailureAndPolicyFloor(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	id := uuid.NewString()
	browserRead(t, o, id)
	probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore), writeFailure: true}
	o.store = probe
	err := o.CaptureBitwardenBrowserState(ctx, id, 0, []byte(`{"account":"retry"}`), []byte(`{"key":"memory"}`), func(BitwardenBrowserSnapshot) error { t.Fatal("failed commit acknowledged"); return nil })
	if err != vaultstore.ErrStorage || o.bitwarden.Revision != 0 || o.bitwarden.Profiles[id].Revision != 0 {
		t.Fatal(err)
	}
	probe.writeFailure = false
	browserCapture(t, o, id, 0, `{"account":"retry"}`, `{"key":"memory"}`)
	probe.missing = true
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	probe.missing = false
	probe.corrupt = true
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	probe.corrupt = false
	browserRead(t, o, id)
	policy, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err = o.PutLocalPolicy(ctx, policy.Policy, vault.Standard, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.ReadBitwardenBrowserState(ctx, id, []byte("{}"), []byte("{}"), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrPolicy {
		t.Fatal("insufficient Standard slots accepted", err)
	}
	if err := o.CaptureBitwardenBrowserState(ctx, id, 1, []byte(`{}`), []byte(`{}`), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}
func TestBitwardenBrowserNativeRestartedBackgroundAlwaysHydrates(t *testing.T) {
	o, _, _, _ := owner(t)
	id := uuid.NewString()
	browserRead(t, o, id)
	browserCapture(t, o, id, 0, `{"account":"saved"}`, `{"key":"memory"}`)
	restarted := browserRead(t, o, id)
	if !restarted.restore || restarted.revision != 1 || restarted.profile != 1 || restarted.session != `{"key":"memory"}` {
		t.Fatal("revision marker was mistaken for live background storage")
	}
}
func TestBitwardenBrowserNativeRevisionCeilingAndInputBounds(t *testing.T) {
	o, _, opts, _ := owner(t)
	ctx := context.Background()
	id := uuid.NewString()
	record, _ := json.Marshal(bitwardenBrowserRecord{1, math.MaxInt64, `{}`})
	if _, err := o.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, record, 0); err != nil {
		t.Fatal(err)
	}
	browserRead(t, o, id)
	browserCapture(t, o, id, math.MaxInt64, `{}`, `{}`)
	if err := o.CaptureBitwardenBrowserState(ctx, id, math.MaxInt64, []byte(`{"x":1}`), []byte(`{}`), func(BitwardenBrowserSnapshot) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	values := make(map[string]json.RawMessage, 65537)
	for i := 0; i < 65537; i++ {
		values[fmt.Sprint(i)] = json.RawMessage(`0`)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := browserObject(raw); err != vault.ErrFormat {
		t.Fatal("unbounded key count", err)
	}
	if _, err := encodeBrowserObject(map[string]json.RawMessage{"bad": json.RawMessage("invalid")}); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := encodeBrowserObject(map[string]json.RawMessage{"large": json.RawMessage(`"` + strings.Repeat("x", MaxBitwardenBrowserJSON) + `"`)}); err != vault.ErrFormat {
		t.Fatal(err)
	}
	for _, q := range [][3][]byte{{[]byte(`[]`), []byte(`{}`), []byte(`{}`)}, {[]byte(`{}`), []byte(`[]`), []byte(`{}`)}, {[]byte(`{}`), []byte(`{}`), []byte(`[]`)}} {
		if _, err := mergeBrowserObject(q[0], q[1], q[2]); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	precise, err := mergeBrowserObject([]byte(`{"n":9007199254740992}`), []byte(`{"n":9007199254740993}`), []byte(`{"n":9007199254740992}`))
	if err != nil || string(precise) != `{"n":9007199254740993}` {
		t.Fatal("revision-sized JSON number rounded", err)
	}
	if o.browserCacheBytes() == 0 {
		t.Fatal("fixture empty")
	}
	unused, _, _, _ := owner(t)
	if unused.browserCacheBytes() != 0 {
		t.Fatal("empty cache counted")
	}
}

func TestBitwardenBrowserNativeSessionOnlyUpdatesNeverRewriteDurableAccounts(t *testing.T) {
	o, path, opts, key := owner(t)
	ctx := context.Background()
	id := uuid.NewString()
	browserRead(t, o, id)
	transient := browserCapture(t, o, id, 0, `{}`, `{"key":"ephemeral"}`)
	if transient.revision != 1 || o.bitwarden.StorageRevision != 0 {
		t.Fatal("volatile state created a database record")
	}
	if _, err := o.ReadLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	live := browserRead(t, o, id)
	if live.revision != 1 || live.session != transient.session {
		t.Fatal("volatile state lost without a durable record")
	}
	browserCapture(t, o, id, 1, `{"account":"remembered"}`, `{"key":"ephemeral"}`)
	browserCapture(t, o, id, 2, `{"account":"remembered"}`, `{"key":"refreshed"}`)
	metadata, err := o.ReadLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 1)
	if err != nil || metadata.RowVersion != 1 {
		t.Fatal("session refresh rewrote durable chunks", err)
	}
	still := browserRead(t, o, id)
	if still.revision != 3 || still.session != `{"key":"refreshed"}` {
		t.Fatal(still)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	cold := browserRead(t, reopened, uuid.NewString())
	if cold.revision != 2 || cold.local != still.local || cold.session != "{}" {
		t.Fatal("cold start retained volatile state or lost durable state", cold)
	}
}

func TestBitwardenBrowserNativePartialRestoreCannotResurrectLoggedOutAccounts(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	a, b := uuid.NewString(), uuid.NewString()
	browserRead(t, o, a)
	browserCapture(t, o, a, 0, `{"account":"old-token"}`, `{"key":"old-key"}`)
	browserRead(t, o, b)
	browserCapture(t, o, a, 1, `{}`, `{}`)
	missed := browserCapture(t, o, b, 1, `{"account":"refresh-one"}`, `{"key":"key-one"}`)
	if missed.revision != 2 || missed.local != "{}" || missed.session != "{}" || !missed.restore {
		t.Fatal(missed)
	}
	// A refresh raced the conditional deletion in Chromium, so the requested
	// empty snapshot was never applied. Keep the submitted refresh as the base.
	again := browserCapture(t, o, b, 2, `{"account":"refresh-two"}`, `{"key":"key-two"}`)
	if again.revision != 2 || again.local != "{}" || again.session != "{}" || !again.restore {
		t.Fatal("stale account resurrected", again)
	}
	// Rehydration of a restarted background uses its real capture as witness,
	// even when its revision marker already equals the shared revision.
	hydrated := browserBorrow(t, func(use func(BitwardenBrowserSnapshot) error) error {
		return o.ReadBitwardenBrowserState(ctx, b, []byte(`{"account":"refresh-two"}`), []byte(`{"key":"key-two"}`), use)
	})
	if !hydrated.restore || hydrated.profile != 2 || hydrated.local != "{}" {
		t.Fatal(hydrated)
	}
	last := browserCapture(t, o, b, 2, `{"account":"refresh-three"}`, `{"key":"key-three"}`)
	if last.revision != 2 || last.local != "{}" || last.session != "{}" {
		t.Fatal("restarted stale account resurrected", last)
	}
	applied := browserCapture(t, o, b, 2, `{}`, `{}`)
	if applied.restore {
		t.Fatal(applied)
	}
	// Once this context really holds the logged-out base, a deliberate new login
	// becomes a new change and is accepted rather than suppressed forever.
	login := browserCapture(t, o, b, 2, `{"account":"new-login"}`, `{"key":"new-key"}`)
	if login.revision != 3 || login.restore {
		t.Fatal(login)
	}
}

func TestBitwardenBrowserNativeHydrationConsumesWitnessOnEveryPath(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	id := uuid.NewString()
	for _, q := range [][2]string{{`[]`, `{}`}, {`{}`, `[]`}, {`{"account":"before"}`, `{"key":"before"}`}} {
		local, session := []byte(q[0]), []byte(q[1])
		var borrowed [][]byte
		err := o.ReadBitwardenBrowserState(ctx, id, local, session, func(s BitwardenBrowserSnapshot) error {
			borrowed = [][]byte{s.LocalJSON, s.SessionJSON}
			return errors.New("synthetic delivery failure")
		})
		if err == nil {
			t.Fatal("failed hydration acknowledged")
		}
		for _, raw := range append([][]byte{local, session}, borrowed...) {
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("hydration witness or borrowed state retained")
			}
		}
		if o.bitwarden != nil && len(o.bitwarden.Profiles) != 0 {
			t.Fatal("failed hydration installed a merge base")
		}
	}
}

func TestBitwardenBrowserNativeCacheBudgetIncludesUnacknowledgedBase(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	a, b, c := uuid.NewString(), uuid.NewString(), uuid.NewString()
	large := `{"v":"` + strings.Repeat("x", MaxBitwardenBrowserJSON-8) + `"}`
	browserRead(t, o, a)
	browserCapture(t, o, a, 0, large, large)
	browserRead(t, o, b)
	browserRead(t, o, c)
	// Remove the shared session without rewriting the large persisted local state.
	browserCapture(t, o, a, 1, large, `{}`)
	// Other live contexts still hold stale, large local/session captures. Their
	// hydration response has not applied yet; those actual bases must be retained.
	for _, witness := range [][2]string{{large, large}, {`{"x":"` + strings.Repeat("x", MaxBitwardenBrowserJSON-512*1024) + `"}`, `{}`}} {
		if err := o.ReadBitwardenBrowserState(ctx, uuid.NewString(), []byte(witness[0]), []byte(witness[1]), func(BitwardenBrowserSnapshot) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	before := o.browserCacheBytes()
	if before > maxBitwardenBrowserCache || before < maxBitwardenBrowserCache-1024*1024 {
		t.Fatal("invalid pressure fixture", before)
	}
	// A smaller replacement base would free enough room only after delivery.
	// If its acknowledgement failed, retaining the old base plus this new global
	// session would exceed the budget. Reject before persisting or delivering.
	incoming := `{"w":"` + strings.Repeat("y", MaxBitwardenBrowserJSON-8) + `"}`
	err := o.CaptureBitwardenBrowserState(ctx, b, 1, []byte(`{}`), []byte(incoming), func(BitwardenBrowserSnapshot) error {
		t.Error("unsafe commit delivered")
		return errors.New("synthetic failed acknowledgement")
	})
	if err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if o.bitwarden.Revision != 2 || o.browserCacheBytes() != before || o.bitwarden.Profiles[b].Revision != 1 {
		t.Fatal("failed admission mutated retained state")
	}
}
