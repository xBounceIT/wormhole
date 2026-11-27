package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func options(t *testing.T) (OpenOptions, []byte) {
	t.Helper()
	key := vault.NewRecoveryKey()
	i := vaultstore.Identity{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), Root: vaultstore.KeyRef{ID: uuid.NewString(), Version: 1}}
	slot, err := vault.CreateRecoverySlot(i.WorkspaceID, uuid.NewString(), 1, key, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	doc := vault.SlotFile{FormatVersion: 1, VaultID: i.WorkspaceID, FileID: i.FileID, Sequence: 1, FileEpoch: 1, Slots: []vault.Slot{slot}}
	doc.RootKeyID, doc.RootKeyVersion = i.Root.ID, i.Root.Version
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return OpenOptions{Identity: i, Slots: doc, MinimumSequence: 1, Create: true}, key
}

func owner(t *testing.T) (*Owner, string, OpenOptions, []byte) {
	t.Helper()
	o, key := options(t)
	path := filepath.Join(t.TempDir(), "vault.db")
	input := bytes.Clone(key)
	result, err := Open(context.Background(), path, o, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, make([]byte, 32)) {
		t.Fatal("key input retained")
	}
	t.Cleanup(func() {
		if err := result.Close(); err != nil {
			t.Error(err)
		}
		vault.Wipe(key)
	})
	return result, path, o, key
}

func secretRef() vaultstore.SecretRef {
	return vaultstore.SecretRef{OwnerKind: "credential", OwnerID: uuid.NewString(), Field: "password"}
}

func TestOwnerEncryptsEachFieldAndRotatesKeys(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	ref := secretRef()
	plain := []byte("unique-sensitive-password-never-written-to-sqlite")
	if rev, err := o.Put(ctx, ref, plain, 0); err != nil || rev != 1 {
		t.Fatalf("create: %d %v", rev, err)
	}
	stored, err := o.store.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	other := ref
	other.Field = "privateKey"
	if _, err := o.Put(ctx, other, plain, 0); err != nil {
		t.Fatal(err)
	}
	second, err := o.store.ReadSecret(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if second.DEK.ID == stored.DEK.ID || bytes.Equal(second.Envelope.Ciphertext, stored.Envelope.Ciphertext) {
		t.Fatal("DEK or ciphertext reused")
	}
	var borrowed []byte
	if err := o.WithSecret(ctx, ref, 1, func(value []byte) error {
		if !bytes.Equal(value, plain) {
			t.Error("plaintext mismatch")
		}
		borrowed = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(plain))) {
		t.Fatal("borrowed plaintext retained")
	}
	if _, err := o.Put(ctx, ref, []byte("new-secret"), 1); err != nil {
		t.Fatal(err)
	}
	updated, err := o.store.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DEK.ID != stored.DEK.ID || updated.DEK.Version != 2 || updated.RowVersion != 2 {
		t.Fatal("DEK version not advanced")
	}
	firstDEK, err := vault.Open(key, copyBinding(opts.Identity, stored), stored.Copy.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(firstDEK)
	secondDEK, err := vault.Open(key, copyBinding(opts.Identity, updated), updated.Copy.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(secondDEK)
	if bytes.Equal(firstDEK, secondDEK) {
		t.Fatal("DEK bytes reused")
	}
	if _, err := o.Put(ctx, ref, plain, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, secretRef(), plain, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{plain, []byte("new-secret"), key, firstDEK, secondDEK} {
			if bytes.Contains(body, secret) {
				t.Fatalf("plaintext in %s", filepath.Base(file))
			}
		}
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.WithSecret(ctx, ref, 2, func(value []byte) error {
		if string(value) != "new-secret" {
			t.Error("reopen mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.WithSecret(ctx, ref, 3, func([]byte) error { t.Error("stale value released"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
}

func TestOwnerAuthenticatesBeforeOpeningDatabase(t *testing.T) {
	for _, name := range []string{"wrong-key", "wrong-identity", "tampered-slots", "rollback", "tampered-mode", "cancelled", "missing", "invalid-root"} {
		t.Run(name, func(t *testing.T) {
			opts, key := options(t)
			defer vault.Wipe(key)
			path := filepath.Join(t.TempDir(), "not-created.db")
			ctx := context.Background()
			var want error
			switch name {
			case "wrong-key":
				key[0] ^= 1
				want = vault.ErrKeyCheck
			case "wrong-identity":
				opts.Identity.FileID = uuid.NewString()
				want = vault.ErrKeyCheck
			case "tampered-slots":
				opts.Slots.Authentication[0] ^= 1
				want = vault.ErrAuthentication
			case "rollback":
				opts.MinimumSequence = 2
				want = vault.ErrRollback
			case "tampered-mode":
				opts.Slots.Encrypted = true
				want = vault.ErrAuthentication
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "missing":
				opts.Create = false
				want = vaultstore.ErrMissing
			case "invalid-root":
				opts.Identity.Root.Version = 0
				want = vaultstore.ErrIdentity
			}
			if result, err := Open(ctx, path, opts, key); !errors.Is(err, want) {
				if result != nil {
					result.Close()
				}
				t.Fatalf("got %v want %v", err, want)
			}
			if !bytes.Equal(key, make([]byte, 32)) {
				t.Fatal("failed unlock kept key")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("database touched before unlock: %v", err)
			}
		})
	}
}

func TestOwnerKeepsAuthenticatedEncryptedMode(t *testing.T) {
	ctx := context.Background()
	opts, key := options(t)
	defer vault.Wipe(key)
	path := filepath.Join(t.TempDir(), "vault.db")
	plaintextSlots := opts.Slots
	opts.Slots.Encrypted = true
	opts.Slots.ProfileSequence = 1
	raw, err := vault.EncodeSlotFile(key, opts.Slots)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Clone(key)
	o, err := Open(ctx, path, opts, input)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if !o.LockedMemory() || !bytes.Equal(input, make([]byte, 32)) {
		t.Fatal("encrypted owner did not acquire the locked root")
	}
	factor := bytes.Repeat([]byte{3}, 32)
	id := opts.Slots.Slots[0].ID
	if err := o.VerifyReauthentication(ctx, opts.Slots, id, nil, factor, nil); err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyReauthentication(ctx, plaintextSlots, id, nil, factor, nil); err != vault.ErrAuthentication {
		t.Fatalf("reauthentication accepted other database mode: %v", err)
	}
	checkpoint := func(vault.SlotFile, []byte) error { t.Fatal("unexpected checkpoint write"); return nil }
	if err := o.PersistVPNSSOCheckpoints(ctx, opts.Slots, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := o.PersistVPNSSOCheckpoints(ctx, plaintextSlots, checkpoint); err != vault.ErrAuthentication {
		t.Fatalf("checkpoint accepted other database mode: %v", err)
	}
	if _, err := o.StageRootRotation(ctx, filepath.Join(t.TempDir(), "rotation.db"), plaintextSlots, nil, vault.NewRecoveryKey()); !errors.Is(err, vault.ErrFormat) {
		t.Fatalf("plaintext rotation accepted encrypted owner: %v", err)
	}
}

type transformingStore struct {
	vaultstore.Store
	transform             func(*vaultstore.Secret)
	readError, writeError error
}

func (s transformingStore) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	if s.readError != nil {
		return vaultstore.Secret{}, s.readError
	}
	value, err := s.Store.ReadSecret(ctx, ref)
	if err == nil && s.transform != nil {
		s.transform(&value)
	}
	return value, err
}

func (s transformingStore) WriteSecret(ctx context.Context, value vaultstore.Secret, expected uint64) error {
	if s.writeError != nil {
		return s.writeError
	}
	return s.Store.WriteSecret(ctx, value, expected)
}

func TestOwnerRejectsTamperedGraphAndSubstitution(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*vaultstore.Secret)
	}{
		{"value", func(v *vaultstore.Secret) { v.Envelope.Ciphertext[0] ^= 1 }},
		{"copy", func(v *vaultstore.Secret) { v.Copy.Envelope.Ciphertext[0] ^= 1 }},
		{"issuer", func(v *vaultstore.Secret) { v.Copy.Issuer.ID = uuid.NewString() }},
		{"holder", func(v *vaultstore.Secret) { v.Copy.Holder.ID = uuid.NewString() }},
		{"signature", func(v *vaultstore.Secret) { v.Copy.Signature[0] ^= 1 }},
		{"row", func(v *vaultstore.Secret) { v.RowVersion++ }},
		{"owner", func(v *vaultstore.Secret) { v.Ref.OwnerID = uuid.NewString() }},
		{"field", func(v *vaultstore.Secret) { v.Ref.Field = "other" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			o, _, _, _ := owner(t)
			ref := secretRef()
			ctx := context.Background()
			if _, err := o.Put(ctx, ref, []byte("secret"), 0); err != nil {
				t.Fatal(err)
			}
			o.store = transformingStore{Store: o.store, transform: mutate.change}
			if err := o.WithSecret(ctx, ref, 0, func([]byte) error { t.Error("corrupt secret exposed"); return nil }); err != vault.ErrAuthentication {
				t.Fatal(err)
			}
			expected := uint64(1)
			if mutate.name == "row" {
				expected = 2
			}
			if _, err := o.Put(ctx, ref, []byte("overwrite"), expected); err != vault.ErrAuthentication {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnerCallbackLifetimeAndClose(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	ref := secretRef()
	if _, err := o.Put(ctx, ref, []byte("temporary"), 0); err != nil {
		t.Fatal(err)
	}
	var borrowed []byte
	callbackError := errors.New("callback failed")
	if err := o.WithSecret(ctx, ref, 0, func(value []byte) error { borrowed = value; return callbackError }); err != callbackError {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("error retained plaintext")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		_ = o.WithSecret(ctx, ref, 0, func(value []byte) error { borrowed = value; panic("callback") })
	}()
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("panic retained plaintext")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- o.WithSecret(ctx, ref, 0, func(value []byte) error {
			close(entered)
			<-release
			if string(value) != "temporary" {
				return errors.New("key closed during borrow")
			}
			return nil
		})
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case <-closed:
		t.Fatal("close did not wait for borrowed secret")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if o.LockedMemory() {
		t.Fatal("closed memory active")
	}
	if err := o.root.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, ref, nil, 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if err := o.WithSecret(ctx, ref, 0, func([]byte) error { return nil }); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestOwnerLimitsFailuresAndConcurrentCAS(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	ref := secretRef()
	_ = o.LockedMemory()
	if _, err := o.Put(ctx, vaultstore.SecretRef{}, nil, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, ref, make([]byte, vault.MaxSecretBytes+1), 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, ref, nil, math.MaxInt64); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithSecret(ctx, ref, 0, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithSecret(ctx, ref, 0, func([]byte) error { return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.Put(cancelled, ref, nil, 0); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.WithSecret(cancelled, ref, 0, func([]byte) error { return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	original := o.store
	o.store = transformingStore{Store: original, readError: vaultstore.ErrBusy}
	if _, err := o.Put(ctx, ref, nil, 0); err != vaultstore.ErrBusy {
		t.Fatal(err)
	}
	o.store = transformingStore{Store: original, writeError: vaultstore.ErrConflict}
	if _, err := o.Put(ctx, ref, nil, 0); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	o.store = original
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := o.Put(ctx, ref, []byte("secret"), 0); results <- err }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners: %d", wins)
	}
}

func TestOwnerAEADAndLateCancellationFailClosed(t *testing.T) {
	for _, mode := range []string{"wrapped-key", "value", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			o, _, opts, key := owner(t)
			ref := secretRef()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := o.Put(ctx, ref, []byte("secret"), 0); err != nil {
				t.Fatal(err)
			}
			o.store = transformingStore{Store: o.store, transform: func(v *vaultstore.Secret) {
				switch mode {
				case "wrapped-key":
					v.Copy.Envelope.Ciphertext[0] ^= 1
				case "value":
					v.Envelope.Ciphertext[0] ^= 1
				case "cancelled":
					cancel()
				}
				var err error
				v.Copy.Signature, err = recordMAC(key, opts.Identity, *v)
				if err != nil {
					t.Fatal(err)
				}
			}}
			want := vault.ErrAuthentication
			if mode == "cancelled" {
				want = context.Canceled
			}
			if err := o.WithSecret(ctx, ref, 0, func([]byte) error { t.Error("invalid secret released"); return nil }); err != want {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnerWorkspaceID(t *testing.T) {
	o, _, opts, _ := owner(t)
	if id, err := o.WorkspaceID(context.Background()); err != nil || id != opts.Identity.WorkspaceID {
		t.Fatal(id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.WorkspaceID(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.WorkspaceID(context.Background()); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}
