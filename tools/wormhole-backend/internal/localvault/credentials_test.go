package localvault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func draft() vaultstore.CredentialMetadata {
	id := uuid.NewString()
	return vaultstore.CredentialMetadata{ID: id, Name: "Account " + id, Protocol: "ssh", Kind: "password", Provider: "local", Username: "user"}
}

func TestCredentialOwnerAtomicFieldsAndRemoval(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	metadata := draft()
	metadata.Kind = "sshKey"
	pass, keyBytes := []byte("unique-aggregate-passphrase-never-store-clear"), []byte("unique-aggregate-private-key-never-store-clear")
	c, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "privateKey", Value: keyBytes}, {Field: "passphrase", Value: pass}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.RowVersion != 1 || len(c.Fields) != 2 || c.Fields[0].Field != "passphrase" {
		t.Fatal(c)
	}
	read, err := o.ReadCredential(ctx, c.ID, 1)
	if err != nil || !reflect.DeepEqual(read, c) {
		t.Fatal(err)
	}
	var borrowed []byte
	if err := o.WithCredentialSecret(ctx, c.ID, "privateKey", 1, func(value []byte) error {
		if !bytes.Equal(value, keyBytes) {
			t.Error("wrong key")
		}
		borrowed = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed key not wiped")
	}
	metadata.Name = "Renamed"
	c, err = o.PutCredential(ctx, metadata, []SecretChange{{Field: "passphrase", Remove: true}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fields[0].Version != 2 || c.Fields[0].Present {
		t.Fatal(c.Fields)
	}
	if err := o.WithCredentialSecret(ctx, c.ID, "passphrase", 2, func([]byte) error { t.Fatal("deleted field released"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	var tombstone []byte
	if err := o.WithSecret(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: "passphrase"}, 2, func(v []byte) error { tombstone = bytes.Clone(v); return nil }); err != nil || len(tombstone) != 0 {
		t.Fatal(err)
	}
	c, err = o.PutCredential(ctx, metadata, []SecretChange{{Field: "passphrase", Value: pass}}, 2)
	if err != nil || c.Fields[0].Version != 3 {
		t.Fatal(c, err)
	}
	if _, err := o.ReadCredential(ctx, c.ID, 4); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, c.ID, "privateKey", 4, func([]byte) error { return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: "privateKey"}, keyBytes, 1); err != vaultstore.ErrConflict {
		t.Fatal("standalone bypass", err)
	}
	if err := o.DeleteCredential(ctx, c.ID, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadCredential(ctx, c.ID, 4); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, c.ID, "privateKey", 4, func([]byte) error { t.Fatal("deleted credential released"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	page, err := o.ListCredentials(ctx, "", 128)
	if err != nil || len(page) != 0 {
		t.Fatal(page, err)
	}
	if _, err := o.PutCredential(ctx, metadata, nil, 0); err != vaultstore.ErrConflict {
		t.Fatal("ID reused", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(path + "*")
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, pass) || bytes.Contains(data, keyBytes) {
			t.Fatal("plaintext in database files")
		}
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.ReadCredential(ctx, c.ID, 4); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

type credentialFilter struct {
	vaultstore.CredentialStore
	read     func(vaultstore.Credential) (vaultstore.Credential, error)
	list     func([]vaultstore.Credential) ([]vaultstore.Credential, error)
	writeErr error
	secret   func(vaultstore.Secret) (vaultstore.Secret, error)
}

func (s credentialFilter) ReadCredential(ctx context.Context, id string) (vaultstore.Credential, error) {
	c, err := s.CredentialStore.ReadCredential(ctx, id)
	if err == nil && s.read != nil {
		return s.read(c)
	}
	return c, err
}
func (s credentialFilter) ListCredentials(ctx context.Context, after string, limit int) ([]vaultstore.Credential, error) {
	cs, err := s.CredentialStore.ListCredentials(ctx, after, limit)
	if err == nil && s.list != nil {
		return s.list(cs)
	}
	return cs, err
}
func (s credentialFilter) WriteCredential(ctx context.Context, c vaultstore.Credential, vs []vaultstore.Secret, e uint64) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.CredentialStore.WriteCredential(ctx, c, vs, e)
}
func (s credentialFilter) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	sval, err := s.CredentialStore.ReadSecret(ctx, ref)
	if err == nil && s.secret != nil {
		return s.secret(sval)
	}
	return sval, err
}

func TestCredentialOwnerRejectsTamperedMetadataAndSubstitution(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := draft()
	original, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("secret")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := o.store.(vaultstore.CredentialStore)
	for _, mutate := range []func(*vaultstore.Credential){
		func(c *vaultstore.Credential) { c.Name = "redirected" }, func(c *vaultstore.Credential) { c.Username = "other" }, func(c *vaultstore.Credential) { c.ID = uuid.NewString() }, func(c *vaultstore.Credential) { c.Seal = nil }, func(c *vaultstore.Credential) { c.Fields[0].Present = false },
	} {
		o.store = credentialFilter{CredentialStore: store, read: func(c vaultstore.Credential) (vaultstore.Credential, error) { mutate(&c); return c, nil }, list: func(cs []vaultstore.Credential) ([]vaultstore.Credential, error) { mutate(&cs[0]); return cs, nil }}
		if _, err := o.ReadCredential(ctx, metadata.ID, 0); err == nil {
			t.Fatal("unverified metadata")
		}
		if _, err := o.PutCredential(ctx, metadata, nil, 1); err == nil {
			t.Fatal("rewrote unverified metadata")
		}
		if err := o.WithCredentialSecret(ctx, metadata.ID, "password", 0, func([]byte) error { t.Fatal("released unverified credential"); return nil }); err == nil {
			t.Fatal("accepted metadata")
		}
		if _, err := o.ListCredentials(ctx, "", 1); err == nil {
			t.Fatal("listed unverified metadata")
		}
	}
	o.store = store
	current, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("new")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	o.store = credentialFilter{CredentialStore: store, read: func(vaultstore.Credential) (vaultstore.Credential, error) { return original, nil }}
	if _, err := o.ReadCredential(ctx, metadata.ID, 2); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "password", 0, func([]byte) error { t.Fatal("newer field substituted for old manifest"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = store
	other := draft()
	otherCred, err := o.PutCredential(ctx, other, []SecretChange{{Field: "password", Value: []byte("other")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: other.ID, Field: "password"})
	if err != nil {
		t.Fatal(err)
	}
	o.store = credentialFilter{CredentialStore: store, secret: func(vaultstore.Secret) (vaultstore.Secret, error) { return otherSecret, nil }}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "password", current.RowVersion, func([]byte) error { t.Fatal("substituted field released"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("changed")}}, 2); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = credentialFilter{CredentialStore: store, read: func(vaultstore.Credential) (vaultstore.Credential, error) { return otherCred, nil }}
	if _, err := o.ReadCredential(ctx, metadata.ID, 0); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "password", 0, func([]byte) error { return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = store
}

func TestCredentialOwnerValidationFailureAndConcurrentMutation(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := draft()
	for _, changes := range [][]SecretChange{
		{{Field: "token"}}, {{Field: "password"}, {Field: "password"}}, {{Field: "password", Remove: true}}, {{Field: "password", Value: make([]byte, vault.MaxSecretBytes+1)}}, make([]SecretChange, 5),
	} {
		if _, err := o.PutCredential(ctx, metadata, changes, 0); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := o.PutCredential(ctx, metadata, nil, math.MaxUint64); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutCredential(ctx, metadata, nil, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if err := o.DeleteCredential(ctx, metadata.ID, 0); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	bad := metadata
	bad.Name = ""
	if _, err := o.PutCredential(ctx, bad, nil, 0); err != vaultstore.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("secret")}}, 0); err != nil {
		t.Fatal(err)
	}
	for _, changes := range [][]SecretChange{{{Field: "password", Remove: true, Value: []byte("unexpected")}}, {{Field: "privateKey", Value: []byte("incompatible")}}} {
		if _, err := o.PutCredential(ctx, metadata, changes, 1); err == nil {
			t.Fatal("invalid change")
		}
	}
	store := o.store.(vaultstore.CredentialStore)
	o.store = credentialFilter{CredentialStore: store, writeErr: vaultstore.ErrStorage}
	if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("new")}}, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = store
	if c, err := o.ReadCredential(ctx, metadata.ID, 1); err != nil || c.RowVersion != 1 {
		t.Fatal(c, err)
	}
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() { _, err := o.PutCredential(ctx, metadata, nil, 1); results <- err })
	}
	group.Wait()
	close(results)
	ok, conflicts := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if err == vaultstore.ErrConflict {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatal(ok, conflicts)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PutCredential(cancelled, metadata, nil, 2); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := o.ReadCredential(cancelled, metadata.ID, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := o.ListCredentials(cancelled, "", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(cancelled, metadata.ID, "password", 0, func([]byte) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "invalid", 0, func([]byte) error { return nil }); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "password", 0, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	o.store = struct{ vaultstore.Store }{store}
	if _, err := o.ReadCredential(ctx, metadata.ID, 0); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = store
	o.Close()
	if _, err := o.PutCredential(ctx, metadata, nil, 2); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.ReadCredential(ctx, metadata.ID, 0); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.ListCredentials(ctx, "", 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if err := o.WithCredentialSecret(ctx, metadata.ID, "password", 0, func([]byte) error { return nil }); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestCredentialProviderChangeMustRetireLocalFieldsAtomically(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := draft()
	if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("local")}}, 0); err != nil {
		t.Fatal(err)
	}
	metadata.Provider = "bitwarden"
	metadata.BitwardenItemID = "selected-item"
	if _, err := o.PutCredential(ctx, metadata, nil, 1); err != vaultstore.ErrFormat {
		t.Fatal("hidden local secret retained", err)
	}
	c, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Remove: true}}, 1)
	if err != nil || c.Fields[0].Version != 2 || c.Fields[0].Present {
		t.Fatal(c, err)
	}
	if err := o.WithCredentialSecret(ctx, c.ID, "password", 2, func([]byte) error { t.Fatal("old provider secret released"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	metadata.Provider = "local"
	metadata.BitwardenItemID = ""
	c, err = o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("new")}}, 2)
	if err != nil || c.Fields[0].Version != 3 {
		t.Fatal(c, err)
	}
}

func TestCredentialSchemaUpgradeRequiresAuthenticationBeforeAnySQLiteChange(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("DROP TABLE LocalState; DROP TABLE Nodes; DROP TABLE TunnelConfigs; DROP TABLE CredentialProfiles; UPDATE WorkspaceMeta SET SchemaVersion=1;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	if opened, err := Open(ctx, path, opts, vault.NewRecoveryKey()); err == nil || opened != nil {
		t.Fatal("wrong factor reached schema upgrade", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("database changed before authentication")
	}
	opened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.PutCredential(ctx, draft(), nil, 0); err != nil {
		t.Fatal("authenticated upgrade failed", err)
	}
}
