package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// SecretChange borrows plaintext owned by the native request handler. No factor
// or field value is ever part of the metadata DTO or a renderer response.
type SecretChange struct {
	Field  string
	Value  []byte
	Remove bool
}

func credentialMAC(key []byte, identity vaultstore.Identity, credential vaultstore.Credential) ([]byte, error) {
	subkey, err := vault.DeriveKey(key, []byte(identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	credential.Seal = nil
	body, err := json.Marshal(struct {
		Identity   vaultstore.Identity   `json:"identity"`
		Credential vaultstore.Credential `json:"credential"`
	}{identity, credential})
	if err != nil {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-credential\x00"))
	mac.Write(body)
	return mac.Sum(nil), nil
}

func (o *Owner) verifyCredential(credential vaultstore.Credential) error {
	if credential.Validate() != nil {
		return vault.ErrFormat
	}
	return o.root.With(func(key []byte) error {
		mac, err := credentialMAC(key, o.store.Identity(), credential)
		if err != nil {
			return err
		}
		if !hmac.Equal(mac, credential.Seal) {
			return vault.ErrAuthentication
		}
		return nil
	})
}

func (o *Owner) credentialStore() (vaultstore.CredentialStore, error) {
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	store, ok := o.store.(vaultstore.CredentialStore)
	if !ok {
		return nil, vaultstore.ErrStorage
	}
	return store, nil
}

func (o *Owner) ReadCredential(ctx context.Context, id string, minimum uint64) (vaultstore.Credential, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	store, err := o.credentialStore()
	if err != nil {
		return vaultstore.Credential{}, err
	}
	c, err := store.ReadCredential(ctx, id)
	if err != nil {
		return vaultstore.Credential{}, err
	}
	if c.ID != id {
		return vaultstore.Credential{}, vault.ErrAuthentication
	}
	if err := o.verifyCredential(c); err != nil {
		return vaultstore.Credential{}, err
	}
	if c.RowVersion < minimum {
		return vaultstore.Credential{}, vault.ErrRollback
	}
	if c.Deleted {
		return vaultstore.Credential{}, vaultstore.ErrMissing
	}
	return c, nil
}

func (o *Owner) ListCredentials(ctx context.Context, after string, limit int) ([]vaultstore.Credential, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	store, err := o.credentialStore()
	if err != nil {
		return nil, err
	}
	values, err := store.ListCredentials(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	for _, c := range values {
		if err := o.verifyCredential(c); err != nil {
			return nil, err
		}
		if c.Deleted {
			return nil, vault.ErrAuthentication
		}
	}
	return values, nil
}

func (o *Owner) PutCredential(ctx context.Context, metadata vaultstore.CredentialMetadata, changes []SecretChange, expected uint64) (vaultstore.Credential, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeCredential(ctx, metadata, changes, expected, false, nil)
}

// ImportCredential creates an absent record with its original provenance. It is
// native-only; normal edits cannot replace creation time, even on an old record
// whose time is unknown. The migration controller owns staging and source locks.
func (o *Owner) ImportCredential(ctx context.Context, metadata vaultstore.CredentialMetadata, createdAt string, changes []SecretChange) (vaultstore.Credential, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeCredential(ctx, metadata, changes, 0, false, &createdAt)
}

func (o *Owner) DeleteCredential(ctx context.Context, id string, expected uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.writeCredential(ctx, vaultstore.CredentialMetadata{ID: id}, nil, expected, true, nil)
	return err
}

func (o *Owner) writeCredential(ctx context.Context, metadata vaultstore.CredentialMetadata, changes []SecretChange, expected uint64, deleted bool, importedCreatedAt *string) (vaultstore.Credential, error) {
	store, err := o.credentialStore()
	if err != nil {
		return vaultstore.Credential{}, err
	}
	if expected >= math.MaxInt64 || len(changes) > 4 {
		return vaultstore.Credential{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vaultstore.Credential{}, err
	}
	previous, err := store.ReadCredential(ctx, metadata.ID)
	if errors.Is(err, vaultstore.ErrMissing) {
		if expected != 0 || deleted {
			return vaultstore.Credential{}, vaultstore.ErrConflict
		}
	} else if err != nil {
		return vaultstore.Credential{}, err
	} else {
		if previous.ID != metadata.ID {
			return vaultstore.Credential{}, vault.ErrAuthentication
		}
		if err := o.verifyCredential(previous); err != nil {
			return vaultstore.Credential{}, err
		}
		if previous.RowVersion != expected || previous.Deleted {
			return vaultstore.Credential{}, vaultstore.ErrConflict
		}
	}
	if deleted || (expected != 0 && metadata.Protocol != previous.Protocol) {
		if err := o.checkMigrationCredentialReferences(ctx, metadata.ID); err != nil {
			return vaultstore.Credential{}, err
		}
	}
	if deleted {
		metadata = previous.CredentialMetadata
		for _, f := range previous.Fields {
			if f.Present {
				changes = append(changes, SecretChange{Field: f.Field, Remove: true})
			}
		}
	}
	value := vaultstore.Credential{CredentialMetadata: metadata, RowVersion: expected + 1, Deleted: deleted, Fields: append([]vaultstore.CredentialField{}, previous.Fields...), Seal: make([]byte, 32)}
	value.CreatedAt = previous.CreatedAt
	if expected == 0 {
		if importedCreatedAt != nil {
			value.CreatedAt = *importedCreatedAt
		} else {
			value.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	fields := make(map[string]vaultstore.CredentialField, len(value.Fields))
	for _, f := range value.Fields {
		fields[f.Field] = f
	}
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		old := fields[change.Field]
		if !vaultstore.CredentialSecretField(change.Field) || seen[change.Field] || len(change.Value) > vault.MaxSecretBytes || (change.Remove && (len(change.Value) != 0 || !old.Present)) || old.Version >= math.MaxInt64 {
			return vaultstore.Credential{}, vault.ErrFormat
		}
		seen[change.Field] = true
		fields[change.Field] = vaultstore.CredentialField{Field: change.Field, Version: old.Version + 1, Present: !change.Remove}
	}
	value.Fields = value.Fields[:0]
	for _, f := range fields {
		value.Fields = append(value.Fields, f)
	}
	sort.Slice(value.Fields, func(i, j int) bool { return value.Fields[i].Field < value.Fields[j].Field })
	if err := value.Validate(); err != nil {
		return vaultstore.Credential{}, err
	}
	secrets := make([]vaultstore.Secret, 0, len(changes))
	for _, change := range changes {
		ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: metadata.ID, Field: change.Field}
		secret, err := o.prepareSecret(ctx, ref, change.Value, fields[change.Field].Version-1)
		if err != nil {
			return vaultstore.Credential{}, err
		}
		secrets = append(secrets, secret)
	}
	err = o.root.With(func(key []byte) error {
		var err error
		value.Seal, err = credentialMAC(key, store.Identity(), value)
		return err
	})
	if err != nil {
		return vaultstore.Credential{}, err
	}
	if err := store.WriteCredential(ctx, value, secrets, expected); err != nil {
		return vaultstore.Credential{}, err
	}
	return value, nil
}

// Release is tied to the authenticated aggregate manifest. The resolver must
// first authorize this credential for its complete connection chain. A newer
// standalone field version is not accepted as a substitute for that manifest.
func (o *Owner) WithCredentialSecret(ctx context.Context, id, field string, minimum uint64, use func([]byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	store, err := o.credentialStore()
	if err != nil {
		return err
	}
	if !vaultstore.CredentialSecretField(field) || use == nil {
		return vault.ErrFormat
	}
	c, err := store.ReadCredential(ctx, id)
	if err != nil {
		return err
	}
	if c.ID != id {
		return vault.ErrAuthentication
	}
	if err := o.verifyCredential(c); err != nil {
		return err
	}
	if c.RowVersion < minimum {
		return vault.ErrRollback
	}
	if c.Deleted {
		return vaultstore.ErrMissing
	}
	for _, f := range c.Fields {
		if f.Field == field && f.Present {
			return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: id, Field: field}, f.Version, true, use)
		}
	}
	return vaultstore.ErrMissing
}
