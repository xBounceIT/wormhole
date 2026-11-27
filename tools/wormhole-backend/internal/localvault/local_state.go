package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func localStateMAC(key []byte, identity vaultstore.Identity, value vaultstore.LocalState) ([]byte, error) {
	subkey, err := vault.DeriveKey(key, []byte(identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	value.Seal = nil
	body, err := json.Marshal(struct {
		Identity vaultstore.Identity   `json:"identity"`
		Value    vaultstore.LocalState `json:"value"`
	}{identity, value})
	if err != nil {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-state\x00"))
	mac.Write(body)
	return mac.Sum(nil), nil
}

func (o *Owner) verifyLocalState(value vaultstore.LocalState) error {
	if value.Validate() != nil {
		return vault.ErrFormat
	}
	return o.root.With(func(key []byte) error {
		mac, err := localStateMAC(key, o.store.Identity(), value)
		if err != nil {
			return err
		}
		if !hmac.Equal(mac, value.Seal) {
			return vault.ErrAuthentication
		}
		return nil
	})
}

func (o *Owner) localStateStore() (vaultstore.LocalStateStore, error) {
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	s, ok := o.store.(vaultstore.LocalStateStore)
	if !ok {
		return nil, vaultstore.ErrStorage
	}
	return s, nil
}

func (o *Owner) readLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	s, err := o.localStateStore()
	if err != nil {
		return vaultstore.LocalState{}, err
	}
	if !o.validLocalStateScope(kind, scope) {
		return vaultstore.LocalState{}, vault.ErrFormat
	}
	value, err := s.ReadLocalState(ctx, kind, scope)
	if err != nil {
		return vaultstore.LocalState{}, err
	}
	if value.Kind != kind || value.ScopeID != scope {
		return vaultstore.LocalState{}, vault.ErrAuthentication
	}
	if err := o.verifyLocalState(value); err != nil {
		return vaultstore.LocalState{}, err
	}
	return value, nil
}

func (o *Owner) validLocalStateScope(kind, scope string) bool {
	ref := vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: scope, Field: "chunk00"}
	if !vaultstore.LocalStateKind(kind) || !ref.Valid() {
		return false
	}
	switch kind {
	case "migration-source-inventory", "migration-retirement", "bitwarden-cli", "mcp-token", "bitwarden-browser", "bitwarden-browser-backup", bitwardenInstallationKind, bitwardenIntentKind:
		return scope == o.store.Identity().WorkspaceID
	}
	return true
}

// ReadLocalState includes authenticated tombstones so a native owner can resume
// writes with their current revision. It never returns payload bytes.
func (o *Owner) ReadLocalState(ctx context.Context, kind, scope string, minimum uint64) (vaultstore.LocalState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	value, err := o.readLocalState(ctx, kind, scope)
	if err != nil {
		return vaultstore.LocalState{}, err
	}
	if value.RowVersion < minimum {
		return vaultstore.LocalState{}, vault.ErrRollback
	}
	return value, nil
}

func (o *Owner) ListLocalStates(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.listLocalStates(ctx, after, limit)
}

func (o *Owner) listLocalStates(ctx context.Context, after string, limit int) ([]vaultstore.LocalState, error) {
	s, err := o.localStateStore()
	if err != nil {
		return nil, err
	}
	values, err := s.ListLocalStates(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if value.ID <= after || value.Deleted || !o.validLocalStateScope(value.Kind, value.ScopeID) {
			return nil, vault.ErrAuthentication
		}
		if err := o.verifyLocalState(value); err != nil {
			return nil, err
		}
		after = value.ID
	}
	return values, nil
}

// PutLocalState borrows payload. Every revision rewrites the complete chunk set,
// atomically with its authenticated length/presence manifest. Shrinking retains
// empty encrypted tombstones, so growing again cannot reset chunk versions.
func (o *Owner) PutLocalState(ctx context.Context, kind, scope string, payload []byte, expected uint64) (vaultstore.LocalState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeLocalState(ctx, kind, scope, payload, expected, false)
}

func (o *Owner) DeleteLocalState(ctx context.Context, kind, scope string, expected uint64) (vaultstore.LocalState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writeLocalState(ctx, kind, scope, nil, expected, true)
}

func (o *Owner) writeLocalState(ctx context.Context, kind, scope string, payload []byte, expected uint64, deleted bool) (vaultstore.LocalState, error) {
	s, err := o.localStateStore()
	if err != nil {
		return vaultstore.LocalState{}, err
	}
	if !o.validLocalStateScope(kind, scope) || len(payload) > vaultstore.MaxLocalStateBytes || expected >= math.MaxInt64 {
		return vaultstore.LocalState{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vaultstore.LocalState{}, err
	}
	old, err := o.readLocalState(ctx, kind, scope)
	if errors.Is(err, vaultstore.ErrMissing) {
		if expected != 0 || deleted {
			return vaultstore.LocalState{}, vaultstore.ErrConflict
		}
	} else if err != nil {
		return vaultstore.LocalState{}, err
	} else if old.RowVersion != expected || (deleted && old.Deleted) {
		return vaultstore.LocalState{}, vaultstore.ErrConflict
	}
	value := vaultstore.LocalState{ID: old.ID, Kind: kind, ScopeID: scope, Size: len(payload), RowVersion: expected + 1, Deleted: deleted, Seal: make([]byte, 32)}
	if value.ID == "" {
		value.ID = uuid.NewString()
	}
	count := max(value.ActiveChunks(), len(old.Fields))
	value.Fields = make([]vaultstore.SecretField, count)
	secrets := make([]vaultstore.Secret, 0, count)
	for i := 0; i < count; i++ {
		previous := uint64(0)
		if i < len(old.Fields) {
			previous = old.Fields[i].Version
		}
		field := vaultstore.SecretField{Field: vaultstore.LocalStateChunkField(i), Version: previous + 1, Present: i < value.ActiveChunks()}
		var chunk []byte
		if field.Present {
			start := i * vault.MaxSecretBytes
			chunk = payload[start:min(start+vault.MaxSecretBytes, len(payload))]
		}
		secret, err := o.prepareSecret(ctx, vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: value.ID, Field: field.Field}, chunk, previous)
		if err != nil {
			return vaultstore.LocalState{}, err
		}
		value.Fields[i] = field
		secrets = append(secrets, secret)
	}
	if value.Validate() != nil {
		return vaultstore.LocalState{}, vault.ErrFormat
	}
	if err := o.root.With(func(key []byte) error {
		var err error
		value.Seal, err = localStateMAC(key, s.Identity(), value)
		return err
	}); err != nil {
		return vaultstore.LocalState{}, err
	}
	if err := s.WriteLocalState(ctx, value, secrets, expected); err != nil {
		return vaultstore.LocalState{}, err
	}
	return value, nil
}

// WithLocalState authenticates every chunk before lending the assembled value.
// Callback data is wiped on success/error/cancellation and must not be retained.
// Consumers cannot reenter this owner while its callback is running.
func (o *Owner) WithLocalState(ctx context.Context, kind, scope string, minimum uint64, use func([]byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.withLocalState(ctx, kind, scope, minimum, use)
}

// Caller holds o.mu, including throughout use.
func (o *Owner) withLocalState(ctx context.Context, kind, scope string, minimum uint64, use func([]byte) error) error {
	if use == nil {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, err := o.readLocalState(ctx, kind, scope)
	if err != nil {
		return err
	}
	if value.RowVersion < minimum {
		return vault.ErrRollback
	}
	if value.Deleted {
		return vaultstore.ErrMissing
	}
	return o.withLocalStateChunks(ctx, value, use)
}

// Caller holds o.mu and has authenticated value, including its presence and
// revision. Assemble that exact manifest rather than rereading mutable metadata.
func (o *Owner) withLocalStateChunks(ctx context.Context, value vaultstore.LocalState, use func([]byte) error) error {
	payload := make([]byte, value.Size)
	defer vault.Wipe(payload)
	for i, field := range value.Fields {
		if !field.Present {
			continue
		}
		start := i * vault.MaxSecretBytes
		end := min(start+vault.MaxSecretBytes, value.Size)
		ref := vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: value.ID, Field: field.Field}
		if err := o.withSecret(ctx, ref, field.Version, true, func(chunk []byte) error {
			if len(chunk) != end-start {
				return vault.ErrAuthentication
			}
			copy(payload[start:end], chunk)
			return nil
		}); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(payload)
}
