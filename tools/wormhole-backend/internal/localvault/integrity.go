package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"hash"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// IntegrityInventory describes authenticated live aggregates, not a renderer DTO.
// It does not establish completeness against a previously observed inventory.
type IntegrityInventory struct {
	Credentials, Tunnels, Nodes, LocalStates int
}

// VerifyIntegrity authenticates metadata, relationships, every manifested field
// and every local-state chunk under one owner lock. Plaintext is discarded inside
// its bounded borrowing callback. Migration uses this after closing and reopening
// the destination, before sealing the exact persisted file for publication.
func (o *Owner) VerifyIntegrity(ctx context.Context) (IntegrityInventory, error) {
	result, _, err := o.verifyIntegrity(ctx, false)
	return result, err
}

// VerifyMigrationIntegrity binds every immutable record and borrowed plaintext
// field, while still verifying the mutable retirement journal. The native-only
// MAC is frozen before retirement; journal writes alone cannot invalidate it.
func (o *Owner) VerifyMigrationIntegrity(ctx context.Context) (IntegrityInventory, []byte, error) {
	return o.verifyIntegrity(ctx, true)
}

func (o *Owner) verifyIntegrity(ctx context.Context, checkpoint bool) (IntegrityInventory, []byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, policyRaw, err := o.readLocalPolicy(ctx)
	if err != nil {
		return IntegrityInventory{}, nil, err
	}
	catalog, err := o.readCatalog(ctx, 8*1024*1024)
	if err != nil {
		return IntegrityInventory{}, nil, err
	}
	var mac hash.Hash
	if checkpoint {
		err := o.root.With(func(key []byte) error {
			subkey, err := vault.DeriveKey(key, []byte(o.store.Identity().WorkspaceID), vault.PurposeLocalSeal)
			if err != nil {
				return err
			}
			defer vault.Wipe(subkey)
			mac = hmac.New(sha256.New, subkey)
			mac.Write([]byte("wormhole/v1/migration-immutable-content\x00"))
			return nil
		})
		if err != nil {
			return IntegrityInventory{}, nil, err
		}
	}
	piece := func(tag string, value []byte) {
		if mac == nil {
			return
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(tag)))
		mac.Write(size[:])
		mac.Write([]byte(tag))
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		mac.Write(size[:])
		mac.Write(value)
	}
	jsonPiece := func(tag string, value any) error {
		if mac == nil {
			return nil
		}
		raw, err := json.Marshal(value)
		defer vault.Wipe(raw)
		if err != nil {
			return err
		}
		piece(tag, raw)
		return nil
	}
	piece("policy", policyRaw)
	if err := jsonPiece("identity", o.store.Identity()); err != nil {
		return IntegrityInventory{}, nil, err
	}
	if err := jsonPiece("catalog", catalog); err != nil {
		return IntegrityInventory{}, nil, err
	}
	verifyFields := func(kind, id string, fields []vaultstore.SecretField) error {
		for _, field := range fields {
			ref := vaultstore.SecretRef{OwnerKind: kind, OwnerID: id, Field: field.Field}
			if err := o.withSecret(ctx, ref, field.Version, true, func(value []byte) error {
				if !field.Present && len(value) != 0 {
					return vault.ErrAuthentication
				}
				if mac != nil {
					piece(kind+"/"+id+"/"+field.Field, value)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, value := range catalog.Credentials {
		if err := verifyFields("credential", value.ID, value.Fields); err != nil {
			return IntegrityInventory{}, nil, err
		}
	}
	for _, value := range catalog.Nodes {
		if err := verifyFields("node", value.ID, value.Fields); err != nil {
			return IntegrityInventory{}, nil, err
		}
	}
	for _, value := range catalog.Tunnels {
		if err := verifyFields("tunnel", value.ID, []vaultstore.SecretField{{Field: "settings", Version: value.ConfigurationVersion, Present: true}}); err != nil {
			return IntegrityInventory{}, nil, err
		}
	}
	store, err := o.localStateStore()
	if err != nil {
		return IntegrityInventory{}, nil, err
	}
	result := IntegrityInventory{Credentials: len(catalog.Credentials), Nodes: len(catalog.Nodes), Tunnels: len(catalog.Tunnels)}
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return IntegrityInventory{}, nil, err
		}
		page, err := store.ListLocalStates(ctx, after, 128)
		if err != nil {
			return IntegrityInventory{}, nil, err
		}
		if len(page) > 128 {
			return IntegrityInventory{}, nil, vault.ErrAuthentication
		}
		for _, value := range page {
			if value.ID <= after || value.Deleted || !o.validLocalStateScope(value.Kind, value.ScopeID) {
				return IntegrityInventory{}, nil, vault.ErrAuthentication
			}
			if err := o.verifyLocalState(value); err != nil {
				return IntegrityInventory{}, nil, err
			}
			track := mac != nil && !(value.Kind == vaultstore.LocalStateMigrationRetirement && value.ScopeID == o.store.Identity().WorkspaceID)
			if track {
				if err := jsonPiece("local-state", value); err != nil {
					return IntegrityInventory{}, nil, err
				}
			}
			for i, field := range value.Fields {
				size := 0
				if field.Present {
					size = min(vault.MaxSecretBytes, value.Size-i*vault.MaxSecretBytes)
				}
				ref := vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: value.ID, Field: field.Field}
				if err := o.withSecret(ctx, ref, field.Version, true, func(chunk []byte) error {
					if len(chunk) != size {
						return vault.ErrAuthentication
					}
					if track {
						piece("local-state/"+value.ID+"/"+field.Field, chunk)
					}
					return nil
				}); err != nil {
					return IntegrityInventory{}, nil, err
				}
			}
			result.LocalStates++
			after = value.ID
		}
		if len(page) < 128 {
			if mac != nil {
				return result, mac.Sum(nil), nil
			}
			return result, nil, nil
		}
	}
}
