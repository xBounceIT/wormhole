// Package vaultstore defines the ciphertext-only persistence boundary. Domain
// callers resolve and authorize a connection before requesting a secret; this
// package never receives passwords, private keys or an unlock credential.
package vaultstore

import (
	"context"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	ErrFormat   = errors.New("vault_store_invalid_record")
	ErrStorage  = errors.New("vault_store_unavailable")
	ErrBusy     = errors.New("vault_store_busy")
	ErrConflict = errors.New("vault_store_conflict")
	ErrMissing  = errors.New("vault_store_missing")
	ErrIdentity = errors.New("vault_store_identity_mismatch")
	ErrVersion  = errors.New("vault_store_newer_schema")
	ErrClosed   = errors.New("vault_store_closed")
)

type KeyRef struct {
	ID      string `json:"id"`
	Version uint32 `json:"version"`
}

type Identity struct {
	WorkspaceID string `json:"workspaceId"`
	FileID      string `json:"fileId"`
	Root        KeyRef `json:"root"`
}

type SecretRef struct {
	OwnerKind string `json:"ownerKind"`
	OwnerID   string `json:"ownerId"`
	Field     string `json:"field"`
}

type KeyCopy struct {
	Key       KeyRef         `json:"key"`
	Holder    KeyRef         `json:"holder"`
	Issuer    KeyRef         `json:"issuer"`
	Envelope  vault.Envelope `json:"envelope"`
	Signature []byte         `json:"signature"`
}

type Secret struct {
	Ref        SecretRef      `json:"ref"`
	DEK        KeyRef         `json:"dek"`
	Envelope   vault.Envelope `json:"envelope"`
	RowVersion uint64         `json:"rowVersion"`
	Copy       KeyCopy        `json:"copy"`
}

// SecretField is the authenticated presence/version entry shared by domain
// aggregates. CredentialField remains source-compatible with existing callers.
type SecretField = CredentialField

// Each write atomically installs a fresh DEK version, its authenticated copy and
// the value. expectedVersion=0 means insert only. No SQL/transaction objects leak
// into the vault's domain layer, so a PostgreSQL implementation can share this API.
type Store interface {
	Identity() Identity
	ReadSecret(context.Context, SecretRef) (Secret, error)
	WriteSecret(context.Context, Secret, uint64) error
	Close() error
}

func validID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func (r KeyRef) Valid() bool { return validID(r.ID) && r.Version > 0 }

func (r SecretRef) Valid() bool {
	switch r.OwnerKind {
	case "credential", "node", "tunnel", "slot-value", "local-state":
	default:
		return false
	}
	return validID(r.OwnerID) && len(r.Field) > 0 && len(r.Field) <= 128 && utf8.ValidString(r.Field) && !strings.ContainsRune(r.Field, 0)
}

func validEnvelope(e vault.Envelope, key KeyRef, size int) bool {
	return e.FormatVersion == vault.FormatVersion && e.SuiteID == vault.SuiteAES256GCM && e.KeyID == key.ID && e.KeyVersion == key.Version && len(e.Nonce) == 12 && len(e.Ciphertext) >= 16 && len(e.Ciphertext) <= size+16
}

func (s Secret) valid(identity Identity) bool {
	return s.Ref.Valid() && s.DEK.Valid() && s.DEK.ID != identity.Root.ID && s.RowVersion > 0 && s.RowVersion <= math.MaxInt64 &&
		s.Copy.Key == s.DEK && s.Copy.Holder == identity.Root && s.Copy.Issuer == identity.Root && len(s.Copy.Signature) == 32 &&
		validEnvelope(s.Envelope, s.DEK, vault.MaxSecretBytes) && validEnvelope(s.Copy.Envelope, identity.Root, 32) && len(s.Copy.Envelope.Ciphertext) == 48
}
