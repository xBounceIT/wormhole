package vaultstore

import (
	"context"
	"math"
	"strings"
	"unicode/utf8"
)

// Credential contains only metadata and an authenticated manifest of its fields.
// Deleted credentials remain tombstones: an old insert cannot reuse their ID.
// Removed fields retain a version and encrypt an empty tombstone so re-adding a
// field never resets the authenticated rollback floor.
type CredentialMetadata struct {
	ID                 string `json:"id"`
	OwnerUserID        string `json:"ownerUserId"`
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Kind               string `json:"kind"`
	Username           string `json:"username"`
	Domain             string `json:"domain"`
	Provider           string `json:"provider"`
	BitwardenItemID    string `json:"bitwardenItemId"`
	BitwardenItemName  string `json:"bitwardenItemName"`
	BitwardenFieldPath string `json:"bitwardenFieldPath"`
	PrivateKeyName     string `json:"privateKeyName"`
	CertificateName    string `json:"certificateName"`
}

type Credential struct {
	CredentialMetadata
	// Omit empty legacy provenance so schema upgrades preserve existing MACs.
	CreatedAt  string            `json:"createdAt,omitempty"`
	RowVersion uint64            `json:"rowVersion"`
	Deleted    bool              `json:"deleted"`
	Fields     []CredentialField `json:"fields"`
	Seal       []byte            `json:"seal"`
}

type CredentialField struct {
	Field   string `json:"field"`
	Version uint64 `json:"version"`
	Present bool   `json:"present"`
}

// CredentialStore exposes aggregate operations, not SQL or transaction handles.
// A write installs metadata, all changed DEKs/copies/values and one ChangeSeq in
// one transaction. Unchanged fields must exactly match the previous manifest.
type CredentialStore interface {
	Store
	ReadCredential(context.Context, string) (Credential, error)
	ListCredentials(context.Context, string, int) ([]Credential, error)
	WriteCredential(context.Context, Credential, []Secret, uint64) error
}

func CredentialSecretField(field string) bool {
	switch field {
	case "password", "passphrase", "privateKey", "certificate":
		return true
	}
	return false
}

func metadataText(value string, max int, required bool) bool {
	return len(value) <= max && utf8.ValidString(value) && !strings.ContainsRune(value, 0) && (!required || strings.TrimSpace(value) != "")
}

// Validate checks the stored aggregate including its canonical field ordering.
// Protocol-specific availability and permission checks belong to the resolver.
func (c Credential) Validate() error {
	if len(c.Seal) != 32 {
		return ErrFormat
	}
	return c.ValidateContent()
}

// ValidateContent checks metadata and the field manifest without assuming a seal
// suite. Local storage additionally requires its HMAC shape through Validate;
// shared storage authenticates its Ed25519 seal separately. Neither method proves
// authenticity or grants permission to release a secret.
func (c Credential) ValidateContent() error {
	if !metadataText(c.CreatedAt, 128, false) {
		return ErrFormat
	}
	if !validID(c.ID) || (c.OwnerUserID != "" && !validID(c.OwnerUserID)) || c.RowVersion == 0 || c.RowVersion > math.MaxInt64 || len(c.Fields) > 4 {
		return ErrFormat
	}
	if !metadataText(c.Name, 1024, true) || !metadataText(c.Username, 2048, false) || !metadataText(c.Domain, 2048, false) || !metadataText(c.BitwardenItemID, 2048, false) || !metadataText(c.BitwardenItemName, 4096, false) || !metadataText(c.BitwardenFieldPath, 2048, false) || !metadataText(c.PrivateKeyName, 1024, false) || !metadataText(c.CertificateName, 1024, false) {
		return ErrFormat
	}
	switch c.Protocol {
	case "ssh", "rdp", "vnc":
	default:
		return ErrFormat
	}
	if c.Kind != "password" && c.Kind != "sshKey" {
		return ErrFormat
	}
	if c.Provider != "local" && c.Provider != "bitwarden" {
		return ErrFormat
	}
	if c.Kind == "sshKey" && c.Protocol != "ssh" {
		return ErrFormat
	}
	if c.Provider == "local" && (c.BitwardenItemID != "" || c.BitwardenItemName != "" || c.BitwardenFieldPath != "") {
		return ErrFormat
	}
	if c.Provider == "bitwarden" && (c.BitwardenItemID == "" || c.Kind != "password" || c.PrivateKeyName != "" || c.CertificateName != "") {
		return ErrFormat
	}
	previous := ""
	for _, f := range c.Fields {
		if !CredentialSecretField(f.Field) || f.Field <= previous || f.Version == 0 || f.Version > math.MaxInt64 || (c.Deleted && f.Present) {
			return ErrFormat
		}
		previous = f.Field
		if c.Provider == "bitwarden" && f.Present {
			return ErrFormat
		}
		if f.Present && ((c.Kind == "password" && f.Field != "password") || (c.Kind == "sshKey" && f.Field == "password")) {
			return ErrFormat
		}
	}
	return nil
}
