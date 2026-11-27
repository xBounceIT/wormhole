package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Native stdin contract only. Secret edits must originate in the protected
// native flow; this is not a renderer IPC API. The transport owns/wipes payload.
// Revisions are decimal strings so a future JS metadata client cannot round them.
type vaultCredentialView struct {
	vaultstore.CredentialMetadata
	CreatedAt      string `json:"createdAt,omitempty"`
	RowVersion     string `json:"rowVersion"`
	HasPassword    bool   `json:"hasPassword"`
	HasPassphrase  bool   `json:"hasPassphrase"`
	HasPrivateKey  bool   `json:"hasPrivateKey"`
	HasCertificate bool   `json:"hasCertificate"`
}

func credentialView(c vaultstore.Credential) vaultCredentialView {
	v := vaultCredentialView{CredentialMetadata: c.CredentialMetadata, CreatedAt: c.CreatedAt, RowVersion: strconv.FormatUint(c.RowVersion, 10)}
	for _, f := range c.Fields {
		switch f.Field {
		case "password":
			v.HasPassword = f.Present
		case "passphrase":
			v.HasPassphrase = f.Present
		case "privateKey":
			v.HasPrivateKey = f.Present
		case "certificate":
			v.HasCertificate = f.Present
		}
	}
	return v
}

// Exact unique property names, no null coercion, and no trailing document.
// Raw intermediates are wiped, including on partial decode failures.
func decodeVaultObject(payload []byte, targets map[string]any, required ...string) error {
	return decodeVaultNullableObject(payload, targets, nil, required...)
}

// Only explicitly named inheritance fields may decode null. Other contracts
// keep their existing strict null rejection through decodeVaultObject.
func decodeVaultNullableObject(payload []byte, targets map[string]any, nullable map[string]bool, required ...string) error {
	if len(payload) == 0 || len(payload) > vaultwire.MaxFrameBytes || !utf8.Valid(payload) {
		return vaultwire.ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return vaultwire.ErrProtocol
	}
	seen := make(map[string]bool, len(targets))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return vaultwire.ErrProtocol
		}
		name, ok := token.(string)
		target, known := targets[name]
		if !ok || !known || seen[name] {
			return vaultwire.ErrProtocol
		}
		seen[name] = true
		var raw json.RawMessage
		err = d.Decode(&raw)
		if err == nil && (!bytes.Equal(raw, []byte("null")) || nullable[name]) {
			err = json.Unmarshal(raw, target)
		} else {
			err = vaultwire.ErrProtocol
		}
		vault.Wipe(raw)
		if err != nil {
			return vaultwire.ErrProtocol
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return vaultwire.ErrProtocol
	}
	if _, err := d.Token(); err != io.EOF {
		return vaultwire.ErrProtocol
	}
	for _, name := range required {
		if !seen[name] {
			return vaultwire.ErrProtocol
		}
	}
	return nil
}

func vaultCredentialID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil && u.String() == id
}

func vaultCredentialRevision(value string, allowZero bool) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 63)
	if err != nil || strconv.FormatUint(n, 10) != value || (!allowZero && n == 0) {
		return 0, vaultwire.ErrProtocol
	}
	return n, nil
}

func decodeVaultCredentialMetadata(raw []byte) (m vaultstore.CredentialMetadata, err error) {
	if len(raw) > 128*1024 {
		return m, vaultwire.ErrProtocol
	}
	err = decodeVaultObject(raw, map[string]any{
		"id": &m.ID, "name": &m.Name, "protocol": &m.Protocol, "kind": &m.Kind,
		"username": &m.Username, "domain": &m.Domain, "provider": &m.Provider,
		"bitwardenItemId": &m.BitwardenItemID, "bitwardenItemName": &m.BitwardenItemName,
		"bitwardenFieldPath": &m.BitwardenFieldPath, "privateKeyName": &m.PrivateKeyName,
		"certificateName": &m.CertificateName,
	}, "id", "name", "protocol", "kind", "provider")
	// Local owner only; shared owner selection requires authenticated identity.
	c := vaultstore.Credential{CredentialMetadata: m, RowVersion: 1, Seal: make([]byte, 32)}
	if err != nil || c.Validate() != nil {
		return m, vaultwire.ErrProtocol
	}
	return m, nil
}

func wipeVaultCredentialChanges(changes []localvault.SecretChange) {
	for i := range changes {
		vault.Wipe(changes[i].Value)
	}
}

func decodeVaultCredentialChanges(raw []byte) (changes []localvault.SecretChange, err error) {
	return decodeVaultSecretChanges(raw, vaultstore.CredentialSecretField, 4)
}

func decodeVaultSecretChanges(raw []byte, allowed func(string) bool, maximum int) (changes []localvault.SecretChange, err error) {
	// On failure, no partial decoded secret escapes the decoder.
	defer func() {
		if err != nil {
			wipeVaultCredentialChanges(changes)
			changes = nil
		}
	}()
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, e := d.Token(); e != nil || token != json.Delim('[') {
		return changes, vaultwire.ErrProtocol
	}
	seen := make(map[string]bool, maximum)
	for d.More() {
		if len(changes) == maximum {
			return changes, vaultwire.ErrProtocol
		}
		var item json.RawMessage
		e := d.Decode(&item)
		var change localvault.SecretChange
		// Decode only base64 strings, never JSON byte arrays or null coercions.
		var value json.RawMessage
		if e == nil {
			e = decodeVaultObject(item, map[string]any{"field": &change.Field, "remove": &change.Remove, "value": &value}, "field", "remove")
		}
		vault.Wipe(item)
		if len(value) != 0 {
			if value[0] != '"' || json.Unmarshal(value, &change.Value) != nil {
				e = vaultwire.ErrProtocol
			}
		}
		vault.Wipe(value)
		changes = append(changes, change)
		if e != nil || !allowed(change.Field) || seen[change.Field] || len(change.Value) > vault.MaxSecretBytes || (change.Remove && len(value) != 0) || (!change.Remove && len(value) == 0) {
			return changes, vaultwire.ErrProtocol
		}
		seen[change.Field] = true
	}
	if token, e := d.Token(); e != nil || token != json.Delim(']') {
		return changes, vaultwire.ErrProtocol
	}
	if _, e := d.Token(); e != io.EOF {
		return changes, vaultwire.ErrProtocol
	}
	return changes, nil
}

func (h *vaultFoundationHandler) credential(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	var result any
	var err error
	switch operation {
	case "credential-list":
		var after string
		var limit int
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"after": &after, "limit": &limit}, "after", "limit") != nil || (after != "" && !vaultCredentialID(after)) || limit < 1 || limit > 16 {
			return nil, vaultwire.ErrProtocol
		}
		var credentials []vaultstore.Credential
		credentials, err = h.owner.ListCredentials(ctx, after, limit)
		views := make([]vaultCredentialView, 0, len(credentials))
		for _, c := range credentials {
			views = append(views, credentialView(c))
		}
		result = struct {
			Credentials []vaultCredentialView `json:"credentials"`
		}{views}
	case "credential-read", "credential-delete":
		var id, version string
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) {
			return nil, vaultwire.ErrProtocol
		}
		revision, e := vaultCredentialRevision(version, operation == "credential-read")
		if e != nil || (operation == "credential-delete" && revision == math.MaxInt64) {
			return nil, vaultwire.ErrProtocol
		}
		if operation == "credential-read" {
			var c vaultstore.Credential
			c, err = h.owner.ReadCredential(ctx, id, revision)
			result = credentialView(c)
		} else {
			err = h.owner.DeleteCredential(ctx, id, revision)
			result = struct {
				ID         string `json:"id"`
				RowVersion string `json:"rowVersion"`
				Deleted    bool   `json:"deleted"`
			}{id, strconv.FormatUint(revision+1, 10), true}
		}
	case "credential-save":
		var metadata, edits json.RawMessage
		var version string
		e := decodeVaultObject(payload, map[string]any{"metadata": &metadata, "changes": &edits, "rowVersion": &version}, "metadata", "changes", "rowVersion")
		defer vault.Wipe(metadata)
		defer vault.Wipe(edits)
		if e != nil {
			return nil, e
		}
		revision, e := vaultCredentialRevision(version, true)
		if e != nil || revision == math.MaxInt64 {
			return nil, vaultwire.ErrProtocol
		}
		m, e := decodeVaultCredentialMetadata(metadata)
		if e != nil {
			return nil, e
		}
		changes, e := decodeVaultCredentialChanges(edits)
		defer wipeVaultCredentialChanges(changes)
		if e != nil {
			return nil, e
		}
		var c vaultstore.Credential
		c, err = h.owner.PutCredential(ctx, m, changes, revision)
		result = credentialView(c)
	default:
		return nil, vaultwire.ErrProtocol
	}
	return h.domainResult(result, err)
}

func (h *vaultFoundationHandler) domainResult(result any, err error) (json.RawMessage, error) {
	if err != nil {
		// A corrupt authenticated row must never leave a usable owner. Format
		// failures after input validation are also retired conservatively.
		if errors.Is(err, vault.ErrAuthentication) || errors.Is(err, vault.ErrRollback) || errors.Is(err, vault.ErrFormat) || errors.Is(err, vaultstore.ErrFormat) || errors.Is(err, vaultstore.ErrIdentity) || errors.Is(err, vaultstore.ErrClosed) {
			return nil, h.retire(err)
		}
		return nil, err
	}
	return json.Marshal(result)
}
