package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/internal/sshauth"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"golang.org/x/crypto/ssh"
)

// Native stdin only. Main substitutes its one-use file selections; renderer
// requests never supply paths. Secret values have separate mutable byte fields.
func (h *vaultFoundationHandler) editCredential(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 128*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var metadata, rawPassword, rawPassphrase json.RawMessage
	defer func() { vault.Wipe(metadata); vault.Wipe(rawPassword); vault.Wipe(rawPassphrase) }()
	var version, id string
	if decodeVaultObject(payload, map[string]any{"metadata": &metadata, "rowVersion": &version, "password": &rawPassword, "passphrase": &rawPassphrase}, "metadata", "rowVersion", "password", "passphrase") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var password, passphrase []byte
	defer func() { vault.Wipe(password); vault.Wipe(passphrase) }()
	for _, field := range []struct {
		raw  []byte
		into *[]byte
	}{{rawPassword, &password}, {rawPassphrase, &passphrase}} {
		if len(field.raw) == 0 || field.raw[0] != '"' || json.Unmarshal(field.raw, field.into) != nil || !utf8.Valid(*field.into) || utf8.RuneCount(*field.into) > maxStoredCredentialPassword {
			return nil, vaultwire.ErrProtocol
		}
	}
	var request credentialCreateRequest
	if decodeVaultObject(metadata, map[string]any{
		"id": &id, "name": &request.Name, "protocol": &request.Protocol, "kind": &request.Kind,
		"username": &request.Username, "domain": &request.Domain, "provider": &request.Provider,
		"bitwardenItemId": &request.BitwardenItemID, "bitwardenItemName": &request.BitwardenItemName,
		"privateKeyPath": &request.PrivateKeyPath, "certificatePath": &request.CertificatePath,
		"clearPassphrase": &request.ClearPassphrase, "clearCertificate": &request.ClearCertificate,
	}, "id", "name", "protocol", "kind", "username", "domain", "provider", "bitwardenItemId", "bitwardenItemName", "privateKeyPath", "certificatePath", "clearPassphrase", "clearCertificate") != nil {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, true)
	if err != nil || revision == math.MaxInt64 || (revision == 0) != (id == "") || (id != "" && !vaultCredentialID(id)) {
		return nil, vaultwire.ErrProtocol
	}
	// Reuse metadata validation without making immutable copies of secret bytes.
	if len(password) != 0 {
		request.Password = "present"
	}
	if len(passphrase) != 0 {
		request.Passphrase = "present"
	}
	draft, err := normalizeCredentialDraft(request, revision != 0)
	if err != nil || (revision == 0 && draft.provider != 0) || (draft.provider != 0 && len(password) != 0) {
		return nil, vaultwire.ErrProtocol
	}
	previous := vaultstore.Credential{}
	if revision != 0 {
		previous, err = h.owner.ReadCredential(ctx, id, 0)
		if err != nil {
			return h.domainResult(nil, err)
		}
		if previous.RowVersion != revision || previous.Kind != draft.kindName {
			return nil, vaultstore.ErrConflict
		}
	} else {
		id = uuid.NewString()
	}
	present := make(map[string]bool, len(previous.Fields))
	for _, f := range previous.Fields {
		present[f.Field] = f.Present
	}
	m := previous.CredentialMetadata
	m.ID, m.Name, m.Protocol, m.Kind = id, draft.name, draft.protocol, draft.kindName
	m.Username, m.Domain = draft.username, draft.domain
	m.Provider, m.BitwardenItemID, m.BitwardenItemName, m.BitwardenFieldPath = "local", "", "", ""
	changes := make([]localvault.SecretChange, 0, 4)
	remove := func(field string) {
		if present[field] {
			changes = append(changes, localvault.SecretChange{Field: field, Remove: true})
		}
	}
	if draft.kind == 0 {
		if draft.provider != 0 {
			m.Provider, m.BitwardenItemID, m.BitwardenItemName, m.BitwardenFieldPath = "bitwarden", draft.itemID, draft.itemName, draft.fieldPath
			remove("password")
		} else if len(password) != 0 {
			changes = append(changes, localvault.SecretChange{Field: "password", Value: password})
		} else if previous.Provider != "local" || !present["password"] {
			return nil, vaultwire.ErrProtocol
		}
	} else {
		var key, certificate, validationPassword []byte
		defer func() { vault.Wipe(key); vault.Wipe(certificate); vault.Wipe(validationPassword) }()
		readStored := func(field string) ([]byte, error) {
			var value []byte
			err := h.owner.WithCredentialSecret(ctx, id, field, revision, func(bytes []byte) error { value = append([]byte{}, bytes...); return nil })
			return value, err
		}
		if draft.privateKeyPath != "" {
			key, err = readBoundedRegularFile(draft.privateKeyPath, maxSshPrivateKeyBytes)
			if err != nil || len(key) == 0 {
				return nil, vaultwire.ErrProtocol
			}
			m.PrivateKeyName = draft.privateKeyFileName
		} else if !present["privateKey"] {
			return nil, vaultwire.ErrProtocol
		} else if len(passphrase) != 0 || draft.certificatePath != "" {
			key, err = readStored("privateKey")
			if err != nil {
				return h.domainResult(nil, err)
			}
		}
		validationPassword = append([]byte{}, passphrase...)
		if len(key) != 0 && len(passphrase) == 0 && draft.privateKeyPath == "" && !draft.clearPassphrase && present["passphrase"] {
			validationPassword, err = readStored("passphrase")
			if err != nil {
				return h.domainResult(nil, err)
			}
		}
		if len(key) != 0 && validateVaultEditorKey(key, validationPassword) != nil {
			return nil, vaultwire.ErrProtocol
		}
		if draft.clearCertificate {
			remove("certificate")
			m.CertificateName = ""
		} else if draft.certificatePath != "" {
			certificate, err = readBoundedRegularFile(draft.certificatePath, maxSSHCertificateBytes)
			if err != nil {
				return nil, vaultwire.ErrProtocol
			}
			m.CertificateName = sshCertificateDisplayName(filepath.Base(draft.certificatePath))
		} else if len(key) != 0 && present["certificate"] {
			certificate, err = readStored("certificate")
			if err != nil {
				return h.domainResult(nil, err)
			}
		}
		if len(certificate) != 0 || draft.certificatePath != "" {
			cert, err := parseSSHUserCertificate(certificate)
			if err != nil || sshauth.ValidateCertificateKeyBytes(cert, key, validationPassword) != nil || (draft.certificatePath != "" && checkSSHCertificateTime(cert, time.Now()) != nil) {
				return nil, vaultwire.ErrProtocol
			}
		}
		if draft.privateKeyPath != "" {
			changes = append(changes, localvault.SecretChange{Field: "privateKey", Value: key})
		}
		if draft.certificatePath != "" {
			changes = append(changes, localvault.SecretChange{Field: "certificate", Value: certificate})
		}
		if len(passphrase) != 0 {
			changes = append(changes, localvault.SecretChange{Field: "passphrase", Value: passphrase})
		} else if draft.clearPassphrase || draft.privateKeyPath != "" {
			remove("passphrase")
		}
	}
	saved, err := h.owner.PutCredential(ctx, m, changes, revision)
	return h.domainResult(struct {
		ID         string `json:"id"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{saved.ID, strconv.FormatUint(saved.RowVersion, 10), true}, err)
}

func validateVaultEditorKey(key, password []byte) error {
	_, err := parseSSHSigner(key, nil)
	if err == nil {
		if len(password) != 0 {
			return vaultwire.ErrProtocol
		}
		return nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return err
	}
	if len(password) == 0 {
		return nil
	}
	_, err = parseSSHSigner(key, password)
	return err
}
