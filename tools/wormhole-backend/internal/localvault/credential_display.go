package localvault

import (
	"context"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type CredentialDisplay = NotesDisplay

// The native handler enforces reveal policy/fresh authentication. Resolution,
// revision checking and secret borrowing occur under one owner lock; the ordinary
// renderer receives neither the account identity nor the plaintext.
func (o *Owner) SealConnectionCredentials(ctx context.Context, id, request string, revision uint64, publicKey []byte) (CredentialDisplay, error) {
	var result CredentialDisplay
	err := o.withConnectionCredentials(ctx, id, revision, true, func(workspace string, payload vault.CredentialDisplayPayload) error {
		result = CredentialDisplay{WorkspaceID: workspace, NodeID: id, RequestID: request, RowVersion: strconv.FormatUint(revision, 10)}
		raw, err := vault.EncodeCredentialDisplay(payload)
		if err != nil {
			return err
		}
		defer vault.Wipe(raw)
		if err := ctx.Err(); err != nil {
			return err
		}
		result.Bundle, err = vault.SealCredentialDisplay(publicKey, workspace, id, request, revision, raw)
		return err
	})
	if err != nil {
		return CredentialDisplay{}, err
	}
	return result, nil
}

// The callback borrows only the selected field for native clipboard publication.
// Identity-only copies never decrypt a password or an SSH private key.
func (o *Owner) CopyConnectionCredential(ctx context.Context, id string, revision uint64, field string, copyValue func([]byte) error) error {
	return o.withConnectionCredential(ctx, id, revision, field, func(_ string, value []byte) error { return copyValue(value) })
}

func (o *Owner) withConnectionCredential(ctx context.Context, id string, revision uint64, field string, use func(string, []byte) error) error {
	if field != "username" && field != "domain" && field != "secret" {
		return vault.ErrFormat
	}
	return o.withConnectionCredentials(ctx, id, revision, field == "secret", func(workspace string, payload vault.CredentialDisplayPayload) error {
		if field == "secret" {
			return use(workspace, payload.Secret)
		}
		value := []byte(payload.Username)
		if field == "domain" {
			vault.Wipe(value)
			value = []byte(payload.Domain)
		}
		defer vault.Wipe(value)
		return use(workspace, value)
	})
}

func (o *Owner) withConnectionCredentials(ctx context.Context, id string, revision uint64, needSecret bool, use func(string, vault.CredentialDisplayPayload) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionPath(ctx, id, "", "reveal")
	if err != nil {
		return err
	}
	if r.leaf.RowVersion != revision {
		return vaultstore.ErrConflict
	}
	payload := vault.CredentialDisplayPayload{Username: r.Account.Username, Domain: r.Account.Domain}
	fields := r.leaf.Fields
	ref := vaultstore.SecretRef{OwnerKind: "node", OwnerID: id, Field: "inlinePassword"}
	if r.Account.SourceKind != "inline" {
		fields = nil
		if c := r.Credential; c != nil {
			if c.Provider != "local" {
				return vault.ErrPolicy
			}
			payload.Passphrase = c.Kind == "sshKey"
			ref = vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: "password"}
			if payload.Passphrase {
				ref.Field = "passphrase"
			}
			fields = c.Fields
		}
	}
	release := func(value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload.Secret = value
		return use(r.Identity.WorkspaceID, payload)
	}
	if needSecret {
		for _, field := range fields {
			if field.Field == ref.Field && field.Present {
				return o.withSecret(ctx, ref, field.Version, true, release)
			}
		}
	}
	return release(nil)
}
