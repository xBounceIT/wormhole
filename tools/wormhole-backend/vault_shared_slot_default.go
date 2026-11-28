package main

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedSlotDefaultSession interface {
	sharedRuntimeStateSession
	SlotDefaultSupported(context.Context) (bool, error)
	PersonalSlotSupported(context.Context) (bool, error)
	ReadPersonalSlot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, string) (sharedpg.TrustState, *sharedpg.SlotReview, string, error)
	CommitPersonalSlot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.SlotReview, *vault.UserKeys) (sharedpg.TrustState, string, error)
	ReadSlotDefault(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, string) (sharedpg.TrustState, *sharedpg.SlotReview, string, error)
	CommitSlotDefault(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.SlotReview, *vault.UserKeys) (sharedpg.TrustState, string, error)
}

type slotDefaultConfirmation struct{ workspace, user, slotRevision, valueRevision, credentialID, credentialRevision string }

func decodeSlotDefaultConfirmation(raw []byte, name string, personal bool) (*slotDefaultConfirmation, error) {
	var r slotDefaultConfirmation
	fields := map[string]any{"workspaceId": &r.workspace, "slotRevision": &r.slotRevision, "credentialId": &r.credentialID, "credentialRevision": &r.credentialRevision}
	required := []string{"workspaceId", "slotRevision", "credentialId", "credentialRevision"}
	if personal {
		fields["userId"], fields["valueRevision"] = &r.user, &r.valueRevision
		required = append(required, "userId", "valueRevision")
	}
	if decodeVaultObject(raw, fields, required...) != nil || !vaultCredentialID(r.workspace) {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(r.slotRevision, false)
	if err != nil || (!personal && revision >= math.MaxInt64) {
		return nil, vaultwire.ErrProtocol
	}
	if personal {
		revision, err = vaultCredentialRevision(r.valueRevision, true)
		if err != nil || revision >= math.MaxInt64 || !vaultCredentialID(r.user) {
			return nil, vaultwire.ErrProtocol
		}
	}
	if name == "" {
		if r.credentialID != "" || r.credentialRevision != "" {
			return nil, vaultwire.ErrProtocol
		}
	} else if _, err = vaultCredentialRevision(r.credentialRevision, false); err != nil || !vaultCredentialID(r.credentialID) {
		return nil, vaultwire.ErrProtocol
	}
	return &r, nil
}

type sharedSlotDefaultReply struct {
	Status                 string               `json:"status"`
	WorkspaceID            string               `json:"workspaceId,omitempty"`
	Choice                 *sharedpg.SlotChoice `json:"choice,omitempty"`
	AuthenticationRequired bool                 `json:"authenticationRequired,omitempty"`
}

func (h *vaultFoundationHandler) sharedSlotChange(ctx context.Context, raw []byte, personal bool) (json.RawMessage, error) {
	var action, encoded, confirmed json.RawMessage
	defer func() { vault.Wipe(raw); vault.Wipe(encoded) }()
	var id, name string
	if len(raw) > 32*1024 || decodeVaultObject(raw, map[string]any{"action": &action, "authentication": &encoded}, "action") != nil ||
		decodeVaultObject(action, map[string]any{"slotId": &id, "credentialName": &name, "confirmation": &confirmed}, "slotId", "credentialName") != nil ||
		!vaultCredentialID(id) || len(name) > 1024 || strings.IndexFunc(name, unicode.IsControl) >= 0 || (encoded != nil && confirmed == nil) {
		return nil, vaultwire.ErrProtocol
	}
	var confirmation *slotDefaultConfirmation
	var err error
	if confirmed != nil {
		confirmation, err = decodeSlotDefaultConfirmation(confirmed, name, personal)
		if err != nil {
			return nil, err
		}
	}
	var auth vaultUnlockInput
	if encoded != nil {
		auth, err = decodeSharedExportAuthentication(encoded)
		defer auth.wipe()
		if err != nil {
			return nil, err
		}
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedSlotDefaultSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	supports, read, commit := session.SlotDefaultSupported, session.ReadSlotDefault, session.CommitSlotDefault
	if personal {
		supports, read, commit = session.PersonalSlotSupported, session.ReadPersonalSlot, session.CommitPersonalSlot
	}
	reply := sharedSlotDefaultReply{Status: "unavailable"}
	var tls *sharedpg.VerifiedTLSBundle
	var reviewed *sharedpg.SlotReview
	var fresh bool
	err = c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		runtime, err := c.observeRuntime(ctx, session, trust, pending)
		if err != nil || (!personal && !runtime.Administrator) || !c.tlsManaged || runtime.TLS != sharedpg.TLSVerified ||
			(runtime.Security.Effective != vault.Default && runtime.Security.Effective != vault.Standard) {
			return err
		}
		if confirmation != nil && (confirmation.workspace != pending.WorkspaceID.String() || (personal && confirmation.user != pending.UserID.String())) {
			return nil
		}
		supported, err := supports(ctx)
		if err != nil || !supported {
			reply.Status = "unsupported"
			return err
		}
		tls, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		next, r, status, err := read(ctx, *pending, tls, uuid.MustParse(id), name)
		if next.Revision != 0 {
			*pending = next
		}
		if err != nil {
			return err
		}
		if r == nil {
			reply.Status = status
			return nil
		}
		fresh = runtime.Security.Effective == vault.Standard
		if confirmation == nil {
			if r.Unchanged() {
				reply.Status = "unchanged"
				return nil
			}
			reply = sharedSlotDefaultReply{Status: "review", WorkspaceID: pending.WorkspaceID.String(), Choice: &r.Choice, AuthenticationRequired: fresh}
			return nil
		}
		if confirmation.slotRevision != r.Choice.SlotRevision || confirmation.credentialID != r.Choice.CredentialID ||
			confirmation.credentialRevision != r.Choice.CredentialRevision || confirmation.valueRevision != r.Choice.ValueRevision || r.Unchanged() {
			reply.Status = "stale"
			return nil
		}
		if fresh && encoded == nil {
			reply.Status = "authentication-required"
			return nil
		}
		reviewed = r
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if reviewed == nil {
			return nil
		}
		if fresh {
			valid, err := h.verifySharedExportFactors(ctx, c, trust.Revision, auth)
			auth.wipe()
			if err != nil || !valid {
				return err
			}
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrTrustState
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			next, status, err := commit(ctx, trust, tls, reviewed, keys)
			if next.Revision != 0 && next.Revision != trust.Revision {
				if e := c.commitCatalogTrust(trust, next); e != nil {
					return e
				}
			}
			reply.Status = status
			return err
		})
	}, confirmation != nil)
	if err != nil {
		return nil, h.retire(err)
	}
	if reply.Status == "saved" {
		h.notifySharedCatalog()
	}
	return json.Marshal(reply)
}
