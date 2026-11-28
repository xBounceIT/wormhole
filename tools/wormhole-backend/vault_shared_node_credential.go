package main

import (
	"context"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedNodeCredentialSession interface {
	sharedRuntimeStateSession
	NodeOverrideSupported(context.Context) (bool, error)
	ReadNodeOverride(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, string, string) (sharedpg.TrustState, *sharedpg.NodeOverrideReview, string, error)
	CommitNodeOverride(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.NodeOverrideReview, *vault.UserKeys) (sharedpg.TrustState, string, error)
}

type nodeCredentialReply struct {
	Status                 string                       `json:"status"`
	Workspace              string                       `json:"workspaceId,omitempty"`
	Choice                 *sharedpg.NodeOverrideChoice `json:"choice,omitempty"`
	Review                 string                       `json:"review,omitempty"`
	AuthenticationRequired bool                         `json:"authenticationRequired,omitempty"`
}

func (h *vaultFoundationHandler) sharedNodeCredential(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var action, encoded json.RawMessage
	defer func() { vault.Wipe(raw); vault.Wipe(encoded) }()
	var node, scope, name string
	var confirmation *string
	if len(raw) > 32*1024 || decodeVaultObject(raw, map[string]any{"action": &action, "authentication": &encoded}, "action") != nil ||
		decodeVaultObject(action, map[string]any{"nodeId": &node, "scope": &scope, "credentialName": &name, "confirmation": &confirmation}, "nodeId", "scope", "credentialName") != nil ||
		!vaultCredentialID(node) || (scope != "personal" && scope != "shared" && scope != "inherit") || (scope == "inherit") != (name == "") ||
		len(name) > 1024 || strings.IndexFunc(name, unicode.IsControl) >= 0 || (confirmation != nil && !validRootRotationDigest(*confirmation)) ||
		(encoded != nil && confirmation == nil) {
		return nil, vaultwire.ErrProtocol
	}
	var auth vaultUnlockInput
	if encoded != nil {
		var err error
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
	session, ok := c.session.(sharedNodeCredentialSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := nodeCredentialReply{Status: "unavailable"}
	var tls *sharedpg.VerifiedTLSBundle
	var reviewed *sharedpg.NodeOverrideReview
	var fresh bool
	err = c.withCatalogOperation(ctx, func(ctx context.Context, t sharedpg.TrustState, pending *sharedpg.TrustState) error {
		runtime, err := c.observeRuntime(ctx, session, t, pending)
		if err != nil || !c.tlsManaged || runtime.TLS != sharedpg.TLSVerified || (runtime.Security.Effective != vault.Default && runtime.Security.Effective != vault.Standard) {
			return err
		}
		ok, err := session.NodeOverrideSupported(ctx)
		if err != nil || !ok {
			reply.Status = "unsupported"
			return err
		}
		tls, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		next, r, status, err := session.ReadNodeOverride(ctx, *pending, tls, uuid.MustParse(node), scope, name)
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
		if confirmation != nil && *confirmation != r.Confirmation() {
			reply.Status = "stale"
			return nil
		}
		if r.Unchanged() {
			reply.Status = "unchanged"
			return nil
		}
		fresh = runtime.Security.Effective == vault.Standard
		if confirmation == nil {
			reply = nodeCredentialReply{Status: "review", Workspace: pending.WorkspaceID.String(), Choice: &r.Choice, Review: r.Confirmation(), AuthenticationRequired: fresh}
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
		return h.signSharedCredentialChange(ctx, c, trust, fresh, &auth, &reply.Status, func(keys *vault.UserKeys) (sharedpg.TrustState, string, error) {
			return session.CommitNodeOverride(ctx, trust, tls, reviewed, keys)
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
