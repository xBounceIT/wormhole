package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type invitationClipboard struct {
	workspace, device, account, request, invite uuid.UUID
	sealed                                      vault.Envelope
	expires                                     time.Time
}

func (c *invitationClipboard) binding() vault.Binding {
	return vault.Binding{WorkspaceID: c.workspace.String(), Table: "member-invitation-clipboard", OwnerID: c.invite.String(),
		Field: c.request.String() + "/" + c.device.String(), KeyID: c.account.String(), KeyVersion: 1}
}

func (c *invitationClipboard) prepare(root []byte, trust sharedpg.TrustState, request, invite uuid.UUID, expiresAt int64, code []byte) error {
	if len(code) != vault.InviteCodeBytes || expiresAt <= time.Now().Unix() || request == uuid.Nil || invite == uuid.Nil || trust.DeviceID == uuid.Nil || trust.UserID == uuid.Nil || trust.WorkspaceID == uuid.Nil {
		return vault.ErrFormat
	}
	*c = invitationClipboard{workspace: trust.WorkspaceID, device: trust.DeviceID, account: trust.UserID, request: request, invite: invite,
		expires: time.Unix(expiresAt, 0)}
	var err error
	c.sealed, err = vault.Seal(root, c.binding(), code)
	return err
}

type invitationCopyReply struct {
	Status  string              `json:"status"`
	Seconds int                 `json:"expiresInSeconds,omitempty"`
	Bundle  *vault.SealedBundle `json:"bundle,omitempty"`
}

func (h *vaultFoundationHandler) dismissMemberInvitation(raw []byte) (json.RawMessage, error) {
	var request string
	if len(raw) > 128 || decodeVaultObject(raw, map[string]any{"requestId": &request}, "requestId") != nil || !vaultCredentialID(request) {
		return nil, vaultwire.ErrProtocol
	}
	if h.memberClipboard != nil && h.memberClipboard.request.String() == request {
		h.memberClipboard = nil
	}
	return json.RawMessage("true"), nil
}

func (h *vaultFoundationHandler) copyMemberInvitationCode(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var request, invite, copyID string
	var recipient []byte
	if len(raw) > 1024 || decodeVaultObject(raw, map[string]any{"requestId": &request, "inviteId": &invite, "copyId": &copyID, "recipient": &recipient},
		"requestId", "inviteId", "copyId") != nil || !vaultCredentialID(request) || !vaultCredentialID(invite) || !vaultCredentialID(copyID) ||
		(runtime.GOOS == "linux" && len(recipient) != 32) || (runtime.GOOS != "linux" && len(recipient) != 0) {
		return nil, vaultwire.ErrProtocol
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	reply := invitationCopyReply{Status: "unavailable"}
	ticket := h.memberClipboard
	if ticket == nil || !time.Now().Before(ticket.expires) || ticket.invite.String() != invite || ticket.request.String() != request {
		return json.Marshal(reply)
	}
	session, ok := c.session.(sharedRuntimeStateSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	var seconds int
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		state, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !state.Administrator || !c.tlsManaged || state.TLS != sharedpg.TLSVerified {
			return err
		}
		if lifetime, err := vaultClipboardLifetime(state.Security.Effective); err == nil {
			seconds = int(lifetime / time.Second)
		}
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seconds == 0 || trust.WorkspaceID != ticket.workspace || trust.DeviceID != ticket.device || trust.UserID != ticket.account ||
			!time.Now().Before(ticket.expires) {
			return nil
		}
		return c.root.With(func(root []byte) error {
			code, err := vault.Open(root, ticket.binding(), ticket.sealed)
			if err != nil {
				return err
			}
			defer vault.Wipe(code)
			if len(code) != vault.InviteCodeBytes {
				return vault.ErrFormat
			}
			value := hex.AppendEncode(nil, code)
			defer vault.Wipe(value)
			if runtime.GOOS == "linux" {
				id, _ := uuid.Parse(copyID)
				bundle, err := vault.SealMemberInvitationClipboard(recipient, ticket.workspace, ticket.request, ticket.invite, id, seconds, value)
				if err != nil {
					return err
				}
				reply = invitationCopyReply{Status: "sealed", Bundle: &bundle}
				return nil
			}
			if err := h.writeNativeClipboard(ctx, value, time.Duration(seconds)*time.Second); err != nil {
				return nil
			}
			reply = invitationCopyReply{Status: "copied", Seconds: seconds}
			return nil
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
