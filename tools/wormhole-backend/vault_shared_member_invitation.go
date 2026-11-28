package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedMemberInvitationIssuer interface {
	sharedRuntimeStateSession
	MemberInvitationSupported(context.Context) (bool, error)
	IssueMemberInvitation(context.Context, sharedpg.TrustState, sharedpg.Settings, *vault.UserKeys, sharedpg.MemberInvitationRequest) (sharedpg.MemberInvitationHandover, error)
}

type sharedMemberInvitationReply struct {
	Status   string                             `json:"status"`
	Handover *sharedpg.MemberInvitationHandover `json:"handover,omitempty"`
}

func (h *vaultFoundationHandler) issueMemberInvitation(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var workspace, request, login, name string
	var recipient []byte
	var authentication json.RawMessage
	defer func() { vault.Wipe(authentication) }()
	if len(raw) > 48*1024 || decodeVaultObject(raw, map[string]any{
		"workspaceId": &workspace, "requestId": &request, "login": &login, "name": &name,
		"recipient": &recipient, "authentication": &authentication,
	}, "workspaceId", "requestId", "login", "name", "recipient", "authentication") != nil ||
		!vaultCredentialID(workspace) || !vaultCredentialID(request) || len(recipient) != 32 ||
		len(name) > 4096 || strings.IndexFunc(name, unicode.IsControl) >= 0 ||
		len(login) == 0 || len(login) > 256 || strings.IndexFunc(login, unicode.IsControl) >= 0 {
		return nil, vaultwire.ErrProtocol
	}
	auth, err := decodeSharedExportAuthentication(authentication)
	defer auth.wipe()
	if err != nil {
		return nil, err
	}
	reply := sharedMemberInvitationReply{Status: "unavailable"}
	if _, err := vault.SharedSalt(workspace, login); err != nil {
		reply.Status = "invalid-login"
		return json.Marshal(reply)
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedMemberInvitationIssuer)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	requestID, _ := uuid.Parse(request)
	err = c.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, tls *sharedpg.VerifiedTLSBundle) error {
		if tls == nil || trust.WorkspaceID.String() != workspace {
			return nil
		}
		supported, err := session.MemberInvitationSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		valid, err := h.verifySharedExportFactors(ctx, c, trust.Revision, auth)
		if err != nil {
			return err
		}
		if !valid {
			reply.Status = "invalid-authentication"
			return nil
		}
		settings, err := c.currentTransportSettings(trust)
		if err != nil {
			return err
		}
		var handover sharedpg.MemberInvitationHandover
		var clipboard invitationClipboard
		issuance := sharedpg.MemberInvitationRequest{Login: login, Name: name, RequestID: requestID, Recipient: recipient,
			PrepareCopy: func(invite uuid.UUID, expiresAt int64, code []byte) error {
				return c.root.With(func(root []byte) error {
					return clipboard.prepare(root, trust, requestID, invite, expiresAt, code)
				})
			},
		}
		err = c.privateKeys.With(func(rawKeys []byte) error {
			if len(rawKeys) != 64 {
				return sharedpg.ErrAuthentication
			}
			keys := &vault.UserKeys{EncryptionPrivate: rawKeys[:32:32], SigningSeed: rawKeys[32:]}
			var issueErr error
			handover, issueErr = session.IssueMemberInvitation(ctx, trust, settings, keys, issuance)
			return issueErr
		})
		switch {
		case err == nil:
			h.memberClipboard = &clipboard
			reply = sharedMemberInvitationReply{Status: "issued", Handover: &handover}
		case errors.Is(err, sharedpg.ErrAccountRevision):
			reply.Status = "changed"
		case errors.Is(err, sharedpg.ErrChangeInProgress):
			reply.Status = "busy"
		case errors.Is(err, sharedpg.ErrAccountResetLogging):
			reply.Status = "publication-disabled"
		case errors.Is(err, sharedpg.ErrMemberInvitationRecipient):
			reply.Status = "invalid-recipient"
		case errors.Is(err, sharedpg.ErrServerCertificateAuthority), errors.Is(err, sharedpg.ErrAccountRecovery):
			// A valid session can lose custody between opening this window and confirming.
		default:
			return err
		}
		return nil
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
