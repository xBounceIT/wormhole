package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAccountResetIssuer interface {
	sharedRuntimeStateSession
	AccountResetSupported(context.Context) (bool, error)
	PrepareAccountReset(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []sharedpg.Endpoint, *vault.UserKeys, string) (*sharedpg.PreparedAccountReset, error)
	PublishAccountResetHandover(context.Context, sharedpg.TrustState, *sharedpg.PreparedAccountReset, []byte, uuid.UUID, func([]byte) error) (sharedpg.AccountResetHandover, error)
}

type sharedAccountReenrollmentIssuer interface {
	PrepareAccountReenrollment(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []sharedpg.Endpoint, *vault.UserKeys, uuid.UUID, uint64) (*sharedpg.PreparedAccountReset, error)
}

type sharedAccountResetIssueRequest struct {
	path, login string
	requestID   uuid.UUID
	targetID    uuid.UUID
	suspension  uint64
	recipient   []byte
	auth        vaultUnlockInput
}

type sharedAccountResetIssueReply struct {
	Status   string                         `json:"status"`
	Handover *sharedpg.AccountResetHandover `json:"handover,omitempty"`
}

func decodeSharedAccountResetIssue(payload []byte) (sharedAccountResetIssueRequest, error) {
	var request sharedAccountResetIssueRequest
	var requestID string
	var targetID *string
	var authentication, suspension json.RawMessage
	defer func() { vault.Wipe(authentication) }()
	if len(payload) > 48*1024 || decodeVaultObject(payload, map[string]any{
		"path": &request.path, "targetLogin": &request.login, "targetUserId": &targetID, "requestId": &requestID,
		"recipient": &request.recipient, "authentication": &authentication, "suspension": &suspension,
	}, "path", "targetLogin", "requestId", "recipient", "authentication") != nil ||
		!sharedFilePathValid(request.path, ".whreset") || len(request.login) == 0 || len(request.login) > 256 || len(request.recipient) != 32 {
		return sharedAccountResetIssueRequest{}, vaultwire.ErrProtocol
	}
	id, err := uuid.Parse(requestID)
	if err != nil || id == uuid.Nil || id.String() != requestID {
		return sharedAccountResetIssueRequest{}, vaultwire.ErrProtocol
	}
	request.requestID = id
	if targetID != nil {
		if !vaultCredentialID(*targetID) {
			return sharedAccountResetIssueRequest{}, vaultwire.ErrProtocol
		}
		request.targetID, _ = uuid.Parse(*targetID)
	}
	if len(suspension) != 0 {
		var revision string
		if request.targetID == uuid.Nil || json.Unmarshal(suspension, &revision) != nil {
			return sharedAccountResetIssueRequest{}, vaultwire.ErrProtocol
		}
		request.suspension, err = vaultCredentialRevision(revision, false)
		if err != nil {
			return sharedAccountResetIssueRequest{}, vaultwire.ErrProtocol
		}
	}
	request.auth, err = decodeSharedExportAuthentication(authentication)
	return request, err
}

// Issue only from an admitted custodian whose device has freshly verified its
// factors. The protected display is the only recipient of the sealed factors.
func (h *vaultFoundationHandler) issueSharedAccountReset(ctx context.Context, payload []byte) (json.RawMessage, error) {
	request, err := decodeSharedAccountResetIssue(payload)
	defer request.auth.wipe()
	if err != nil {
		return nil, err
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := controller.session.(sharedAccountResetIssuer)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := sharedAccountResetIssueReply{Status: "unavailable"}
	err = controller.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil {
			return nil
		}
		if _, err := vault.SharedSalt(trust.WorkspaceID.String(), request.login); err != nil {
			reply.Status = "invalid-login"
			return nil
		}
		valid, err := h.verifySharedExportFactors(ctx, controller, trust.Revision, request.auth)
		if err != nil {
			return err
		}
		if !valid {
			reply.Status = "invalid-authentication"
			return nil
		}
		if request.suspension == 0 {
			supported, err := session.AccountResetSupported(ctx)
			if err != nil || !supported {
				return err
			}
		}
		handover, err := controller.createSharedAccountReset(ctx, session, trust, bundle, request)
		switch {
		case err == nil:
			reply = sharedAccountResetIssueReply{Status: "issued", Handover: &handover}
		case errors.Is(err, sharedpg.ErrAccountRecovery), errors.Is(err, sharedpg.ErrChangeInProgress):
			// The server can reject insufficient custody, a missing target or a concurrent change.
		case errors.Is(err, sharedpg.ErrAccountResetLogging):
			reply.Status = "publication-disabled"
		case errors.Is(err, sharedpg.ErrAccountResetRecipient):
			reply.Status = "invalid-recipient"
		case errors.Is(err, sharedpg.ErrAccountResetSave):
			reply.Status = "save-failed"
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

func (c *sharedAdmissionController) createSharedAccountReset(ctx context.Context, session sharedAccountResetIssuer, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle, request sharedAccountResetIssueRequest) (handover sharedpg.AccountResetHandover, err error) {
	var settings sharedpg.Settings
	err = c.root.With(func(key []byte) error {
		var err error
		settings, err = readSharedTransportSetup(sharedAdmissionOptions{
			TrustPath: c.trustPath, Binding: c.trustBinding, OSFloor: c.runtimeOSFloor,
			UserFloor: c.runtimeUserFloor, Request: sharedpg.AdmissionRequest{API: 1},
		}, key, trust)
		return err
	})
	if err != nil {
		return handover, err
	}
	var prepared *sharedpg.PreparedAccountReset
	err = c.privateKeys.With(func(keys []byte) error {
		if len(keys) != 64 {
			return sharedpg.ErrAuthentication
		}
		var err error
		actor := &vault.UserKeys{EncryptionPrivate: keys[:32:32], SigningSeed: keys[32:]}
		if request.suspension != 0 {
			issuer, ok := session.(sharedAccountReenrollmentIssuer)
			if !ok {
				return sharedpg.ErrAccountRecovery
			}
			prepared, err = issuer.PrepareAccountReenrollment(ctx, trust, bundle, settings.Endpoints, actor, request.targetID, request.suspension)
		} else {
			prepared, err = session.PrepareAccountReset(ctx, trust, bundle, settings.Endpoints, actor, request.login)
		}
		return err
	})
	defer func() { err = errors.Join(err, prepared.Close()) }()
	if err != nil {
		return handover, err
	}
	if request.targetID != uuid.Nil && !prepared.MatchesTarget(request.targetID) {
		return handover, sharedpg.ErrAccountRecovery
	}
	if request.suspension != 0 && !prepared.MatchesReenrollment(request.targetID, request.login, request.suspension) {
		return handover, sharedpg.ErrAccountRecovery
	}
	return session.PublishAccountResetHandover(ctx, trust, prepared, request.recipient, request.requestID, func(document []byte) error {
		return publishSharedSetupFile(request.path, document)
	})
}
