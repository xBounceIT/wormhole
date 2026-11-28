package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedPersonalRootRecoverySession interface {
	sharedRuntimeStateSession
	PersonalRootRecoverySupported(context.Context) (bool, error)
	PreparePersonalRootRecovery(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle,
		sharedpg.PersonalRootRecoveryRequest) (sharedpg.TrustState, sharedpg.PersonalRootRecoveryReply, *sharedpg.PersonalRootRecoveryPreparation, error)
	CommitPreparedPersonalRootRecovery(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle,
		*sharedpg.PersonalRootRecoveryPreparation, *vault.UserKeys) (sharedpg.PersonalRootRecoveryReply, error)
}

func decodeSharedPersonalRootRecovery(raw []byte) (request sharedpg.PersonalRootRecoveryRequest, auth vaultUnlockInput, err error) {
	var account, suspension string
	var review, authentication json.RawMessage
	defer func() { vault.Wipe(authentication) }()
	fields := map[string]any{"accountId": &account, "suspension": &suspension, "review": &review, "authentication": &authentication}
	if len(raw) > 48*1024 || decodeVaultObject(raw, fields, "accountId", "suspension") != nil || !vaultCredentialID(account) ||
		(len(review) == 0) != (len(authentication) == 0) {
		return request, auth, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(suspension, false)
	if err != nil {
		return request, auth, vaultwire.ErrProtocol
	}
	request.AccountID, request.Suspension = uuid.MustParse(account), revision
	if len(review) != 0 {
		var encoded string
		var digest [32]byte
		if json.Unmarshal(review, &encoded) != nil || len(encoded) != 64 {
			return request, auth, vaultwire.ErrProtocol
		}
		if _, err := hex.Decode(digest[:], []byte(encoded)); err != nil || hex.EncodeToString(digest[:]) != encoded {
			return request, auth, vaultwire.ErrProtocol
		}
		request.Review = &digest
		auth, err = decodeSharedExportAuthentication(authentication)
	}
	return request, auth, err
}

func (h *vaultFoundationHandler) sharedPersonalRootRecovery(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, auth, err := decodeSharedPersonalRootRecovery(raw)
	defer auth.wipe()
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedPersonalRootRecoverySession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := sharedpg.PersonalRootRecoveryReply{Status: "unavailable"}
	err = c.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil || request.AccountID == trust.UserID {
			return nil
		}
		supported, err := session.PersonalRootRecoverySupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		if request.Review != nil {
			valid, err := h.verifySharedExportFactors(ctx, c, trust.Revision, auth)
			if err != nil {
				return err
			}
			if !valid {
				reply.Status = "invalid-authentication"
				return nil
			}
		}
		observed, prepared, plan, err := session.PreparePersonalRootRecovery(ctx, trust, bundle, request)
		if observed.Revision != 0 && observed.Revision != trust.Revision {
			if persistErr := c.commitCatalogTrust(trust, observed); persistErr != nil {
				return persistErr
			}
			trust = observed
		}
		if errors.Is(err, sharedpg.ErrServerCertificateAuthority) || errors.Is(err, vault.ErrPolicy) {
			return nil
		}
		reply = prepared
		if err != nil {
			return err
		}
		if plan == nil {
			if issuer, ok := session.(interface {
				AccountReenrollmentSupported(context.Context) (bool, error)
			}); ok && request.Review == nil && reply.Status == "enrollment-required" {
				reply.CanReenroll, err = issuer.AccountReenrollmentSupported(ctx)
			}
			return err
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrAuthentication
			}
			reply, err = session.CommitPreparedPersonalRootRecovery(ctx, trust, bundle, plan,
				&vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]})
			return err
		})
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
