package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAccountBoundaryRotationSession interface {
	sharedRuntimeStateSession
	AccountBoundaryRotationSupported(context.Context) (bool, error)
	PrepareAccountBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle,
		sharedpg.AccountBoundaryRotationRequest) (sharedpg.TrustState, sharedpg.AccountBoundaryRotationReply, *sharedpg.AccountBoundaryRotationPreparation, error)
	CommitPreparedAccountBoundaryRotation(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle,
		*sharedpg.AccountBoundaryRotationPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.AccountBoundaryRotationReply, error)
}

func decodeSharedAccountBoundaryRotation(raw []byte) (request sharedpg.AccountBoundaryRotationRequest, err error) {
	var accountID, suspension, boundaryID, purpose, rootID, version string
	var review json.RawMessage
	fields := map[string]any{"accountId": &accountID, "suspension": &suspension, "boundaryId": &boundaryID,
		"purpose": &purpose, "rootId": &rootID, "rootVersion": &version, "review": &review}
	if len(raw) > 768 || decodeVaultObject(raw, fields, "accountId", "suspension", "boundaryId", "purpose", "rootId", "rootVersion") != nil ||
		!vaultCredentialID(accountID) || !vaultCredentialID(boundaryID) || !vaultCredentialID(rootID) {
		return request, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(suspension, false)
	keyVersion, versionErr := vaultCredentialRevision(version, false)
	if err != nil || versionErr != nil || keyVersion >= math.MaxInt32 {
		return request, vaultwire.ErrProtocol
	}
	request.AccountID, request.BoundaryID, request.Suspension = uuid.MustParse(accountID), uuid.MustParse(boundaryID), revision
	request.Root = vault.KeyRef{ID: uuid.MustParse(rootID), Version: uint32(keyVersion)}
	switch purpose {
	case "view":
		request.Affected = permissions.View
	case "secret":
		request.Affected = permissions.Use
	default:
		return request, vaultwire.ErrProtocol
	}
	if len(review) != 0 {
		var encoded string
		var digest [32]byte
		if json.Unmarshal(review, &encoded) != nil || len(encoded) != 64 {
			return request, vaultwire.ErrProtocol
		}
		if _, err := hex.Decode(digest[:], []byte(encoded)); err != nil || hex.EncodeToString(digest[:]) != encoded {
			return request, vaultwire.ErrProtocol
		}
		request.Review = &digest
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedAccountBoundaryRotation(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedAccountBoundaryRotation(raw)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	reply, err := c.rotateSuspendedRoot(ctx, request)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}

func (c *sharedAdmissionController) rotateSuspendedRoot(ctx context.Context, request sharedpg.AccountBoundaryRotationRequest) (sharedpg.AccountBoundaryRotationReply, error) {
	session, ok := c.session.(sharedAccountBoundaryRotationSession)
	if !ok {
		return sharedpg.AccountBoundaryRotationReply{}, sharedpg.ErrConfiguration
	}
	reply := sharedpg.AccountBoundaryRotationReply{Status: "unavailable"}
	var bundle *sharedpg.VerifiedTLSBundle
	var plan *sharedpg.AccountBoundaryRotationPreparation
	err := c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		runtime, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !runtime.Administrator {
			return err
		}
		supported, err := session.AccountBoundaryRotationSupported(ctx)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		bundle, err = readSharedTLSCache(c.trustPath, *pending)
		if err != nil {
			return err
		}
		observed, result, prepared, err := session.PrepareAccountBoundaryRotation(ctx, *pending, bundle, request)
		if observed.Revision != 0 {
			*pending = observed
		}
		if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
			return nil
		}
		reply, plan = result, prepared
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if plan == nil {
			return nil
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrAuthentication
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			next, result, err := session.CommitPreparedAccountBoundaryRotation(ctx, trust, bundle, plan, keys)
			if next.Revision != 0 && next.Revision != trust.Revision {
				if persistErr := c.commitCatalogTrust(trust, next); persistErr != nil {
					return persistErr
				}
			}
			if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
				reply = sharedpg.AccountBoundaryRotationReply{Status: "unavailable"}
				return nil
			}
			reply = result
			return err
		})
	}, false)
	return reply, err
}
