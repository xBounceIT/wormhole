package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedGroupKeySession interface {
	sharedRuntimeStateSession
	GroupKeySupported(context.Context) (bool, error)
	PrepareGroupKey(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.GroupKeyRequest) (sharedpg.TrustState, sharedpg.GroupKeyReply, *sharedpg.GroupKeyPreparation, error)
	CommitPreparedGroupKey(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, *sharedpg.GroupKeyPreparation, *vault.UserKeys) (sharedpg.TrustState, sharedpg.GroupKeyReply, error)
}

func decodeSharedGroupKey(raw []byte) (sharedpg.GroupKeyRequest, error) {
	var id, revision string
	var review *string
	var request sharedpg.GroupKeyRequest
	if len(raw) > 512 || decodeVaultObject(raw, map[string]any{"groupId": &id, "revision": &revision, "review": &review},
		"groupId", "revision") != nil || !vaultCredentialID(id) {
		return request, vaultwire.ErrProtocol
	}
	version, err := vaultCredentialRevision(revision, false)
	if err != nil || version == math.MaxInt64 {
		return request, vaultwire.ErrProtocol
	}
	request.GroupID, request.Revision = uuid.MustParse(id), version
	if review != nil {
		var digest [32]byte
		if len(*review) != 64 {
			return request, vaultwire.ErrProtocol
		}
		if _, err := hex.Decode(digest[:], []byte(*review)); err != nil || hex.EncodeToString(digest[:]) != *review {
			return request, vaultwire.ErrProtocol
		}
		request.Review = &digest
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedGroupKey(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedGroupKey(raw)
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedGroupKeySession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	var plan *sharedpg.GroupKeyPreparation
	var bundle *sharedpg.VerifiedTLSBundle
	reply := sharedpg.GroupKeyReply{Status: "unavailable"}
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		runtime, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil || !runtime.Administrator {
			return err
		}
		supported, err := session.GroupKeySupported(ctx)
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
		next, result, prepare, err := session.PrepareGroupKey(ctx, *pending, bundle, request)
		if next.Revision != 0 {
			*pending = next
		}
		if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
			return nil
		}
		if err != nil {
			return err
		}
		reply, plan = result, prepare
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if plan == nil {
			return nil
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrAuthentication
			}
			keys := &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]}
			next, result, err := session.CommitPreparedGroupKey(ctx, trust, bundle, plan, keys)
			if next.Revision != 0 && next.Revision != trust.Revision {
				if persistErr := c.commitCatalogTrust(trust, next); persistErr != nil {
					return persistErr
				}
			}
			if errors.Is(err, sharedpg.ErrServerCertificateAuthority) {
				reply = sharedpg.GroupKeyReply{Status: "unavailable"}
				return nil
			}
			reply = result
			return err
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}
