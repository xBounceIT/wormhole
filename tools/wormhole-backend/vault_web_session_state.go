package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type webArchiveReply struct {
	Revision uint64              `json:"revision,string"`
	Bundle   *vault.SealedBundle `json:"bundle,omitempty"`
}

type sharedWebCheckpointSession interface {
	WebSessionCheckpointsSupported(context.Context) (bool, error)
	SetWebSessionCheckpoint(context.Context, uuid.UUID, uuid.UUID, bool) (bool, error)
}

func webSessionPersistenceAllowed(profile vault.Profile) bool {
	return profile == vault.Default || profile == vault.Standard
}

// The main-process browser passes the fingerprint issued with its plan.
// Every operation independently re-resolves the target and its current access.
func (h *vaultFoundationHandler) webSessionState(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	defer vault.Wipe(raw)
	if len(raw) > 2*vault.MaxWebSessionArchiveBytes {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelPlanRequest
	var epoch, archiveBinding, lastRevision string
	var recipient, archive []byte
	defer func() { vault.Wipe(archive) }()
	fields := map[string]any{
		"nodeId": &q.NodeID, "sessionId": &q.SessionID, "requestId": &q.RequestID,
		"epoch": &epoch, "archiveBinding": &archiveBinding,
	}
	required := []string{"nodeId", "sessionId", "requestId", "epoch", "archiveBinding"}
	if operation == "web-session-read" {
		fields["recipient"] = &recipient
		required = append(required, "recipient")
	} else {
		fields["revision"] = &lastRevision
		required = append(required, "revision")
		if operation == "web-session-save" {
			fields["archive"] = &archive
			required = append(required, "archive")
		}
	}
	if decodeVaultObject(raw, fields, required...) != nil || len(archiveBinding) != 64 {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || q.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	var expected uint64
	if operation == "web-session-read" {
		if len(recipient) != 32 {
			return nil, vaultwire.ErrProtocol
		}
	} else {
		expected, err = strconv.ParseUint(lastRevision, 10, 63)
		if err != nil || expected >= math.MaxInt64 || strconv.FormatUint(expected, 10) != lastRevision ||
			(operation == "web-session-save" && (len(archive) == 0 || len(archive) > vault.MaxWebSessionArchiveBytes)) {
			return nil, vaultwire.ErrProtocol
		}
	}
	var reply webArchiveReply
	defer func() {
		if reply.Bundle != nil {
			vault.Wipe(reply.Bundle.Enc)
			vault.Wipe(reply.Bundle.Ciphertext)
		}
	}()
	use := func(ctx context.Context, owner *localvault.Owner, plan localvault.WebConnectionPlan, account string, generation uuid.UUID, checkpoint func(bool) error) error {
		if plan.Temporary {
			return vault.ErrPolicy
		}
		binding := browserArchiveBinding(plan, account, generation)
		fingerprint, err := binding.Fingerprint()
		if err != nil {
			return err
		}
		if hex.EncodeToString(fingerprint[:]) != archiveBinding {
			return vaultstore.ErrConflict
		}
		switch operation {
		case "web-session-read":
			err := owner.WithWebSessionState(ctx, binding, func(revision uint64, value []byte) error {
				reply.Revision = revision
				if len(value) == 0 {
					return nil
				}
				sealed, err := vault.SealWebSessionArchive(recipient, binding.WorkspaceID, binding.NodeID, q.RequestID, revision, value)
				if err != nil {
					return err
				}
				reply.Bundle = &sealed
				return nil
			})
			if err == nil && checkpoint != nil && reply.Bundle != nil {
				err = checkpoint(true)
			}
			return err
		case "web-session-save":
			// Reserve the marker first so an interruption after the local
			// commit cannot hide a possibly retained checkpoint.
			if checkpoint != nil {
				if err := checkpoint(true); err != nil {
					return err
				}
			}
			reply.Revision, err = owner.SaveWebSessionState(ctx, binding, expected, archive)
		case "web-session-forget":
			reply.Revision, err = owner.ForgetWebSessionState(ctx, binding, expected)
			if err == nil && checkpoint != nil {
				err = checkpoint(false)
			}
		default:
			return vaultwire.ErrProtocol
		}
		return err
	}
	if h.shared != nil {
		err = h.withSharedWebSessionState(ctx, q, use)
	} else if h.owner != nil {
		// The dispatch has already authenticated the local profile. Temporary
		// browser targets remain outside this device-local persistence path.
		var plan localvault.WebConnectionPlan
		plan, err = h.owner.PlanWebConnection(ctx, q)
		if err == nil {
			err = use(ctx, h.owner, plan, plan.Binding.WorkspaceID, uuid.Nil, nil)
		}
	} else {
		err = vaultwire.ErrProtocol
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}

func (h *vaultFoundationHandler) withSharedWebSessionState(ctx context.Context, q localvault.TunnelPlanRequest, use func(context.Context, *localvault.Owner, localvault.WebConnectionPlan, string, uuid.UUID, func(bool) error) error) error {
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return err
	}
	var rejection error
	node := uuid.MustParse(q.NodeID)
	err = c.withWebConnectionPlan(ctx, node, func(ctx context.Context, current sharedpg.ResolvedConnectionPlan) error {
		if !webSessionPersistenceAllowed(c.runtimeProfile) || c.vpnSSO == nil || c.vpnSSO.owner == nil {
			rejection = vault.ErrPolicy
			return nil
		}
		if c.vpnSSO.fileID != h.shared.fileID {
			return vault.ErrAuthentication
		}
		plan, err := sharedWebConnectionMetadata(c.trustBinding.WorkspaceID, h.shared.fileID, q, current)
		if err != nil {
			return err
		}
		session, err := c.webViewSession(ctx)
		if err != nil {
			return err
		}
		if session == nil {
			rejection = vault.ErrPolicy
			return nil
		}
		generations, err := session.CheckWebSessionViews(ctx, []uuid.UUID{node})
		if err != nil {
			return err
		}
		generation := generations[node]
		if generation == uuid.Nil {
			rejection = vault.ErrPolicy
			return nil
		}
		var checkpoint func(bool) error
		if tracker, ok := c.session.(sharedWebCheckpointSession); ok {
			supported, err := tracker.WebSessionCheckpointsSupported(ctx)
			if err != nil {
				return err
			}
			if supported {
				checkpoint = func(present bool) error {
					accepted, err := tracker.SetWebSessionCheckpoint(ctx, node, generation, present)
					if err == nil && !accepted && present {
						return vault.ErrPolicy
					}
					return err
				}
			}
		}
		err = use(ctx, c.vpnSSO.owner, plan, c.trustBinding.UserID.String(), generation, checkpoint)
		if errors.Is(err, vaultstore.ErrConflict) || errors.Is(err, vault.ErrPolicy) {
			rejection = err
			return nil
		}
		return err
	})
	if err != nil {
		if errors.Is(err, sharedpg.ErrImportedConnectionPins) && c.Unlocked() {
			return err
		}
		return h.retire(err)
	}
	return rejection
}
