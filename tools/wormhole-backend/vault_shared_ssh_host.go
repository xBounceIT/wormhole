package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedSSHHostPinSession interface {
	sharedRuntimeStateSession
	PrepareSSHHostPin(context.Context, sharedpg.TrustState, sharedpg.ResolvedConnectionPlan) (sharedpg.TrustState, *sharedpg.SSHHostPinEdit, error)
	CommitSSHHostPin(context.Context, sharedpg.TrustState, *sharedpg.SSHHostPinEdit, string, *vault.UserKeys) (uint64, error)
	VerifySSHHostPin(context.Context, sharedpg.TrustState, *sharedpg.SSHHostPinEdit, string, uint64) (sharedpg.TrustState, bool, error)
}

func (h *vaultFoundationHandler) sharedSSHHostTrust(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var action, encoded json.RawMessage
	defer func() { vault.Wipe(raw); vault.Wipe(encoded) }()
	if h.shared == nil {
		return nil, vault.ErrPolicy
	}
	if len(raw) > 32*1024 || decodeVaultObject(raw, map[string]any{"action": &action, "authentication": &encoded}, "action") != nil {
		return nil, vaultwire.ErrProtocol
	}
	if encoded == nil {
		return h.sshHostAction(ctx, "shared-ssh-host-trust", action, nil)
	}
	auth, err := decodeSharedExportAuthentication(encoded)
	defer auth.wipe()
	if err != nil {
		return nil, err
	}
	return h.sshHostAction(ctx, "shared-ssh-host-trust", action, &auth)
}

func (h *vaultFoundationHandler) commitSharedSSHHost(ctx context.Context, c *sharedAdmissionController, plan sharedpg.ResolvedConnectionPlan, received string, auth *vaultUnlockInput) (json.RawMessage, error) {
	session, ok := c.session.(sharedSSHHostPinSession)
	if !ok {
		return nil, sharedpg.ErrConfiguration
	}
	var edit *sharedpg.SSHHostPinEdit
	var revision uint64
	var profile vault.Profile
	var denial error
	err := c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		runtime, err := c.observeRuntime(ctx, session, trust, pending)
		if err != nil {
			return err
		}
		profile = runtime.Security.Effective
		if profile != vault.Default && profile != vault.Standard || (profile == vault.Standard && auth == nil) {
			denial = vault.ErrPolicy
			return nil
		}
		next, prepared, err := session.PrepareSSHHostPin(ctx, *pending, plan)
		if next.Revision != 0 {
			*pending = next
		}
		edit = prepared
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if denial != nil || edit == nil {
			return nil
		}
		if profile == vault.Standard {
			valid, err := h.verifySharedExportFactors(ctx, c, trust.Revision, *auth)
			auth.wipe()
			if err != nil {
				return err
			}
			if !valid {
				denial = vault.ErrAuthentication
				return nil
			}
		}
		return c.privateKeys.With(func(raw []byte) error {
			if len(raw) != 64 {
				return sharedpg.ErrTrustState
			}
			var err error
			revision, err = session.CommitSSHHostPin(ctx, trust, edit, received, &vault.UserKeys{EncryptionPrivate: raw[:32:32], SigningSeed: raw[32:]})
			return err
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	if denial != nil {
		return nil, denial
	}
	if revision == 0 {
		return nil, vault.ErrPolicy
	}
	// Publish the new signed revision to the device's rollback floor before
	// acknowledging the confirmation. The connection still verifies the host.
	var verified bool
	err = c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if plan.Plan.TunnelID == "" && !c.runtimeProfile.AllowsDirectRoute() {
			return vault.ErrPolicy
		}
		next, matched, err := session.VerifySSHHostPin(ctx, trust, edit, received, revision)
		if next.Revision != 0 {
			*pending = next
		}
		verified = matched
		return err
	}, nil, false)
	if err != nil {
		return nil, h.retire(err)
	}
	if !verified {
		return nil, vault.ErrPolicy
	}
	return json.Marshal(struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{plan.Plan.NodeID, strconv.FormatUint(revision, 10), true})
}
