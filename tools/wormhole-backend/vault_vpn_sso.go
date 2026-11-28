package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func decodeVPNSSOTransferContext(raw []byte) (c vault.VPNSSOTransferContext, err error) {
	var source, binding, capture, restore string
	if len(raw) > 4096 || decodeVaultObject(raw, map[string]any{
		"workspaceId": &c.WorkspaceID, "fileId": &c.FileID, "profileId": &c.ProfileID, "requestId": &c.RequestID, "transferId": &c.TransferID, "sessionId": &c.SessionID, "challengeId": &c.ChallengeID, "epoch": &c.Epoch, "policySequence": &c.PolicySequence, "sourceRevision": &c.SourceRevision, "sourceDeleted": &c.SourceDeleted, "sourceDigest": &source, "bindingDigest": &binding, "capturePublicKey": &capture, "restorePublicKey": &restore,
	}, "workspaceId", "fileId", "profileId", "requestId", "transferId", "sessionId", "challengeId", "epoch", "policySequence", "sourceRevision", "sourceDeleted", "sourceDigest", "bindingDigest", "capturePublicKey", "restorePublicKey") != nil {
		return c, vaultwire.ErrProtocol
	}
	c.SourceDigest, err = browserTransferBytes(source, 32, 32)
	if err == nil {
		c.BindingDigest, err = browserTransferBytes(binding, 32, 32)
	}
	if err == nil {
		c.CapturePublicKey, err = browserTransferBytes(capture, 32, 32)
	}
	if err == nil {
		c.RestorePublicKey, err = browserTransferBytes(restore, 32, 32)
	}
	if err != nil || c.Validate() != nil {
		return c, vaultwire.ErrProtocol
	}
	return c, nil
}

func decodeVPNSSOManifest(raw []byte) (m vault.VPNSSOTransferManifest, err error) {
	var digest string
	if len(raw) > 256 || decodeVaultObject(raw, map[string]any{"bytes": &m.Bytes, "digest": &digest}, "bytes", "digest") != nil {
		return m, vaultwire.ErrProtocol
	}
	m.Digest, err = browserTransferBytes(digest, 32, 32)
	if err != nil {
		return m, vaultwire.ErrProtocol
	}
	return m, nil
}

func decodeVPNSSOPacket(raw []byte) (p vault.VPNSSOTransferPacket, err error) {
	var contextRaw, manifestRaw, bundleRaw json.RawMessage
	if decodeVaultObject(raw, map[string]any{"context": &contextRaw, "manifest": &manifestRaw, "direction": &p.Direction, "index": &p.Index, "bundle": &bundleRaw}, "context", "manifest", "direction", "index", "bundle") != nil {
		return p, vaultwire.ErrProtocol
	}
	p.Context, err = decodeVPNSSOTransferContext(contextRaw)
	if err == nil {
		p.Manifest, err = decodeVPNSSOManifest(manifestRaw)
	}
	var enc, ciphertext string
	if err != nil || decodeVaultObject(bundleRaw, map[string]any{"formatVersion": &p.Bundle.FormatVersion, "suiteId": &p.Bundle.SuiteID, "enc": &enc, "ciphertext": &ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return p, vaultwire.ErrProtocol
	}
	p.Bundle.Enc, err = browserTransferBytes(enc, 32, 32)
	if err == nil {
		p.Bundle.Ciphertext, err = browserTransferBytes(ciphertext, 17, vault.MaxSecretBytes+16)
	}
	if err != nil || vault.ValidateVPNSSOTransferPacket(p) != nil {
		vault.Wipe(p.Bundle.Ciphertext)
		return vault.VPNSSOTransferPacket{}, vaultwire.ErrProtocol
	}
	return p, nil
}

func describeNativeSSLSSO(startURL string, ignoreCertificateErrors bool) localvault.VPNSSODescribeProvider {
	return func(kind uint16, configuration []byte) (localvault.VPNSSOProvider, error) {
		if kind != 2 {
			return localvault.VPNSSOProvider{}, vault.ErrPolicy
		}
		settings, err := decodeVaultTunnelSettings(configuration)
		if err != nil {
			return localvault.VPNSSOProvider{}, err
		}
		defer clearTunnelSettingsMap(settings)
		if !tunnelSettingBool(settings, "UseSingleSignOn") || validateTunnelSettings(2, settings) != nil {
			return localvault.VPNSSOProvider{}, vault.ErrPolicy
		}
		port := int(tunnelSettingNumber(settings, "Port"))
		if port == 0 {
			port = 443
		}
		base, err := buildWebURL("https", tunnelSettingString(settings, "Host"), port)
		if err != nil {
			return localvault.VPNSSOProvider{}, vault.ErrFormat
		}
		start, _ := url.Parse(base)
		start.Path = "/remote/saml/start"
		realm := strings.TrimSpace(tunnelSettingString(settings, "Realm"))
		if realm != "" {
			start.RawQuery = url.Values{"realm": {realm}}.Encode()
		}
		ignore := tunnelSettingBool(settings, "TrustServerCertificate")
		if len(startURL) > 4096 || start.String() != startURL || ignore != ignoreCertificateErrors {
			return localvault.VPNSSOProvider{}, vault.ErrAuthentication
		}
		trust, _ := json.Marshal(struct {
			Purpose string
			Ignore  bool
			Pin     string
		}{"wormhole/v1/fortinet-ssl-trust", ignore, tunnelSettingString(settings, "ServerCertSha256Pin")})
		return localvault.VPNSSOProvider{GatewayOrigin: start.Scheme + "://" + start.Host, Realm: realm, TrustDigest: sha256.Sum256(trust)}, nil
	}
}

func (h *vaultFoundationHandler) checkpointVPNSSO(ctx context.Context) error {
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return err
	}
	return h.persistVaultCheckpoint(ctx, document)
}

func (h *vaultFoundationHandler) persistVaultCheckpoint(ctx context.Context, document vault.SlotFile) error {
	return h.owner.PersistVPNSSOCheckpoints(ctx, document, func(next vault.SlotFile, key []byte) error {
		return writeVaultSlotFile(h.databasePath, key, next, document.Sequence)
	})
}

// Only the native route/browser controller invokes this stdio API. No renderer
// IPC exposes binding/recipient selection or archive packets. Native local source
// re-resolution and personal custody are inseparable; shared admission is separate.
func (h *vaultFoundationHandler) vpnSSO(ctx context.Context, operation string, raw []byte) (result json.RawMessage, resultErr error) {
	if h.shared != nil && h.owner == nil {
		return h.shared.controller.runVPNSSO(ctx, operation, raw)
	}
	if h.owner == nil || h.shared != nil {
		return nil, vaultwire.ErrProtocol
	}
	if err := h.checkpointVPNSSO(ctx); err != nil {
		return nil, h.retire(err)
	}
	var receiptContext *vault.VPNSSOTransferContext
	var committed *localvault.VPNSSOCheckpoint
	var receiptSource func(context.Context) error
	// Persist observations even on denial; no prepared response escapes before
	// durable publication and final validation against the original source.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := h.checkpointVPNSSO(cleanup); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, h.retire(err))
		} else if resultErr == nil && receiptContext != nil {
			if receiptSource != nil {
				sourceErr := receiptSource(cleanup)
				if err := h.checkpointVPNSSO(cleanup); err != nil {
					result, resultErr = nil, errors.Join(sourceErr, h.retire(err))
					return
				}
				// Publication can import a newer authentic source floor. Recheck
				// afterward; success is allowed only without new observations.
				if sourceErr == nil {
					sourceErr = receiptSource(cleanup)
				}
				if sourceErr != nil {
					if err := h.checkpointVPNSSO(cleanup); err != nil {
						result, resultErr = nil, errors.Join(sourceErr, h.retire(err))
						return
					}
					result, resultErr = nil, sourceErr
					return
				}
			}
			if err := h.owner.ValidateVPNSSOReceipt(cleanup, *receiptContext, committed); err != nil {
				result, resultErr = nil, err
			}
		}
	}()
	var value any
	var err error
	if operation == "vpn-sso-begin" {
		q, e := decodeNativeVPNSSOBegin(raw)
		if e != nil {
			return nil, e
		}
		if q.custodyWorkspace != "" && (q.custodyWorkspace != q.binding.WorkspaceID || q.custodyFile != q.binding.FileID) {
			return nil, vaultwire.ErrProtocol
		}
		describe := describeNativeVPNSSO(q.startURL, q.ignore)
		if q.hasFallback {
			planned, e := h.owner.PlanConnectionFallbackVPNSSO(ctx, q.request, q.fallback, selectNativeIPsecFallback, describe)
			if e != nil {
				return nil, e
			}
			offer, e := h.owner.BeginConnectionFallbackVPNSSOTransfer(ctx, q.request, q.fallback, planned, q.transfer, selectNativeIPsecFallback, describe)
			value, err, receiptContext = offer, e, &offer.Context
		} else {
			planned, e := h.owner.PlanConnectionVPNSSO(ctx, q.request, q.binding, describe)
			if e != nil {
				return nil, e
			}
			offer, e := h.owner.BeginConnectionVPNSSOTransfer(ctx, q.request, q.binding, planned, q.transfer, describe)
			value, err, receiptContext = offer, e, &offer.Context
		}
	} else {
		q, e := decodeNativeVPNSSOAction(operation, raw)
		defer vault.Wipe(q.packet.Bundle.Ciphertext)
		if e != nil {
			return nil, e
		}
		if operation == "vpn-sso-commit" {
			receiptSource, e = h.owner.CaptureVPNSSOReceiptSource(ctx, q.context)
			if e != nil {
				return nil, e
			}
		}
		value, committed, err = performNativeVPNSSOAction(h.owner, ctx, operation, q)
		if operation != "vpn-sso-cancel" {
			receiptContext = &q.context
		}
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
