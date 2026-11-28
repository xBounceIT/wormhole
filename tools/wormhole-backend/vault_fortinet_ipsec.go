package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Kept separate from legacy presence markers: the vault owns full configuration
// and never accepts Has/Replace aliases or exposes stored PEM/PSK bytes.
func validVaultIPsecEditorValue(field string, raw []byte) bool {
	switch field {
	case "AutoProposals", "TrustServerCertificate", "DeadPeerDetection", "NatTraversal", "EnableLocalLan", "Phase2TimeLifetime", "Phase2ByteLifetime", "ReplayDetection", "Pfs":
		var v bool
		return json.Unmarshal(raw, &v) == nil
	case "Port", "SamlPort", "AuthMethod", "UserAuth", "IkeVersion", "ExchangeMode", "AddressAssignment", "Phase1Encryption", "Phase1Authentication", "Phase1Encryption2", "Phase1Authentication2", "Phase1Lifetime", "Phase2Encryption", "Phase2Authentication", "Phase2Encryption2", "Phase2Authentication2", "Phase2Lifetime", "Phase2LifetimeKb", "PfsGroup":
		var v int64
		return json.Unmarshal(raw, &v) == nil
	default:
		var v string
		return json.Unmarshal(raw, &v) == nil
	}
}

// Only complete, bounded, unencrypted PEM is accepted. Partial imports are
// encrypted in their editor-owned stage; key-pair matching occurs at save.
func readVaultIPsecPEM(contents []byte, field string) error {
	if len(contents) == 0 || len(contents) > 131072 {
		return vaultwire.ErrProtocol
	}
	remaining := bytes.TrimSpace(contents)
	count := 0
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return vaultwire.ErrProtocol
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return vaultwire.ErrProtocol
		}
		defer vault.Wipe(block.Bytes)
		if len(block.Headers) != 0 {
			return vaultwire.ErrProtocol
		}
		if field == "ClientKey" {
			if count != 0 {
				return vaultwire.ErrProtocol
			}
			var err error
			switch block.Type {
			case "PRIVATE KEY":
				_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			case "RSA PRIVATE KEY":
				_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			case "EC PRIVATE KEY":
				_, err = x509.ParseECPrivateKey(block.Bytes)
			default:
				return vaultwire.ErrProtocol
			}
			if err != nil {
				return vaultwire.ErrProtocol
			}
		} else {
			if field != "ClientCert" && field != "CaCert" || block.Type != "CERTIFICATE" {
				return vaultwire.ErrProtocol
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return vaultwire.ErrProtocol
			}
		}
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 || bytes.IndexByte(contents, 0) >= 0 {
		return vaultwire.ErrProtocol
	}
	return nil
}

// A saved fallback is an authenticated Fortinet SSL record in this owner, never
// a legacy database ID or an arbitrary URL. Runtime still requires fresh sealed
// authorization and does not acquire a fallback merely because it is stored.
func (h *vaultFoundationHandler) validateVaultIPsecFallback(ctx context.Context, id string, settings map[string]json.RawMessage) error {
	fallback := tunnelSettingString(settings, "FallbackTunnelId")
	if fallback == "" {
		return nil
	}
	if fallback == id {
		return vaultwire.ErrProtocol
	}
	target, err := h.owner.ReadTunnel(ctx, fallback, 0)
	if err != nil || target.Kind != 2 || target.Deleted {
		return vaultwire.ErrProtocol
	}
	return nil
}
