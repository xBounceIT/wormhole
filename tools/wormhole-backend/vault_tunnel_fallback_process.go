package main

import (
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// The main owner may create this recipient only after it has confirmed the
// original controller's OS exit. The packet authenticates both sources, not an
// exit receipt. No renderer endpoint selects this recipient or its key.
func openSealedTunnelFallbackConfiguration(packet, private []byte) (vault.TunnelBundleBinding, []byte, error) {
	var pair, envelope json.RawMessage
	if decodeVaultObject(packet, map[string]any{"binding": &pair, "bundle": &envelope}, "binding", "bundle") != nil {
		return vault.TunnelBundleBinding{}, nil, vaultwire.ErrProtocol
	}
	binding, err := decodeTunnelFallbackBinding(pair)
	if err != nil {
		return vault.TunnelBundleBinding{}, nil, err
	}
	// Reuse the exact ordinary envelope and binding codec, but never its opener.
	bundle, err := decodeSealedTunnelEnvelope(envelope)
	if err != nil {
		return vault.TunnelBundleBinding{}, nil, err
	}
	configuration, err := vault.OpenTunnelFallback(private, binding, bundle)
	return binding.Fallback, configuration, err
}

func decodeTunnelFallbackBinding(raw []byte) (binding vault.TunnelFallbackBinding, err error) {
	var primary, fallback json.RawMessage
	if decodeVaultObject(raw, map[string]any{"primary": &primary, "fallback": &fallback}, "primary", "fallback") != nil {
		return binding, vaultwire.ErrProtocol
	}
	binding.Primary, err = decodeTunnelBundleBinding(primary)
	if err != nil {
		return binding, err
	}
	binding.Fallback, err = decodeTunnelBundleBinding(fallback)
	if err != nil || binding.Validate() != nil {
		return vault.TunnelFallbackBinding{}, vaultwire.ErrProtocol
	}
	return binding, nil
}
