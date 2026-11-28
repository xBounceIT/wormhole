package main

import (
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Only this explicit primary actor handles a configured fallback reference.
// Ordinary launch/auth/browser adapters keep their rejection guards. The target
// ID never selects a native secondary or authorizes its settings here.
func prepareSealedPrimaryTunnel(binding vault.TunnelBundleBinding, configuration []byte) ([]byte, bool, error) {
	if binding.Kind != 9 {
		return nil, false, vault.ErrPolicy
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, false, err
	}
	defer clearTunnelSettingsMap(settings)
	if validateTunnelSettings(9, settings) != nil {
		return nil, false, vault.ErrFormat
	}
	target, err := selectNativeIPsecFallbackSettings(settings)
	if err != nil {
		return nil, false, err
	}
	if target == "" {
		return configuration, false, nil
	}
	if target == binding.TunnelConfigID {
		return nil, false, vault.ErrPolicy
	}
	// Provider control belongs to this actor; native authentication still uses
	// the original primary binding. Never invoke the legacy recursive launcher.
	delete(settings, "FallbackTunnelId")
	prepared, err := json.Marshal(settings)
	if err != nil || len(prepared) > vault.MaxSecretBytes {
		vault.Wipe(prepared)
		return nil, false, vault.ErrFormat
	}
	return prepared, true, nil
}

func writeSealedFallbackRequired(encoder *json.Encoder, binding vault.TunnelBundleBinding) error {
	if err := encoder.Encode(struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
		RequestID string `json:"requestId"`
	}{"fallback-required", binding.SessionID, binding.RequestID}); err != nil {
		return vaultwire.ErrProtocol
	}
	return nil
}
