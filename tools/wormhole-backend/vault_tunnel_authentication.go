package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sealedTunnelAuthentication struct {
	binding  vault.TunnelAuthenticationBinding
	key      *securemem.Buffer
	public   []byte
	response chan vault.SealedBundle
}

func newSealedTunnelAuthentication(b vault.TunnelBundleBinding, configuration []byte) (*sealedTunnelAuthentication, error) {
	if b.Kind != 9 {
		return nil, nil
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	if fortinetUserAuth(settings) != 1 {
		return nil, nil
	}
	if validateFortinetIPsecSettings(settings) != nil || strings.TrimSpace(tunnelSettingString(settings, "FallbackTunnelId")) != "" {
		return nil, vault.ErrPolicy
	}
	key, public, err := newSealedTunnelRecipientKey()
	if err != nil {
		return nil, err
	}
	a := &sealedTunnelAuthentication{binding: vault.TunnelAuthenticationBinding{Route: b, ChallengeID: uuid.NewString(), UsernameRequired: strings.TrimSpace(tunnelSettingString(settings, "Username")) == ""}, key: key, public: public, response: make(chan vault.SealedBundle, 1)}
	return a, nil
}

func newSealedTunnelRecipientKey() (*securemem.Buffer, []byte, error) {
	return newSealedRecipientKey(true)
}

func newSealedRecipientKey(requireLocked bool) (*securemem.Buffer, []byte, error) {
	key, err := securemem.New(32, requireLocked)
	if err != nil {
		return nil, nil, err
	}
	var public []byte
	err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err == nil {
			public = private.PublicKey().Bytes()
		}
		return err
	})
	if err != nil {
		_ = key.Close()
		return nil, nil, err
	}
	return key, public, nil
}

type sealedTunnelControlRecipient struct {
	kind, challenge string
	response        chan vault.SealedBundle
	maxBytes        int
}

// One reader owns all controls. Authentication can arrive once; close/EOF keeps
// cancelling the same attempt while factor processing or native startup runs.
func readSealedTunnelControls(ctx context.Context, cancel context.CancelFunc, scanner *bufio.Scanner, b vault.TunnelBundleBinding, a *sealedTunnelControlRecipient) error {
	used := false
	for scanner.Scan() {
		raw := scanner.Bytes()
		var header struct{ Type string }
		if json.Unmarshal(raw, &header) != nil || len(header.Type) > 32 {
			cancel()
			return vaultwire.ErrProtocol
		}
		if header.Type == "authentication" || header.Type == "browser-authentication" || header.Type == "cookie-authentication" {
			if a == nil || header.Type != a.kind || used || len(raw) > a.maxBytes {
				cancel()
				return vaultwire.ErrProtocol
			}
			var kind, session, challenge string
			var envelope json.RawMessage
			if decodeVaultObject(raw, map[string]any{"type": &kind, "sessionId": &session, "challengeId": &challenge, "envelope": &envelope}, "type", "sessionId", "challengeId", "envelope") != nil || session != b.SessionID || challenge != a.challenge {
				cancel()
				return vaultwire.ErrProtocol
			}
			var sealed vault.SealedBundle
			if decodeVaultObject(envelope, map[string]any{"formatVersion": &sealed.FormatVersion, "suiteId": &sealed.SuiteID, "enc": &sealed.Enc, "ciphertext": &sealed.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
				cancel()
				return vaultwire.ErrProtocol
			}
			used = true
			select {
			case a.response <- sealed:
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		var kind, session string
		if decodeVaultObject(raw, map[string]any{"type": &kind, "sessionId": &session}, "type", "sessionId") != nil || session != b.SessionID || (kind != "close" && kind != "app-lock") {
			cancel()
			return vaultwire.ErrProtocol
		}
		cancel()
		return nil
	}
	cancel()
	if scanner.Err() != nil {
		return vaultwire.ErrProtocol
	}
	return nil
}

func (a *sealedTunnelAuthentication) complete(ctx context.Context, encoder *json.Encoder, configuration []byte) ([]byte, error) {
	defer a.key.Close()
	if err := encoder.Encode(struct {
		Type             string `json:"type"`
		SessionID        string `json:"sessionId"`
		ChallengeID      string `json:"challengeId"`
		PublicKey        []byte `json:"publicKey"`
		UsernameRequired bool   `json:"usernameRequired"`
	}{"authentication-required", a.binding.Route.SessionID, a.binding.ChallengeID, a.public, a.binding.UsernameRequired}); err != nil {
		return nil, vaultwire.ErrProtocol
	}
	var envelope vault.SealedBundle
	select {
	case envelope = <-a.response:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var raw []byte
	err := a.key.With(func(key []byte) error {
		var e error
		raw, e = vault.OpenTunnelAuthentication(key, a.binding, envelope)
		return e
	})
	defer vault.Wipe(raw)
	if err != nil {
		return nil, err
	}
	if err := a.key.Close(); err != nil {
		return nil, err
	}
	payload, err := vault.DecodeTunnelAuthentication(raw, a.binding.UsernameRequired)
	if err != nil {
		return nil, err
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	// Only this transient launch is converted to supplied-factor mode. The saved
	// UserAuth=1 record is unchanged, and any cached password is never reused.
	vault.Wipe(settings["Password"])
	settings["Password"], _ = json.Marshal(string(payload.Password))
	if a.binding.UsernameRequired {
		vault.Wipe(settings["Username"])
		settings["Username"], _ = json.Marshal(string(payload.Username))
	}
	vault.Wipe(settings["UserAuth"])
	settings["UserAuth"] = json.RawMessage("2")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}
