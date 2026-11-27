package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"net/url"
	"strings"
)

type sealedTunnelCookie struct {
	binding  vault.TunnelCookieBinding
	key      *securemem.Buffer
	public   []byte
	response chan vault.SealedBundle
}

func newSealedTunnelCookie(b vault.TunnelBundleBinding, configuration []byte) (*sealedTunnelCookie, error) {
	if b.Kind != 2 {
		return nil, nil
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	if !tunnelSettingBool(settings, "UseSingleSignOn") {
		return nil, nil
	}
	if validateTunnelSettings(2, settings) != nil {
		return nil, vault.ErrPolicy
	}
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	base, err := buildWebURL("https", tunnelSettingString(settings, "Host"), port)
	if err != nil {
		return nil, vault.ErrFormat
	}
	start, _ := url.Parse(base)
	start.Path = "/remote/saml/start"
	callback := tunnelSettingBool(settings, "UseSamlCallback")
	if callback {
		start.RawQuery = "redirect=1"
	} else if realm := strings.TrimSpace(tunnelSettingString(settings, "Realm")); realm != "" {
		start.RawQuery = url.Values{"realm": {realm}}.Encode()
	}
	if len(start.String()) > 4096 {
		return nil, vault.ErrFormat
	}
	key, public, err := newSealedTunnelRecipientKey()
	if err != nil {
		return nil, err
	}
	return &sealedTunnelCookie{binding: vault.TunnelCookieBinding{Route: b, ChallengeID: uuid.NewString(), StartURL: start.String(), UseSamlCallback: callback, IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate")}, key: key, public: public, response: make(chan vault.SealedBundle, 1)}, nil
}
func (a *sealedTunnelCookie) close() { _ = a.key.Close() }
func (a *sealedTunnelCookie) recipient() *sealedTunnelControlRecipient {
	return &sealedTunnelControlRecipient{"cookie-authentication", a.binding.ChallengeID, a.response, 32768}
}
func (a *sealedTunnelCookie) complete(ctx context.Context, encoder *json.Encoder, configuration []byte) ([]byte, error) {
	defer a.close()
	cookieName, completion, field := "SVPNCOOKIE", "", "SvpnCookie"
	if a.binding.UseSamlCallback {
		cookieName, completion, field = "", "fortinet-ssl", "SamlAuthId"
	}
	if err := encoder.Encode(struct {
		Type                    string `json:"type"`
		SessionID               string `json:"sessionId"`
		ChallengeID             string `json:"challengeId"`
		PublicKey               []byte `json:"publicKey"`
		StartURL                string `json:"startURL"`
		IgnoreCertificateErrors bool   `json:"ignoreCertificateErrors"`
		CookieName              string `json:"cookieName,omitempty"`
		Completion              string `json:"completion,omitempty"`
	}{"cookie-authentication-required", a.binding.Route.SessionID, a.binding.ChallengeID, a.public, a.binding.StartURL, a.binding.IgnoreCertificateErrors, cookieName, completion}); err != nil {
		return nil, err
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
		raw, e = vault.OpenTunnelCookie(key, a.binding, envelope)
		return e
	})
	defer vault.Wipe(raw)
	if err != nil {
		return nil, err
	}
	if err = a.key.Close(); err != nil {
		return nil, err
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	for _, name := range []string{"Username", "Password", "TotpSecret", "SamlAuthId", "SvpnCookie", "UseExternalBrowser", "SamlRedirectPort"} {
		vault.Wipe(settings[name])
		delete(settings, name)
	}
	settings[field], _ = json.Marshal(string(raw[6:]))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}
func sealedTunnelCookieConfig(configuration []byte) (string, []byte, error) {
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return "", nil, err
	}
	defer clearTunnelSettingsMap(settings)
	field, other, valid := "SvpnCookie", "SamlAuthId", vault.ValidTunnelCookie
	if tunnelSettingBool(settings, "UseSamlCallback") {
		field, other, valid = "SamlAuthId", "SvpnCookie", vault.ValidFortinetAuthID
	}
	if !tunnelSettingBool(settings, "UseSingleSignOn") || !valid([]byte(tunnelSettingString(settings, field))) || settings[other] != nil {
		return "", nil, vault.ErrPolicy
	}
	vault.Wipe(settings[field])
	delete(settings, field)
	if validateTunnelSettings(2, settings) != nil {
		return "", nil, vault.ErrFormat
	}
	return tunnelSidecarCommand(2, configuration)
}
