package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Browser credentials belong to a single connection attempt.
func clearFortinetSSLCredentials(settings map[string]json.RawMessage) {
	for _, key := range []string{"SamlAuthId", "SvpnCookie"} {
		clearBytes(settings[key])
		delete(settings, key)
	}
}

func fortinetSSLEditorSettings(raw json.RawMessage) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, errors.New("Fortinet SSL settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	clearFortinetSSLCredentials(settings)
	return json.Marshal(settings)
}

// Every Fortinet SAML login uses the native isolated authentication window.
// Legacy browser/callback settings are ignored even for already saved tunnels.
func prepareFortinetAuthentication(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if !tunnelSettingBool(settings, "UseSingleSignOn") {
		return raw, nil
	}
	if strings.TrimSpace(tunnelSettingString(settings, "ServerCertSha256Pin")) != "" {
		return nil, errors.New("dedicated-browser Fortinet single sign-on cannot enforce a server certificate pin")
	}
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	base, err := buildWebURL("https", tunnelSettingString(settings, "Host"), port)
	if err != nil {
		return nil, errors.New("Fortinet SAML gateway is invalid")
	}
	start, _ := url.Parse(base)
	start.Path = "/remote/saml/start"
	prompt := tunnelPrompt{
		Title: "Fortinet SAML sign-in", Browser: true,
		Completion: "cookie", CookieName: "SVPNCOOKIE", RequireHTTPOnly: true,
		IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate"),
	}
	useCallback := tunnelSettingBool(settings, "UseSamlCallback")
	realm := strings.TrimSpace(tunnelSettingString(settings, "Realm"))
	if useCallback {
		if realm != "" {
			return nil, errors.New("Fortinet SAML callback requires a tunnel without a realm")
		}
		start.RawQuery = "redirect=1"
		prompt.Completion, prompt.CookieName, prompt.RequireHTTPOnly = "fortinet-ssl", "", false
	} else if realm != "" {
		start.RawQuery = url.Values{"realm": {realm}}.Encode()
	}
	startURL := start.String()
	// Electron bounds each native browser URL to 4096 characters. Check after
	// percent-encoding the realm so a rejected event cannot leave Go waiting.
	if len(startURL) > 4096 {
		return nil, errors.New("Fortinet SAML sign-in URL is too long")
	}
	prompt.URLs = []string{startURL}
	value, err := requestTunnelPrompt(ctx, prompt)
	if err != nil {
		return nil, err
	}
	delete(settings, "UseExternalBrowser")
	delete(settings, "SamlRedirectPort")
	clearFortinetSSLCredentials(settings)
	if useCallback {
		if !vault.ValidFortinetAuthID([]byte(value)) {
			return nil, errors.New("Fortinet SAML returned an invalid authentication ID")
		}
		settings["SamlAuthId"], _ = json.Marshal(value)
	} else {
		if strings.TrimSpace(value) == "" || len(value) > 16*1024 {
			return nil, errors.New("Fortinet SAML returned no VPN cookie")
		}
		settings["SvpnCookie"], _ = json.Marshal(value)
	}
	return json.Marshal(settings)
}
