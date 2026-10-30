package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

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
	if realm := strings.TrimSpace(tunnelSettingString(settings, "Realm")); realm != "" {
		start.RawQuery = url.Values{"realm": {realm}}.Encode()
	}
	startURL := start.String()
	// Electron bounds each native browser URL to 4096 characters. Check after
	// percent-encoding the realm so a rejected event cannot leave Go waiting.
	if len(startURL) > 4096 {
		return nil, errors.New("Fortinet SAML sign-in URL is too long")
	}
	cookie, err := requestTunnelPrompt(ctx, tunnelPrompt{
		Title: "Fortinet SAML sign-in", Browser: true, URLs: []string{startURL},
		Completion: "cookie", CookieName: "SVPNCOOKIE", RequireHTTPOnly: true,
		IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate"),
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cookie) == "" || len(cookie) > 16*1024 {
		return nil, errors.New("Fortinet SAML returned no VPN cookie")
	}
	delete(settings, "UseExternalBrowser")
	delete(settings, "SamlRedirectPort")
	delete(settings, "SamlAuthId")
	settings["SvpnCookie"], _ = json.Marshal(cookie)
	return json.Marshal(settings)
}
