package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var fortinetIPsecRedirect = regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)

func validateFortinetIPsecSettings(settings map[string]json.RawMessage) error {
	allowed := map[string]bool{"Host": true, "Port": true, "SamlPort": true, "PreSharedKey": true, "LocalId": true, "RemoteId": true, "TrustServerCertificate": true}
	for key, raw := range settings {
		if !allowed[key] {
			return errors.New("Fortinet IPsec setting is unsupported")
		}
		if key == "Port" || key == "SamlPort" {
			if err := validateOptionalTunnelInteger(settings, key, 1, 65535); err != nil {
				return err
			}
		} else if key == "TrustServerCertificate" {
			if err := validateOptionalTunnelBool(settings, key); err != nil {
				return err
			}
		} else {
			var value string
			if json.Unmarshal(raw, &value) != nil || len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return fmt.Errorf("Fortinet IPsec setting %q is invalid", key)
			}
		}
	}
	for _, key := range []string{"Host", "PreSharedKey"} {
		if strings.TrimSpace(tunnelSettingString(settings, key)) == "" {
			return fmt.Errorf("Fortinet IPsec setting %q is required", key)
		}
	}
	host := tunnelSettingString(settings, "Host")
	if len(host) > 253 || strings.ContainsAny(host, "/\\?#@ \t\r\n\x00") {
		return errors.New("Fortinet IPsec gateway must be a bare host name or IP address")
	}
	if _, err := buildWebURL("https", host, 1001); err != nil {
		return errors.New("Fortinet IPsec gateway is invalid")
	}
	return nil
}

// The UID and token are per-attempt EAP credentials. They never enter persistence,
// renderer state, process arguments, or diagnostics. Chromium intercepts the
// callback before sending HTTP to the port reserved by this attempt.
func prepareFortinetIPsecAuthentication(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil {
		return nil, errors.New("Fortinet IPsec settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if err := validateFortinetIPsecSettings(settings); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("could not reserve the Fortinet IPsec SAML callback")
	}
	defer listener.Close()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, errors.New("could not initialize Fortinet IPsec SAML")
	}
	uid := strings.ToUpper(hex.EncodeToString(entropy[:]))
	port := listener.Addr().(*net.TCPAddr).Port
	samlPort := tunnelSettingNumber(settings, "SamlPort")
	if samlPort == 0 {
		samlPort = 1001
	}
	base, _ := buildWebURL("https", tunnelSettingString(settings, "Host"), int(samlPort))
	startURL, err := requestFortinetIPsecSAML(ctx, base, uid, port, tunnelSettingBool(settings, "TrustServerCertificate"))
	if err != nil {
		return nil, err
	}
	token, err := requestTunnelPrompt(ctx, tunnelPrompt{
		Title: "Fortinet IPsec SAML sign-in", Browser: true, URLs: []string{startURL},
		Completion: "fortinet-ipsec", RedirectPrefix: fmt.Sprintf("http://127.0.0.1:%d/", port),
		IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate"),
	})
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 16 {
		return nil, errors.New("Fortinet IPsec SAML returned an invalid token")
	}
	settings["SamlUid"], _ = json.Marshal(uid)
	settings["SamlToken"], _ = json.Marshal(token)
	return json.Marshal(settings)
}

func requestFortinetIPsecSAML(ctx context.Context, base, uid string, callbackPort int, trust bool) (string, error) {
	body, _ := json.Marshal(map[string]string{"type": "rawData", "bytes": fmt.Sprintf("UID=%s&REDIRECT_PORT=%d", uid, callbackPort)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/saml_login?", bytes.NewReader(body))
	if err != nil {
		return "", errors.New("Fortinet IPsec SAML gateway is invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FortiSSLVPN (Linux; SV1 [SV{v=02.01; f=05;}])")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: trust}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return "", errors.New("could not initialize Fortinet IPsec SAML; verify the SAML port and gateway certificate")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 || response.StatusCode != http.StatusOK {
		return "", errors.New("Fortinet IPsec SAML initialization failed")
	}
	match := fortinetIPsecRedirect.FindSubmatch(data)
	if len(match) != 2 {
		return "", errors.New("Fortinet IPsec SAML returned no sign-in URL")
	}
	origin, err := url.Parse(base)
	if err != nil {
		return "", errors.New("Fortinet IPsec SAML gateway is invalid")
	}
	redirect, err := origin.Parse(string(match[1]))
	if err != nil || redirect.Scheme != "https" || redirect.Host != origin.Host || redirect.User != nil || redirect.Path != "/saml" || redirect.Fragment != "" || len(redirect.String()) > 4096 {
		return "", errors.New("Fortinet IPsec SAML returned an invalid sign-in URL")
	}
	return redirect.String(), nil
}
