package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var fortinetIPsecRedirect = regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)

func validateFortinetIPsecSettings(settings map[string]json.RawMessage) error {
	return validateFortinetIPsecConfiguration(settings, true)
}

func fortinetUserAuth(settings map[string]json.RawMessage) int64 {
	if _, ok := settings["UserAuth"]; !ok {
		return 3
	} // Preserve existing SAML profiles.
	return tunnelSettingNumber(settings, "UserAuth")
}

var fortinetIPsecSecretKeys = []string{"PreSharedKey", "Password", "ClientCert", "ClientKey", "CaCert"}

func fortinetIPsecPublicOptions(settings map[string]json.RawMessage) map[string]json.RawMessage {
	if _, explicit := settings["UserAuth"]; !explicit {
		return nil
	}
	options := make(map[string]json.RawMessage)
	for key, raw := range settings {
		secret := key == "SamlUid" || key == "SamlToken"
		for _, name := range fortinetIPsecSecretKeys {
			secret = secret || key == name
		}
		if !secret {
			options[key] = raw
		}
	}
	return options
}

func validateFortinetIPsecConfiguration(settings map[string]json.RawMessage, checkCertificate bool) error {
	stringsAllowed := map[string]bool{"Host": true, "PreSharedKey": true, "LocalId": true, "RemoteId": true, "RemoteGateways": true, "Description": true, "Username": true, "Password": true, "ClientCert": true, "ClientKey": true, "CaCert": true, "ManualAddress": true, "ManualDns": true, "DhGroups": true}
	numbers := map[string][2]int64{"Port": {1, 65535}, "SamlPort": {1, 65535}, "AuthMethod": {0, 1}, "UserAuth": {0, 3}, "IkeVersion": {1, 2}, "ExchangeMode": {0, 1}, "AddressAssignment": {0, 2}, "Phase1Lifetime": {1, 2147483647}, "Phase2Lifetime": {1, 2147483647}, "Phase2LifetimeKb": {1, 2147483647}, "PfsGroup": {1, 21}}
	for _, phase := range []string{"Phase1", "Phase2"} {
		for _, suffix := range []string{"", "2"} {
			numbers[phase+"Encryption"+suffix] = [2]int64{0, 3}
			numbers[phase+"Authentication"+suffix] = [2]int64{0, 4}
		}
	}
	bools := map[string]bool{"AutoProposals": true, "TrustServerCertificate": true, "DeadPeerDetection": true, "NatTraversal": true, "EnableLocalLan": true, "Phase2TimeLifetime": true, "Phase2ByteLifetime": true, "ReplayDetection": true, "Pfs": true}
	for key, raw := range settings {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("Fortinet IPsec setting %q is invalid", key)
		}
		if bounds, ok := numbers[key]; ok {
			if err := validateOptionalTunnelInteger(settings, key, bounds[0], bounds[1]); err != nil {
				return err
			}
		} else if bools[key] {
			if err := validateOptionalTunnelBool(settings, key); err != nil {
				return err
			}
		} else if stringsAllowed[key] {
			var value string
			pem := key == "ClientCert" || key == "ClientKey" || key == "CaCert"
			limit := 4096
			if pem {
				limit = 131072
			}
			if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil || len(value) > limit || strings.IndexFunc(value, func(r rune) bool { return (r < 32 && !(pem && (r == '\r' || r == '\n' || r == '\t'))) || r == 127 }) >= 0 {
				return fmt.Errorf("Fortinet IPsec setting %q is invalid", key)
			}
		} else {
			return errors.New("Fortinet IPsec setting is unsupported")
		}
	}
	required := []string{"Host"}
	if tunnelSettingNumber(settings, "AuthMethod") == 1 {
		required = append(required, "ClientCert", "ClientKey")
	} else {
		required = append(required, "PreSharedKey")
	}
	if fortinetUserAuth(settings) == 2 {
		required = append(required, "Username", "Password")
	}
	if tunnelSettingNumber(settings, "AddressAssignment") == 1 {
		required = append(required, "ManualAddress")
	}
	for _, key := range required {
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
	gateways := tunnelSettingString(settings, "RemoteGateways")
	if gateways != "" {
		if len(strings.Split(gateways, ",")) > 8 {
			return errors.New("Fortinet IPsec supports up to eight additional gateways")
		}
		for _, gateway := range strings.Split(gateways, ",") {
			gateway = strings.TrimSpace(gateway)
			if gateway == "" || len(gateway) > 253 || strings.ContainsAny(gateway, "/\\?#@ \t\r\n") {
				return errors.New("Fortinet IPsec additional gateway is invalid")
			}
			if _, err := buildWebURL("https", gateway, 1001); err != nil {
				return errors.New("Fortinet IPsec additional gateway is invalid")
			}
		}
	}
	groups := map[int]bool{1: true, 2: true, 5: true, 14: true, 15: true, 16: true, 17: true, 18: true, 19: true, 20: true, 21: true}
	if raw := tunnelSettingString(settings, "DhGroups"); raw != "" {
		seen := map[int]bool{}
		for _, token := range strings.Split(raw, ",") {
			group, err := strconv.Atoi(strings.TrimSpace(token))
			if err != nil || !groups[group] || seen[group] {
				return errors.New("Fortinet IPsec DH groups are invalid")
			}
			seen[group] = true
		}
	}
	if _, ok := settings["PfsGroup"]; ok && !groups[int(tunnelSettingNumber(settings, "PfsGroup"))] {
		return errors.New("Fortinet IPsec PFS group is invalid")
	}
	if fortinetUserAuth(settings) == 3 && (tunnelSettingNumber(settings, "AuthMethod") == 1 || tunnelSettingNumber(settings, "IkeVersion") == 1) {
		return errors.New("Fortinet IPsec SAML requires IKEv2 and a gateway PSK")
	}
	if tunnelSettingNumber(settings, "AddressAssignment") == 1 {
		if net.ParseIP(tunnelSettingString(settings, "ManualAddress")).To4() == nil {
			return errors.New("Fortinet IPsec manual IPv4 address is invalid")
		}
	}
	if dns := tunnelSettingString(settings, "ManualDns"); dns != "" {
		for _, ip := range strings.Split(dns, ",") {
			if net.ParseIP(strings.TrimSpace(ip)) == nil {
				return errors.New("Fortinet IPsec DNS server is invalid")
			}
		}
	}
	if checkCertificate && tunnelSettingNumber(settings, "AuthMethod") == 1 {
		if _, err := tls.X509KeyPair([]byte(tunnelSettingString(settings, "ClientCert")), []byte(tunnelSettingString(settings, "ClientKey"))); err != nil {
			return errors.New("Fortinet IPsec client certificate and private key are invalid or do not match")
		}
		if ca := tunnelSettingString(settings, "CaCert"); ca != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(ca)) {
			return errors.New("Fortinet IPsec CA certificate is invalid")
		}
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
	if fortinetUserAuth(settings) != 3 {
		if fortinetUserAuth(settings) == 1 {
			if strings.TrimSpace(tunnelSettingString(settings, "Username")) == "" {
				username, err := requestTunnelPrompt(ctx, tunnelPrompt{Title: "Fortinet IPsec username", Message: "Enter the VPN username."})
				if err != nil {
					return nil, err
				}
				if strings.TrimSpace(username) == "" || len(username) > 4096 || strings.ContainsAny(username, "\r\n\x00") {
					return nil, errors.New("Fortinet IPsec username is invalid")
				}
				settings["Username"], _ = json.Marshal(username)
			}
			password, err := requestTunnelPrompt(ctx, tunnelPrompt{Title: "Fortinet IPsec password", Message: "Enter the VPN password.", Secret: true})
			if err != nil {
				return nil, err
			}
			if password == "" || len(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
				return nil, errors.New("Fortinet IPsec password is invalid")
			}
			settings["Password"], _ = json.Marshal(password)
		}
		return json.Marshal(settings)
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
	gateways := []string{tunnelSettingString(settings, "Host")}
	if additional := tunnelSettingString(settings, "RemoteGateways"); additional != "" {
		gateways = append(gateways, strings.Split(additional, ",")...)
	}
	var startURL string
	for _, host := range gateways {
		host = strings.TrimSpace(host)
		base, _ := buildWebURL("https", host, int(samlPort))
		startURL, err = requestFortinetIPsecSAML(ctx, base, uid, port, tunnelSettingBool(settings, "TrustServerCertificate"))
		if err == nil {
			settings["Host"], _ = json.Marshal(host)
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
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
