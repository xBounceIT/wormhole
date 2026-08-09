package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	azureRedirectURI       = "http://localhost:2023"
	azureTokenMaxBytes     = 1 << 20
	azureProfileMaxBytes   = 4 << 20
	azureRefreshMaxAge     = 90 * 24 * time.Hour
	azureServerSecretChars = 512
)

var azureOAuthAuthority = "https://login.microsoftonline.com"

const azureDigiCertGlobalRootG2 = `-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----`

type azureTokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

type azureRefreshCache struct {
	Version      int       `json:"version"`
	SettingsHash string    `json:"settingsHash"`
	RefreshToken string    `json:"refreshToken"`
	CreatedAt    time.Time `json:"createdAt"`
}

type azureBrowserResult struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	Error       string `json:"error"`
	Description string `json:"description"`
}

type azureImportRequest struct {
	Path string `json:"path"`
}

type azureImportResult struct {
	Name     string         `json:"name,omitempty"`
	Settings map[string]any `json:"settings"`
}

func prepareAzureVPN(
	ctx context.Context,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil {
		return nil, errors.New("Azure VPN settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	profile, err := buildAzureVPNProfile(settings)
	if err != nil {
		return nil, err
	}
	var snapshot tunnelConfigSnapshot
	if len(snapshots) > 0 {
		snapshot = snapshots[0]
	}
	settingsHash := providerCacheIdentity(5, settings)
	cacheState := providerCacheState(5, settings)
	accessToken := ""
	if snapshot.id != "" {
		if refresh := readAzureRefreshToken(snapshot, settingsHash); refresh != "" {
			if token, refreshErr := requestAzureToken(ctx, settings, url.Values{
				"client_id": {azureClientID(settings)}, "grant_type": {"refresh_token"},
				"refresh_token": {refresh}, "scope": {azureScope(settings)},
			}); refreshErr == nil {
				accessToken = token.AccessToken
				rotatedRefresh := token.RefreshToken
				if rotatedRefresh == "" {
					rotatedRefresh = refresh
				}
				_ = persistTunnelCacheIfCurrent(snapshot, 5, cacheState, func() error {
					return writeAzureRefreshToken(snapshot, settingsHash, rotatedRefresh)
				})
			} else if strings.Contains(strings.ToLower(refreshErr.Error()), "rejected") {
				removeProtectedTunnelFileIfCurrent(snapshot, azureRefreshPath(snapshot))
			}
		}
	}
	if accessToken == "" {
		verifier, challenge, err := azurePKCE()
		if err != nil {
			return nil, err
		}
		stateBytes := make([]byte, 16)
		if _, err := rand.Read(stateBytes); err != nil {
			return nil, errors.New("could not start Microsoft sign-in")
		}
		state := base64.RawURLEncoding.EncodeToString(stateBytes)
		authorizeURL, err := azureAuthorizeURL(settings, challenge, state)
		if err != nil {
			return nil, err
		}
		encoded, err := requestTunnelPrompt(ctx, tunnelPrompt{
			Title: "Sign in to Microsoft", Browser: true, URLs: []string{authorizeURL},
			Completion: "oauth-code", RedirectPrefix: azureRedirectURI, ExpectedState: state,
		})
		if err != nil {
			return nil, err
		}
		var browser azureBrowserResult
		if json.Unmarshal([]byte(encoded), &browser) != nil || browser.State != state {
			return nil, errors.New("Microsoft sign-in returned an invalid state")
		}
		if browser.Error != "" {
			return nil, fmt.Errorf("Microsoft sign-in failed: %s", browser.Error)
		}
		if browser.Code == "" || len(browser.Code) > 16*1024 {
			return nil, errors.New("Microsoft sign-in returned no authorization code")
		}
		token, err := requestAzureToken(ctx, settings, url.Values{
			"client_id": {azureClientID(settings)}, "grant_type": {"authorization_code"},
			"code": {browser.Code}, "redirect_uri": {azureRedirectURI},
			"code_verifier": {verifier}, "scope": {azureScope(settings)},
		})
		if err != nil {
			return nil, err
		}
		accessToken = token.AccessToken
		if snapshot.id != "" && token.RefreshToken != "" {
			_ = persistTunnelCacheIfCurrent(snapshot, 5, cacheState, func() error {
				return writeAzureRefreshToken(snapshot, settingsHash, token.RefreshToken)
			})
		}
	}
	settings["ProfileOvpn"], _ = json.Marshal(profile)
	settings["Username"], _ = json.Marshal("AzureAD")
	settings["Password"], _ = json.Marshal(accessToken)
	return json.Marshal(settings)
}

func azureClientID(settings map[string]json.RawMessage) string {
	if value := strings.TrimSpace(tunnelSettingString(settings, "ApplicationId")); value != "" {
		return value
	}
	return strings.TrimSpace(tunnelSettingString(settings, "Audience"))
}

func azureScope(settings map[string]json.RawMessage) string {
	return strings.TrimSpace(tunnelSettingString(settings, "Audience")) + "/.default offline_access"
}

func azureTenant(settings map[string]json.RawMessage) (string, error) {
	tenant := strings.TrimSpace(tunnelSettingString(settings, "TenantId"))
	if tenant == "" || len(tenant) > 256 || strings.ContainsAny(tenant, "/\\?#@ \t\r\n") {
		return "", errors.New("Azure VPN tenant ID is invalid")
	}
	return tenant, nil
}

func azureAuthorizeURL(settings map[string]json.RawMessage, challenge, state string) (string, error) {
	tenant, err := azureTenant(settings)
	if err != nil {
		return "", err
	}
	clientID := azureClientID(settings)
	if clientID == "" || strings.TrimSpace(tunnelSettingString(settings, "Audience")) == "" {
		return "", errors.New("Azure VPN audience and application ID are invalid")
	}
	endpoint := azureOAuthAuthority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/authorize"
	query := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {azureRedirectURI},
		"response_mode": {"query"}, "scope": {azureScope(settings)}, "state": {state},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"select_account"},
	}
	return endpoint + "?" + query.Encode(), nil
}

func azurePKCE() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", errors.New("could not create the Microsoft sign-in challenge")
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func requestAzureToken(
	ctx context.Context,
	settings map[string]json.RawMessage,
	form url.Values,
) (azureTokenResult, error) {
	tenant, err := azureTenant(settings)
	if err != nil {
		return azureTokenResult{}, err
	}
	endpoint := azureOAuthAuthority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Microsoft token endpoint redirected unexpectedly")
	}}
	response, err := client.Do(request)
	if err != nil {
		return azureTokenResult{}, errors.New("could not reach Microsoft Entra ID")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, azureTokenMaxBytes+1))
	if err != nil || len(body) > azureTokenMaxBytes {
		return azureTokenResult{}, errors.New("Microsoft token response exceeded the safety limit")
	}
	var token azureTokenResult
	if json.Unmarshal(body, &token) != nil {
		return azureTokenResult{}, errors.New("Microsoft token response was invalid")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 || token.AccessToken == "" {
		return azureTokenResult{}, fmt.Errorf("Microsoft Entra ID rejected the token request: %s", token.Error)
	}
	if len(token.AccessToken) > 64*1024 || len(token.RefreshToken) > 64*1024 {
		return azureTokenResult{}, errors.New("Microsoft token response was too large")
	}
	return token, nil
}

func buildAzureVPNProfile(settings map[string]json.RawMessage) (string, error) {
	servers := stringListSetting(settings, "Servers")
	if len(servers) == 0 {
		return "", errors.New("Azure VPN requires at least one gateway server")
	}
	protocol := "tcp-client"
	if tunnelSettingNumber(settings, "Protocol") == 1 {
		protocol = "udp"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "client\ndev tun\nproto %s\n", protocol)
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if hasTunnelDirectiveDelimiter(server, true) {
			return "", errors.New("Azure VPN gateway server is invalid")
		}
		if _, err := buildWebURL("https", server, 443); err != nil {
			return "", errors.New("Azure VPN gateway server is invalid")
		}
		fmt.Fprintf(&builder, "remote %s 443\n", server)
	}
	builder.WriteString("nobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\ncipher AES-256-GCM\ntls-version-min 1.2\nauth-user-pass\nsetenv CLIENT_CERT 0\n")
	ca := strings.TrimSpace(tunnelSettingString(settings, "CaPem"))
	if ca == "" {
		ca = azureDigiCertGlobalRootG2
	}
	if strings.ContainsAny(ca, "<>") {
		return "", errors.New("Azure VPN CA certificate is invalid")
	}
	fmt.Fprintf(&builder, "<ca>\n%s\n</ca>\n", ca)
	secret := strings.Join(strings.Fields(tunnelSettingString(settings, "ServerSecretHex")), "")
	if secret != "" {
		decoded, err := hex.DecodeString(secret)
		if err != nil || len(secret) != azureServerSecretChars || len(decoded) != azureServerSecretChars/2 {
			return "", errors.New("Azure VPN server secret must contain 512 hexadecimal characters")
		}
		builder.WriteString("key-direction 1\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n")
		for offset := 0; offset < len(secret); offset += 32 {
			builder.WriteString(secret[offset : offset+32])
			builder.WriteByte('\n')
		}
		builder.WriteString("-----END OpenVPN Static key V1-----\n</tls-auth>\n")
	}
	return builder.String(), nil
}

func azureRefreshPath(snapshot tunnelConfigSnapshot) string {
	return tunnelProviderCachePath(snapshot, "azure-token-cache", ".token")
}

func winUIAzureRefreshPath(snapshot tunnelConfigSnapshot) string {
	return tunnelProviderCachePath(snapshot, "azurevpn-cache", ".tokencache")
}

func readAzureRefreshToken(snapshot tunnelConfigSnapshot, settingsHash string) string {
	path := azureRefreshPath(snapshot)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > azureTokenMaxBytes {
		return ""
	}
	plaintext, err := unprotectFile(path)
	if err != nil {
		return ""
	}
	defer clearBytes(plaintext)
	var record azureRefreshCache
	age := time.Duration(0)
	if json.Unmarshal(plaintext, &record) == nil {
		age = time.Since(record.CreatedAt)
	}
	if record.Version != 1 || record.SettingsHash != settingsHash || record.RefreshToken == "" || age < 0 || age > azureRefreshMaxAge {
		return ""
	}
	return record.RefreshToken
}

func writeAzureRefreshToken(snapshot tunnelConfigSnapshot, settingsHash, token string) error {
	plaintext, err := json.Marshal(azureRefreshCache{
		Version: 1, SettingsHash: settingsHash, RefreshToken: token, CreatedAt: time.Now().UTC(),
	})
	if err != nil || len(plaintext) > azureTokenMaxBytes {
		return errors.New("Azure refresh token cache is invalid")
	}
	defer clearBytes(plaintext)
	return protectFile(azureRefreshPath(snapshot), plaintext)
}

func importAzureVPNFile(request azureImportRequest) (azureImportResult, error) {
	path := strings.TrimSpace(request.Path)
	if path == "" || !filepath.IsAbs(path) {
		return azureImportResult{}, errors.New("Azure VPN import path is invalid")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > azureProfileMaxBytes {
		return azureImportResult{}, errors.New("Azure VPN profile is invalid or too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return azureImportResult{}, errors.New("could not read the Azure VPN profile")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, azureProfileMaxBytes+1))
	if err != nil || len(contents) > azureProfileMaxBytes {
		return azureImportResult{}, errors.New("Azure VPN profile exceeded the safety limit")
	}
	return parseAzureVPNProfile(contents)
}

func parseAzureVPNProfile(contents []byte) (azureImportResult, error) {
	type serverEntry struct {
		FQDN string `xml:"fqdn"`
	}
	var document struct {
		XMLName xml.Name `xml:"AzVpnProfile"`
		Name    string   `xml:"name"`
		Servers struct {
			Entries []serverEntry `xml:"ServerEntry"`
		} `xml:"serverlist"`
		Protocol struct {
			SSL struct {
				Transport string `xml:"transportprotocol"`
			} `xml:"sslprotocolConfig"`
		} `xml:"protocolconfig"`
		ClientAuth struct {
			Type string `xml:"type"`
			AAD  struct {
				Tenant, Audience, Issuer, ApplicationID, AppID string
			} `xml:"aad"`
		} `xml:"clientauth"`
		Validation struct {
			ServerSecret string `xml:"serversecret"`
		} `xml:"servervalidation"`
	}
	if xml.Unmarshal(contents, &document) != nil || !strings.EqualFold(document.XMLName.Local, "AzVpnProfile") {
		return azureImportResult{}, errors.New("file is not a valid Azure VPN profile")
	}
	// encoding/xml cannot attach tags to grouped fields; extract the AAD block namespace-agnostically.
	var raw struct {
		ClientAuth struct {
			Type string `xml:"type"`
			AAD  struct {
				Tenant        string `xml:"tenant"`
				Audience      string `xml:"audience"`
				Issuer        string `xml:"issuer"`
				ApplicationID string `xml:"applicationid"`
				AppID         string `xml:"appid"`
			} `xml:"aad"`
		} `xml:"clientauth"`
	}
	_ = xml.Unmarshal(contents, &raw)
	if !strings.EqualFold(strings.TrimSpace(raw.ClientAuth.Type), "aad") {
		return azureImportResult{}, errors.New("Azure VPN profile does not use Microsoft Entra ID authentication")
	}
	servers := make([]string, 0, len(document.Servers.Entries))
	for _, entry := range document.Servers.Entries {
		if value := strings.TrimSpace(entry.FQDN); value != "" {
			servers = append(servers, value)
		}
	}
	if len(servers) == 0 || strings.TrimSpace(raw.ClientAuth.AAD.Audience) == "" {
		return azureImportResult{}, errors.New("Azure VPN profile is missing gateway or audience settings")
	}
	tenant := strings.TrimSpace(raw.ClientAuth.AAD.Tenant)
	if parsed, err := url.Parse(tenant); err == nil && parsed.Host != "" {
		tenant = strings.Trim(strings.TrimSpace(parsed.Path), "/")
	}
	applicationID := strings.TrimSpace(raw.ClientAuth.AAD.ApplicationID)
	if applicationID == "" {
		applicationID = strings.TrimSpace(raw.ClientAuth.AAD.AppID)
	}
	protocol := 0
	if strings.EqualFold(strings.TrimSpace(document.Protocol.SSL.Transport), "udp") {
		protocol = 1
	}
	return azureImportResult{Name: strings.TrimSpace(document.Name), Settings: map[string]any{
		"Servers": servers, "Protocol": protocol, "TenantId": tenant,
		"Audience": strings.TrimSpace(raw.ClientAuth.AAD.Audience),
		"Issuer":   strings.TrimSpace(raw.ClientAuth.AAD.Issuer), "ApplicationId": applicationID,
		"ServerSecretHex": strings.TrimSpace(document.Validation.ServerSecret),
	}}, nil
}
