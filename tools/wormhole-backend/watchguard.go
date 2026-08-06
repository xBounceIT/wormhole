package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	watchguardMaxBundleBytes = 64 << 20
	watchguardMaxEntryBytes  = 1 << 20
	watchguardMaxEntries     = 64
	watchguardCacheMaxAge    = 30 * 24 * time.Hour
	watchguardCacheMaxBytes  = 2 << 20
	watchguardRequestTimeout = 120 * time.Second
)

type watchguardCacheRecord struct {
	Version      int       `json:"version"`
	SettingsHash string    `json:"settingsHash"`
	Profile      string    `json:"profile"`
	CreatedAt    time.Time `json:"createdAt"`
}

type watchguardLogonResponse struct {
	Status      int    `xml:"logon_status"`
	LogonID     string `xml:"logon_id"`
	Prompt      string `xml:"chaStr"`
	Message     string `xml:"message"`
	Error       string `xml:"errStr"`
	SAMLEnabled string `xml:"saml_enabled"`
}

type watchguardBrowserCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
}

type watchguardSAMLResult struct {
	Username string                    `json:"username"`
	Token    string                    `json:"token"`
	Cookies  []watchguardBrowserCookie `json:"cookies"`
}

type watchguardImportRequest struct {
	Path string `json:"path"`
}

type watchguardImportResult struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	ProfileOvpn string `json:"profileOvpn"`
}

func importWatchguardFile(request watchguardImportRequest) (watchguardImportResult, error) {
	path := strings.TrimSpace(request.Path)
	if path == "" || !filepath.IsAbs(path) {
		return watchguardImportResult{}, errors.New("WatchGuard import path is invalid")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > watchguardMaxBundleBytes {
		return watchguardImportResult{}, errors.New("WatchGuard profile bundle is invalid or too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return watchguardImportResult{}, errors.New("could not open the WatchGuard profile bundle")
	}
	defer file.Close()
	bundle, err := io.ReadAll(io.LimitReader(file, watchguardMaxBundleBytes+1))
	if err != nil || len(bundle) > watchguardMaxBundleBytes {
		return watchguardImportResult{}, errors.New("WatchGuard profile bundle exceeded the safety limit")
	}
	profile, err := importWatchguardBundle(bundle)
	if err != nil {
		return watchguardImportResult{}, err
	}
	host, port, err := watchguardRemote(profile)
	if err != nil {
		return watchguardImportResult{}, err
	}
	return watchguardImportResult{Server: host, Port: port, ProfileOvpn: profile}, nil
}

func watchguardRemote(profile string) (string, int, error) {
	insideBlock := false
	for _, line := range strings.Split(strings.ReplaceAll(profile, "\r", ""), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<") && !strings.HasPrefix(trimmed, "</") {
			insideBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "</") {
			insideBlock = false
			continue
		}
		if insideBlock {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "remote") {
			continue
		}
		host := fields[1]
		port := 443
		if len(fields) >= 3 {
			parsed, parseErr := strconv.Atoi(fields[2])
			if parseErr != nil || parsed < 1 || parsed > 65535 {
				return "", 0, errors.New("WatchGuard profile has an invalid remote port")
			}
			port = parsed
		}
		if _, err := buildWebURL("https", host, port); err != nil {
			return "", 0, errors.New("WatchGuard profile has an invalid remote host")
		}
		return host, port, nil
	}
	return "", 0, errors.New("WatchGuard profile contains no remote gateway")
}

func prepareWatchguardProfile(
	ctx context.Context,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	var snapshot tunnelConfigSnapshot
	if len(snapshots) > 0 {
		snapshot = snapshots[0]
	}
	settingsHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	authMode := tunnelSettingNumber(settings, "AuthMode")
	if authMode == 2 {
		return prepareWatchguardSAML(ctx, settings)
	}
	if authMode == 0 && (strings.TrimSpace(tunnelSettingString(settings, "Username")) == "" || tunnelSettingString(settings, "Password") == "") {
		client, clientErr := newWatchguardHTTPClient(settings)
		if clientErr != nil {
			return nil, clientErr
		}
		status, statusErr := watchguardLogon(ctx, client, settings, url.Values{
			"action": {"sslvpn_logon"}, "style": {"fw_logon.xsl"}, "fw_logon_type": {"status"},
		})
		client.CloseIdleConnections()
		if statusErr == nil && watchguardSAMLIsEnabled(status.SAMLEnabled) {
			return prepareWatchguardSAML(ctx, settings)
		}
	}
	profile := strings.TrimSpace(tunnelSettingString(settings, "ProfileOvpn"))
	if profile != "" || watchguardHasManualMaterial(settings) {
		built, err := buildWatchguardProfile(settings)
		if err != nil {
			return nil, err
		}
		return finishWatchguardStoredProfile(ctx, settings, built)
	}
	if snapshot.id != "" {
		if cached := readWatchguardCachedProfile(snapshot, settingsHash); cached != "" {
			return finishWatchguardStoredProfile(ctx, settings, cached)
		}
	}

	client, err := newWatchguardHTTPClient(settings)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	username := strings.TrimSpace(tunnelSettingString(settings, "Username"))
	password := tunnelSettingString(settings, "Password")
	if username == "" || password == "" {
		return nil, errors.New("WatchGuard username and password are required")
	}
	domain := strings.TrimSpace(tunnelSettingString(settings, "Domain"))
	if strings.EqualFold(domain, "Firebox-DB") {
		domain = ""
	}
	result, err := watchguardLogon(ctx, client, settings, url.Values{
		"action": {"sslvpn_logon"}, "fw_username": {username}, "fw_password": {password},
		"style": {"fw_logon_progress.xsl"}, "fw_logon_type": {"logon"}, "fw_domain": {domain},
	})
	if err != nil {
		return nil, err
	}
	dataPlanePassword := password
	if result.Status == 4 || result.Status == 8 {
		if strings.TrimSpace(result.LogonID) == "" {
			return nil, errors.New("WatchGuard requested 2FA without a logon identifier")
		}
		message := strings.TrimSpace(result.Prompt)
		if message == "" {
			message = "Enter an AuthPoint OTP code, or type 'p' to send a push notification."
		}
		answer, promptErr := requestTunnelPrompt(ctx, tunnelPrompt{
			Title: "WatchGuard two-factor authentication", Message: message, Secret: true,
		})
		answer = strings.TrimSpace(answer)
		if promptErr != nil {
			return nil, promptErr
		}
		if answer == "" {
			return nil, errors.New("WatchGuard two-factor response is required")
		}
		responseType, responseField := "response", "response"
		if strings.EqualFold(answer, "p") {
			responseType, responseField = "mfa_response", "mfa_choice"
			answer = "p"
		}
		result, err = watchguardLogon(ctx, client, settings, url.Values{
			"action": {"sslvpn_logon"}, "style": {"fw_logon_progress.xsl"},
			"fw_logon_type": {responseType}, responseField: {answer}, "fw_logon_id": {result.LogonID},
		})
		if err != nil {
			return nil, err
		}
		dataPlanePassword = answer
	}
	if result.Status != 1 {
		message := strings.TrimSpace(result.Message)
		if message == "" {
			message = strings.TrimSpace(result.Error)
		}
		if message == "" {
			message = fmt.Sprintf("credentials were rejected (status %d)", result.Status)
		}
		return nil, errors.New("WatchGuard authentication failed: " + message)
	}

	bundle, err := downloadWatchguardBundle(ctx, client, settings)
	if err != nil {
		return nil, err
	}
	profile, err = importWatchguardBundle(bundle)
	if err != nil {
		return nil, err
	}
	if snapshot.id != "" {
		_ = writeWatchguardCachedProfile(snapshot, settingsHash, profile)
	}
	settings["ProfileOvpn"], _ = json.Marshal(profile)
	settings["Password"], _ = json.Marshal(dataPlanePassword)
	delete(settings, "ChallengeResponse")
	return json.Marshal(settings)
}

func prepareWatchguardSAML(
	ctx context.Context,
	settings map[string]json.RawMessage,
) (json.RawMessage, error) {
	client, err := newWatchguardHTTPClient(settings)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	base, err := watchguardURL(settings, "/", nil)
	if err != nil {
		return nil, err
	}
	baseURL, _ := url.Parse(base)
	urls := make([]string, 0, 3)
	for _, path := range []string{"/auth/saml", "/auth/saml/login", "/saml/login"} {
		candidate := *baseURL
		candidate.Path = path
		candidate.RawQuery = "from=sslvpn_client"
		urls = append(urls, candidate.String())
	}
	encoded, err := requestTunnelPrompt(ctx, tunnelPrompt{
		Title: "WatchGuard SAML sign-in", Browser: true, URLs: urls,
		Completion:              "query-token",
		IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate"),
	})
	if err != nil {
		return nil, err
	}
	var result watchguardSAMLResult
	if json.Unmarshal([]byte(encoded), &result) != nil || strings.TrimSpace(result.Username) == "" ||
		strings.TrimSpace(result.Token) == "" || len(result.Username) > 1024 || len(result.Token) > 16*1024 ||
		len(result.Cookies) > 256 {
		return nil, errors.New("WatchGuard SAML response is invalid")
	}
	cookies := make([]*http.Cookie, 0, len(result.Cookies))
	for _, cookie := range result.Cookies {
		if cookie.Name == "" || len(cookie.Name) > 256 || len(cookie.Value) > 16*1024 ||
			strings.ContainsAny(cookie.Name, "\r\n;=") {
			return nil, errors.New("WatchGuard SAML returned an invalid cookie")
		}
		cookies = append(cookies, &http.Cookie{
			Name: cookie.Name, Value: cookie.Value, Path: cookie.Path,
			Domain: cookie.Domain, Secure: cookie.Secure, HttpOnly: cookie.HTTPOnly,
		})
	}
	client.Jar.SetCookies(baseURL, cookies)
	bundle, err := downloadWatchguardBundle(ctx, client, settings)
	if err != nil {
		return nil, err
	}
	profile, err := importWatchguardBundle(bundle)
	if err != nil {
		return nil, err
	}
	settings["ProfileOvpn"], _ = json.Marshal(profile)
	settings["Username"], _ = json.Marshal(strings.TrimSpace(result.Username))
	settings["Password"], _ = json.Marshal(result.Token)
	delete(settings, "ChallengeResponse")
	return json.Marshal(settings)
}

func finishWatchguardStoredProfile(
	ctx context.Context,
	settings map[string]json.RawMessage,
	profile string,
) (json.RawMessage, error) {
	answer, err := requestTunnelPrompt(ctx, tunnelPrompt{
		Title:   "WatchGuard two-factor authentication",
		Message: "Enter your one-time passcode, or type 'p' to approve with a push notification.",
		Secret:  true,
	})
	answer = strings.TrimSpace(answer)
	if err != nil {
		return nil, err
	}
	if answer == "" {
		return nil, errors.New("WatchGuard two-factor response is required")
	}
	if strings.EqualFold(answer, "p") {
		if err := approveWatchguardPush(ctx, settings); err != nil {
			return nil, err
		}
		answer = "p"
	}
	settings["ProfileOvpn"], _ = json.Marshal(profile)
	settings["ChallengeResponse"], _ = json.Marshal(answer)
	return json.Marshal(settings)
}

func watchguardSAMLIsEnabled(value string) bool {
	value = strings.TrimSpace(value)
	return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
}

func approveWatchguardPush(ctx context.Context, settings map[string]json.RawMessage) error {
	username := strings.TrimSpace(tunnelSettingString(settings, "Username"))
	password := tunnelSettingString(settings, "Password")
	if username == "" || password == "" {
		return errors.New("WatchGuard push approval requires a username and password")
	}
	client, err := newWatchguardHTTPClient(settings)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	domain := strings.TrimSpace(tunnelSettingString(settings, "Domain"))
	if strings.EqualFold(domain, "Firebox-DB") {
		domain = ""
	}
	result, err := watchguardLogon(ctx, client, settings, url.Values{
		"action": {"sslvpn_logon"}, "fw_username": {username}, "fw_password": {password},
		"style": {"fw_logon_progress.xsl"}, "fw_logon_type": {"logon"}, "fw_domain": {domain},
	})
	if err != nil {
		return err
	}
	if result.Status == 1 {
		return nil
	}
	if (result.Status != 4 && result.Status != 8) || strings.TrimSpace(result.LogonID) == "" {
		return errors.New("WatchGuard push pre-authentication was rejected")
	}
	result, err = watchguardLogon(ctx, client, settings, url.Values{
		"action": {"sslvpn_logon"}, "style": {"fw_logon_progress.xsl"},
		"fw_logon_type": {"mfa_response"}, "mfa_choice": {"p"}, "fw_logon_id": {result.LogonID},
	})
	if err != nil {
		return err
	}
	if result.Status != 1 {
		return errors.New("WatchGuard push was not approved")
	}
	return nil
}

func newWatchguardHTTPClient(settings map[string]json.RawMessage) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if tunnelSettingBool(settings, "TrustServerCertificate") {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec -- explicit user opt-in
	} else if caPEM := strings.TrimSpace(tunnelSettingString(settings, "CaPem")); caPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("WatchGuard CA certificate is invalid")
		}
		tlsConfig.RootCAs = roots
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}
	return &http.Client{
		Transport: transport, Jar: jar, Timeout: watchguardRequestTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 0 && (request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Host, via[0].URL.Host)) {
				return errors.New("WatchGuard portal redirected outside the configured gateway")
			}
			return nil
		},
	}, nil
}

func watchguardURL(settings map[string]json.RawMessage, path string, query url.Values) (string, error) {
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	base, err := buildWebURL("https", tunnelSettingString(settings, "Server"), port)
	if err != nil {
		return "", errors.New("WatchGuard portal address is invalid")
	}
	parsed, _ := url.Parse(base)
	parsed.Path = path
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func watchguardLogon(
	ctx context.Context,
	client *http.Client,
	settings map[string]json.RawMessage,
	query url.Values,
) (watchguardLogonResponse, error) {
	endpoint, err := watchguardURL(settings, "/", query)
	if err != nil {
		return watchguardLogonResponse{}, err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("User-Agent", "WatchGuard/wgsslvpnc.exe")
	response, err := client.Do(request)
	if err != nil {
		return watchguardLogonResponse{}, errors.New("could not reach the WatchGuard authentication portal")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return watchguardLogonResponse{}, fmt.Errorf("WatchGuard authentication returned HTTP %d", response.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "" && mediaType != "application/xml" && mediaType != "text/xml" {
		return watchguardLogonResponse{}, errors.New("WatchGuard authentication returned a non-XML response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || len(body) == 1<<20 {
		return watchguardLogonResponse{}, errors.New("WatchGuard authentication response exceeded the safety limit")
	}
	var result watchguardLogonResponse
	if xml.Unmarshal(body, &result) != nil {
		return watchguardLogonResponse{}, errors.New("WatchGuard authentication returned malformed XML")
	}
	return result, nil
}

func downloadWatchguardBundle(
	ctx context.Context,
	client *http.Client,
	settings map[string]json.RawMessage,
) ([]byte, error) {
	endpoint, err := watchguardURL(settings, "/", url.Values{
		"action": {"sslvpn_download"}, "filename": {"client.wgssl"},
	})
	if err != nil {
		return nil, err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("User-Agent", "WatchGuard/wgsslvpnc.exe")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("could not download the WatchGuard VPN profile")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("WatchGuard profile download returned HTTP %d", response.StatusCode)
	}
	bundle, err := io.ReadAll(io.LimitReader(response.Body, watchguardMaxBundleBytes+1))
	if err != nil || len(bundle) > watchguardMaxBundleBytes {
		return nil, errors.New("WatchGuard profile bundle exceeded the safety limit")
	}
	return bundle, nil
}

func importWatchguardBundle(bundle []byte) (string, error) {
	var reader io.Reader = bytes.NewReader(bundle)
	if len(bundle) >= 2 && bundle[0] == 0x1f && bundle[1] == 0x8b {
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return "", errors.New("WatchGuard profile bundle is not valid gzip")
		}
		defer gzipReader.Close()
		reader = io.LimitReader(gzipReader, watchguardMaxBundleBytes+1)
	}
	archive := tar.NewReader(reader)
	files := make(map[string]string)
	for index := 0; ; index++ {
		if index >= watchguardMaxEntries {
			return "", errors.New("WatchGuard profile bundle has too many entries")
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("WatchGuard profile bundle is invalid")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if header.Size < 0 || header.Size > watchguardMaxEntryBytes {
			return "", errors.New("WatchGuard profile bundle entry exceeded the safety limit")
		}
		contents, err := io.ReadAll(io.LimitReader(archive, watchguardMaxEntryBytes+1))
		if err != nil || len(contents) > watchguardMaxEntryBytes {
			return "", errors.New("WatchGuard profile bundle entry exceeded the safety limit")
		}
		files[strings.ToLower(filepath.Base(strings.ReplaceAll(header.Name, "\\", "/")))] = string(contents)
	}
	for _, name := range []string{"client.ovpn", "ca.crt", "client.crt", "client.pem"} {
		if strings.TrimSpace(files[name]) == "" {
			return "", fmt.Errorf("WatchGuard profile bundle is missing %s", name)
		}
	}
	profile, unresolved := inlineStormshieldFiles(files["client.ovpn"], func(name string) (string, bool) {
		value, ok := files[strings.ToLower(filepath.Base(strings.ReplaceAll(name, "\\", "/")))]
		return value, ok
	})
	if len(unresolved) > 0 {
		return "", errors.New("WatchGuard profile references missing key material")
	}
	return normalizeStormshieldProfile(profile)
}

func watchguardHasManualMaterial(settings map[string]json.RawMessage) bool {
	return strings.TrimSpace(tunnelSettingString(settings, "CaPem")) != "" &&
		strings.TrimSpace(tunnelSettingString(settings, "ClientCertPem")) != "" &&
		strings.TrimSpace(tunnelSettingString(settings, "ClientKeyPem")) != ""
}

func buildWatchguardProfile(settings map[string]json.RawMessage) (string, error) {
	profile := strings.TrimSpace(tunnelSettingString(settings, "ProfileOvpn"))
	if profile != "" {
		files := map[string]string{
			"ca.crt": tunnelSettingString(settings, "CaPem"), "client.crt": tunnelSettingString(settings, "ClientCertPem"),
			"client.pem": tunnelSettingString(settings, "ClientKeyPem"),
		}
		inlined, unresolved := inlineStormshieldFiles(profile, func(name string) (string, bool) {
			value, ok := files[strings.ToLower(filepath.Base(strings.ReplaceAll(name, "\\", "/")))]
			return value, ok && strings.TrimSpace(value) != ""
		})
		if len(unresolved) > 0 {
			return "", errors.New("WatchGuard profile references missing key material")
		}
		return normalizeStormshieldProfile(inlined)
	}
	server := tunnelSettingString(settings, "Server")
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	if _, err := buildWebURL("https", server, port); err != nil {
		return "", errors.New("WatchGuard server is invalid")
	}
	verify := strings.TrimSpace(tunnelSettingString(settings, "VerifyX509Name"))
	if strings.ContainsAny(verify, "\r\n\"") {
		return "", errors.New("WatchGuard certificate subject is invalid")
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "client\ndev tun\nproto tcp-client\nremote %s %d\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\n", server, port)
	if verify != "" && !tunnelSettingBool(settings, "TrustServerCertificate") {
		fmt.Fprintf(&builder, "verify-x509-name \"%s\" subject\n", verify)
	}
	builder.WriteString("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC\ndata-ciphers-fallback AES-256-CBC\ncipher AES-256-CBC\nauth SHA256\nauth-user-pass\n")
	for _, block := range []struct{ name, value string }{
		{"ca", tunnelSettingString(settings, "CaPem")}, {"cert", tunnelSettingString(settings, "ClientCertPem")}, {"key", tunnelSettingString(settings, "ClientKeyPem")},
	} {
		if strings.Contains(strings.ToLower(block.value), "</"+block.name+">") {
			return "", errors.New("WatchGuard PEM material is invalid")
		}
		fmt.Fprintf(&builder, "<%s>\n%s\n</%s>\n", block.name, strings.TrimSpace(block.value), block.name)
	}
	return normalizeStormshieldProfile(builder.String())
}

func watchguardCachePath(snapshot tunnelConfigSnapshot) string {
	compact := strings.ReplaceAll(normalizeTunnelID(snapshot.id), "-", "")
	return filepath.Join(filepath.Dir(snapshot.databasePath), "watchguard-cache", compact+".ovpncache")
}

func readWatchguardCachedProfile(snapshot tunnelConfigSnapshot, settingsHash string) string {
	path := watchguardCachePath(snapshot)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > watchguardCacheMaxBytes {
		return ""
	}
	plaintext, err := unprotectFile(path)
	if err != nil {
		return ""
	}
	defer clearBytes(plaintext)
	var record watchguardCacheRecord
	age := time.Duration(0)
	if json.Unmarshal(plaintext, &record) == nil {
		age = time.Since(record.CreatedAt)
	}
	if record.Version != 1 || record.SettingsHash != settingsHash || record.Profile == "" ||
		record.CreatedAt.IsZero() || age < 0 || age > watchguardCacheMaxAge {
		return ""
	}
	return record.Profile
}

func writeWatchguardCachedProfile(snapshot tunnelConfigSnapshot, settingsHash, profile string) error {
	plaintext, err := json.Marshal(watchguardCacheRecord{
		Version: 1, SettingsHash: settingsHash, Profile: profile, CreatedAt: time.Now().UTC(),
	})
	if err != nil || len(plaintext) > watchguardCacheMaxBytes {
		return errors.New("WatchGuard profile cache is invalid")
	}
	defer clearBytes(plaintext)
	return protectFile(watchguardCachePath(snapshot), plaintext)
}
