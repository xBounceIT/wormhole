package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	stormshieldMaxProfileBytes = 1 << 20
	stormshieldMaxZipEntries   = 32
	stormshieldRequestTimeout  = 30 * time.Second
	stormshieldCacheMaxAge     = 7 * 24 * time.Hour
	stormshieldCacheMaxBytes   = 2 << 20
	stormshieldCacheVersion    = 2
)

type stormshieldCacheRecord struct {
	Version      int       `json:"version"`
	SettingsHash string    `json:"settingsHash"`
	ConfigHash   string    `json:"configHash,omitempty"`
	Profile      string    `json:"profile"`
	CreatedAt    time.Time `json:"createdAt"`
}

type stormshieldPortalRequestError struct{ cause error }

func (err *stormshieldPortalRequestError) Error() string {
	return "could not reach the Stormshield configuration portal"
}

func (err *stormshieldPortalRequestError) Unwrap() error { return err.cause }

var stormshieldTLSConsentGate sync.Mutex

var stormshieldOTPGuard = struct {
	sync.Mutex
	recent map[string]stormshieldSpentOTP
}{recent: make(map[string]stormshieldSpentOTP)}

type stormshieldSpentOTP struct {
	hash [sha256.Size]byte
	at   time.Time
}

func prepareStormshieldProfile(
	ctx context.Context,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	prepared, err := prepareStormshieldProfileCore(ctx, raw, snapshots...)
	if err == nil || !isStormshieldCertificateError(err) {
		return prepared, err
	}
	var initial map[string]json.RawMessage
	if json.Unmarshal(raw, &initial) != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(initial)
	if tunnelSettingBool(initial, "TrustServerCertificate") {
		return nil, err
	}
	if strings.TrimSpace(tunnelSettingString(initial, "CaPem")) != "" {
		return nil, errors.New("the Stormshield server certificate does not chain to the CA pinned in this tunnel; update the pinned CA if the firewall certificate changed")
	}

	// Multiple sessions can discover the same factory certificate together. Only one prompt is
	// useful; after the gate, reload the protected settings in case another session already saved
	// consent while this one waited.
	stormshieldTLSConsentGate.Lock()
	defer stormshieldTLSConsentGate.Unlock()
	if len(snapshots) > 0 && snapshots[0].id != "" {
		if current, readErr := readTunnel(snapshots[0].databasePath, tunnelReadRequest{ID: snapshots[0].id}); readErr == nil {
			defer clearBytes(current.Settings)
			if current.Kind == 4 {
				var currentSettings map[string]json.RawMessage
				currentErr := json.Unmarshal(current.Settings, &currentSettings)
				defer clearTunnelSettingsMap(currentSettings)
				if currentErr == nil && tunnelSettingBool(currentSettings, "TrustServerCertificate") {
					return prepareStormshieldProfileCore(ctx, current.Settings, snapshots...)
				}
			}
		}
	}

	name := "Stormshield"
	if len(snapshots) > 0 && strings.TrimSpace(snapshots[0].name) != "" {
		name = snapshots[0].name
	}
	host := tunnelSettingString(initial, "Server")
	port := int(tunnelSettingNumber(initial, "Port"))
	if port == 0 {
		port = 443
	}
	accepted, promptErr := requestTunnelPrompt(ctx, tunnelPrompt{
		Title:        "Unverified VPN server certificate — " + name,
		Message:      fmt.Sprintf("The TLS certificate presented by %s:%d could not be verified. Stormshield appliances commonly use a private or factory certificate. Trust this only if this is your firewall: accepting disables certificate verification for this tunnel and may expose the VPN password and one-time codes to an impersonating server.", host, port),
		Confirmation: true,
		AcceptLabel:  "Trust and connect",
	})
	if promptErr != nil {
		return nil, promptErr
	}
	if accepted != "accept" {
		return nil, errors.New("Stormshield server certificate was not trusted")
	}
	trusted, _ := json.Marshal(true)
	initial["TrustServerCertificate"] = trusted
	trustedRaw, marshalErr := json.Marshal(initial)
	if marshalErr != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	defer clearBytes(trustedRaw)
	if len(snapshots) > 0 && snapshots[0].id != "" {
		persistStormshieldTrustIfUnchanged(snapshots[0], raw, trustedRaw)
	}
	return prepareStormshieldProfileCore(ctx, trustedRaw, snapshots...)
}

func prepareStormshieldProfileCore(
	ctx context.Context,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if tunnelSettingBool(settings, "UseSingleSignOn") {
		return nil, errors.New("Stormshield single sign-on is not available yet")
	}
	profile := tunnelSettingString(settings, "ProfileOvpn")
	automatic := tunnelSettingNumber(settings, "Mode") == 0
	useOTP := tunnelSettingBool(settings, "UseOtp")
	downloadedWithOTP := false
	optimisticCacheHit := false
	configHash := ""
	var err error
	var snapshot tunnelConfigSnapshot
	if len(snapshots) > 0 {
		snapshot = snapshots[0]
	}
	settingsHash := providerCacheIdentity(4, settings)
	cacheState := providerCacheState(4, settings)
	if automatic && useOTP && snapshot.id != "" {
		cached := readStormshieldCachedProfile(snapshot, settingsHash)
		configHash, err = getStormshieldConfigHash(ctx, settings)
		if err != nil {
			if cached == nil || !isStormshieldCertificateError(err) {
				return nil, err
			}
			// A cache hit does not send portal credentials. If only the unauthenticated
			// change-check's certificate failed, reuse the protected profile optimistically;
			// OpenVPN still applies the profile's own server-certificate policy.
			configHash = ""
		}
		if cached != nil && (configHash == "" || strings.EqualFold(cached.ConfigHash, configHash)) {
			profile = cached.Profile
			optimisticCacheHit = configHash == ""
		} else {
			profile = ""
		}
	}
	var otp string
	if useOTP {
		var err error
		otp, err = requestTunnelPrompt(ctx, tunnelPrompt{
			Title:   "Stormshield one-time code",
			Message: "Enter a fresh one-time password for this VPN connection.",
			Secret:  true,
		})
		otp = strings.TrimSpace(otp)
		if err != nil {
			return nil, err
		}
		if otp == "" {
			return nil, errors.New("Stormshield one-time code is required")
		}
		if snapshot.id != "" && stormshieldOTPWasRecentlySpent(snapshot.id, otp, false) {
			return nil, errors.New("that Stormshield one-time code was just used; wait until your authenticator shows a new code, then reconnect")
		}
	}
	if automatic && profile == "" {
		if useOTP {
			password, _ := json.Marshal(tunnelSettingString(settings, "Password") + otp)
			settings["Password"] = password
			downloadedWithOTP = true
		}
		if err := reportTunnelProgress(ctx, "downloading", ""); err != nil {
			return nil, err
		}
		var err error
		profile, err = downloadStormshieldProfile(ctx, settings)
		if err != nil {
			return nil, err
		}
	}
	baseProfile, err := normalizeStormshieldProfile(profile)
	if err != nil {
		return nil, err
	}
	if automatic && downloadedWithOTP {
		stormshieldOTPWasRecentlySpent(snapshot.id, otp, true)
		if snapshot.id == "" || snapshot.databasePath == "" {
			return nil, errors.New("Stormshield could not cache the downloaded VPN profile")
		}
		if err := persistTunnelCacheIfCurrent(snapshot, 4, cacheState, func() error {
			return writeStormshieldCachedProfile(snapshot, settingsHash, configHash, baseProfile)
		}); err != nil {
			return nil, errors.New("Stormshield downloaded a fresh VPN profile, but could not protect its cache; reconnecting will download it again and require another new one-time code")
		}
		return nil, errors.New("Stormshield downloaded and protected a fresh VPN profile; connect again with a new one-time code")
	}
	effectiveProfile, err := applyStormshieldTransportOverride(baseProfile, int(tunnelSettingNumber(settings, "OpenVpnTransportOverride")))
	if err != nil {
		return nil, err
	}
	if tunnelSettingNumber(settings, "OpenVpnCompressionFramingOverride") == 1 {
		effectiveProfile, err = applyStormshieldLegacyCompressionStub(effectiveProfile)
		if err != nil {
			return nil, err
		}
	}
	if useOTP {
		password, _ := json.Marshal(tunnelSettingString(settings, "Password") + otp)
		settings["Password"] = password
	}
	if optimisticCacheHit {
		settings["_WormholeStormshieldOptimisticCache"] = json.RawMessage("true")
	}
	encoded, _ := json.Marshal(effectiveProfile)
	settings["ProfileOvpn"] = encoded
	return json.Marshal(settings)
}

func stormshieldOTPWasRecentlySpent(id, code string, record bool) bool {
	if id == "" || strings.TrimSpace(code) == "" {
		return false
	}
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(strings.TrimSpace(code)))
	stormshieldOTPGuard.Lock()
	defer stormshieldOTPGuard.Unlock()
	for key, prior := range stormshieldOTPGuard.recent {
		if now.Sub(prior.at) >= 90*time.Second || now.Before(prior.at) {
			delete(stormshieldOTPGuard.recent, key)
		}
	}
	prior, present := stormshieldOTPGuard.recent[id]
	reused := present && subtle.ConstantTimeCompare(prior.hash[:], digest[:]) == 1
	if record {
		stormshieldOTPGuard.recent[id] = stormshieldSpentOTP{hash: digest, at: now}
	}
	return reused
}

func clearStormshieldOTPGuard(id string) {
	stormshieldOTPGuard.Lock()
	delete(stormshieldOTPGuard.recent, id)
	stormshieldOTPGuard.Unlock()
}

func stormshieldCachePath(snapshot tunnelConfigSnapshot) string {
	return tunnelProviderCachePath(snapshot, "electron-stormshield-cache", ".ovpncache")
}

func winUIStormshieldCachePath(snapshot tunnelConfigSnapshot) string {
	return tunnelProviderCachePath(snapshot, "stormshield-cache", ".ovpncache")
}

func readStormshieldCachedProfile(snapshot tunnelConfigSnapshot, settingsHash string) *stormshieldCacheRecord {
	path := stormshieldCachePath(snapshot)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > stormshieldCacheMaxBytes {
		return nil
	}
	plaintext, err := unprotectFile(path)
	if err != nil {
		return nil
	}
	defer clearBytes(plaintext)
	var record stormshieldCacheRecord
	if json.Unmarshal(plaintext, &record) != nil || record.Version != stormshieldCacheVersion ||
		record.SettingsHash != settingsHash || record.Profile == "" ||
		record.CreatedAt.IsZero() || time.Since(record.CreatedAt) < 0 ||
		time.Since(record.CreatedAt) > stormshieldCacheMaxAge {
		return nil
	}
	return &record
}

func writeStormshieldCachedProfile(
	snapshot tunnelConfigSnapshot,
	settingsHash string,
	configHash string,
	profile string,
) error {
	record := stormshieldCacheRecord{
		Version: stormshieldCacheVersion, SettingsHash: settingsHash, ConfigHash: configHash, Profile: profile, CreatedAt: time.Now().UTC(),
	}
	plaintext, err := json.Marshal(record)
	if err != nil || len(plaintext) > stormshieldCacheMaxBytes {
		return errors.New("Stormshield profile cache is invalid")
	}
	defer clearBytes(plaintext)
	return protectFile(stormshieldCachePath(snapshot), plaintext)
}

func persistStormshieldTrustIfUnchanged(snapshot tunnelConfigSnapshot, original, trusted json.RawMessage) {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	details, err := readTunnelUnlocked(snapshot.databasePath, tunnelReadRequest{ID: snapshot.id})
	if err != nil {
		return
	}
	defer clearBytes(details.Settings)
	if details.Kind != 4 || !bytes.Equal(details.Settings, original) {
		return
	}
	if protectFile(legacyTunnelSecretPath(snapshot.databasePath, snapshot.id), trusted) == nil {
		removeProtectedTunnelFile(stormshieldCachePath(snapshot))
		clearStormshieldOTPGuard(snapshot.id)
	}
}

func isStormshieldCertificateError(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verification) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}

func getStormshieldConfigHash(ctx context.Context, settings map[string]json.RawMessage) (string, error) {
	endpoint, client, closeTransport, err := stormshieldPortalEndpoint(settings, "/auth/v1/sslvpn/hash", "")
	if err != nil {
		return "", err
	}
	defer closeTransport()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New("could not create the Stormshield configuration request")
	}
	request.Header.Set("Accept", "text/html, text/plain")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if isStormshieldCertificateError(err) {
			return "", &stormshieldPortalRequestError{cause: err}
		}
		return "", nil
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return "", nil
	}
	hash := strings.ToUpper(strings.Trim(strings.TrimSpace(string(body)), `"`))
	if len(hash) != 64 {
		return "", nil
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", nil
	}
	return hash, nil
}

func downloadStormshieldProfile(ctx context.Context, settings map[string]json.RawMessage) (string, error) {
	endpoint, client, closeTransport, err := stormshieldPortalEndpoint(
		settings, "/auth/config.html", "version=1&type=openvpn",
	)
	if err != nil {
		return "", err
	}
	defer closeTransport()
	form := url.Values{
		"user": {tunnelSettingString(settings, "Username")},
		"pass": {tunnelSettingString(settings, "Password")},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("could not create the Stormshield configuration request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", &stormshieldPortalRequestError{cause: err}
	}
	defer response.Body.Close()
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType == "text/xml" || mediaType == "application/xml" {
		body, readErr := readBoundedStormshieldBody(response.Body)
		if readErr != nil {
			return "", readErr
		}
		return "", errors.New(describeStormshieldXMLError(body))
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("Stormshield configuration download returned HTTP %d", response.StatusCode)
	}
	if !strings.EqualFold(mediaType, "application/zip") {
		return "", errors.New("Stormshield configuration download did not return an OpenVPN zip bundle")
	}
	bundle, err := readBoundedStormshieldBody(response.Body)
	if err != nil {
		return "", err
	}
	return assembleStormshieldProfile(bundle)
}

func stormshieldPortalEndpoint(
	settings map[string]json.RawMessage,
	path string,
	rawQuery string,
) (*url.URL, *http.Client, func(), error) {
	host := tunnelSettingString(settings, "Server")
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	base, err := buildWebURL("https", host, port)
	if err != nil {
		return nil, nil, nil, errors.New("Stormshield portal address is invalid")
	}
	endpoint, _ := url.Parse(base)
	endpoint.Path = path
	endpoint.RawQuery = rawQuery
	tlsConfig, err := stormshieldTLSConfig(settings)
	if err != nil {
		return nil, nil, nil, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}
	transport.DialContext = physicalPortalDialContext
	client := &http.Client{
		Transport: transport,
		Timeout:   stormshieldRequestTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Host, endpoint.Host) {
				return errors.New("Stormshield portal redirected outside the configured gateway")
			}
			return nil
		},
	}
	return endpoint, client, transport.CloseIdleConnections, nil
}

func stormshieldTLSConfig(settings map[string]json.RawMessage) (*tls.Config, error) {
	if tunnelSettingBool(settings, "TrustServerCertificate") {
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, nil //nolint:gosec -- explicit user opt-in
	}
	caPEM := strings.TrimSpace(tunnelSettingString(settings, "CaPem"))
	if caPEM == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("Stormshield CA certificate is invalid")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // verified below against the explicitly pinned CA; hostname mismatch is intentionally tolerated
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("Stormshield portal returned no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
			return err
		},
	}, nil
}

func readBoundedStormshieldBody(reader io.Reader) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, stormshieldMaxProfileBytes+1))
	if err != nil || len(contents) > stormshieldMaxProfileBytes {
		return nil, errors.New("Stormshield configuration response exceeded the safety limit")
	}
	return contents, nil
}

func describeStormshieldXMLError(body []byte) string {
	type node struct {
		Code string `xml:"code,attr"`
		Msg  string `xml:"msg,attr"`
		Text string `xml:",chardata"`
	}
	var envelope struct {
		Ret node `xml:"ret"`
	}
	if xml.Unmarshal(body, &envelope) == nil {
		message := strings.TrimSpace(envelope.Ret.Msg)
		if message == "" {
			message = strings.TrimSpace(envelope.Ret.Text)
		}
		if message != "" {
			if code := strings.TrimSpace(envelope.Ret.Code); code != "" {
				return fmt.Sprintf("Stormshield rejected the configuration request (code %s): %s", code, message)
			}
			return "Stormshield rejected the configuration request: " + message
		}
	}
	return "Stormshield rejected the configuration request"
}

func assembleStormshieldProfile(bundle []byte) (string, error) {
	archive, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		return "", errors.New("Stormshield returned an invalid configuration zip bundle")
	}
	if len(archive.File) > stormshieldMaxZipEntries {
		return "", errors.New("Stormshield configuration bundle has too many entries")
	}
	files := make(map[string]string)
	profileName := ""
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		contents, err := readStormshieldZipEntry(entry)
		if err != nil {
			return "", err
		}
		name := filepath.Base(strings.ReplaceAll(entry.Name, "\\", "/"))
		files[strings.ToLower(name)] = string(contents)
		if profileName == "" && strings.EqualFold(filepath.Ext(name), ".ovpn") {
			profileName = strings.ToLower(name)
		}
	}
	if profileName == "" {
		return "", errors.New("Stormshield configuration bundle contains no OpenVPN profile")
	}
	assembled, unresolved := inlineStormshieldFiles(files[profileName], func(name string) (string, bool) {
		value, ok := files[strings.ToLower(filepath.Base(strings.ReplaceAll(name, "\\", "/")))]
		return value, ok
	})
	if len(unresolved) > 0 {
		return "", fmt.Errorf("Stormshield configuration bundle is missing referenced key material: %s", strings.Join(unresolved, ", "))
	}
	lower := strings.ToLower(assembled)
	if !strings.Contains(lower, "remote ") || (!strings.Contains(lower, "dev tun") && !strings.Contains(lower, "dev tap") && !strings.Contains(lower, "<ca>")) {
		return "", errors.New("Stormshield configuration bundle did not yield a usable OpenVPN profile")
	}
	return assembled, nil
}

func readStormshieldZipEntry(entry *zip.File) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, errors.New("could not read the Stormshield configuration bundle")
	}
	defer reader.Close()
	contents, err := io.ReadAll(io.LimitReader(reader, stormshieldMaxProfileBytes+1))
	if err != nil || len(contents) > stormshieldMaxProfileBytes {
		return nil, fmt.Errorf("Stormshield configuration bundle entry %q exceeded the safety limit", entry.Name)
	}
	return contents, nil
}

func inlineStormshieldFiles(profile string, resolve func(string) (string, bool)) (string, []string) {
	lines := splitVPNProfileLines(profile)
	var output strings.Builder
	var openBlock string
	var unresolved []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if openBlock != "" {
			output.WriteString(line + "\n")
			if isVPNCloseTag(trimmed, openBlock) {
				openBlock = ""
			}
			continue
		}
		if block, ok := vpnOpenTag(trimmed); ok {
			openBlock = block
			output.WriteString(line + "\n")
			continue
		}
		directive, argument := vpnDirective(trimmed)
		if isStormshieldInlineDirective(directive) && argument != "" {
			if contents, ok := resolve(argument); ok && contents != "" {
				output.WriteString("<" + strings.ToLower(directive) + ">\n")
				output.WriteString(strings.TrimRight(strings.ReplaceAll(contents, "\r", ""), "\n") + "\n")
				output.WriteString("</" + strings.ToLower(directive) + ">\n")
				continue
			}
			unresolved = append(unresolved, argument)
		}
		output.WriteString(line + "\n")
	}
	return output.String(), unresolved
}

func normalizeStormshieldProfile(profile string) (string, error) {
	if strings.TrimSpace(profile) == "" {
		return "", errors.New("Stormshield OpenVPN profile is empty")
	}
	lines := splitVPNProfileLines(profile)
	var output strings.Builder
	var openBlock string
	hasCipher, hasDataCiphers := false, false
	profileCipher := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if openBlock != "" {
			output.WriteString(line + "\n")
			if isVPNCloseTag(trimmed, openBlock) {
				openBlock = ""
			}
			continue
		}
		if block, ok := vpnOpenTag(trimmed); ok {
			openBlock = block
			output.WriteString(line + "\n")
			continue
		}
		directive, argument := vpnDirective(trimmed)
		if strings.EqualFold(directive, "tls-cipher") || strings.EqualFold(directive, "tls-ciphersuites") {
			continue
		}
		if strings.EqualFold(directive, "cipher") {
			hasCipher = true
			if argument != "" {
				profileCipher = strings.Fields(argument)[0]
			}
		}
		if strings.EqualFold(directive, "data-ciphers") {
			hasDataCiphers = true
		}
		output.WriteString(line + "\n")
	}
	if hasCipher && !hasDataCiphers {
		if profileCipher == "" {
			profileCipher = "AES-256-CBC"
		}
		ciphers := "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
		if !strings.EqualFold(profileCipher, "AES-256-GCM") && !strings.EqualFold(profileCipher, "AES-128-GCM") && !strings.EqualFold(profileCipher, "CHACHA20-POLY1305") {
			ciphers += ":" + profileCipher
		}
		output.WriteString("data-ciphers " + ciphers + "\n")
		output.WriteString("data-ciphers-fallback " + profileCipher + "\n")
	}
	return output.String(), nil
}

func applyStormshieldLegacyCompressionStub(profile string) (string, error) {
	if strings.TrimSpace(profile) == "" {
		return "", errors.New("Stormshield OpenVPN profile is empty")
	}
	lines := splitVPNProfileLines(profile)
	var output strings.Builder
	var openBlock string
	hasFraming := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if openBlock != "" {
			output.WriteString(line + "\n")
			if isVPNCloseTag(trimmed, openBlock) {
				openBlock = ""
			}
			continue
		}
		if block, ok := vpnOpenTag(trimmed); ok {
			openBlock = block
			output.WriteString(line + "\n")
			continue
		}
		directive, _ := vpnDirective(trimmed)
		hasFraming = hasFraming || strings.EqualFold(directive, "compress") || strings.EqualFold(directive, "comp-lzo")
		output.WriteString(line + "\n")
	}
	if !hasFraming {
		output.WriteString("comp-lzo no\n")
	}
	return output.String(), nil
}

func applyStormshieldTransportOverride(profile string, override int) (string, error) {
	if override == 0 {
		return profile, nil
	}
	desired := "udp"
	desiredProto := "udp"
	label := "UDP"
	if override == 1 {
		desired = "tcp"
		desiredProto = "tcp-client"
		label = "TCP"
	}
	lines := splitVPNProfileLines(profile)
	var output strings.Builder
	sawRemote, keptRemote, sawProto, keptUnqualified := false, false, false, false
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "<connection>") {
			end := index + 1
			for end < len(lines) && !strings.EqualFold(strings.TrimSpace(lines[end]), "</connection>") {
				end++
			}
			if end >= len(lines) {
				return "", errors.New("Stormshield OpenVPN profile has an unterminated connection block")
			}
			rewritten, blockSaw, blockKept := rewriteStormshieldConnectionBlock(lines[index:end+1], desired, desiredProto)
			sawRemote = sawRemote || blockSaw
			keptRemote = keptRemote || blockKept
			if blockKept {
				for _, blockLine := range rewritten {
					output.WriteString(blockLine + "\n")
				}
			}
			index = end
			continue
		}
		if block, ok := vpnOpenTag(trimmed); ok {
			output.WriteString(line + "\n")
			for index+1 < len(lines) {
				index++
				output.WriteString(lines[index] + "\n")
				if isVPNCloseTag(strings.TrimSpace(lines[index]), block) {
					break
				}
			}
			continue
		}
		directive, argument := vpnDirective(trimmed)
		if strings.EqualFold(directive, "proto") {
			sawProto = true
			output.WriteString("proto " + desiredProto + "\n")
			continue
		}
		if strings.EqualFold(directive, "remote") {
			sawRemote = true
			transport := remoteTransport(argument)
			if transport == "" || transport == desired {
				keptRemote = true
				keptUnqualified = keptUnqualified || transport == ""
				output.WriteString(line + "\n")
			}
			continue
		}
		output.WriteString(line + "\n")
	}
	if sawRemote && !keptRemote {
		return "", fmt.Errorf("Stormshield OpenVPN profile has no %s remote", label)
	}
	if keptUnqualified && !sawProto {
		output.WriteString("proto " + desiredProto + "\n")
	}
	return output.String(), nil
}

func rewriteStormshieldConnectionBlock(lines []string, desired, desiredProto string) ([]string, bool, bool) {
	blockProto := ""
	for _, line := range lines {
		directive, argument := vpnDirective(strings.TrimSpace(line))
		if strings.EqualFold(directive, "proto") {
			blockProto = protocolTransport(argument)
		}
	}
	sawRemote, keptRemote, unqualified, sawProto := false, false, false, false
	output := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		directive, argument := vpnDirective(strings.TrimSpace(line))
		if strings.EqualFold(directive, "proto") {
			sawProto = true
			output = append(output, "proto "+desiredProto)
			continue
		}
		if strings.EqualFold(directive, "remote") {
			sawRemote = true
			transport := remoteTransport(argument)
			effective := transport
			if effective == "" {
				effective = blockProto
			}
			if effective != "" && effective != desired {
				continue
			}
			keptRemote = true
			unqualified = unqualified || transport == "" && blockProto == ""
		}
		output = append(output, line)
	}
	if keptRemote && unqualified && !sawProto {
		for index := len(output) - 1; index >= 0; index-- {
			if strings.EqualFold(strings.TrimSpace(output[index]), "</connection>") {
				output = append(output[:index], append([]string{"proto " + desiredProto}, output[index:]...)...)
				break
			}
		}
	}
	return output, sawRemote, keptRemote
}

func splitVPNProfileLines(profile string) []string {
	return strings.Split(strings.ReplaceAll(strings.ReplaceAll(profile, "\r\n", "\n"), "\r", "\n"), "\n")
}

func vpnDirective(line string) (string, string) {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", ""
	}
	index := strings.IndexAny(line, " \t")
	if index < 0 {
		return line, ""
	}
	directive := line[:index]
	argument := strings.TrimSpace(line[index:])
	if strings.HasPrefix(argument, "\"") {
		if end := strings.Index(argument[1:], "\""); end >= 0 {
			argument = argument[1 : end+1]
		}
	}
	return directive, argument
}

func vpnOpenTag(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[1] == '/' || line[len(line)-1] != '>' {
		return "", false
	}
	name := line[1 : len(line)-1]
	if strings.ContainsAny(name, "<> \t\r\n") {
		return "", false
	}
	return name, name != ""
}

func isVPNCloseTag(line, block string) bool {
	return strings.EqualFold(line, "</"+block+">")
}

func isStormshieldInlineDirective(value string) bool {
	switch strings.ToLower(value) {
	case "ca", "cert", "key", "tls-crypt", "tls-auth", "tls-crypt-v2", "extra-certs":
		return true
	default:
		return false
	}
}

func remoteTransport(argument string) string {
	parts := strings.Fields(argument)
	if len(parts) < 3 {
		return ""
	}
	return protocolTransport(parts[2])
}

func protocolTransport(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "tcp") {
		return "tcp"
	}
	if strings.HasPrefix(value, "udp") {
		return "udp"
	}
	return ""
}
