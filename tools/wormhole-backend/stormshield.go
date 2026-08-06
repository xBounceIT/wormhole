package main

import (
	"archive/zip"
	"bytes"
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	stormshieldMaxProfileBytes = 1 << 20
	stormshieldMaxZipEntries   = 32
	stormshieldRequestTimeout  = 30 * time.Second
	stormshieldCacheMaxAge     = 7 * 24 * time.Hour
	stormshieldCacheMaxBytes   = 2 << 20
)

type stormshieldCacheRecord struct {
	Version      int       `json:"version"`
	SettingsHash string    `json:"settingsHash"`
	Profile      string    `json:"profile"`
	CreatedAt    time.Time `json:"createdAt"`
}

func prepareStormshieldProfile(
	ctx context.Context,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	if tunnelSettingBool(settings, "UseSingleSignOn") {
		return nil, errors.New("Stormshield single sign-on is not available yet")
	}
	profile := tunnelSettingString(settings, "ProfileOvpn")
	automatic := tunnelSettingNumber(settings, "Mode") == 0
	useOTP := tunnelSettingBool(settings, "UseOtp")
	downloadedWithOTP := false
	var snapshot tunnelConfigSnapshot
	if len(snapshots) > 0 {
		snapshot = snapshots[0]
	}
	settingsHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	if automatic && useOTP && snapshot.id != "" {
		profile = readStormshieldCachedProfile(snapshot, settingsHash)
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
	}
	if automatic && profile == "" {
		if useOTP {
			password, _ := json.Marshal(tunnelSettingString(settings, "Password") + otp)
			settings["Password"] = password
			downloadedWithOTP = true
		}
		var err error
		profile, err = downloadStormshieldProfile(ctx, settings)
		if err != nil {
			return nil, err
		}
	}
	normalized, err := normalizeStormshieldProfile(profile)
	if err != nil {
		return nil, err
	}
	normalized, err = applyStormshieldTransportOverride(normalized, int(tunnelSettingNumber(settings, "OpenVpnTransportOverride")))
	if err != nil {
		return nil, err
	}
	if tunnelSettingNumber(settings, "OpenVpnCompressionFramingOverride") == 1 {
		normalized, err = applyStormshieldLegacyCompressionStub(normalized)
		if err != nil {
			return nil, err
		}
	}
	if automatic && downloadedWithOTP {
		if snapshot.id == "" || snapshot.databasePath == "" {
			return nil, errors.New("Stormshield could not cache the downloaded VPN profile")
		}
		if err := writeStormshieldCachedProfile(snapshot, settingsHash, normalized); err != nil {
			return nil, errors.New("Stormshield downloaded the VPN profile but could not protect its cache")
		}
		return nil, errors.New("Stormshield downloaded and protected a fresh VPN profile; connect again with a new one-time code")
	}
	if useOTP {
		password, _ := json.Marshal(tunnelSettingString(settings, "Password") + otp)
		settings["Password"] = password
	}
	encoded, _ := json.Marshal(normalized)
	settings["ProfileOvpn"] = encoded
	return json.Marshal(settings)
}

func stormshieldCachePath(snapshot tunnelConfigSnapshot) string {
	compact := strings.ReplaceAll(normalizeTunnelID(snapshot.id), "-", "")
	return filepath.Join(filepath.Dir(snapshot.databasePath), "stormshield-cache", compact+".ovpncache")
}

func readStormshieldCachedProfile(snapshot tunnelConfigSnapshot, settingsHash string) string {
	path := stormshieldCachePath(snapshot)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > stormshieldCacheMaxBytes {
		return ""
	}
	plaintext, err := unprotectFile(path)
	if err != nil {
		return ""
	}
	defer clearBytes(plaintext)
	var record stormshieldCacheRecord
	if json.Unmarshal(plaintext, &record) != nil || record.Version != 1 ||
		record.SettingsHash != settingsHash || record.Profile == "" ||
		record.CreatedAt.IsZero() || time.Since(record.CreatedAt) < 0 ||
		time.Since(record.CreatedAt) > stormshieldCacheMaxAge {
		return ""
	}
	return record.Profile
}

func writeStormshieldCachedProfile(
	snapshot tunnelConfigSnapshot,
	settingsHash string,
	profile string,
) error {
	record := stormshieldCacheRecord{
		Version: 1, SettingsHash: settingsHash, Profile: profile, CreatedAt: time.Now().UTC(),
	}
	plaintext, err := json.Marshal(record)
	if err != nil || len(plaintext) > stormshieldCacheMaxBytes {
		return errors.New("Stormshield profile cache is invalid")
	}
	defer clearBytes(plaintext)
	return protectFile(stormshieldCachePath(snapshot), plaintext)
}

func downloadStormshieldProfile(ctx context.Context, settings map[string]json.RawMessage) (string, error) {
	host := tunnelSettingString(settings, "Server")
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	base, err := buildWebURL("https", host, port)
	if err != nil {
		return "", errors.New("Stormshield portal address is invalid")
	}
	endpoint, _ := url.Parse(base)
	endpoint.Path = "/auth/config.html"
	endpoint.RawQuery = "version=1&type=openvpn"

	tlsConfig, err := stormshieldTLSConfig(settings)
	if err != nil {
		return "", err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
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
		return "", errors.New("could not reach the Stormshield configuration portal")
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

func stormshieldTLSConfig(settings map[string]json.RawMessage) (*tls.Config, error) {
	if tunnelSettingBool(settings, "TrustServerCertificate") {
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec -- explicit user opt-in
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
