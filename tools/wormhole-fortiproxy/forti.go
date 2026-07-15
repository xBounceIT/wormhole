package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// session is the outcome of a successful FortiGate login + tunnel upgrade. From this point
// the byte channel on Conn carries PPP-over-Fortinet-encap frames in both directions.
type session struct {
	Conn       *tls.Conn
	AssignedIP netip.Addr
	MTU        int
	DNS        []netip.Addr
}

// fortinetUserAgent matches the spoofed UA openconnect's fortinet.c sends in
// fortinet_common_headers — some FortiGate firmwares gate the SSL VPN endpoints on a
// non-empty Windows-looking User-Agent and refuse default Go clients.
const fortinetUserAgent = "Mozilla/5.0 SV1"

func fortiLogin(ctx context.Context, cfg config) (*session, error) {
	// Normalize cfg.Host BEFORE buildTLSConfig — tls.Config.ServerName is set from
	// cfg.Host and a bracketed IPv6 literal (e.g. "[2001:db8::1]") would otherwise
	// propagate into SNI as a bracketed string, which the TLS stack rejects. Doing the
	// strip here covers both buildTLSConfig and the later net.JoinHostPort calls in one
	// place. (Hostnames and IPv4 literals pass through unchanged.)
	cfg.Host = stripHostBrackets(cfg.Host)

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}

	// Auth phase gets a 20s budget; tunnel upgrade gets a separate 15s. Sharing a single
	// deadline meant a slow MFA challenge could leave the TLS handshake starved.
	authCtx, authCancel := context.WithTimeout(ctx, 20*time.Second)
	defer authCancel()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext:     dialer.DialContext,
		// FortiGate keeps the auth connection alive between the login POST and the tunnel
		// upgrade; reusing the TCP+TLS handshake on the second request saves ~200 ms.
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	// Release idle connections when fortiLogin returns. The tunnel itself runs on a fresh
	// TLS dial below; nothing past this function needs the auth-phase transport, and leaving
	// it sitting in the pool keeps 1-2 idle TLS sockets open for the full IdleConnTimeout.
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   15 * time.Second,
	}

	// Path="/" keeps baseURL canonical regardless of Go-version quirks; the cookie lookups
	// that actually matter for SVPNCOOKIE (writeTunnelUpgrade, hasSvpnCookie) use the
	// derived tunnelURL below (Path=/remote/sslvpn-tunnel) so cookies stored under the
	// default-path /remote of /remote/logincheck still match.
	baseURL := &url.URL{Scheme: "https", Host: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), Path: "/"}

	tunnelURL := baseURL.JoinPath("remote", "sslvpn-tunnel")
	if err := obtainFortinetCookie(authCtx, client, jar, baseURL, tunnelURL, cfg); err != nil {
		return nil, err
	}

	// Step 3: fetch the tunnel config XML (assigned IP, DNS, MTU).
	xmlBytes, err := httpGet(authCtx, client, "config-xml", baseURL.JoinPath("remote", "fortisslvpn_xml").String(), cfg)
	if err != nil {
		return nil, fmt.Errorf("config XML: %w", err)
	}
	cfgXML, err := parseTunnelConfigXML(xmlBytes)
	if err != nil {
		return nil, fmt.Errorf("parse config XML: %w", err)
	}

	// Step 4: open a fresh TLS connection and write a hand-rolled GET that does NOT consume
	// the HTTP response — FortiGate flips the stream to PPP frames immediately on success.
	// net/http would buffer until it sees \r\n\r\n and then close the body reader, which
	// loses the first PPP frame bytes that arrive in the same TCP segment.
	//
	// Give the tunnel phase its OWN 15s deadline rooted at the caller's ctx rather than
	// reusing the loginCtx that may have already burned 10-15s on auth+challenge. Sharing
	// loginCtx's 20s budget meant a slow auth could leave the TLS handshake with only ~5s,
	// surfacing as a misleading 'tunnel TLS handshake: context deadline exceeded'.
	tunnelCtx, tunnelCancel := context.WithTimeout(ctx, 15*time.Second)
	defer tunnelCancel()
	rawConn, err := dialer.DialContext(tunnelCtx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("tunnel dial: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(tunnelCtx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tunnel TLS handshake: %w", err)
	}
	if err := writeTunnelUpgrade(tlsConn, baseURL.Host, jar, tunnelURL); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tunnel upgrade: %w", err)
	}

	return &session{
		Conn:       tlsConn,
		AssignedIP: cfgXML.AssignedIP,
		MTU:        cfgXML.MTU,
		DNS:        cfgXML.DNS,
	}, nil
}

func obtainFortinetCookie(
	ctx context.Context,
	client *http.Client,
	jar *cookiejar.Jar,
	baseURL, tunnelURL *url.URL,
	cfg config,
) error {
	var body []byte
	var err error

	switch {
	case cfg.SvpnCookie != nil && *cfg.SvpnCookie != "":
		jar.SetCookies(tunnelURL, []*http.Cookie{{
			Name:     "SVPNCOOKIE",
			Value:    *cfg.SvpnCookie,
			Path:     "/remote",
			Secure:   true,
			HttpOnly: true,
		}})
	case cfg.SamlAuthID != nil && *cfg.SamlAuthID != "":
		authURL := baseURL.JoinPath("remote", "saml", "auth_id")
		query := authURL.Query()
		query.Set("id", *cfg.SamlAuthID)
		authURL.RawQuery = query.Encode()
		body, err = httpGet(ctx, client, "saml-auth-id", authURL.String(), cfg)
		if err != nil {
			return errors.New("SAML auth ID exchange failed; verify gateway connectivity and certificate settings")
		}
	default:
		form := url.Values{}
		form.Set("username", cfg.Username)
		form.Set("credential", cfg.Password)
		form.Set("ajax", "1")
		form.Set("just_logged_in", "1")
		if cfg.Realm != nil && *cfg.Realm != "" {
			form.Set("realm", *cfg.Realm)
		}
		body, err = postForm(ctx, client, "logincheck", baseURL.JoinPath("remote", "logincheck").String(), form, cfg)
		if err != nil {
			return fmt.Errorf("logincheck POST: %w", err)
		}

		if challenge := parseChallenge(string(body)); challenge != nil {
			if cfg.TotpSecret == nil || *cfg.TotpSecret == "" {
				return errors.New("server requested 2FA but no TOTP secret was configured for this tunnel")
			}
			code, err := totp.GenerateCode(*cfg.TotpSecret, time.Now())
			if err != nil {
				return fmt.Errorf("generate TOTP code: %w", err)
			}
			challenge.respond(code, cfg)
			body, err = postForm(ctx, client, "logincheck-2fa", baseURL.JoinPath("remote", "logincheck").String(), challenge.form, cfg)
			if err != nil {
				return fmt.Errorf("logincheck challenge POST: %w", err)
			}
		}
	}

	if !hasSvpnCookie(jar, tunnelURL) {
		tags := strings.Join(classifyLoginBody(body), ",")
		tunnelCookies := strings.Join(cookieNames(jar, tunnelURL), ",")
		logf("login failed: SVPNCOOKIE absent. body=[%s] jar(tunnel-path)=[%s] jar(root)=[%s]",
			tags, tunnelCookies, strings.Join(cookieNames(jar, baseURL), ","))
		return fmt.Errorf(
			"login did not yield an SVPNCOOKIE (server returned %d bytes, body=[%s], cookies=[%s] without a recognized challenge)",
			len(body), tags, tunnelCookies)
	}
	return nil
}

func buildTLSConfig(cfg config) (*tls.Config, error) {
	t := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	if cfg.TrustServerCertificate {
		t.InsecureSkipVerify = true
	}
	if cfg.ServerCertSha256Pin != nil && *cfg.ServerCertSha256Pin != "" {
		// Fail closed on a malformed pin: if the user typed garbage or a SHA-1 by mistake,
		// silently falling back to default CA verification (or, with TrustServerCertificate=
		// true, NO verification at all) inverts the user's stated intent and the connection
		// would proceed wide-open with no warning. Refuse to build the config instead.
		raw := strings.ReplaceAll(strings.TrimSpace(*cfg.ServerCertSha256Pin), ":", "")
		want, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("server_cert_sha256_pin is not valid hex: %w", err)
		}
		if len(want) != sha256.Size {
			return nil, fmt.Errorf("server_cert_sha256_pin must be a SHA-256 hash (%d bytes); got %d bytes",
				sha256.Size, len(want))
		}
		t.InsecureSkipVerify = true
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificates")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytesEqual(got[:], want) {
				return fmt.Errorf("server cert SHA-256 %x does not match configured pin", got)
			}
			return nil
		}
	}
	return t, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// maxResponseBody bounds how much of any FortiGate HTTP response we will buffer. Login,
// challenge, and config-XML responses are all well under this in normal operation; anything
// larger is either a misconfigured proxy returning an error page, a firmware bug, or an
// attempt to wedge us into a misclassified-auth state by padding the body past parseChallenge.
const maxResponseBody = 1 << 20

func postForm(ctx context.Context, client *http.Client, label, url string, form url.Values, cfg config) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", fortinetUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, url)
	if err != nil {
		return nil, err
	}
	logResponseDiagnostics(label, resp, body, cfg)
	return body, nil
}

func httpGet(ctx context.Context, client *http.Client, label, url string, cfg config) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fortinetUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, url)
	if err != nil {
		return nil, err
	}
	// Classify before the status gate so a non-2xx error page is still logged.
	logResponseDiagnostics(label, resp, body, cfg)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// readBoundedBody reads up to maxResponseBody bytes. Unlike io.ReadAll(io.LimitReader(...)),
// it errors when the cap is reached rather than silently returning a truncated body —
// otherwise parseChallenge / parseTunnelConfigXML could misclassify auth state from a body
// they only see part of.
func readBoundedBody(body io.Reader, ctxURL string) ([]byte, error) {
	// Read limit+1 bytes so a body that's exactly limit-long succeeds, but anything strictly
	// larger reports the overflow.
	buf, err := io.ReadAll(io.LimitReader(body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxResponseBody {
		return nil, fmt.Errorf("response from %s exceeds %d bytes; refusing to truncate", ctxURL, maxResponseBody)
	}
	return buf, nil
}

// writeTunnelUpgrade sends the raw HTTP GET that FortiGate accepts as a request to upgrade
// the byte stream to PPP. Per openconnect's fortinet.c the server returns no HTTP response
// on success; PPP framing begins on the next byte. We hand-write the request because
// net/http would close the body reader and discard prefix PPP bytes. The cookie lookup uses
// the target tunnel URL (not the root) so cookies stored under Path=/remote (FortiGate's
// default-path of /remote/logincheck) are correctly returned.
func writeTunnelUpgrade(c *tls.Conn, host string, jar *cookiejar.Jar, tunnelURL *url.URL) error {
	var b strings.Builder
	fmt.Fprintf(&b, "GET /remote/sslvpn-tunnel HTTP/1.1\r\n")
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", fortinetUserAgent)
	fmt.Fprintf(&b, "Cookie: %s\r\n", cookieHeader(jar, tunnelURL))
	fmt.Fprintf(&b, "Connection: keep-alive\r\n")
	fmt.Fprintf(&b, "\r\n")
	_, err := c.Write([]byte(b.String()))
	return err
}

func cookieHeader(jar *cookiejar.Jar, u *url.URL) string {
	parts := make([]string, 0, 4)
	for _, c := range jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func hasSvpnCookie(jar *cookiejar.Jar, u *url.URL) bool {
	for _, c := range jar.Cookies(u) {
		if strings.EqualFold(c.Name, "SVPNCOOKIE") && c.Value != "" {
			return true
		}
	}
	return false
}

// cookieNames returns the names (never values) of cookies the jar would send to u. Diagnostics
// only — used on the login-failure path to show whether SVPNCOOKIE was set under an unexpected
// path versus not set at all.
func cookieNames(jar *cookiejar.Jar, u *url.URL) []string {
	var names []string
	for _, c := range jar.Cookies(u) {
		names = append(names, c.Name)
	}
	return names
}

// retCodeRE captures FortiGate's ajax/text result code, e.g. "ret=1" or "ret=2,reqid=...".
var retCodeRE = regexp.MustCompile(`(?i)\bret=(-?\d+)`)

// wsRE collapses any run of whitespace to a single space for one-line log excerpts.
var wsRE = regexp.MustCompile(`\s+`)

// sensitiveKVRE matches the VALUES of challenge/session keys in FortiGate's ajax/url-encoded
// responses (magic, reqid, SAMLResponse, …) so redactBody can strip them. Keys are ordered
// longest-first where one prefixes another (grpid before grp) for an unambiguous match.
var sensitiveKVRE = regexp.MustCompile(`(?i)\b(magic|reqid|polid|grpid|grp|portal|peer|tokeninfo|credential|svpncookie|samlrequest|samlresponse|id)=([^,&\s'"<>]+)`)

// htmlValueAttrRE matches any HTML value="…" attribute. redactBody masks ALL of them: in a
// FortiGate challenge/SAML page the value attributes carry the live tokens, and name↔value
// can't be reliably paired with a single regex across arbitrary attribute order. Field names,
// input types and tag structure stay visible — all the excerpt needs for shape diagnosis.
var htmlValueAttrRE = regexp.MustCompile(`(?is)(\bvalue\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)`)

// classifyLoginBody returns small, secret-free tags describing a FortiGate login/logincheck
// response, for diagnostics only. It echoes no body data beyond a matched numeric ret= code.
func classifyLoginBody(body []byte) []string {
	s := string(body)
	lower := strings.ToLower(s)
	var tags []string
	if strings.Contains(lower, "/remote/saml/") || strings.Contains(s, "SAMLRequest") ||
		strings.Contains(lower, "saml_request") {
		tags = append(tags, "saml")
	}
	if m := retCodeRE.FindStringSubmatch(s); m != nil {
		tags = append(tags, "ret="+m[1])
	}
	if strings.Contains(lower, "<form") &&
		(strings.Contains(lower, `name="username"`) || strings.Contains(lower, "name='username'") ||
			strings.Contains(lower, `name="credential"`)) {
		tags = append(tags, "login-page")
	}
	if strings.Contains(lower, `name="magic"`) || strings.Contains(lower, "name='magic'") ||
		strings.Contains(lower, "magic=") {
		tags = append(tags, "has-magic")
	}
	if strings.Contains(lower, "tokeninfo") || strings.Contains(lower, "chal_msg") ||
		strings.Contains(lower, "ftm_push") || strings.Contains(lower, "fortitoken") {
		tags = append(tags, "2fa-hint")
	}
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "login failed") ||
		strings.Contains(lower, "invalid") || strings.Contains(lower, "locked") ||
		strings.Contains(lower, "too many") {
		tags = append(tags, "auth-error")
	}
	return tags
}

// redactBody renders a single-line, length-capped, secret-scrubbed excerpt of a response body
// for the debug-only verbose log. Whitespace is collapsed; the configured username/password AND
// any challenge/session tokens (magic, reqid, SAMLResponse, every HTML value="…" attribute) are
// masked. Only reached when debugLog is set (operator opted in for a capture).
func redactBody(body []byte, cfg config) string {
	s := strings.TrimSpace(wsRE.ReplaceAllString(string(body), " "))
	// Structural redaction FIRST, while the markup is intact: strip the live challenge/session
	// material the gateway includes in 2FA/SAML responses — magic, reqid, SAMLResponse, etc. —
	// by masking the VALUES of sensitive keys and every HTML value="…" attribute. Only values
	// go; field names stay (useful, non-secret) for shape diagnosis. This must precede the
	// literal credential scrub below: a short username/password that is a substring of
	// "value"/"input"/etc. would otherwise corrupt the markup and defeat the attribute match,
	// leaking the token it was meant to hide.
	s = sensitiveKVRE.ReplaceAllString(s, "${1}=<redacted>")
	s = htmlValueAttrRE.ReplaceAllString(s, `${1}"<redacted>"`)
	// Then scrub the configured credentials wherever they still appear in plaintext.
	if cfg.Username != "" {
		s = strings.ReplaceAll(s, cfg.Username, "<user>")
	}
	if cfg.Password != "" {
		s = strings.ReplaceAll(s, cfg.Password, "<redacted>")
	}
	if cfg.SamlAuthID != nil && *cfg.SamlAuthID != "" {
		s = strings.ReplaceAll(s, *cfg.SamlAuthID, "<redacted>")
	}
	if cfg.SvpnCookie != nil && *cfg.SvpnCookie != "" {
		s = strings.ReplaceAll(s, *cfg.SvpnCookie, "<redacted>")
	}
	const limit = 256
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…(truncated)"
	}
	return s
}

// logResponseDiagnostics emits one secret-free line summarizing a FortiGate HTTP response so a
// failed login is diagnosable from the parent's [fortiproxy] log without a packet capture:
// status, body length, the NAMES of any Set-Cookie headers (never their values), and a coarse
// body classification. With debugLog set it adds a redacted, capped body excerpt.
func logResponseDiagnostics(label string, resp *http.Response, body []byte, cfg config) {
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name)
	}
	logf("%s: status=%d bodyLen=%d set-cookie=[%s] body=[%s]",
		label, resp.StatusCode, len(body),
		strings.Join(names, ","), strings.Join(classifyLoginBody(body), ","))
	if debugLog {
		logf("%s body-excerpt: %s", label, redactBody(body, cfg))
	}
}

// challenge represents a FortiGate 2FA prompt parsed from the logincheck response body.
// The server expects the second POST to echo back reqid/polid/grp/portal/magic and supply
// the user-entered code.
type challenge struct {
	form url.Values
	// tokenField is the form-field name where the OTP must be written on the second
	// /remote/logincheck POST. FortiGate's ajax/text challenge expects `code`; the HTML
	// form expects `credential` (the same field name as the initial password). Wrong
	// field name silently fails auth even with a valid TOTP secret.
	tokenField string
}

// challengeFields are the form fields the gateway expects the client to echo back in the
// challenge POST. Shared by both the comma-format and HTML-form parsers. Both `grp` and
// `grpid` appear in the wild — the comma form typically uses `grp`, the HTML form uses
// `grpid`, and some firmwares include both. Forwarding whatever the server gave us avoids
// the "second logincheck rejected" failure mode where a missing token makes auth bounce.
var challengeFields = []string{"reqid", "polid", "grp", "grpid", "portal", "magic", "peer"}

// hiddenInputRE matches FortiGate's HTML hidden-input pattern. Variants seen in firmware:
//
//	<input type="hidden" name="magic" value="abc">
//	<input type='hidden' name='magic' value='abc'>
//	<input name="magic" value="abc" type="hidden">
//
// The regex tolerates attribute reordering AND quote-style swap. It's deliberately
// permissive on whitespace between attributes; case-insensitive via the (?i) flag.
var hiddenInputRE = regexp.MustCompile(`(?is)<input\b[^>]*?>`)
var attrRE = regexp.MustCompile(`(?is)(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))`)

func parseChallenge(body string) *challenge {
	// First try FortiGate's ajax/plaintext form: ret=2,reqid=1234,polid=1,...
	if c := parseChallengeText(body); c != nil {
		return c
	}
	// Fall back to the HTML form some firmwares return (typically when AJAX challenge
	// is disabled or for the SAML / FortiToken Mobile push flows).
	return parseChallengeHTML(body)
}

func parseChallengeText(body string) *challenge {
	if !strings.Contains(body, "ret=") {
		return nil
	}
	fields := map[string]string{}
	for _, part := range strings.Split(body, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			fields[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if fields["ret"] != "2" {
		return nil
	}
	form := url.Values{}
	for _, k := range challengeFields {
		if v, ok := fields[k]; ok {
			form.Set(k, v)
		}
	}
	return &challenge{form: form, tokenField: "code"}
}

// parseChallengeHTML scans an HTML body for a 2FA challenge form. We don't bring in a full
// HTML parser (golang.org/x/net/html); a regex walk over <input ...> tags is sufficient for
// the FortiGate template, which is server-generated and stable. We require at least the
// `magic` field (the canonical FortiGate session token for the challenge round-trip) to
// classify the body as a real challenge — without it we'd false-positive on the standard
// login page that also contains hidden inputs.
func parseChallengeHTML(body string) *challenge {
	if !strings.Contains(strings.ToLower(body), "<input") {
		return nil
	}
	fields := map[string]string{}
	for _, tag := range hiddenInputRE.FindAllString(body, -1) {
		// Parse attributes once and inspect them; substring-matching `type="hidden"`
		// missed valid HTML with whitespace around the equals (e.g. `type = "hidden"`)
		// or attribute reordering with surrounding whitespace. attrRE tolerates both.
		var typ, name, value string
		for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
			// m[1]=attr, m[2]=double-quoted, m[3]=single-quoted, m[4]=unquoted
			val := m[2] + m[3] + m[4]
			switch strings.ToLower(m[1]) {
			case "type":
				typ = val
			case "name":
				name = val
			case "value":
				value = val
			}
		}
		if !strings.EqualFold(typ, "hidden") {
			continue
		}
		if name != "" {
			fields[name] = value
		}
	}
	// Magic is the load-bearing field — refuse to treat anything without it as a challenge,
	// or we'd POST a meaningless second logincheck for any login page that happens to have
	// hidden inputs.
	if _, ok := fields["magic"]; !ok {
		return nil
	}
	form := url.Values{}
	for _, k := range challengeFields {
		if v, ok := fields[k]; ok {
			form.Set(k, v)
		}
	}
	return &challenge{form: form, tokenField: "credential"}
}

func (c *challenge) respond(code string, cfg config) {
	c.form.Set("username", cfg.Username)
	field := c.tokenField
	if field == "" {
		field = "code" // safety default for any future callers that forget to set it
	}
	c.form.Set(field, code)
	c.form.Set("ajax", "1")
}

type tunnelConfigXML struct {
	AssignedIP netip.Addr
	MTU        int
	DNS        []netip.Addr
}

// FortiGate XML schema — two layouts are observed in the wild, both accepted here:
//
//	Layout A (older firmwares, attribute form):
//	  <sslvpn-tunnel mtu="1500" dpd-retry-interval="3" ...>
//	    <ipv4 assigned-addr="10.212.134.205" ...>
//	      <dns ip="10.0.0.1"/>
//	    </ipv4>
//	  </sslvpn-tunnel>
//
//	Layout B (newer firmwares, nested element form with `ipv4` attribute):
//	  <sslvpn-tunnel mtu="1500" ...>
//	    <ipv4>
//	      <assigned-addr ipv4="10.212.134.205"/>
//	      <dns ip="10.0.0.1"/>
//	    </ipv4>
//	  </sslvpn-tunnel>
//
// A parser that handles only one layout silently fails on the other with "no assigned
// IPv4 address" even when the login succeeded, leaving users stuck with no diagnostic.
func parseTunnelConfigXML(b []byte) (tunnelConfigXML, error) {
	type dnsEl struct {
		IP string `xml:"ip,attr"`
	}
	type assignedAddrEl struct {
		// Layout B uses an `ipv4` attribute on the nested element; some firmwares also
		// emit `addr` for the same field. Accept either.
		IPv4 string `xml:"ipv4,attr"`
		Addr string `xml:"addr,attr"`
	}
	type ipv4El struct {
		// Layout A: attribute on the ipv4 element itself.
		AssignedAddrAttr string `xml:"assigned-addr,attr"`
		// Layout B: nested <assigned-addr ipv4="..."/> element.
		AssignedAddrEl assignedAddrEl `xml:"assigned-addr"`
		DNS            []dnsEl        `xml:"dns"`
	}
	type rootEl struct {
		MTU  int    `xml:"mtu,attr"`
		IPv4 ipv4El `xml:"ipv4"`
	}
	var root rootEl
	if err := xml.Unmarshal(b, &root); err != nil {
		return tunnelConfigXML{}, err
	}
	out := tunnelConfigXML{MTU: root.MTU}
	if out.MTU <= 0 {
		out.MTU = 1500
	}
	// Prefer layout A's attribute; fall back to layout B's nested element. The element
	// form can carry the IP under either `ipv4` or `addr` depending on firmware.
	raw := root.IPv4.AssignedAddrAttr
	if raw == "" {
		raw = root.IPv4.AssignedAddrEl.IPv4
	}
	if raw == "" {
		raw = root.IPv4.AssignedAddrEl.Addr
	}
	if raw == "" {
		return tunnelConfigXML{}, errors.New("no assigned IPv4 address in tunnel config XML")
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return tunnelConfigXML{}, fmt.Errorf("assigned-addr %q: %w", raw, err)
	}
	out.AssignedIP = addr
	for _, d := range root.IPv4.DNS {
		if a, err := netip.ParseAddr(d.IP); err == nil {
			out.DNS = append(out.DNS, a)
		}
	}
	return out, nil
}

// stripHostBrackets removes a single pair of surrounding `[ ]` from a host string.
// Users often paste IPv6 literals in their canonical bracketed URL form (`[2001:db8::1]`);
// net.JoinHostPort would then re-wrap them producing `[[...]]:port`, which Go's net stack
// rejects. Hostnames and IPv4 literals pass through unchanged.
func stripHostBrackets(host string) string {
	h := strings.TrimSpace(host)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}
