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

	// Step 1: POST /remote/logincheck with credentials.
	form := url.Values{}
	form.Set("username", cfg.Username)
	form.Set("credential", cfg.Password)
	form.Set("ajax", "1")
	form.Set("just_logged_in", "1")
	if cfg.Realm != nil && *cfg.Realm != "" {
		form.Set("realm", *cfg.Realm)
	}
	body, err := postForm(authCtx, client, baseURL.JoinPath("remote", "logincheck").String(), form)
	if err != nil {
		return nil, fmt.Errorf("logincheck POST: %w", err)
	}

	// Step 2: if the body announces a 2FA challenge, complete it.
	if challenge := parseChallenge(string(body)); challenge != nil {
		if cfg.TotpSecret == nil || *cfg.TotpSecret == "" {
			return nil, errors.New("server requested 2FA but no TOTP secret was configured for this tunnel")
		}
		code, err := totp.GenerateCode(*cfg.TotpSecret, time.Now())
		if err != nil {
			return nil, fmt.Errorf("generate TOTP code: %w", err)
		}
		challenge.respond(code, cfg)
		body, err = postForm(authCtx, client, baseURL.JoinPath("remote", "logincheck").String(), challenge.form)
		if err != nil {
			return nil, fmt.Errorf("logincheck challenge POST: %w", err)
		}
	}

	// Use the tunnel-upgrade URL for the cookie check, not baseURL: FortiGate may set
	// SVPNCOOKIE without an explicit Path attribute, in which case Go's cookiejar uses the
	// default-path of the original /remote/logincheck request (= "/remote") — looking up
	// against the root would miss it. The tunnel-upgrade URL is the one we actually need
	// the cookie for, so check it there.
	tunnelURL := baseURL.JoinPath("remote", "sslvpn-tunnel")
	if !hasSvpnCookie(jar, tunnelURL) {
		return nil, fmt.Errorf("login did not yield an SVPNCOOKIE (server body: %s)", truncate(string(body), 200))
	}

	// Step 3: fetch the tunnel config XML (assigned IP, DNS, MTU).
	xmlBytes, err := httpGet(authCtx, client, baseURL.JoinPath("remote", "fortisslvpn_xml").String())
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

func postForm(ctx context.Context, client *http.Client, url string, form url.Values) ([]byte, error) {
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
	return readBoundedBody(resp.Body, url)
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
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
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return readBoundedBody(resp.Body, url)
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

// challenge represents a FortiGate 2FA prompt parsed from the logincheck response body.
// The server expects the second POST to echo back reqid/polid/grp/portal/magic and supply
// the user-entered code.
type challenge struct {
	form url.Values
}

func parseChallenge(body string) *challenge {
	// FortiGate returns plaintext like: ret=2,reqid=1234,polid=1,grp=somegrp,portal=Portal,magic=abc,tokeninfo=
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
	for _, k := range []string{"reqid", "polid", "grp", "portal", "magic", "peer"} {
		if v, ok := fields[k]; ok {
			form.Set(k, v)
		}
	}
	return &challenge{form: form}
}

func (c *challenge) respond(code string, cfg config) {
	c.form.Set("username", cfg.Username)
	c.form.Set("code", code)
	c.form.Set("ajax", "1")
}

type tunnelConfigXML struct {
	AssignedIP netip.Addr
	MTU        int
	DNS        []netip.Addr
}

// FortiGate XML schema — two layouts are observed in the wild, both accepted here:
//
//   Layout A (older firmwares, attribute form):
//     <sslvpn-tunnel mtu="1500" dpd-retry-interval="3" ...>
//       <ipv4 assigned-addr="10.212.134.205" ...>
//         <dns ip="10.0.0.1"/>
//       </ipv4>
//     </sslvpn-tunnel>
//
//   Layout B (newer firmwares, nested element form with `ipv4` attribute):
//     <sslvpn-tunnel mtu="1500" ...>
//       <ipv4>
//         <assigned-addr ipv4="10.212.134.205"/>
//         <dns ip="10.0.0.1"/>
//       </ipv4>
//     </sslvpn-tunnel>
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
