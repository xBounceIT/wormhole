package main

import (
	"bufio"
	"bytes"
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

// session is the outcome of a successful AnyConnect login + CSTP tunnel upgrade. From this
// point the byte channel on Reader/Conn carries STF-framed packets in both directions.
type session struct {
	Conn       *tls.Conn
	Reader     *bufio.Reader // wraps Conn; may already hold tunnel bytes read past the CONNECT response
	AssignedIP netip.Addr
	MTU        int
	DNS        []netip.Addr
	DPDSeconds int // gateway dead-peer-detection interval (X-CSTP-DPD); 0 = none advertised
}

// ciscoUserAgent mirrors the official Cisco Secure Client (AnyConnect) Windows User-Agent. Some
// ASA/FTD gateways gate the SSL VPN endpoints on an "AnyConnect"-looking UA and reject the
// default Go client (openconnect spoofs the same shape in its default UA).
const ciscoUserAgent = "AnyConnect Windows 4.10.06079"

// clientVersion is echoed in the aggregate-auth XML <version> element; cosmetic but some
// gateways log/inspect it.
const clientVersion = "4.10.06079"

// maxAuthForms bounds how many challenge/response auth forms we will answer before giving up.
// A primary form plus a single second-factor challenge is the common case; the cap stops a
// misbehaving (or hostile) gateway from looping us forever.
const maxAuthForms = 6

// ciscoLogin runs the aggregate-auth XML exchange, then opens the CSTP tunnel and returns the
// resulting session.
func ciscoLogin(ctx context.Context, cfg config) (*session, error) {
	// Strip a bracketed IPv6 literal (e.g. "[2001:db8::1]") BEFORE it reaches tls.Config.ServerName
	// and net.JoinHostPort: SNI rejects a bracketed name and JoinHostPort would re-wrap it to
	// "[[...]]". Mutating the local cfg copy here also covers the CONNECT phase, since cstpConnect
	// is called below with this same cfg. Hostnames and IPv4 literals pass through unchanged.
	cfg.Host = stripHostBrackets(cfg.Host)

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}

	authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
	defer authCancel()

	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         netDialer.DialContext,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   20 * time.Second,
	}

	baseURL := &url.URL{Scheme: "https", Host: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), Path: "/"}
	loginURL := baseURL.String()

	// Step 1: POST the init request. The gateway answers with the primary auth form (and any
	// group list / opaque blob to echo back).
	body, err := postAuthXML(authCtx, client, "auth-init", loginURL, buildInitXML(cfg))
	if err != nil {
		return nil, fmt.Errorf("auth init POST: %w", err)
	}
	resp, err := parseConfigAuth(body)
	if err != nil {
		return nil, fmt.Errorf("parse auth init response: %w", err)
	}

	// Step 2: answer each auth form in turn (primary credentials, then any second-factor
	// challenge) until the gateway returns id="success" or an error. primarySent latches once the
	// account password has been placed on a form, so every later form's password field is
	// answered with the SECOND factor instead of re-sending the primary password.
	primarySent := false
	for form := 0; form < maxAuthForms; form++ {
		switch strings.ToLower(resp.Auth.ID) {
		case "success":
			cookie := captureWebvpnCookie(jar, baseURL, resp)
			if cookie == "" {
				return nil, errors.New("gateway reported auth success but no webvpn session cookie was issued")
			}
			return cstpConnect(ctx, cfg, tlsCfg, cookie)
		case "error":
			return nil, fmt.Errorf("gateway rejected authentication: %s", firstNonEmpty(resp.Auth.Error, resp.Auth.Message, "unspecified error"))
		}

		reply, err := buildAuthReplyXML(cfg, resp, &primarySent)
		if err != nil {
			return nil, err
		}
		body, err = postAuthXML(authCtx, client, fmt.Sprintf("auth-reply-%d", form+1), loginURL, reply)
		if err != nil {
			return nil, fmt.Errorf("auth reply POST: %w", err)
		}
		resp, err = parseConfigAuth(body)
		if err != nil {
			return nil, fmt.Errorf("parse auth reply response: %w", err)
		}
	}
	return nil, fmt.Errorf("authentication did not complete after %d forms (last form id=%q)", maxAuthForms, resp.Auth.ID)
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
		// Fail closed on a malformed pin rather than silently dropping to default (or no)
		// verification — same posture as the Fortinet sidecar.
		raw := strings.ReplaceAll(strings.TrimSpace(*cfg.ServerCertSha256Pin), ":", "")
		want, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("server_cert_sha256_pin is not valid hex: %w", err)
		}
		if len(want) != sha256.Size {
			return nil, fmt.Errorf("server_cert_sha256_pin must be a SHA-256 hash (%d bytes); got %d bytes", sha256.Size, len(want))
		}
		t.InsecureSkipVerify = true
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificates")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			// bytes.Equal is fine here (no constant-time requirement): both sides are
			// already-public certificate digests, not secrets.
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("server cert SHA-256 %x does not match configured pin", got)
			}
			return nil
		}
	}
	return t, nil
}

// cstpConnect opens a fresh TLS connection and performs the CSTP CONNECT upgrade, parsing the
// assigned address / MTU / DNS out of the response headers. The webvpn session cookie from the
// auth phase authorizes the tunnel.
func cstpConnect(ctx context.Context, cfg config, tlsCfg *tls.Config, cookie string) (*session, error) {
	tunnelCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := netDialer.DialContext(tunnelCtx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("tunnel dial: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(tunnelCtx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tunnel TLS handshake: %w", err)
	}

	// Bound the CONNECT request/response exchange; cleared once the tunnel is up so the data
	// loop has no I/O deadline.
	if dl, ok := tunnelCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(dl)
	}

	if err := writeCstpConnect(tlsConn, cfg, cookie); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("CSTP CONNECT write: %w", err)
	}

	// Read the CONNECT response headers via a bufio.Reader, then KEEP that reader for the data
	// loop: the gateway may flush the first STF frame in the same TLS record as the response
	// headers, and a fresh reader would lose those buffered bytes.
	br := bufio.NewReaderSize(tlsConn, 16*1024)
	sess, err := readCstpConnectResponse(br)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	sess.Conn = tlsConn
	sess.Reader = br
	return sess, nil
}

func writeCstpConnect(c *tls.Conn, cfg config, cookie string) error {
	host := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT /CSTP HTTP/1.1\r\n")
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", ciscoUserAgent)
	fmt.Fprintf(&b, "Cookie: webvpn=%s\r\n", cookie)
	fmt.Fprintf(&b, "X-CSTP-Version: 1\r\n")
	fmt.Fprintf(&b, "X-CSTP-Hostname: wormhole\r\n")
	fmt.Fprintf(&b, "X-CSTP-Address-Type: IPv4\r\n")
	fmt.Fprintf(&b, "X-CSTP-Base-MTU: 1280\r\n")
	fmt.Fprintf(&b, "X-CSTP-MTU: 1406\r\n")
	fmt.Fprintf(&b, "X-CSTP-Full-IPv6: false\r\n")
	// Deliberately advertise neither DTLS (no X-DTLS-Master-Secret) nor compression (no
	// X-CSTP-Accept-Encoding): this sidecar only carries CSTP-over-TLS and never decodes a
	// compressed frame, so a present-but-empty header would be malformed and could make a gateway
	// either wait for a DTLS/UDP channel that never opens or push frames we'd have to drop.
	fmt.Fprintf(&b, "\r\n")
	_, err := c.Write([]byte(b.String()))
	return err
}

// readCstpConnectResponse reads the CSTP CONNECT status line + headers and extracts the tunnel
// parameters. Returns a session with Conn/Reader unset (the caller fills those in).
func readCstpConnectResponse(br *bufio.Reader) (*session, error) {
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read CSTP status line: %w", err)
	}
	status = strings.TrimRight(status, "\r\n")
	// Expected: "HTTP/1.1 200 CONNECTED". Anything else is a rejection (often 401/403 for an
	// expired cookie, or 503 for a tunnel-limit). Parse the numeric status-code TOKEN rather than
	// substring-matching "200" (which would also accept a reason phrase or a different code that
	// merely contains those digits). Surface the line for diagnosis.
	statusFields := strings.Fields(status)
	if len(statusFields) < 2 || statusFields[1] != "200" {
		return nil, fmt.Errorf("gateway refused CSTP tunnel: %q", status)
	}

	headers := map[string][]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read CSTP headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		headers[key] = append(headers[key], strings.TrimSpace(v))
	}

	sess := &session{MTU: 1406}
	if addrs := headers["x-cstp-address"]; len(addrs) > 0 {
		a, err := netip.ParseAddr(strings.TrimSpace(addrs[0]))
		if err != nil {
			return nil, fmt.Errorf("X-CSTP-Address %q: %w", addrs[0], err)
		}
		if !a.Is4() {
			return nil, fmt.Errorf("X-CSTP-Address %v is not IPv4; IPv6-only tunnels are unsupported", a)
		}
		sess.AssignedIP = a
	} else {
		return nil, errors.New("gateway did not assign an IPv4 address (no X-CSTP-Address header)")
	}
	if mtus := headers["x-cstp-mtu"]; len(mtus) > 0 {
		if m, err := strconv.Atoi(strings.TrimSpace(mtus[0])); err == nil && m > 0 {
			sess.MTU = m
		}
	}
	if dpd := headers["x-cstp-dpd"]; len(dpd) > 0 {
		if d, err := strconv.Atoi(strings.TrimSpace(dpd[0])); err == nil && d > 0 {
			sess.DPDSeconds = d
		}
	}
	// X-CSTP-DNS may appear multiple times (one server per header) or as a single space/comma
	// separated value depending on firmware.
	for _, raw := range headers["x-cstp-dns"] {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
			if a, err := netip.ParseAddr(strings.TrimSpace(tok)); err == nil && a.Is4() {
				sess.DNS = append(sess.DNS, a)
			}
		}
	}
	return sess, nil
}

// --- aggregate-auth XML ---------------------------------------------------------------------

type xmlConfigAuth struct {
	XMLName      xml.Name `xml:"config-auth"`
	Auth         xmlAuth  `xml:"auth"`
	Opaque       *xmlRaw  `xml:"opaque"`
	SessionToken string   `xml:"session-token"`
}

type xmlAuth struct {
	ID      string  `xml:"id,attr"`
	Message string  `xml:"message"`
	Error   string  `xml:"error"`
	Form    xmlForm `xml:"form"`
}

type xmlForm struct {
	Inputs []xmlInput `xml:"input"`
}

type xmlInput struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Label string `xml:"label,attr"` // the human-readable prompt (e.g. "Answer:"); kept for diagnostics
}

// xmlRaw captures the inner XML of an element verbatim plus its is-for attribute. The gateway's
// <opaque> blob is opaque session state we must echo back unmodified in the auth-reply.
type xmlRaw struct {
	IsFor string `xml:"is-for,attr"`
	Inner string `xml:",innerxml"`
}

func parseConfigAuth(body []byte) (*xmlConfigAuth, error) {
	var ca xmlConfigAuth
	if err := xml.Unmarshal(body, &ca); err != nil {
		return nil, fmt.Errorf("invalid XML (%d bytes): %w", len(body), err)
	}
	if ca.XMLName.Local != "config-auth" {
		return nil, fmt.Errorf("unexpected root element %q (want config-auth)", ca.XMLName.Local)
	}
	return &ca, nil
}

func buildInitXML(cfg config) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<config-auth client="vpn" type="init" aggregate-auth-version="2">`)
	fmt.Fprintf(&b, `<version who="vpn">%s</version>`, clientVersion)
	b.WriteString(`<device-id>win</device-id>`)
	fmt.Fprintf(&b, `<group-access>https://%s</group-access>`, xmlEscape(cfg.Host))
	if cfg.Group != nil && *cfg.Group != "" {
		fmt.Fprintf(&b, `<group-select>%s</group-select>`, xmlEscape(*cfg.Group))
	}
	b.WriteString(`</config-auth>`)
	return b.String()
}

// buildAuthReplyXML answers the current auth form with the configured credentials. The first
// form (carrying a text/username input) gets username+password; a later form with only a
// password input is treated as a second-factor challenge and answered with the TOTP code (if a
// secret is configured) or the static secondary password. primarySent latches once the account
// password has been placed, so the second factor — not the primary password — answers every
// later form.
func buildAuthReplyXML(cfg config, resp *xmlConfigAuth, primarySent *bool) (string, error) {
	values, err := answerForm(cfg, resp.Auth.Form, primarySent)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">`)
	fmt.Fprintf(&b, `<version who="vpn">%s</version>`, clientVersion)
	b.WriteString(`<device-id>win</device-id>`)
	b.WriteString(`<session-token></session-token>`)
	b.WriteString(`<session-id></session-id>`)
	if resp.Opaque != nil {
		isFor := resp.Opaque.IsFor
		if isFor == "" {
			isFor = "sg"
		}
		fmt.Fprintf(&b, `<opaque is-for="%s">%s</opaque>`, xmlEscape(isFor), resp.Opaque.Inner)
	}
	b.WriteString(`<auth>`)
	for _, kv := range values {
		fmt.Fprintf(&b, `<%s>%s</%s>`, kv.name, xmlEscape(kv.value), kv.name)
	}
	b.WriteString(`</auth>`)
	if cfg.Group != nil && *cfg.Group != "" {
		fmt.Fprintf(&b, `<group-select>%s</group-select>`, xmlEscape(*cfg.Group))
	}
	b.WriteString(`</config-auth>`)
	return b.String(), nil
}

type formValue struct {
	name  string
	value string
}

// answerForm maps the gateway form inputs to credential values. Recognized fields:
//   - a text/non-password input (commonly name="username") → cfg.Username
//   - the FIRST password input across the whole login (primarySent still false) → cfg.Password
//   - any later password input (primarySent already latched) → second factor (TOTP / secondary
//     password)
//
// primarySent is shared across the per-form calls of one login, so a second form that carries
// only a password input is answered with the second factor — not a re-send of the account
// password. answerForm sets *primarySent the moment it consumes the primary password.
func answerForm(cfg config, form xmlForm, primarySent *bool) ([]formValue, error) {
	var out []formValue
	// fillPassword returns the value for a password-type input: the primary password the first
	// time (latching primarySent), the second factor every time after.
	fillPassword := func() (string, error) {
		if !*primarySent {
			*primarySent = true
			return cfg.Password, nil
		}
		return secondFactor(cfg)
	}

	for _, in := range form.Inputs {
		typ := strings.ToLower(in.Type)
		name := in.Name
		if name == "" {
			continue
		}
		switch {
		case typ == "password" || typ == "passwd":
			val, err := fillPassword()
			if err != nil {
				return nil, err
			}
			out = append(out, formValue{name, val})
		case typ == "text" || typ == "" || typ == "email":
			out = append(out, formValue{name, cfg.Username})
		case typ == "hidden":
			// Hidden inputs carrying a default value are echoed by the real client; we omit
			// them since the opaque blob already carries the gateway's session state.
		default:
			// Unknown input type (e.g. a vendor extension). Skip rather than guess.
		}
	}
	if len(out) == 0 {
		// A form with no text/password inputs at all (e.g. a pure second-factor "answer" form
		// whose single input typed itself oddly): fall back to answering the named "password"
		// or "answer" field, still honoring primarySent so a primary-stage form isn't given a
		// second factor it doesn't expect.
		for _, in := range form.Inputs {
			lname := strings.ToLower(in.Name)
			if lname == "password" || lname == "answer" || lname == "secondary_password" {
				val, err := fillPassword()
				if err != nil {
					return nil, err
				}
				out = append(out, formValue{in.Name, val})
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not map any credential onto the gateway auth form (inputs: %s)", describeInputs(form))
	}
	return out, nil
}

// secondFactor returns the answer for a second authentication form: a freshly generated TOTP
// code when a secret is configured, else the static secondary password.
func secondFactor(cfg config) (string, error) {
	if cfg.TotpSecret != nil && *cfg.TotpSecret != "" {
		code, err := totp.GenerateCode(*cfg.TotpSecret, time.Now())
		if err != nil {
			return "", fmt.Errorf("generate TOTP code: %w", err)
		}
		return code, nil
	}
	if cfg.SecondaryPassword != nil && *cfg.SecondaryPassword != "" {
		return *cfg.SecondaryPassword, nil
	}
	return "", errors.New("gateway requested a second authentication factor but no TOTP secret or secondary password was configured for this tunnel")
}

func describeInputs(form xmlForm) string {
	parts := make([]string, 0, len(form.Inputs))
	for _, in := range form.Inputs {
		parts = append(parts, fmt.Sprintf("%s/%s", in.Name, in.Type))
	}
	return strings.Join(parts, ",")
}

// captureWebvpnCookie returns the webvpn session cookie that authorizes the CSTP tunnel. It is
// normally delivered as a Set-Cookie on the success response (captured by the cookie jar); some
// firmwares also echo it in a <session-token> element.
func captureWebvpnCookie(jar *cookiejar.Jar, baseURL *url.URL, resp *xmlConfigAuth) string {
	for _, c := range jar.Cookies(baseURL) {
		if strings.EqualFold(c.Name, "webvpn") && c.Value != "" {
			return c.Value
		}
	}
	if resp.SessionToken != "" {
		return resp.SessionToken
	}
	return ""
}

func postAuthXML(ctx context.Context, client *http.Client, label, url, payload string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("User-Agent", ciscoUserAgent)
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("X-Transcend-Version", "1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("auth response from %s exceeds %d bytes; refusing to parse", url, maxBody)
	}
	logf("%s: status=%d bodyLen=%d", label, resp.StatusCode, len(body))
	if debugLog {
		logf("%s body-excerpt: %s", label, redactAuthBody(body))
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// redactREs masks each secret-bearing aggregate-auth element. RE2 has no backreferences, so one
// regexp per tag (each matching its own open/close) instead of a `</\1>` backref; the non-greedy
// dot-all body match handles attributes and nested children, and replacing the whole element
// (not just its inner text) is the safer choice for a redactor. Case-insensitive via (?i).
var redactREs = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<password\b[^>]*>.*?</password>`),
	regexp.MustCompile(`(?is)<opaque\b[^>]*>.*?</opaque>`),
	regexp.MustCompile(`(?is)<session-token\b[^>]*>.*?</session-token>`),
	regexp.MustCompile(`(?is)<session-id\b[^>]*>.*?</session-id>`),
}

// redactAuthBody renders a length-capped excerpt of an aggregate-auth XML response for the
// debug-only verbose log, masking the values of password/opaque/token-bearing elements. Only
// reached when debugLog is set (operator opted in for a capture).
func redactAuthBody(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	for _, re := range redactREs {
		s = re.ReplaceAllString(s, "<redacted>")
	}
	const limit = 512
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…(truncated)"
	}
	return s
}

// stripHostBrackets removes a single pair of surrounding `[ ]` from a host string. Users often
// paste IPv6 literals in their canonical bracketed form (`[2001:db8::1]`); net.JoinHostPort would
// then re-wrap them producing `[[...]]:port`, and tls.Config.ServerName rejects a bracketed name.
// Hostnames and IPv4 literals pass through unchanged. (Mirrors the Fortinet sidecar.)
func stripHostBrackets(host string) string {
	h := strings.TrimSpace(host)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}
