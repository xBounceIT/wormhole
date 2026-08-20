package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func strptr(s string) *string { return &s }

func TestParseConfigAuth_PrimaryForm(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <opaque is-for="sg"><tunnel-group>DEFAULT</tunnel-group><aggauth-handle>123</aggauth-handle></opaque>
  <auth id="main">
    <message>Please enter your credentials</message>
    <form method="post" action="/+webvpn+/index.html">
      <input type="text" name="username" label="Username:"/>
      <input type="password" name="password" label="Password:"/>
    </form>
  </auth>
</config-auth>`)
	ca, err := parseConfigAuth(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ca.Auth.ID != "main" {
		t.Fatalf("auth id: got %q want main", ca.Auth.ID)
	}
	if ca.Opaque == nil || !strings.Contains(ca.Opaque.Inner, "aggauth-handle") {
		t.Fatalf("opaque inner not captured: %+v", ca.Opaque)
	}
	if len(ca.Auth.Form.Inputs) != 2 {
		t.Fatalf("inputs: got %d want 2", len(ca.Auth.Form.Inputs))
	}
}
func TestAuthFailureMessage_MainFormError(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <auth id="main">
    <message>Please enter your username and password.</message>
    <error id="15" param1="" param2="">Login failed.</error>
    <form>
      <input type="text" name="username" label="Username:"/>
      <input type="password" name="password" label="Password:"/>
    </form>
  </auth>
</config-auth>`)
	ca, err := parseConfigAuth(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := authFailureMessage(ca); got != "Login failed." {
		t.Fatalf("authFailureMessage = %q, want Login failed.", got)
	}
}

func TestAnswerForm_PrimaryCredentials(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cret"}
	form := xmlForm{Inputs: []xmlInput{
		{Name: "username", Type: "text"},
		{Name: "password", Type: "password"},
	}}
	vals, err := answerForm(cfg, form, true /* isPrimaryForm */)
	if err != nil {
		t.Fatalf("answerForm: %v", err)
	}
	got := map[string]string{}
	for _, v := range vals {
		got[v.name] = v.value
	}
	if got["username"] != "alice" || got["password"] != "s3cret" {
		t.Fatalf("mapped values wrong: %+v", got)
	}
}

// TestAnswerForm_ChallengeFormSecondFactor locks the contract that EVERY field on a challenge
// (non-primary) form is answered with the second factor — covering both a password-typed box and,
// critically, a TEXT-typed answer box (the openconnect/RADIUS pattern where the OTP field is
// type="text" name="answer"; the pre-fix code filled it with the username and failed MFA).
func TestAnswerForm_ChallengeFormSecondFactor(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cret", TotpSecret: strptr("JBSWY3DPEHPK3PXP")}
	cases := []struct {
		name string
		form xmlForm
	}{
		{"password-typed", xmlForm{Inputs: []xmlInput{{Name: "password", Type: "password", Label: "Answer:"}}}},
		{"text-typed answer", xmlForm{Inputs: []xmlInput{{Name: "answer", Type: "text", Label: "OTP:"}}}},
		{"text-typed secondary_password", xmlForm{Inputs: []xmlInput{{Name: "secondary_password", Type: "text"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, err := answerForm(cfg, tc.form, false /* isPrimaryForm */)
			if err != nil {
				t.Fatalf("answerForm: %v", err)
			}
			if len(vals) != 1 {
				t.Fatalf("values: %+v", vals)
			}
			if vals[0].value == "alice" {
				t.Fatal("challenge field was filled with the username instead of the second factor")
			}
			if vals[0].value == "s3cret" {
				t.Fatal("challenge field was filled with the account password instead of the second factor")
			}
			if len(vals[0].value) != 6 {
				t.Fatalf("challenge field should carry a 6-digit TOTP code, got %q", vals[0].value)
			}
		})
	}
}

// TestAnswerForm_CombinedPrimaryFormSecondaryPassword locks the case where the gateway puts the
// account password AND the second factor on the SAME (primary) form: a password-typed field named
// secondary_password must get the TOTP/secondary password, not a second copy of the account
// password. (ASA double-auth / RADIUS second-password profiles.)
func TestAnswerForm_CombinedPrimaryFormSecondaryPassword(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cret", TotpSecret: strptr("JBSWY3DPEHPK3PXP")}
	form := xmlForm{Inputs: []xmlInput{
		{Name: "username", Type: "text"},
		{Name: "password", Type: "password"},
		{Name: "secondary_password", Type: "password"},
	}}
	vals, err := answerForm(cfg, form, true /* isPrimaryForm */)
	if err != nil {
		t.Fatalf("answerForm: %v", err)
	}
	got := map[string]string{}
	for _, v := range vals {
		got[v.name] = v.value
	}
	if got["username"] != "alice" {
		t.Fatalf("username: got %q", got["username"])
	}
	if got["password"] != "s3cret" {
		t.Fatalf("password: got %q want the account password", got["password"])
	}
	if got["secondary_password"] == "s3cret" {
		t.Fatal("secondary_password got the account password instead of the second factor (the bug)")
	}
	if len(got["secondary_password"]) != 6 {
		t.Fatalf("secondary_password should carry a 6-digit TOTP code, got %q", got["secondary_password"])
	}
}

// TestAnswerForm_TwoFormFlow_SendsSecondFactorOnChallenge locks the real ciscoLogin contract: the
// primary form (isPrimaryForm=true) collects username+password, and the following challenge form
// (isPrimaryForm=false) is answered with the second factor, NOT a re-send of the account password.
func TestAnswerForm_TwoFormFlow_SendsSecondFactorOnChallenge(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cret", TotpSecret: strptr("JBSWY3DPEHPK3PXP")}

	form1 := xmlForm{Inputs: []xmlInput{
		{Name: "username", Type: "text"},
		{Name: "password", Type: "password"},
	}}
	vals1, err := answerForm(cfg, form1, true)
	if err != nil {
		t.Fatalf("form1: %v", err)
	}
	got1 := map[string]string{}
	for _, v := range vals1 {
		got1[v.name] = v.value
	}
	if got1["username"] != "alice" || got1["password"] != "s3cret" {
		t.Fatalf("form1 should carry the primary credentials: %+v", got1)
	}

	form2 := xmlForm{Inputs: []xmlInput{
		{Name: "password", Type: "password", Label: "Answer:"},
	}}
	vals2, err := answerForm(cfg, form2, false)
	if err != nil {
		t.Fatalf("form2: %v", err)
	}
	if len(vals2) != 1 {
		t.Fatalf("form2 values: %+v", vals2)
	}
	if vals2[0].value == "s3cret" {
		t.Fatal("form2 re-sent the account password as the second factor (the bug)")
	}
	if len(vals2[0].value) != 6 {
		t.Fatalf("form2 should carry a 6-digit TOTP code, got %q", vals2[0].value)
	}
}

func TestAnswerForm_SecondFactorMissingFails(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cret"} // no TOTP, no secondary password
	form := xmlForm{Inputs: []xmlInput{{Name: "password", Type: "password"}}}
	_, err := answerForm(cfg, form, false /* challenge form */)
	if err == nil {
		t.Fatal("expected an error when a second factor is requested but none is configured")
	}
	if !strings.Contains(err.Error(), "second authentication factor") {
		t.Fatalf("error did not mention the missing second factor: %v", err)
	}
}

// TestRedactAuthBody_TerminatesAndMasks guards the debug-log redactor against the infinite-loop
// regression (the opening tag was left in place and re-matched forever).
func TestRedactAuthBody_TerminatesAndMasks(t *testing.T) {
	body := []byte(`<config-auth><opaque is-for="sg"><h>SECRET1</h></opaque>` +
		`<auth><password>SECRET2</password></auth><session-token>SECRET3</session-token></config-auth>`)
	out := redactAuthBody(body) // must return (not hang)
	for _, leaked := range []string{"SECRET1", "SECRET2", "SECRET3"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redactAuthBody leaked %q: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "<redacted>") {
		t.Fatalf("redactAuthBody did not mask anything: %s", out)
	}
}

func TestBuildTLSConfig_LegacyRSACompatibilityMode(t *testing.T) {
	modern, err := buildTLSConfig(config{Host: "vpn.example.com"}, tlsModeModern)
	if err != nil {
		t.Fatalf("modern tls config: %v", err)
	}
	if modern.MinVersion != tls.VersionTLS12 {
		t.Fatalf("modern MinVersion = 0x%x, want TLS 1.2", modern.MinVersion)
	}
	if modern.MaxVersion != 0 {
		t.Fatalf("modern MaxVersion = 0x%x, want runtime default", modern.MaxVersion)
	}
	if len(modern.CipherSuites) != 0 {
		t.Fatalf("modern CipherSuites should use Go defaults, got %#v", modern.CipherSuites)
	}

	legacy, err := buildTLSConfig(config{Host: "vpn.example.com", TrustServerCertificate: true}, tlsModeLegacyRSA)
	if err != nil {
		t.Fatalf("legacy tls config: %v", err)
	}
	if legacy.MinVersion != tls.VersionTLS12 || legacy.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("legacy TLS bounds = min 0x%x max 0x%x, want TLS 1.2 only", legacy.MinVersion, legacy.MaxVersion)
	}
	want := []uint16{
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
	if len(legacy.CipherSuites) != len(want) {
		t.Fatalf("legacy CipherSuites length = %d, want %d", len(legacy.CipherSuites), len(want))
	}
	for i := range want {
		if legacy.CipherSuites[i] != want[i] {
			t.Fatalf("legacy CipherSuites[%d] = 0x%x, want 0x%x", i, legacy.CipherSuites[i], want[i])
		}
	}
	if !legacy.InsecureSkipVerify {
		t.Fatal("legacy config should preserve TrustServerCertificate")
	}
}

func TestIsTLSHandshakeFailure(t *testing.T) {
	wrapped := fmt.Errorf("auth init POST: %w", errors.New("remote error: tls: handshake failure"))
	if !isTLSHandshakeFailure(wrapped) {
		t.Fatal("expected wrapped TLS handshake failure to be detected")
	}
	if isTLSHandshakeFailure(errors.New("remote error: tls: bad certificate")) {
		t.Fatal("non-handshake TLS errors must not trigger legacy fallback")
	}
}

func TestBuildInitXML_IncludesGroup(t *testing.T) {
	cfg := config{Host: "vpn.example.com", Port: 443, Group: strptr("Contractors")}
	xml := buildInitXML(cfg)
	if !strings.Contains(xml, `type="init"`) {
		t.Fatalf("missing init type: %s", xml)
	}
	if !strings.Contains(xml, "<group-select>Contractors</group-select>") {
		t.Fatalf("missing group-select: %s", xml)
	}
	if !strings.Contains(xml, "<group-access>https://vpn.example.com/Contractors</group-access>") {
		t.Fatalf("group-access wrong for default port: %s", xml)
	}
}

func TestGroupAccessURL(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"vpn.example.com", 443, "https://vpn.example.com"},       // default port omitted
		{"vpn.example.com", 0, "https://vpn.example.com"},         // unset treated as default
		{"vpn.example.com", 8443, "https://vpn.example.com:8443"}, // non-default port preserved
		{"10.0.0.1", 8443, "https://10.0.0.1:8443"},
		{"2001:db8::1", 443, "https://[2001:db8::1]"}, // IPv6 literal bracketed
		{"2001:db8::1", 8443, "https://[2001:db8::1]:8443"},
	}
	for _, tc := range cases {
		got := groupAccessURL(config{Host: tc.host, Port: tc.port})
		if got != tc.want {
			t.Errorf("groupAccessURL(%q,%d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestGroupAccessURL_IncludesEscapedGroupPath(t *testing.T) {
	group := "Contractors EU"
	got := groupAccessURL(config{Host: "vpn.example.com", Port: 443, Group: &group})
	want := "https://vpn.example.com/Contractors%20EU"
	if got != want {
		t.Fatalf("groupAccessURL with group = %q, want %q", got, want)
	}
}
func TestBuildInitXML_PreservesNonDefaultPort(t *testing.T) {
	xml := buildInitXML(config{Host: "vpn.example.com", Port: 8443})
	if !strings.Contains(xml, "<group-access>https://vpn.example.com:8443</group-access>") {
		t.Fatalf("group-access dropped the non-default port: %s", xml)
	}
}

func TestBuildAuthReplyXML_EchoesOpaque(t *testing.T) {
	cfg := config{Username: "alice", Password: "p@ss<>&", Group: strptr("Contractors")}
	resp := &xmlConfigAuth{
		Opaque: &xmlRaw{IsFor: "sg", Inner: "<aggauth-handle>9</aggauth-handle>"},
		Auth: xmlAuth{
			ID: "main",
			Form: xmlForm{Inputs: []xmlInput{
				{Name: "username", Type: "text"},
				{Name: "password", Type: "password"},
			}},
		},
	}
	out, err := buildAuthReplyXML(cfg, resp, true /* isPrimaryForm */)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(out, `<opaque is-for="sg"><aggauth-handle>9</aggauth-handle></opaque>`) {
		t.Fatalf("opaque not echoed verbatim: %s", out)
	}
	if !strings.Contains(out, "<username>alice</username>") {
		t.Fatalf("username missing: %s", out)
	}
	// The password contains XML metacharacters and must be escaped.
	if !strings.Contains(out, "p@ss&lt;&gt;&amp;") {
		t.Fatalf("password not XML-escaped: %s", out)
	}
	for _, forbidden := range []string{"<session-token>", "<session-id>", "<group-select>"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("auth reply should not contain %s: %s", forbidden, out)
		}
	}
}

func TestBuildCstpConnectRequest_UsesStandardPath(t *testing.T) {
	cfg := config{Host: "vpn.example.com", Port: 443}
	req := buildCstpConnectRequest(cfg, "COOKIEVAL")
	// ASA/FTD/AnyConnect gateways expect the CONNECT to /CSCOSSLC/tunnel (the OpenConnect path);
	// a non-standard path is rejected after a valid login, so lock it.
	if !strings.HasPrefix(req, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n") {
		t.Fatalf("CSTP request line wrong; got:\n%q", req)
	}
	if strings.Contains(req, "/CSTP ") {
		t.Fatalf("request still uses the bogus /CSTP path:\n%q", req)
	}
	if !strings.Contains(req, "Cookie: webvpn=COOKIEVAL\r\n") {
		t.Fatalf("session cookie missing from CONNECT:\n%q", req)
	}
	if !strings.HasSuffix(req, "\r\n\r\n") {
		t.Fatalf("request not terminated with a blank line:\n%q", req)
	}
}

func TestBuildCstpConnectRequest_AdvertisesCoherentMTU(t *testing.T) {
	req := buildCstpConnectRequest(config{Host: "vpn.example.com", Port: 443}, "COOKIEVAL")
	if !strings.Contains(req, "X-CSTP-Base-MTU: 1500\r\n") {
		t.Fatalf("outer base MTU missing or incorrect:\n%q", req)
	}
	if !strings.Contains(req, "X-CSTP-MTU: 1406\r\n") {
		t.Fatalf("inner tunnel MTU missing or incorrect:\n%q", req)
	}
}

func TestReadCstpConnectResponse_ParsesHeaders(t *testing.T) {
	raw := "HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Address: 10.20.30.40\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DNS: 10.20.0.53\r\n" +
		"X-CSTP-DNS: 10.20.0.54\r\n" +
		"X-CSTP-MTU: 1390\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"\r\n" +
		"STFdata-would-follow"
	br := bufio.NewReader(strings.NewReader(raw))
	sess, err := readCstpConnectResponse(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sess.AssignedIP != netip.MustParseAddr("10.20.30.40") {
		t.Fatalf("address: got %v", sess.AssignedIP)
	}
	if sess.MTU != 1390 {
		t.Fatalf("mtu: got %d want 1390", sess.MTU)
	}
	if sess.DPDSeconds != 30 {
		t.Fatalf("dpd: got %d want 30", sess.DPDSeconds)
	}
	want := []netip.Addr{netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("10.20.0.54")}
	if len(sess.DNS) != 2 || sess.DNS[0] != want[0] || sess.DNS[1] != want[1] {
		t.Fatalf("dns: got %v want %v", sess.DNS, want)
	}
	// The buffered reader must still hold the tunnel bytes that followed the header block.
	rest, _ := br.ReadString('\n')
	if !strings.HasPrefix(rest, "STF") {
		t.Fatalf("tunnel bytes lost; got %q", rest)
	}
}

func TestReadCstpConnectResponse_DefaultsMTUWhenHeaderMissing(t *testing.T) {
	raw := "HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-Address: 10.20.30.40\r\n" +
		"\r\n"
	sess, err := readCstpConnectResponse(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sess.MTU != 1406 {
		t.Fatalf("mtu: got %d want 1406", sess.MTU)
	}
}

func TestReadCstpConnectResponse_DefaultsMTUWhenHeaderExceedsUint16(t *testing.T) {
	raw := "HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-Address: 10.20.30.40\r\n" +
		"X-CSTP-MTU: 65536\r\n" +
		"\r\n"
	sess, err := readCstpConnectResponse(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sess.MTU != defaultCSTPMTU {
		t.Fatalf("mtu: got %d want safe default %d", sess.MTU, defaultCSTPMTU)
	}
}

func TestReadCstpConnectResponse_RejectsNon200(t *testing.T) {
	raw := "HTTP/1.1 403 Forbidden\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	_, err := readCstpConnectResponse(br)
	if err == nil {
		t.Fatal("expected an error for a non-200 CONNECT response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should surface the status line: %v", err)
	}
}

func TestCiscoLoginCompletesAggregateAuthAndCSTPConnect(t *testing.T) {
	requests := make(chan string, 8)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		if r.UserAgent() != ciscoUserAgent {
			t.Errorf("user agent = %q", r.UserAgent())
		}
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `type="init"`) {
				_, _ = io.WriteString(w, `<config-auth><opaque is-for="sg"><handle>1</handle></opaque><auth id="main"><form><input type="text" name="username"/><input type="password" name="password"/></form></auth></config-auth>`)
				return
			}
			if !strings.Contains(string(body), "<username>alice</username>") || !strings.Contains(string(body), "<password>secret</password>") {
				t.Errorf("auth reply = %s", body)
			}
			_, _ = io.WriteString(w, `<config-auth><auth id="success"/><session-token>session-cookie</session-token></config-auth>`)
		case http.MethodConnect:
			if r.URL.Path != cstpTunnelPath || r.Header.Get("Cookie") != "webvpn=session-cookie" {
				t.Errorf("CONNECT path=%q cookie=%q", r.URL.Path, r.Header.Get("Cookie"))
			}
			w.Header().Set("X-CSTP-Address", "10.0.0.2")
			w.Header().Set("X-CSTP-DNS", "10.0.0.53")
			w.Header().Set("X-CSTP-MTU", "1400")
			w.Header().Set("X-CSTP-DPD", "30")
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	sess, err := ciscoLogin(context.Background(), config{Host: host, Port: port, Username: "alice", Password: "secret", TrustServerCertificate: true})
	if err != nil {
		t.Fatalf("ciscoLogin returned %v", err)
	}
	defer sess.Conn.Close()
	if sess.AssignedIP.String() != "10.0.0.2" || sess.MTU != 1400 || len(sess.DNS) != 1 || sess.DPDSeconds != 30 {
		t.Fatalf("session = %#v", sess)
	}
	for _, want := range []string{"POST /", "POST /", "CONNECT " + cstpTunnelPath} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("request = %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("missing request %q", want)
		}
	}

	outerCtx, outerCancel := context.WithCancel(context.Background())
	dialer, arm, cleanup, err := startCisco(outerCtx, outerCancel, config{Host: host, Port: port, Username: "alice", Password: "secret", TrustServerCertificate: true})
	if err != nil {
		t.Fatalf("startCisco returned %v", err)
	}
	if dialer == nil || arm == nil || cleanup == nil {
		t.Fatal("startCisco returned nil lifecycle resources")
	}
	arm()
	cleanup()
}

func TestBuildTLSConfigCertificatePin(t *testing.T) {
	invalid := "not-hex"
	if _, err := buildTLSConfig(config{ServerCertSha256Pin: &invalid}, tlsModeModern); err == nil {
		t.Fatal("invalid pin was accepted")
	}
	short := "0102"
	if _, err := buildTLSConfig(config{ServerCertSha256Pin: &short}, tlsModeModern); err == nil {
		t.Fatal("short pin was accepted")
	}
	raw := []byte("certificate")
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	cfg, err := buildTLSConfig(config{Host: "vpn.example.test", ServerCertSha256Pin: &pin}, tlsModeModern)
	if err != nil || cfg.VerifyConnection == nil || !cfg.InsecureSkipVerify {
		t.Fatalf("pinned config = %#v, %v", cfg, err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("empty certificate chain was accepted")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("wrong")}}}); err == nil {
		t.Fatal("wrong certificate was accepted")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: raw}}}); err != nil {
		t.Fatalf("matching certificate was rejected: %v", err)
	}
}

func TestCookieCaptureDescriptionAndHostNormalization(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	baseURL, _ := url.Parse("https://vpn.example.test/")
	if got := captureWebvpnCookie(jar, baseURL, &xmlConfigAuth{SessionToken: "token"}); got != "token" {
		t.Fatalf("token fallback = %q", got)
	}
	jar.SetCookies(baseURL, []*http.Cookie{{Name: "WEBVPN", Value: "cookie"}})
	if got := captureWebvpnCookie(jar, baseURL, &xmlConfigAuth{SessionToken: "token"}); got != "cookie" {
		t.Fatalf("cookie capture = %q", got)
	}
	emptyJar, _ := cookiejar.New(nil)
	if got := captureWebvpnCookie(emptyJar, baseURL, &xmlConfigAuth{}); got != "" {
		t.Fatalf("empty capture = %q", got)
	}
	form := xmlForm{Inputs: []xmlInput{{Name: "username", Type: "text"}, {Name: "password", Type: "password"}}}
	if got := describeInputs(form); got != "username/text,password/password" {
		t.Fatalf("describeInputs = %q", got)
	}
	for input, want := range map[string]string{" [2001:db8::1] ": "2001:db8::1", " vpn.example.test ": "vpn.example.test"} {
		if got := stripHostBrackets(input); got != want {
			t.Fatalf("stripHostBrackets(%q) = %q", input, got)
		}
	}
}

func TestParseConfigAuthAndAuthMessagesHandleInvalidInput(t *testing.T) {
	if _, err := parseConfigAuth([]byte("<")); err == nil {
		t.Fatal("invalid XML was accepted")
	}
	if _, err := parseConfigAuth([]byte("<other/>")); err == nil {
		t.Fatal("unexpected root was accepted")
	}
	if got := authFailureMessage(nil); got != "" {
		t.Fatalf("nil failure message = %q", got)
	}
	if got := authMessage(nil); got != "unspecified error" {
		t.Fatalf("nil auth message = %q", got)
	}
	if got := authMessage(&xmlConfigAuth{Auth: xmlAuth{Message: " prompt "}}); got != " prompt " {
		t.Fatalf("auth message = %q", got)
	}
}

func TestAnswerFormFallbackAndUnmappableInputs(t *testing.T) {
	secondary := "654321"
	values, err := answerForm(config{SecondaryPassword: &secondary}, xmlForm{Inputs: []xmlInput{
		{Name: "ignored", Type: "hidden"},
		{Name: "answer", Type: "vendor-extension"},
	}}, false)
	if err != nil || len(values) != 1 || values[0].name != "answer" || values[0].value != secondary {
		t.Fatalf("fallback values = %#v, %v", values, err)
	}
	if _, err := answerForm(config{}, xmlForm{Inputs: []xmlInput{{Name: "", Type: "text"}, {Name: "custom", Type: "hidden"}}}, true); err == nil {
		t.Fatal("unmappable form was accepted")
	}
}

type ciscoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f ciscoRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type ciscoErrorReader struct{}

func (ciscoErrorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestPostAuthXMLSurfacesRequestTransportBodySizeAndStatusErrors(t *testing.T) {
	client := &http.Client{Transport: ciscoRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	if _, err := postAuthXML(context.Background(), client, "test", ":", "payload"); err == nil {
		t.Fatal("invalid URL was accepted")
	}
	if _, err := postAuthXML(context.Background(), client, "test", "https://example.test", "payload"); err == nil {
		t.Fatal("transport error was ignored")
	}
	client.Transport = ciscoRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(ciscoErrorReader{})}, nil
	})
	if _, err := postAuthXML(context.Background(), client, "test", "https://example.test", "payload"); err == nil {
		t.Fatal("body read error was ignored")
	}
	client.Transport = ciscoRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("a", (1<<20)+1)))}, nil
	})
	if _, err := postAuthXML(context.Background(), client, "test", "https://example.test", "payload"); err == nil {
		t.Fatal("oversized body was accepted")
	}
	client.Transport = ciscoRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("failed"))}, nil
	})
	if _, err := postAuthXML(context.Background(), client, "test", "https://example.test", "payload"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("status error = %v", err)
	}
}
