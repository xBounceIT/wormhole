package main

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
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

func TestBuildInitXML_IncludesGroup(t *testing.T) {
	cfg := config{Host: "vpn.example.com", Group: strptr("Contractors")}
	xml := buildInitXML(cfg)
	if !strings.Contains(xml, `type="init"`) {
		t.Fatalf("missing init type: %s", xml)
	}
	if !strings.Contains(xml, "<group-select>Contractors</group-select>") {
		t.Fatalf("missing group-select: %s", xml)
	}
	if !strings.Contains(xml, "group-access>https://vpn.example.com") {
		t.Fatalf("missing group-access: %s", xml)
	}
}

func TestBuildAuthReplyXML_EchoesOpaque(t *testing.T) {
	cfg := config{Username: "alice", Password: "p@ss<>&"}
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
