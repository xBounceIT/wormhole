package main

import (
	"reflect"
	"strings"
	"testing"
)

// Both FortiGate XML layouts are seen in the wild. A previous parser that bound the
// assigned IP exclusively to the attribute form silently failed on the nested-element
// form (and vice versa), surfacing as "no assigned IPv4 address" even on successful
// logins. Lock both in.
func TestParseTunnelConfigXML_AttributeLayout(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1500" dpd-retry-interval="3">
		<ipv4 assigned-addr="10.212.134.205">
			<dns ip="10.0.0.1"/>
			<dns ip="10.0.0.2"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.212.134.205" {
		t.Errorf("assigned IP: got %q want 10.212.134.205", got.AssignedIP)
	}
	if got.MTU != 1500 {
		t.Errorf("mtu: got %d want 1500", got.MTU)
	}
	if len(got.DNS) != 2 {
		t.Errorf("dns count: got %d want 2", len(got.DNS))
	}
}

func TestParseTunnelConfigXML_NestedElementLayout(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1400">
		<ipv4>
			<assigned-addr ipv4="10.212.134.205"/>
			<dns ip="10.0.0.1"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.212.134.205" {
		t.Errorf("assigned IP: got %q want 10.212.134.205", got.AssignedIP)
	}
	if got.MTU != 1400 {
		t.Errorf("mtu: got %d want 1400", got.MTU)
	}
}

func TestParseTunnelConfigXML_NestedElementAddrAttr(t *testing.T) {
	// Some firmwares use `addr` instead of `ipv4` on the nested element.
	xml := []byte(`<sslvpn-tunnel>
		<ipv4>
			<assigned-addr addr="10.10.10.10"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.10.10.10" {
		t.Errorf("assigned IP: got %q want 10.10.10.10", got.AssignedIP)
	}
	if got.MTU != 1500 {
		t.Errorf("mtu default: got %d want 1500", got.MTU)
	}
}

func TestParseTunnelConfigXML_MissingAddress(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1500"><ipv4><dns ip="1.1.1.1"/></ipv4></sslvpn-tunnel>`)
	_, err := parseTunnelConfigXML(xml)
	if err == nil {
		t.Fatal("expected error for missing assigned IP, got nil")
	}
}

func TestParseChallenge_TextForm(t *testing.T) {
	body := `ret=2,reqid=1234,polid=5,grp=Engineering,portal=Main,magic=abc123,tokeninfo=`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge for text form")
	}
	if c.form.Get("magic") != "abc123" {
		t.Errorf("magic: got %q want abc123", c.form.Get("magic"))
	}
	if c.form.Get("reqid") != "1234" {
		t.Errorf("reqid: got %q", c.form.Get("reqid"))
	}
	if c.form.Get("polid") != "5" {
		t.Errorf("polid: got %q", c.form.Get("polid"))
	}
}

func TestParseChallenge_HTMLForm(t *testing.T) {
	// Realistic FortiGate HTML 2FA prompt — attributes in various orders, double + single
	// quotes mixed, extra whitespace.
	body := `<html><body>
<form method="post" action="/remote/logincheck">
<input type="hidden" name="reqid" value="1234"/>
<input  type='hidden'  name='polid'  value='5' />
<input name="grp"     value="Engineering" type="hidden">
<input type="hidden" name="portal" value="Main"/>
<input type="hidden" name="magic" value="abc123"/>
<input type="text" name="code" placeholder="Code"/>
<input type="submit" value="Verify"/>
</form>
</body></html>`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge for HTML form")
	}
	if c.form.Get("magic") != "abc123" {
		t.Errorf("magic: got %q want abc123", c.form.Get("magic"))
	}
	if c.form.Get("reqid") != "1234" {
		t.Errorf("reqid: got %q want 1234", c.form.Get("reqid"))
	}
	if c.form.Get("polid") != "5" {
		t.Errorf("polid: got %q want 5", c.form.Get("polid"))
	}
	if c.form.Get("grp") != "Engineering" {
		t.Errorf("grp: got %q want Engineering", c.form.Get("grp"))
	}
}

func TestParseChallenge_HTMLForm_SpacedAttributes(t *testing.T) {
	// Valid HTML: whitespace around `=` is allowed by the HTML spec. Locks W10 against
	// regression to a substring-based type=hidden check that misses this form.
	body := `<form>
<input  type = "hidden"   name = "reqid"   value = "9"  />
<input  type = 'hidden'   name = 'magic'   value = 'm1' />
<input  name = "polid"   value = "5"  type = "hidden" >
</form>`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge for spaced-attribute HTML")
	}
	if c.form.Get("magic") != "m1" {
		t.Errorf("magic: got %q want m1", c.form.Get("magic"))
	}
	if c.form.Get("reqid") != "9" {
		t.Errorf("reqid: got %q want 9", c.form.Get("reqid"))
	}
	if c.form.Get("polid") != "5" {
		t.Errorf("polid: got %q want 5", c.form.Get("polid"))
	}
}

func TestChallengeRespond_TextUsesCodeField(t *testing.T) {
	body := `ret=2,reqid=1,magic=m`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge")
	}
	cfg := config{Username: "alice"}
	c.respond("123456", cfg)
	if c.form.Get("code") != "123456" {
		t.Errorf("text form should write OTP to 'code'; got code=%q credential=%q",
			c.form.Get("code"), c.form.Get("credential"))
	}
	if c.form.Get("credential") != "" {
		t.Errorf("text form should NOT set credential; got %q", c.form.Get("credential"))
	}
}

func TestChallengeRespond_HTMLUsesCredentialField(t *testing.T) {
	body := `<form><input type="hidden" name="magic" value="m"/></form>`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge")
	}
	cfg := config{Username: "alice"}
	c.respond("123456", cfg)
	if c.form.Get("credential") != "123456" {
		t.Errorf("HTML form should write OTP to 'credential'; got credential=%q code=%q",
			c.form.Get("credential"), c.form.Get("code"))
	}
	if c.form.Get("code") != "" {
		t.Errorf("HTML form should NOT set code; got %q", c.form.Get("code"))
	}
}

func TestParseChallenge_HTMLForm_ForwardsGrpid(t *testing.T) {
	// FortiGate HTML challenge typically uses `grpid` rather than `grp` — must be echoed
	// back or the challenge POST is rejected.
	body := `<form><input type="hidden" name="reqid" value="9"/>` +
		`<input type="hidden" name="grpid" value="7"/>` +
		`<input type="hidden" name="magic" value="m1"/></form>`
	c := parseChallenge(body)
	if c == nil {
		t.Fatal("expected non-nil challenge")
	}
	if c.form.Get("grpid") != "7" {
		t.Errorf("grpid: got %q want 7", c.form.Get("grpid"))
	}
}

func TestParseChallenge_HTMLWithoutMagic_NotAChallenge(t *testing.T) {
	// Plain login page with hidden inputs but no `magic` — should NOT be treated as a
	// challenge response, because that would cause us to POST a meaningless second
	// logincheck for every login page in the wild.
	body := `<html><body>
<form><input type="hidden" name="csrf_token" value="xyz"/></form>
</body></html>`
	c := parseChallenge(body)
	if c != nil {
		t.Errorf("expected nil (no magic field), got %v", c.form)
	}
}

func TestParseChallenge_NeitherFormat(t *testing.T) {
	// SVPNCOOKIE-success body has neither ret= nor hidden inputs.
	if parseChallenge(`<html><body>Welcome</body></html>`) != nil {
		t.Error("expected nil for non-challenge HTML")
	}
	if parseChallenge(`ret=1,error=bad-creds`) != nil {
		t.Error("expected nil for ret=1 (not a challenge)")
	}
	if parseChallenge(``) != nil {
		t.Error("expected nil for empty body")
	}
}

func TestStripHostBrackets(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"vpn.example.com", "vpn.example.com"}, // hostname unchanged
		{"10.0.0.1", "10.0.0.1"},               // IPv4 unchanged
		{"[2001:db8::1]", "2001:db8::1"},       // bracketed v6 stripped
		{"[::1]", "::1"},                       // shortest bracketed v6
		{"2001:db8::1", "2001:db8::1"},         // bare v6 unchanged (works with JoinHostPort)
		{"  [::1]  ", "::1"},                   // surrounding whitespace
		{"", ""},                               // empty
		{"[", "["},                             // unmatched bracket: pass-through
		{"]", "]"},
	}
	for _, tc := range cases {
		got := stripHostBrackets(tc.in)
		if got != tc.want {
			t.Errorf("stripHostBrackets(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClassifyLoginBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"empty", ``, nil},
		{"login-page", `<html><body><form action="/remote/logincheck" method="post">` +
			`<input type="text" name="username"/>` +
			`<input type="password" name="credential"/></form></body></html>`,
			[]string{"login-page"}},
		{"saml", `<html><body><form action="https://idp.example.com/sso" method="post">` +
			`<input type="hidden" name="SAMLRequest" value="b64"/></form></body></html>`,
			[]string{"saml"}},
		{"ret-success", `ret=1,redir=/remote/portal`, []string{"ret=1"}},
		{"ret-fail", `ret=0,error=permission denied`, []string{"ret=0", "auth-error"}},
		{"challenge", `ret=2,reqid=1,polid=2,magic=abc`, []string{"ret=2", "has-magic"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyLoginBody([]byte(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("classifyLoginBody(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestRedactBody_ScrubsCredentials(t *testing.T) {
	cfg := config{Username: "alice", Password: "s3cr3t-pw"}
	body := "Hello alice, the password s3cr3t-pw is wrong\n\n   please retry"
	got := redactBody([]byte(body), cfg)
	if strings.Contains(got, "alice") {
		t.Errorf("username leaked into excerpt: %q", got)
	}
	if strings.Contains(got, "s3cr3t-pw") {
		t.Errorf("password leaked into excerpt: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("whitespace not collapsed: %q", got)
	}
}

func TestRedactBody_Caps(t *testing.T) {
	got := redactBody([]byte(strings.Repeat("a", 1000)), config{})
	if r := []rune(got); len(r) > 256+len([]rune("…(truncated)")) {
		t.Errorf("excerpt not capped: %d runes", len(r))
	}
}
