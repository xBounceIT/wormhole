package ipsec

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

func TestConfigValidateRequiresCredentials(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	// A fully-populated config validates and fills defaults.
	ok := base()
	if err := ok.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if ok.MTU != DefaultMTU {
		t.Fatal("validate did not fill defaults")
	}

	// Missing password is rejected (it previously slipped through and failed
	// deep in IKE_AUTH with an opaque error).
	noPass := base()
	noPass.EAP.Password = ""
	if err := noPass.validate(); err == nil {
		t.Fatal("empty EAP.Password accepted")
	}

	noUser := base()
	noUser.EAP.Username = ""
	if err := noUser.validate(); err == nil {
		t.Fatal("empty EAP.Username accepted")
	}

	noServer := base()
	noServer.Server = ""
	if err := noServer.validate(); err == nil {
		t.Fatal("empty Server accepted")
	}
}

// TestConfigValidatePSK covers the PSK/EAP credential dispatch: a PSK-only config
// validates (no EAP, no RootCAs needed), supplying both PSK and EAP is rejected as
// ambiguous, and supplying neither is rejected.
func TestConfigValidatePSK(t *testing.T) {
	pskOnly := Config{Server: "vpn.example.com:500", PSK: "sharedsecret", LocalID: FQDN("client.test")}
	if err := pskOnly.validate(); err != nil {
		t.Fatalf("PSK-only config rejected: %v", err)
	}
	if pskOnly.MTU != DefaultMTU {
		t.Fatal("validate did not fill defaults for a PSK config")
	}

	both := Config{
		Server: "vpn.example.com:500",
		PSK:    "sharedsecret",
		EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
	}
	if err := both.validate(); err == nil {
		t.Fatal("config with both PSK and EAP accepted")
	}

	neither := Config{Server: "vpn.example.com:500"}
	if err := neither.validate(); err == nil {
		t.Fatal("config with neither PSK nor EAP accepted")
	}
}

// TestConfigValidateIdentities: validate() enforces the identity contract that
// identity.go documents — PSK requires an explicit LocalID, EAP defaults an
// unset LocalID from the username, and an invalid identity (a constructor fed
// bad input, or hand-built malformed data) is rejected at config time instead
// of surfacing as an opaque AUTHENTICATION_FAILED deep in IKE_AUTH.
func TestConfigValidateIdentities(t *testing.T) {
	t.Run("psk requires LocalID", func(t *testing.T) {
		c := Config{Server: "vpn:500", PSK: "s"}
		if err := c.validate(); err == nil {
			t.Fatal("PSK config without LocalID accepted")
		}
	})
	t.Run("eap defaults LocalID from username", func(t *testing.T) {
		email := Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "user@corp.test", Password: "p"}}
		if err := email.validate(); err != nil {
			t.Fatal(err)
		}
		if email.LocalID.Kind != IDKindEmail || string(email.LocalID.Data) != "user@corp.test" {
			t.Fatalf("LocalID = %v, want email identity", email.LocalID)
		}
		plain := Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "user1", Password: "p"}}
		if err := plain.validate(); err != nil {
			t.Fatal(err)
		}
		if plain.LocalID.Kind != IDKindFQDN || string(plain.LocalID.Data) != "user1" {
			t.Fatalf("LocalID = %v, want FQDN identity", plain.LocalID)
		}
	})
	t.Run("invalid constructor output rejected", func(t *testing.T) {
		c := Config{
			Server:  "vpn:500",
			PSK:     "s",
			LocalID: IPv4(netip.MustParseAddr("2001:db8::1")), // collapses to invalid
		}
		if err := c.validate(); err == nil {
			t.Fatal("invalid LocalID accepted")
		}
	})
	t.Run("malformed hand-built identity rejected", func(t *testing.T) {
		c := Config{
			Server:  "vpn:500",
			PSK:     "s",
			LocalID: Identity{Kind: IDKindIPv4, Data: []byte{1, 2}},
		}
		if err := c.validate(); err == nil {
			t.Fatal("malformed IPv4 LocalID accepted")
		}
	})
	t.Run("RemoteID optional but must be well-formed", func(t *testing.T) {
		ok := Config{Server: "vpn:500", PSK: "s", LocalID: FQDN("c")}
		if err := ok.validate(); err != nil {
			t.Fatalf("unset RemoteID rejected: %v", err)
		}
		bad := Config{
			Server:   "vpn:500",
			PSK:      "s",
			LocalID:  FQDN("c"),
			RemoteID: IPv6(netip.MustParseAddr("192.0.2.1")), // collapses to invalid
		}
		if err := bad.validate(); err == nil {
			t.Fatal("invalid RemoteID accepted")
		}
	})
}

// TestConfigValidateFloorsRekeyMaxPackets is finding #6: a tiny non-zero
// RekeyMaxPackets is raised to MinRekeyMaxPackets so it cannot churn the data
// plane; zero keeps the "use the built-in default" contract; a value at or above
// the floor is left untouched.
func TestConfigValidateFloorsRekeyMaxPackets(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	tiny := base()
	tiny.RekeyMaxPackets = 1
	if err := tiny.validate(); err != nil {
		t.Fatal(err)
	}
	if tiny.RekeyMaxPackets != MinRekeyMaxPackets {
		t.Fatalf("tiny RekeyMaxPackets = %d, want floored to %d", tiny.RekeyMaxPackets, MinRekeyMaxPackets)
	}

	zero := base()
	zero.RekeyMaxPackets = 0
	if err := zero.validate(); err != nil {
		t.Fatal(err)
	}
	if zero.RekeyMaxPackets != 0 {
		t.Fatalf("zero RekeyMaxPackets = %d, want left at 0 (default contract)", zero.RekeyMaxPackets)
	}

	ok := base()
	ok.RekeyMaxPackets = MinRekeyMaxPackets
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if ok.RekeyMaxPackets != MinRekeyMaxPackets {
		t.Fatalf("at-floor RekeyMaxPackets = %d, want unchanged %d", ok.RekeyMaxPackets, MinRekeyMaxPackets)
	}
}

// TestConfigValidateFloorsKeepAlive: a non-positive KeepAlive (including a
// negative duration that previously slipped through the ==0 check and silently
// disabled NAT keepalives) is floored to the default; a positive value is kept.
func TestConfigValidateFloorsKeepAlive(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	neg := base()
	neg.KeepAlive = -5 * time.Second
	if err := neg.validate(); err != nil {
		t.Fatal(err)
	}
	if neg.KeepAlive != DefaultKeepAlive {
		t.Fatalf("negative KeepAlive = %v, want default %v", neg.KeepAlive, DefaultKeepAlive)
	}

	custom := base()
	custom.KeepAlive = 7 * time.Second
	if err := custom.validate(); err != nil {
		t.Fatal(err)
	}
	if custom.KeepAlive != 7*time.Second {
		t.Fatalf("positive KeepAlive overwritten: %v", custom.KeepAlive)
	}
}

// TestConfigValidateDefaultsNegativeDurations: every duration knob (not just
// KeepAlive) treats a negative value as "unset" and falls back to its default,
// so a negative rekey lifetime cannot silently disable time-based rekey and a
// negative backoff cannot busy-loop the redial.
func TestConfigValidateDefaultsNegativeDurations(t *testing.T) {
	c := Config{
		Server:                  "vpn.example.com:500",
		EAP:                     EAPMSCHAPv2{Username: "user", Password: "secret"},
		DPDTimeout:              -1 * time.Second,
		RekeyLifetime:           -1 * time.Second,
		IKERekeyLifetime:        -1 * time.Second,
		ReconnectBackoffBase:    -1 * time.Second,
		ReconnectBackoffMax:     -1 * time.Second,
		ReconnectAttemptTimeout: -1 * time.Second,
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]struct{ have, want time.Duration }{
		"DPDTimeout":              {c.DPDTimeout, DefaultDPDTimeout},
		"RekeyLifetime":           {c.RekeyLifetime, DefaultRekeyLifetime},
		"IKERekeyLifetime":        {c.IKERekeyLifetime, DefaultIKERekeyLifetime},
		"ReconnectBackoffBase":    {c.ReconnectBackoffBase, DefaultReconnectBackoffBase},
		"ReconnectBackoffMax":     {c.ReconnectBackoffMax, DefaultReconnectBackoffMax},
		"ReconnectAttemptTimeout": {c.ReconnectAttemptTimeout, DefaultReconnectAttemptTimeout},
	} {
		if got.have != got.want {
			t.Errorf("%s = %v, want default %v", name, got.have, got.want)
		}
	}
}

// TestConfigValidateClampsReplayWindow: an oversized ReplayWindow is clamped to
// the maximum the ESP layer can allocate (preventing the word-count overflow /
// unbounded allocation in NewReplayWindow).
func TestConfigValidateClampsReplayWindow(t *testing.T) {
	c := Config{
		Server:       "vpn.example.com:500",
		EAP:          EAPMSCHAPv2{Username: "user", Password: "secret"},
		ReplayWindow: 1 << 30,
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.ReplayWindow != esp.MaxReplayWindow {
		t.Fatalf("ReplayWindow = %d, want clamped to %d", c.ReplayWindow, esp.MaxReplayWindow)
	}
}

// TestConfigRedactsSecrets: a Config (or EAPMSCHAPv2) rendered through fmt or
// slog must never leak the PSK or the EAP password — %+v on a struct and
// slog.Any are tempting debug one-liners in consumer code.
func TestConfigRedactsSecrets(t *testing.T) {
	const secret = "s3cr3t-p4ssw0rd"
	cfg := Config{
		Server: "vpn.example.com:500",
		EAP:    EAPMSCHAPv2{Username: "user", Password: secret},
	}
	pskCfg := Config{Server: "vpn:500", PSK: secret, LocalID: FQDN("c")}

	for name, rendered := range map[string]string{
		"config %v":  fmt.Sprintf("%v", cfg),
		"config %+v": fmt.Sprintf("%+v", cfg),
		"psk %+v":    fmt.Sprintf("%+v", pskCfg),
		"eap %v":     fmt.Sprintf("%v", cfg.EAP),
		"eap %+v":    fmt.Sprintf("%+v", cfg.EAP),
		"config %s":  fmt.Sprint(cfg),
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s leaks the secret: %s", name, rendered)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("dialing", "config", cfg, "eap", cfg.EAP, "psk-config", pskCfg)
	if out := buf.String(); strings.Contains(out, secret) {
		t.Errorf("slog output leaks the secret: %s", out)
	}
}

// TestConfigValidateFloorsMTU: a pathologically small MTU is raised to MinMTU
// (go-tun2net only clamps oversized values down); zero still selects the
// default; sane values pass through.
func TestConfigValidateFloorsMTU(t *testing.T) {
	base := func() Config {
		return Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "u", Password: "p"}}
	}
	tiny := base()
	tiny.MTU = 14
	if err := tiny.validate(); err != nil {
		t.Fatal(err)
	}
	if tiny.MTU != MinMTU {
		t.Fatalf("MTU = %d, want floored to %d", tiny.MTU, MinMTU)
	}
	zero := base()
	if err := zero.validate(); err != nil {
		t.Fatal(err)
	}
	if zero.MTU != DefaultMTU {
		t.Fatalf("MTU = %d, want default %d", zero.MTU, DefaultMTU)
	}
	ok := base()
	ok.MTU = 1300
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if ok.MTU != 1300 {
		t.Fatalf("MTU = %d, want unchanged 1300", ok.MTU)
	}
}

// TestConfigValidateESPCipherSuites: unknown and duplicate suite values fail
// validation; nil and every defined value (in any order) pass; the mapping into
// internal ESP suite ids preserves the caller's preference order.
func TestConfigValidateESPCipherSuites(t *testing.T) {
	base := func() Config {
		return Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "u", Password: "p"}}
	}

	nilSuites := base()
	if err := nilSuites.validate(); err != nil {
		t.Fatalf("nil ESPCipherSuites rejected: %v", err)
	}
	if got := espSuitesFromConfig(nilSuites.ESPCipherSuites); got != nil {
		t.Fatalf("nil ESPCipherSuites mapped to %v, want nil (full built-in table)", got)
	}

	all := base()
	all.ESPCipherSuites = []CipherSuite{CipherSuiteAESCBC256SHA256, CipherSuiteAESGCM256, CipherSuiteChaCha20Poly1305}
	if err := all.validate(); err != nil {
		t.Fatalf("full suite list rejected: %v", err)
	}
	want := []esp.Suite{esp.SuiteAESCBC256SHA256, esp.SuiteAESGCM256, esp.SuiteChaCha20Poly1305}
	got := espSuitesFromConfig(all.ESPCipherSuites)
	if len(got) != len(want) {
		t.Fatalf("mapped %d suites, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("suite %d mapped to %v, want %v (preference order lost)", i, got[i], want[i])
		}
	}

	unknown := base()
	unknown.ESPCipherSuites = []CipherSuite{CipherSuite(99)}
	if err := unknown.validate(); err == nil {
		t.Fatal("unknown cipher suite accepted")
	}

	dup := base()
	dup.ESPCipherSuites = []CipherSuite{CipherSuiteAESGCM256, CipherSuiteAESGCM256}
	if err := dup.validate(); err == nil {
		t.Fatal("duplicate cipher suite accepted")
	}
}

// TestConfigValidateIKECipherSuites: the IKE suite list gets the same
// validation as the ESP one (unknown and duplicate values fail; nil and every
// defined value pass), the error names the right Config field, and the mapping
// into internal IKE suite ids preserves the caller's preference order.
func TestConfigValidateIKECipherSuites(t *testing.T) {
	base := func() Config {
		return Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "u", Password: "p"}}
	}

	nilSuites := base()
	if err := nilSuites.validate(); err != nil {
		t.Fatalf("nil IKECipherSuites rejected: %v", err)
	}
	if got := ikeSuitesFromConfig(nilSuites.IKECipherSuites); got != nil {
		t.Fatalf("nil IKECipherSuites mapped to %v, want nil (full built-in table)", got)
	}

	all := base()
	all.IKECipherSuites = []CipherSuite{CipherSuiteAESCBC256SHA256, CipherSuiteAESGCM256, CipherSuiteChaCha20Poly1305}
	if err := all.validate(); err != nil {
		t.Fatalf("full IKE suite list rejected: %v", err)
	}
	want := []ikesa.Suite{ikesa.SuiteAESCBC256SHA256, ikesa.SuiteAESGCM256, ikesa.SuiteChaCha20Poly1305}
	got := ikeSuitesFromConfig(all.IKECipherSuites)
	if len(got) != len(want) {
		t.Fatalf("mapped %d suites, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("suite %d mapped to %v, want %v (preference order lost)", i, got[i], want[i])
		}
	}

	unknown := base()
	unknown.IKECipherSuites = []CipherSuite{CipherSuite(99)}
	err := unknown.validate()
	if err == nil {
		t.Fatal("unknown IKE cipher suite accepted")
	}
	if !strings.Contains(err.Error(), "IKECipherSuites") {
		t.Fatalf("error does not name the IKECipherSuites field: %v", err)
	}

	dup := base()
	dup.IKECipherSuites = []CipherSuite{CipherSuiteAESGCM256, CipherSuiteAESGCM256}
	if err := dup.validate(); err == nil {
		t.Fatal("duplicate IKE cipher suite accepted")
	}
}

// TestCipherSuiteString pins the diagnostic names (shared with the internal
// esp.Suite names, matching strongSwan's algorithm spelling).
func TestCipherSuiteString(t *testing.T) {
	cases := map[CipherSuite]string{
		CipherSuiteAESGCM256:        "aes256gcm16",
		CipherSuiteChaCha20Poly1305: "chacha20poly1305",
		CipherSuiteAESCBC256SHA256:  "aes256-sha256",
	}
	for cs, want := range cases {
		if got := cs.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", uint8(cs), got, want)
		}
	}
	if got := CipherSuite(99).String(); !strings.Contains(got, "99") {
		t.Errorf("unknown suite String() = %q, want the numeric value in it", got)
	}
}
