package ipsec

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// Default lifecycle parameters.
const (
	DefaultMTU uint32 = 1400
	// MinMTU is the floor for a non-zero MTU. go-tun2net only clamps an
	// oversized MTU down, so a pathologically small value (fat-fingered "14"
	// for 1400) would otherwise reach the netstack and break it; 576 is the
	// classic IPv4 minimum reassembly size.
	MinMTU                  uint32        = 576
	DefaultKeepAlive        time.Duration = 20 * time.Second
	DefaultDPDTimeout       time.Duration = 30 * time.Second
	DefaultRekeyLifetime    time.Duration = time.Hour
	DefaultIKERekeyLifetime time.Duration = 4 * time.Hour
	DefaultReplayWindow     uint32        = 64
	// MinRekeyMaxPackets is the floor for a non-zero RekeyMaxPackets: a tiny value
	// would rekey almost every tick and churn the data plane, so validate() floors
	// it (with a warning) rather than honouring an unusable tuning knob.
	MinRekeyMaxPackets uint32 = 4096
	// retransmit bounds for the IKE request/response machinery.
	DefaultRetransmitBase  time.Duration = 2 * time.Second
	DefaultRetransmitMax   time.Duration = 30 * time.Second
	DefaultRetransmitTries int           = 5

	// Auto-reconnect tuning: the redial loop AutoReconnect drives after the IKE
	// SA is declared dead. Backoff grows from Base to Max between attempts; each
	// attempt is bounded by AttemptTimeout.
	DefaultReconnectBackoffBase    time.Duration = 1 * time.Second
	DefaultReconnectBackoffMax     time.Duration = 30 * time.Second
	DefaultReconnectAttemptTimeout time.Duration = 20 * time.Second
)

// Config describes a single IKEv2 tunnel. The client authenticates with either
// EAP-MSCHAPv2 (set EAP) or a pre-shared key (set PSK) — exactly one of the two.
// Only stdlib-shaped fields are exposed; everything provider-specific lives in the
// caller.
//
// Both the IKE SA encryption (the SK{} envelope, AEAD per RFC 5282) and the
// ESP (Child SA) suite are negotiated from the same suite set — default
// preference AES-256-GCM-16, ChaCha20-Poly1305, then AES-CBC-256 +
// HMAC-SHA2-256-128 — restrictable via IKECipherSuites / ESPCipherSuites
// independently. The IKE PRF is fixed to HMAC-SHA2-256 and the DH group to
// x25519 (group 31, preferred) or MODP-2048 (group 14, fallback), negotiated
// at IKE_SA_INIT.
type Config struct {
	// Wormhole: Fortinet's SAML token is EAP-GTC; the responder is authenticated
	// independently with ServerPSK. This opt-in never changes standard EAP.
	FortinetSAML bool
	ServerPSK    string
	OnDead       func()
	// Server is the responder endpoint, host:port. Port defaults to 500.
	Server string

	// LocalID / RemoteID are the IKE identities. RemoteID, when set, is also
	// matched against the server certificate SANs. With EAP an unset LocalID
	// defaults to an identity derived from EAP.Username; with PSK LocalID is
	// required.
	LocalID  Identity
	RemoteID Identity

	// EAP carries the EAP-MSCHAPv2 credentials. Set either EAP or PSK, not both.
	EAP EAPMSCHAPv2

	// PSK is the pre-shared key for PSK authentication (RFC 7296 §2.15). Set
	// either PSK or EAP, not both. With PSK the IKE identity is taken directly from
	// LocalID/RemoteID (there is no EAP username), and no server certificate is
	// involved, so RootCAs is unused; RemoteID, when set, is the IDr the server
	// must present.
	PSK string

	// RootCAs is the trust anchor pool for the server certificate chain (EAP
	// only). When nil the host's system roots are used.
	RootCAs *x509.CertPool

	// Transport supplies the underlying packet socket. When nil a direct UDP
	// dialer is used.
	Transport PacketDialer

	// MTU is the inner tunnel MTU hint (clamped by the data plane).
	MTU uint32

	// Logger receives structured diagnostics. When nil logs are discarded.
	Logger *slog.Logger

	// Lifecycle timers; zero values fall back to the Default* constants.
	KeepAlive        time.Duration
	DPDTimeout       time.Duration
	RekeyLifetime    time.Duration // Child SA soft lifetime
	IKERekeyLifetime time.Duration // IKE SA soft lifetime
	ReplayWindow     uint32

	// RekeyMaxPackets triggers a Child SA rekey once the outbound ESP sequence
	// number reaches it, bounding how much data a single key protects regardless
	// of elapsed time. Zero selects a built-in default (2^31); it is independent
	// of RekeyLifetime, so a tunnel that is idle on the clock but heavy on the
	// wire still rekeys before sequence-number exhaustion. A non-zero value below
	// MinRekeyMaxPackets is raised to that floor (with a warning) to avoid
	// constant rekey churn.
	RekeyMaxPackets uint32

	// ESPCipherSuites restricts and orders the ESP cipher suites offered for
	// the Child SA, most-preferred first. nil or empty offers every implemented
	// suite in the default preference order (AES-256-GCM-16, ChaCha20-Poly1305,
	// AES-CBC-256+HMAC-SHA2-256-128). Use it to pin a single suite (e.g. an
	// AES-only operator policy) or to reorder the preference; unknown or
	// duplicate values fail validation. The IKE SA suite is not affected.
	ESPCipherSuites []CipherSuite

	// IKECipherSuites restricts and orders the encryption suites offered for
	// the IKE SA itself (the SK{} envelope, RFC 5282 for the AEAD suites) at
	// IKE_SA_INIT and on IKE SA rekeys, most-preferred first. It takes the same
	// CipherSuite values as ESPCipherSuites; nil or empty offers every
	// implemented suite in the default preference order (AES-256-GCM-16,
	// ChaCha20-Poly1305, AES-CBC-256+HMAC-SHA2-256-128). The IKE PRF
	// (HMAC-SHA2-256) and DH groups are fixed — only the encryption transform
	// is negotiated. Unknown or duplicate values fail validation.
	IKECipherSuites []CipherSuite

	// ChildSAPFS offers per-Child Perfect Forward Secrecy (a fresh MODP-2048 /
	// group 14 Diffie-Hellman exchange) on Child SA rekeys this client initiates.
	// A server-initiated PFS rekey is always honored regardless of this setting,
	// and once one is seen the client offers PFS on its own rekeys too. Enable it
	// when the peer REQUIRES Child PFS and may rekey before that is learned (cold
	// start). Only group 14 is supported.
	ChildSAPFS bool

	// RequestIPv6 controls whether the client asks the responder for an inner
	// IPv6 address (CFG INTERNAL_IP6_ADDRESS) and offers IPv6 traffic selectors
	// (::/0), so v6 application traffic is carried over ESP instead of failing
	// "network is unreachable". When enabled (the default: a nil pointer or a
	// pointer to true) the tunnel becomes dual-stack iff the responder assigns a
	// v6 address; a v4-only server simply does not, leaving behaviour unchanged.
	// Set it to a pointer to false for strict v4-only appliances.
	RequestIPv6 *bool

	// AutoReconnect controls in-place tunnel re-establishment after the IKE SA is
	// declared dead — e.g. a NAT mapping that expired during a laptop sleep, after
	// which the peer DPD-times us out. When enabled (the default: a nil pointer or
	// a pointer to true) the Client transparently redials on a fresh socket (which
	// re-punches the NAT mapping) and re-addresses the existing netstack in place,
	// so a long-lived binding such as srv.dial = client.DialContext stays valid.
	// Set it to a pointer to false to restore the legacy behavior of tearing the
	// Client down on peer death.
	AutoReconnect *bool

	// Reconnect backoff/timeout knobs; zero values fall back to the Default*
	// constants. They bound the redial loop AutoReconnect drives and are not
	// propagated to the IKE session.
	ReconnectBackoffBase    time.Duration
	ReconnectBackoffMax     time.Duration
	ReconnectAttemptTimeout time.Duration
}

// CipherSuite selects a transform suite for Config.ESPCipherSuites and
// Config.IKECipherSuites (the same suites are implemented for both layers).
type CipherSuite uint8

const (
	// CipherSuiteAESGCM256 is AES-GCM with a 256-bit key and a 16-octet ICV
	// (ENCR_AES_GCM_16, RFC 4106) — an AEAD suite, hardware-accelerated on
	// most CPUs.
	CipherSuiteAESGCM256 CipherSuite = iota + 1
	// CipherSuiteChaCha20Poly1305 is ChaCha20-Poly1305
	// (ENCR_CHACHA20_POLY1305, RFC 7634) — an AEAD suite, fast without AES
	// hardware.
	CipherSuiteChaCha20Poly1305
	// CipherSuiteAESCBC256SHA256 is AES-CBC-256 encryption with
	// HMAC-SHA2-256-128 integrity (RFC 3602 + RFC 4868) — the RFC-mandatory
	// baseline every IKEv2 gateway supports.
	CipherSuiteAESCBC256SHA256
)

// espSuite maps the public constant to the internal ESP suite id; ok is false
// for values outside the defined set.
func (cs CipherSuite) espSuite() (esp.Suite, bool) {
	switch cs {
	case CipherSuiteAESGCM256:
		return esp.SuiteAESGCM256, true
	case CipherSuiteChaCha20Poly1305:
		return esp.SuiteChaCha20Poly1305, true
	case CipherSuiteAESCBC256SHA256:
		return esp.SuiteAESCBC256SHA256, true
	default:
		return 0, false
	}
}

// ikeSuite maps the public constant to the internal IKE SA suite id; ok is
// false for values outside the defined set.
func (cs CipherSuite) ikeSuite() (ikesa.Suite, bool) {
	switch cs {
	case CipherSuiteAESGCM256:
		return ikesa.SuiteAESGCM256, true
	case CipherSuiteChaCha20Poly1305:
		return ikesa.SuiteChaCha20Poly1305, true
	case CipherSuiteAESCBC256SHA256:
		return ikesa.SuiteAESCBC256SHA256, true
	default:
		return 0, false
	}
}

// defined reports whether cs is a suite of either layer.
func (cs CipherSuite) defined() bool {
	_, esp := cs.espSuite()
	_, ike := cs.ikeSuite()
	return esp || ike
}

// String implements fmt.Stringer with the conventional transform names.
func (cs CipherSuite) String() string {
	if id, ok := cs.espSuite(); ok {
		return id.String()
	}
	if id, ok := cs.ikeSuite(); ok {
		return id.String()
	}
	return fmt.Sprintf("ipsec-cipher-suite-%d", uint8(cs))
}

// autoReconnectEnabled resolves the AutoReconnect tri-state: enabled unless the
// caller explicitly passed a pointer to false.
func (c Config) autoReconnectEnabled() bool {
	return c.AutoReconnect == nil || *c.AutoReconnect
}

// requestIPv6Enabled resolves the RequestIPv6 tri-state: enabled unless the
// caller explicitly passed a pointer to false.
func (c Config) requestIPv6Enabled() bool {
	return c.RequestIPv6 == nil || *c.RequestIPv6
}

// EAPMSCHAPv2 holds the inner EAP credentials.
type EAPMSCHAPv2 struct {
	Username string
	Password string
}

// validate fills defaults and rejects unsupported parameters.
func (c *Config) validate() error {
	if !c.FortinetSAML && c.ServerPSK != "" {
		return errors.New("ipsec: server PSK requires Fortinet SAML mode")
	}
	if c.FortinetSAML && (c.ServerPSK == "" || c.EAP.Username == "" || c.EAP.Password == "" || c.PSK != "") {
		return errors.New("ipsec: Fortinet SAML requires a server PSK and temporary EAP credentials")
	}
	if c.Server == "" {
		return errors.New("ipsec: Config.Server is required")
	}
	// Authentication: exactly one of PSK or EAP. EAP requires both username and
	// password; supplying both PSK and EAP (or neither) is a configuration error.
	hasPSK := c.PSK != ""
	hasEAP := c.EAP.Username != "" || c.EAP.Password != ""
	switch {
	case hasPSK && hasEAP:
		return errors.New("ipsec: set either Config.PSK or Config.EAP, not both")
	case !hasPSK && !hasEAP:
		return errors.New("ipsec: authentication credentials required: set Config.PSK or Config.EAP")
	case hasEAP:
		if c.EAP.Username == "" {
			return errors.New("ipsec: Config.EAP.Username is required")
		}
		if c.EAP.Password == "" {
			return errors.New("ipsec: Config.EAP.Password is required")
		}
	}
	// Identities: LocalID is marshalled into the wire IDi, so an unset or
	// malformed value would otherwise surface as an opaque AUTHENTICATION_FAILED
	// deep in IKE_AUTH. With EAP an unset LocalID defaults to the EAP username;
	// with PSK the identity keys the peer's PSK lookup and must be explicit.
	if c.LocalID.IsZero() {
		if hasPSK {
			return errors.New("ipsec: Config.LocalID is required with PSK authentication")
		}
		c.LocalID = defaultEAPIdentity(c.EAP.Username)
	}
	if err := c.LocalID.check(); err != nil {
		return fmt.Errorf("ipsec: Config.LocalID: %w", err)
	}
	if err := c.RemoteID.check(); err != nil {
		return fmt.Errorf("ipsec: Config.RemoteID: %w", err)
	}
	// Cipher-suite lists: unknown values would be silently unofferable and a
	// duplicate signals a caller-side mixup, so both fail loudly here rather
	// than at the handshake. Each list is validated against its own layer's
	// suite mapper so an ESP-only (or IKE-only) suite added later cannot slip
	// through the wrong list and then be silently dropped at offer time.
	if err := validateCipherSuites("ESPCipherSuites", "ESP", c.ESPCipherSuites, func(cs CipherSuite) bool {
		_, ok := cs.espSuite()
		return ok
	}); err != nil {
		return err
	}
	if err := validateCipherSuites("IKECipherSuites", "IKE", c.IKECipherSuites, func(cs CipherSuite) bool {
		_, ok := cs.ikeSuite()
		return ok
	}); err != nil {
		return err
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	// Duration knobs default on <= 0: a negative value is as meaningless as zero
	// (a negative rekey lifetime would disable time-based rekey, a negative
	// backoff would busy-loop the redial), so treat both uniformly as "unset".
	if c.KeepAlive <= 0 {
		c.KeepAlive = DefaultKeepAlive
	}
	if c.DPDTimeout <= 0 {
		c.DPDTimeout = DefaultDPDTimeout
	}
	if c.RekeyLifetime <= 0 {
		c.RekeyLifetime = DefaultRekeyLifetime
	}
	if c.IKERekeyLifetime <= 0 {
		c.IKERekeyLifetime = DefaultIKERekeyLifetime
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = DefaultReplayWindow
	}
	if c.ReconnectBackoffBase <= 0 {
		c.ReconnectBackoffBase = DefaultReconnectBackoffBase
	}
	if c.ReconnectBackoffMax <= 0 {
		c.ReconnectBackoffMax = DefaultReconnectBackoffMax
	}
	if c.ReconnectAttemptTimeout <= 0 {
		c.ReconnectAttemptTimeout = DefaultReconnectAttemptTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	// Clamp an oversized ReplayWindow (checked after Logger is set so the warning
	// lands). esp.NewReplayWindow also clamps defensively; this warns the operator.
	if c.ReplayWindow > esp.MaxReplayWindow {
		c.Logger.Warn("ipsec: ReplayWindow above maximum, clamping it",
			"configured", c.ReplayWindow, "max", esp.MaxReplayWindow)
		c.ReplayWindow = esp.MaxReplayWindow
	}
	// Floor a non-zero RekeyMaxPackets so a tiny value can't churn the data plane
	// with constant rekeys. Zero keeps the "use the built-in default" contract.
	if c.RekeyMaxPackets != 0 && c.RekeyMaxPackets < MinRekeyMaxPackets {
		c.Logger.Warn("ipsec: RekeyMaxPackets below floor, raising it",
			"configured", c.RekeyMaxPackets, "floor", MinRekeyMaxPackets)
		c.RekeyMaxPackets = MinRekeyMaxPackets
	}
	// Floor a tiny MTU: go-tun2net only clamps oversized values down, so a
	// pathological hint would otherwise reach the netstack unchanged.
	if c.MTU < MinMTU {
		c.Logger.Warn("ipsec: MTU below floor, raising it",
			"configured", c.MTU, "floor", MinMTU)
		c.MTU = MinMTU
	}
	return nil
}

// validateCipherSuites rejects unknown and duplicate values in a Config
// cipher-suite list; field names the offending Config field in the error and
// known reports whether a value maps to a suite implemented by that layer (the
// ESP and IKE layers happen to share a domain today, but validating each
// against its own mapper keeps them decoupled). A value valid only in the other
// layer is reported as unsupported for this layer rather than as unknown.
func validateCipherSuites(field, layer string, suites []CipherSuite, known func(CipherSuite) bool) error {
	seen := make(map[CipherSuite]bool, len(suites))
	for _, cs := range suites {
		if !known(cs) {
			if cs.defined() {
				return fmt.Errorf("ipsec: Config.%s: cipher suite %v is not supported for %s", field, cs, layer)
			}
			return fmt.Errorf("ipsec: Config.%s: unknown cipher suite %d", field, uint8(cs))
		}
		if seen[cs] {
			return fmt.Errorf("ipsec: Config.%s: duplicate cipher suite %v", field, cs)
		}
		seen[cs] = true
	}
	return nil
}

// redactSecret renders a credential for display without leaking its value or
// length.
func redactSecret(s string) string {
	if s == "" {
		return "<unset>"
	}
	return "<redacted>"
}

// String implements fmt.Stringer. It replaces the default struct rendering so
// a Config printed with %v/%+v (a tempting debug one-liner in consumer code)
// cannot leak the PSK or the EAP password.
func (c Config) String() string {
	return fmt.Sprintf("ipsec.Config{Server: %q, LocalID: %v, RemoteID: %v, EAP: %v, PSK: %s, MTU: %d}",
		c.Server, c.LocalID, c.RemoteID, c.EAP, redactSecret(c.PSK), c.MTU)
}

// LogValue implements slog.LogValuer with the same credential redaction for
// structured logging (slog.Any("config", cfg)).
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("server", c.Server),
		slog.String("localID", c.LocalID.String()),
		slog.String("remoteID", c.RemoteID.String()),
		slog.String("eapUser", c.EAP.Username),
		slog.String("psk", redactSecret(c.PSK)),
	)
}

// String implements fmt.Stringer, redacting the password.
func (e EAPMSCHAPv2) String() string {
	return fmt.Sprintf("ipsec.EAPMSCHAPv2{Username: %q, Password: %s}", e.Username, redactSecret(e.Password))
}

// LogValue implements slog.LogValuer, redacting the password.
func (e EAPMSCHAPv2) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("username", e.Username),
		slog.String("password", redactSecret(e.Password)),
	)
}
