package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fpTestConfig() config {
	return config{VPNProtocol: "forcepoint-ssl", Host: "vpn.example.test", Port: 443, Username: "test-user", Password: "test-password"}
}

// The independent wire fixtures specify the four-byte header and the eight-byte
// control header. The version-9 fixture also matches the unauthenticated response
// observed from a Forcepoint gateway; no production address or certificate is stored.
func fpTestWire(op byte, payload []byte) []byte {
	size := len(payload) + 4
	return append([]byte{op, byte(size >> 16), byte(size >> 8), byte(size)}, payload...)
}

func fpTestControl(op byte, body []byte) []byte {
	return append([]byte{op, 0, 0, 0, 0x12, 0x34, 0x56, 0x78}, body...)
}

func fpTestString(value string) []byte {
	return append([]byte{byte(len(value) >> 8), byte(len(value))}, value...)
}

func fpTestVerdict(success bool) []byte {
	flags := byte(0)
	if success {
		flags = 0x80
	}
	// flags, reserved, 28800-second reauthentication lifetime, empty message
	return []byte{flags, 0, 0, 0, 0x70, 0x80, 0, 0}
}

var fpTestAttributes = [][]byte{
	{1, 4, 10, 0, 0, 2},
	{2, 4, 255, 255, 255, 255},
	{3, 4, 10, 0, 0, 1},
	{6, 8, 10, 0, 0, 0, 255, 255, 255, 0},
}

const fpTestPolicy = `<client-config><ssl-tunnel name="test"/><security-checks><antivirus enabled="0"/><firewall enabled="0"/><windows-update enabled="0"/></security-checks></client-config>`

func fpTestNetwork(attributes [][]byte, policy string) []byte {
	body := []byte{byte(len(attributes) >> 8), byte(len(attributes))}
	for _, attribute := range attributes {
		body = append(body, attribute...)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(policy)))
	body = append(body, size[:]...)
	return append(body, policy...)
}

func fpTestSession() (*forcepointSession, *bytes.Buffer) {
	output := new(bytes.Buffer)
	return &forcepointSession{conn: &fakeNetConn{in: new(bytes.Buffer), out: output}, cfg: fpTestConfig()}, output
}

func TestForcepointFrameBoundsAndGoldenWire(t *testing.T) {
	s, output := fpTestSession()
	if err := s.write(fpVersionRequest, []byte{0, 9, 0, 1, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(output.Bytes()); got != "2100000c0009000100000000" {
		t.Fatalf("version request = %s", got)
	}
	op, payload, err := readForcepointFrame(output)
	if err != nil || op != fpVersionRequest || !bytes.Equal(payload, []byte{0, 9, 0, 1, 0, 0, 0, 0}) {
		t.Fatalf("frame = %x %x %v", op, payload, err)
	}
	for _, wire := range [][]byte{
		nil, {0x21, 0}, {0x21, 0, 0, 3}, {0x21, 0x10, 0, 1},
		{fpIPv4, 1, 0, 0}, {fpControl, 0, 0, 5},
	} {
		if _, _, err := readForcepointFrame(bytes.NewReader(wire)); err == nil {
			t.Fatalf("accepted malformed frame header %x", wire)
		}
	}
	if err := s.write(fpControl, make([]byte, fpMaxFrame)); err == nil {
		t.Fatal("oversized control frame accepted")
	}
	if err := s.write(fpIPv4, make([]byte, cstpMaxPayloadLen+1)); err == nil {
		t.Fatal("oversized IPv4 frame accepted")
	}
	s.conn.(*fakeNetConn).err = errors.New("write failure")
	if err := s.write(fpHeartbeat, nil); err == nil {
		t.Fatal("write failure ignored")
	}
}

type fpShortConn struct{ *fakeNetConn }

func (c fpShortConn) Write(value []byte) (int, error) {
	if len(value) > 2 {
		value = value[:2]
	}
	return c.out.Write(value)
}

func TestForcepointWriteCompletesShortWrites(t *testing.T) {
	s, output := fpTestSession()
	s.conn = fpShortConn{s.conn.(*fakeNetConn)}
	if err := s.write(fpHeartbeatReply, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), []byte{0x25, 0, 0, 8, 1, 2, 3, 4}) {
		t.Fatal("short write truncated a frame")
	}
}

func TestForcepointConfigurationAndPolicyValidation(t *testing.T) {
	network, err := parseForcepointNetwork(fpTestNetwork(fpTestAttributes, fpTestPolicy))
	if err != nil || network.address.String() != "10.0.0.2" || network.dns[0].String() != "10.0.0.1" || network.routes[0].String() != "10.0.0.0/24" {
		t.Fatalf("network = %v, %v", network, err)
	}
	attributes := append(append([][]byte{}, fpTestAttributes...), []byte{0x99, 3, 1, 2, 3})
	if _, err := parseForcepointNetwork(fpTestNetwork(attributes, fpTestPolicy)); err != nil {
		t.Fatal("bounded unknown attribute should be skipped", err)
	}
	for _, attributes := range [][][]byte{
		nil,
		{{1, 4, 127, 0, 0, 1}},
		{{1, 3, 1, 2, 3}},
		{{3, 4, 0, 0, 0, 0}},
		{{6, 7, 10, 0, 0, 0, 255, 255, 255}},
		{{6, 8, 10, 0, 0, 0, 255, 0, 255, 0}},
		{fpTestAttributes[0], fpTestAttributes[0]},
		{fpTestAttributes[0]},
		{fpTestAttributes[3]},
	} {
		if _, err := parseForcepointNetwork(fpTestNetwork(attributes, fpTestPolicy)); err == nil {
			t.Fatal("malformed or incomplete IP configuration accepted")
		}
	}
	for _, data := range [][]byte{nil, {1}, {1, 1}, {0, 1}, {0, 1, 1, 5}, {0, 0, 0, 0, 0, 9}} {
		if _, err := parseForcepointNetwork(data); err == nil {
			t.Fatal("truncated IP configuration accepted")
		}
	}
	for _, policy := range []string{
		"", "<broken>", "<a/><b/>", strings.Repeat("<a>", 65),
		`<a><security-checks><antivirus enabled="1"/></security-checks></a>`,
		`<a><security-checks><firewall/></security-checks></a>`,
		`<a><security-checks><security-checks/><antivirus enabled="1"/></security-checks></a>`,
		`<a><eca-connection/></a>`,
		`<a><!--sg-extension-2><security-checks><antivirus enabled="1"/></security-checks></sg-extension-2--></a>`,
		`<a><!--unknown extension: security-checks--></a>`,
	} {
		if err := validateForcepointPolicy([]byte(policy)); err == nil {
			t.Fatal("unsafe or unsupported policy accepted")
		}
	}
	if err := validateForcepointPolicy([]byte(`<a><!--sg-extension><security-checks><firewall enabled="0"/></security-checks></sg-extension--></a>`)); err != nil {
		t.Fatal(err)
	}
	if err := validateForcepointPolicy([]byte(`<a><!--ordinary comment--></a>`)); err != nil {
		t.Fatal(err)
	}
}

func TestForcepointAuthenticationReauthenticationAndReconfiguration(t *testing.T) {
	s, output := fpTestSession()
	if err := s.authenticate(); err != nil {
		t.Fatal(err)
	}
	op, request, err := readForcepointFrame(output)
	if err != nil || op != fpControl || request[0] != fpAuthRequest || !bytes.Equal(request[8:], fpTestString("test-user")) {
		t.Fatal("username request does not match wire format")
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpChallenge, fpTestString("Password"))); err != nil {
		t.Fatal(err)
	}
	_, response, _ := readForcepointFrame(output)
	if response[0] != fpChallengeReply || !bytes.Equal(response[8:], fpTestString("test-password")) {
		t.Fatal("password challenge response does not match wire format")
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpAuthVerdict, fpTestVerdict(true))); err != nil {
		t.Fatal(err)
	}
	_, request, _ = readForcepointFrame(output)
	if request[0] != fpIPRequest || len(request) != 14 || request[8]&3 != 2 {
		t.Fatal("IP request must use a private per-session MAC identity")
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpIPResponse, fpTestNetwork(fpTestAttributes, fpTestPolicy))); err != nil {
		t.Fatal(err)
	}
	if s.paused.Load() || !s.configured || s.expires.Load() <= time.Now().UnixNano() {
		t.Fatal("session did not enter the authenticated configured state")
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpReauthenticate, nil)); err != nil || !s.paused.Load() {
		t.Fatal("reauthentication must suspend data", err)
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpChallenge, fpTestString("Password"))); err != nil {
		t.Fatal(err)
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpAuthVerdict, fpTestVerdict(true))); err != nil || s.paused.Load() {
		t.Fatal("reauthentication did not resume the session", err)
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpReconfigure, nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpIPResponse, fpTestNetwork(fpTestAttributes, fpTestPolicy))); err != nil {
		t.Fatal("unchanged configuration should resume", err)
	}
	if err := s.handleFrame(fpControl, fpTestControl(fpReconfigure, nil)); err != nil {
		t.Fatal(err)
	}
	changed := append([][]byte{}, fpTestAttributes...)
	changed[0] = []byte{1, 4, 10, 0, 0, 3}
	if err := s.handleFrame(fpControl, fpTestControl(fpIPResponse, fpTestNetwork(changed, fpTestPolicy))); err == nil {
		t.Fatal("address change must tear down stale routes and sockets")
	}
}

func TestForcepointRejectsInvalidControlStates(t *testing.T) {
	for _, input := range []struct {
		op      byte
		payload []byte
	}{
		{fpClose, nil}, {0x90, nil}, {fpHeartbeat, nil}, {fpHeartbeatReply, nil},
		{fpControl, nil}, {fpControl, []byte{1, 1, 0, 0, 0, 0, 0, 0}},
		{fpControl, fpTestControl(fpIPResponse, nil)},
		{fpControl, fpTestControl(fpReauthenticate, nil)},
		{fpControl, fpTestControl(fpReconfigure, nil)},
		{fpControl, fpTestControl(0xff, nil)},
		{fpControl, fpTestControl(fpAuthVerdict, nil)},
		{fpControl, fpTestControl(fpChallenge, nil)},
	} {
		s, _ := fpTestSession()
		if err := s.handleFrame(input.op, input.payload); err == nil {
			t.Fatalf("invalid control state accepted, opcode %x", input.op)
		}
	}
	s, _ := fpTestSession()
	s.pause()
	if err := s.handleFrame(fpControl, fpTestControl(fpAuthVerdict, fpTestVerdict(false))); err == nil || strings.Contains(err.Error(), "test-password") {
		t.Fatal("rejected authentication must return a fixed classification")
	}
	s.challenged = true
	if err := s.handleFrame(fpControl, fpTestControl(fpChallenge, fpTestString("OTP"))); err == nil {
		t.Fatal("a second challenge must not reuse the account password as MFA")
	}
	for _, op := range []byte{fpHeartbeat, fpHeartbeatReply} {
		if err := s.handleFrame(op, []byte{1, 2, 3, 4}); err != nil {
			t.Fatal(err)
		}
	}
	if s.lastReply.Load() == 0 {
		t.Fatal("heartbeat response not recorded")
	}
}

func TestForcepointConfigValidation(t *testing.T) {
	for _, change := range []func(*config){
		func(c *config) { c.Host = "" }, func(c *config) { c.Host = "https://example.test" },
		func(c *config) { c.Host = strings.Repeat("a", 254) }, func(c *config) { c.Port = 0 },
		func(c *config) { c.Port = 65536 }, func(c *config) { c.Username = "" },
		func(c *config) { c.Password = "" }, func(c *config) { c.Password = strings.Repeat("x", 256) },
		func(c *config) { c.Username = "x\x00y" }, func(c *config) { c.Username = string([]byte{0xff}) },
		func(c *config) { c.TrustServerCertificate = true }, func(c *config) { c.MTU = 575 },
		func(c *config) { c.MTU = 16385 },
	} {
		cfg := fpTestConfig()
		change(&cfg)
		if _, err := forcepointLogin(context.Background(), cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if err := validateForcepointConfig(fpTestConfig()); err != nil {
		t.Fatal(err)
	}
	cfg := fpTestConfig()
	cfg.Host, cfg.MTU = "[2001:db8::1]", 1390
	if err := validateForcepointConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := startForcepoint(context.Background(), nil, fpTestConfig()); err == nil {
		t.Fatal("nil cancellation handler accepted")
	}
	if _, _, _, err := startSSLVPN(context.Background(), func() {}, config{VPNProtocol: "unknown"}); err == nil {
		t.Fatal("unknown protocol accepted")
	}
	if _, _, _, err := startSSLVPN(context.Background(), func() {}, config{}); err == nil {
		t.Fatal("default AnyConnect validation was bypassed")
	}
}

func TestForcepointDHCPIdentityIsStableWithinOneSessionAndIsolatedBetweenSessions(t *testing.T) {
	first, output := fpTestSession()
	if err := first.requestIP(); err != nil {
		t.Fatal(err)
	}
	_, initial, _ := readForcepointFrame(output)
	if err := first.requestIP(); err != nil {
		t.Fatal(err)
	}
	_, repeated, _ := readForcepointFrame(output)
	if !bytes.Equal(initial[8:], repeated[8:]) {
		t.Fatal("reconfiguration changed the session's DHCP identity")
	}
	second, secondOutput := fpTestSession()
	if err := second.requestIP(); err != nil {
		t.Fatal(err)
	}
	_, independent, _ := readForcepointFrame(secondOutput)
	if bytes.Equal(initial[8:], independent[8:]) || independent[8]&3 != 2 {
		t.Fatal("independent tunnels shared a DHCP identity")
	}
}

func fpTestServer(t *testing.T, handler func(net.Conn) error) (config, <-chan error) {
	t.Helper()
	reference := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := reference.TLS.Certificates[0]
	reference.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		result <- handler(conn)
	}()
	cfg := fpTestConfig()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	cfg.Host, cfg.Port = host, func() int { n, _ := strconv.Atoi(port); return n }()
	digest := sha256.Sum256(certificate.Certificate[0])
	pin := hex.EncodeToString(digest[:])
	cfg.ServerCertSha256Pin = &pin
	return cfg, result
}

func fpServeLogin(conn net.Conn) error {
	op, request, err := readForcepointFrame(conn)
	if err != nil || op != fpVersionRequest || len(request) != 8 || binary.BigEndian.Uint16(request) != 9 {
		return errors.New("unexpected version request")
	}
	version := append([]byte{}, request...)
	version[4] = 0x80 // server capability is not an instruction to enable endpoint control
	if _, err := conn.Write(fpTestWire(fpVersionResponse, version)); err != nil {
		return err
	}
	op, request, err = readForcepointFrame(conn)
	if err != nil || op != fpControl || len(request) < 8 || request[0] != fpAuthRequest || !bytes.Equal(request[8:], fpTestString("test-user")) {
		return errors.New("unexpected username request")
	}
	challenge := fpTestControl(fpChallenge, fpTestString("Password"))
	if _, err := conn.Write(fpTestWire(fpControl, challenge)); err != nil {
		return err
	}
	op, request, err = readForcepointFrame(conn)
	if err != nil || op != fpControl || len(request) < 8 || request[0] != fpChallengeReply ||
		!bytes.Equal(request[4:8], challenge[4:8]) || !bytes.Equal(request[8:], fpTestString("test-password")) {
		return errors.New("unexpected password response")
	}
	if _, err := conn.Write(fpTestWire(fpControl, fpTestControl(fpAuthVerdict, fpTestVerdict(true)))); err != nil {
		return err
	}
	op, request, err = readForcepointFrame(conn)
	if err != nil || op != fpControl || len(request) != 14 || request[0] != fpIPRequest {
		return errors.New("unexpected IP request")
	}
	_, err = conn.Write(fpTestWire(fpControl, fpTestControl(fpIPResponse, fpTestNetwork(fpTestAttributes, fpTestPolicy))))
	return err
}

func TestForcepointLoginTLSAndIsolatedLifecycle(t *testing.T) {
	serverProceed := make(chan struct{})
	cfg, result := fpTestServer(t, func(conn net.Conn) error {
		if err := fpServeLogin(conn); err != nil {
			return err
		}
		<-serverProceed
		_, err := conn.Write(fpTestWire(fpClose, nil))
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer, arm, cleanup, err := startSSLVPN(ctx, cancel, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := dialer.DialContext(ctx, "tcp", "192.0.2.123:1234"); err == nil {
		t.Fatal("a destination outside the protected routes must fail closed")
	}
	close(serverProceed)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("parent cancellation preceded READY publication")
	}
	arm()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("gateway closure did not stop the SOCKS lifecycle")
	}
	cleanup() // deterministic and idempotent
}

func TestForcepointLoginCertificateAndNegotiationFailures(t *testing.T) {
	for _, mode := range []string{"trust", "wrong-pin", "version", "version-tag", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			cfg, result := fpTestServer(t, func(conn net.Conn) error {
				op, request, err := readForcepointFrame(conn)
				if mode == "trust" || mode == "wrong-pin" {
					if err == nil {
						return errors.New("untrusted TLS peer received VPN application data")
					}
					return nil
				}
				if err != nil {
					return err
				}
				if op != fpVersionRequest || len(request) != 8 {
					return errors.New("expected an SSVTP version request")
				}
				if mode == "truncated" {
					return nil
				}
				if mode == "version" {
					request[1] = 8
				} else {
					request[2] ^= 1
				}
				if _, err := conn.Write(fpTestWire(fpVersionResponse, request)); err != nil {
					return err
				}
				if _, _, err := readForcepointFrame(conn); err == nil {
					return errors.New("client sent authentication after invalid version negotiation")
				}
				return nil
			})
			want := "Forcepoint SSVTP version 9 negotiation failed"
			if mode == "trust" {
				cfg.ServerCertSha256Pin = nil
				want = "Forcepoint TLS connection failed"
			}
			if mode == "wrong-pin" {
				pin := strings.Repeat("00", 32)
				cfg.ServerCertSha256Pin = &pin
				want = "Forcepoint TLS connection failed"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := forcepointLogin(ctx, cfg); err == nil || !strings.Contains(err.Error(), want) || ctx.Err() != nil {
				t.Fatalf("expected %q before timeout, got %v", want, err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
	cfg := fpTestConfig()
	malformed := "bad-pin"
	cfg.ServerCertSha256Pin = &malformed
	if _, err := forcepointLogin(context.Background(), cfg); err == nil {
		t.Fatal("malformed pin accepted")
	}
}

func TestForcepointCancellationClosesBlockedNegotiation(t *testing.T) {
	started := make(chan struct{})
	cfg, result := fpTestServer(t, func(conn net.Conn) error {
		op, _, err := readForcepointFrame(conn)
		close(started)
		if err != nil {
			return err
		}
		if op != fpVersionRequest {
			return errors.New("expected negotiation before cancellation")
		}
		_, err = io.Copy(io.Discard, conn)
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	if _, err := forcepointLogin(ctx, cfg); err == nil {
		t.Fatal("cancelled negotiation succeeded")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("login ended without the coordinated cancellation", ctx.Err())
	}
	if err := <-result; err != nil {
		t.Fatal("cancellation did not close the server connection", err)
	}
}
