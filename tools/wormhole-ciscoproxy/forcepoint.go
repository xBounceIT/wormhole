package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// SSVTP uses an opcode followed by a 24-bit network-order length INCLUDING the
// four header bytes. Control payloads have an eight-byte header of their own:
// subtype, three reserved bytes, and a network-order request identifier.
// Version 9 is the version implemented here and negotiated by the 6.11 client.
// This is a native transport: no Forcepoint executable, driver, OS route, or
// adapter participates. Never log frame contents, including configuration XML.
const (
	fpVersionRequest  = 0x21
	fpVersionResponse = 0x22
	fpControl         = 0x23
	fpHeartbeat       = 0x24
	fpHeartbeatReply  = 0x25
	fpIPv4            = 0x81
	fpClose           = 0x1f
	fpAuthRequest     = 0x01
	fpAuthVerdict     = 0x02
	fpReauthenticate  = 0x03
	fpChallenge       = 0x04
	fpChallengeReply  = 0x05
	fpIPRequest       = 0x11
	fpIPResponse      = 0x12
	fpReconfigure     = 0x13
	fpMaxFrame        = 1 << 20
	fpDefaultMTU      = 1390
	fpAuthTimeout     = 30 * time.Second
	fpWriteTimeout    = 10 * time.Second
)

var (
	errForcepointProtocol    = errors.New("invalid Forcepoint SSL VPN message")
	errForcepointAuthExpired = errors.New("Forcepoint authentication expired")
)

type forcepointNetwork struct {
	address netip.Addr
	dns     []netip.Addr
	routes  []netip.Prefix
}

type forcepointSession struct {
	conn        net.Conn
	cfg         config
	network     forcepointNetwork // immutable once configured; shared with the dialer
	mac         [6]byte           // stable throughout reauthentication/reconfiguration of this session
	configured  bool              // control state is owned by the reader, including during login
	configuring bool
	challenged  bool
	writeMu     sync.Mutex
	paused      atomic.Bool
	pauseSince  atomic.Int64
	expires     atomic.Int64
	lastReply   atomic.Int64
}

func validateForcepointConfig(cfg config) error {
	host := stripHostBrackets(cfg.Host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\?#@ \t\r\n\x00") {
		return errors.New("Forcepoint gateway must be a host name or IP address")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errors.New("Forcepoint SSL port must be between 1 and 65535")
	}
	for _, value := range []string{cfg.Username, cfg.Password} {
		if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return errors.New("Forcepoint username and password must contain 1-255 UTF-8 bytes without NUL")
		}
	}
	if cfg.TrustServerCertificate {
		return errors.New("Forcepoint requires certificate verification or a SHA-256 certificate pin")
	}
	if cfg.MTU != 0 && (cfg.MTU < 576 || cfg.MTU > cstpMaxPayloadLen) {
		return errors.New("Forcepoint MTU must be between 576 and 16384")
	}
	return nil
}

func forcepointLogin(ctx context.Context, cfg config) (*forcepointSession, error) {
	if err := validateForcepointConfig(cfg); err != nil {
		return nil, err
	}
	cfg.Host = stripHostBrackets(cfg.Host)
	tlsConfig, err := buildTLSConfig(cfg, tlsModeModern)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{"ssvtp/1"}
	loginCtx, cancel := context.WithTimeout(ctx, fpAuthTimeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: tlsConfig}
	conn, err := dialer.DialContext(loginCtx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, errors.New("Forcepoint TLS connection failed; check gateway and certificate trust")
	}
	stop := context.AfterFunc(loginCtx, func() { _ = conn.Close() })
	defer stop()
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	deadline, _ := loginCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	s := &forcepointSession{conn: conn, cfg: cfg}
	if err := s.negotiate(); err != nil {
		return nil, err
	}
	if err := s.authenticate(); err != nil {
		return nil, err
	}
	for messages := 0; messages < 64; messages++ {
		op, payload, err := readForcepointFrame(conn)
		if err != nil {
			return nil, errors.New("Forcepoint SSL login ended before the tunnel was configured")
		}
		err = s.handleFrame(op, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
		if s.configured {
			if !stop() || loginCtx.Err() != nil {
				return nil, errors.New("Forcepoint SSL login was cancelled")
			}
			_ = conn.SetDeadline(time.Time{})
			s.lastReply.Store(time.Now().UnixNano())
			success = true
			return s, nil
		}
	}
	return nil, errors.New("Forcepoint SSL login exceeded the message limit")
}

func (s *forcepointSession) negotiate() error {
	var token [2]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		return errors.New("could not initialize Forcepoint SSL negotiation")
	}
	request := []byte{0, 9, token[0], token[1], 0, 0, 0, 0}
	if err := s.write(fpVersionRequest, request); err != nil {
		return err
	}
	op, response, err := readForcepointFrame(s.conn)
	if err != nil || op != fpVersionResponse || len(response) != 8 ||
		binary.BigEndian.Uint16(response) != 9 || !bytes.Equal(response[2:4], token[:]) {
		return errors.New("Forcepoint SSVTP version 9 negotiation failed")
	}
	// Feature bits are capabilities. We advertised neither IPv6 nor endpoint
	// control; the gateway cannot enable either on this session unilaterally.
	return nil
}

func readForcepointFrame(reader io.Reader) (byte, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	size := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if size < 4 || size > fpMaxFrame || (header[0] == fpIPv4 && size > cstpMaxPayloadLen+4) {
		return 0, nil, errForcepointProtocol
	}
	payload := make([]byte, size-4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return 0, nil, err
	}
	return header[0], payload, nil
}

func (s *forcepointSession) write(op byte, payload []byte) error {
	size := len(payload) + 4
	if size > fpMaxFrame || (op == fpIPv4 && len(payload) > cstpMaxPayloadLen) {
		return errForcepointProtocol
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// Recheck after waiting for the writer: authentication can change while a
	// packet is queued behind a control frame or a slow network write.
	if op == fpIPv4 {
		if s.authenticationExpired(time.Now()) {
			return errForcepointAuthExpired
		}
		if s.paused.Load() {
			return nil
		}
	}
	frame := make([]byte, size)
	frame[0], frame[1], frame[2], frame[3] = op, byte(size>>16), byte(size>>8), byte(size)
	copy(frame[4:], payload)
	defer clear(frame)
	_ = s.conn.SetWriteDeadline(time.Now().Add(fpWriteTimeout))
	for len(frame) > 0 {
		n, err := s.conn.Write(frame)
		if err != nil || n == 0 {
			return errors.New("Forcepoint SSL write failed")
		}
		frame = frame[n:]
	}
	return nil
}

// Client-initiated requests generate an ID; replies retain the gateway's opaque ID.
func (s *forcepointSession) control(op byte, body []byte, requestID *[4]byte) error {
	payload := make([]byte, 8+len(body))
	defer clear(payload)
	payload[0] = op
	if requestID == nil {
		if _, err := io.ReadFull(rand.Reader, payload[4:8]); err != nil {
			return errors.New("could not initialize Forcepoint SSL request")
		}
	} else {
		copy(payload[4:8], requestID[:])
	}
	copy(payload[8:], body)
	return s.write(fpControl, payload)
}

func (s *forcepointSession) credential(op byte, value string, requestID *[4]byte) error {
	body := make([]byte, 2+len(value))
	defer clear(body)
	binary.BigEndian.PutUint16(body, uint16(len(value)))
	copy(body[2:], value)
	return s.control(op, body, requestID)
}

func (s *forcepointSession) pause() {
	s.pauseSince.Store(time.Now().UnixNano())
	s.paused.Store(true)
}

func (s *forcepointSession) authenticationExpired(now time.Time) bool {
	expiry := s.expires.Load()
	return expiry > 0 && now.UnixNano() >= expiry
}

func (s *forcepointSession) authenticate() error {
	s.pause()
	s.challenged = false
	return s.credential(fpAuthRequest, s.cfg.Username, nil)
}

func (s *forcepointSession) requestIP() error {
	s.pause()
	s.configuring = true
	if s.mac == ([6]byte{}) {
		if _, err := io.ReadFull(rand.Reader, s.mac[:]); err != nil {
			return errors.New("could not initialize Forcepoint virtual address request")
		}
		s.mac[0] = s.mac[0]&0xfe | 0x02 // private DHCP identity, never a host adapter
	}
	return s.control(fpIPRequest, s.mac[:], nil)
}

func (s *forcepointSession) handleFrame(op byte, payload []byte) error {
	switch op {
	case fpHeartbeat:
		if len(payload) != 4 {
			return errForcepointProtocol
		}
		return s.write(fpHeartbeatReply, payload)
	case fpHeartbeatReply:
		if len(payload) != 4 {
			return errForcepointProtocol
		}
		s.lastReply.Store(time.Now().UnixNano())
		return nil
	case fpControl:
		if len(payload) < 8 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
			return errForcepointProtocol
		}
		body := payload[8:]
		switch payload[0] {
		case fpChallenge:
			if !s.paused.Load() || s.configuring || s.challenged || !validForcepointString(body) {
				return errors.New("Forcepoint requires an unsupported authentication challenge")
			}
			s.challenged = true
			requestID := [4]byte(payload[4:8])
			return s.credential(fpChallengeReply, s.cfg.Password, &requestID)
		case fpAuthVerdict:
			if !s.paused.Load() || s.configuring || len(body) < 8 || !validForcepointString(body[6:]) {
				return errForcepointProtocol
			}
			if body[0]&0x80 == 0 {
				return errors.New("Forcepoint authentication failed")
			}
			if ttl := binary.BigEndian.Uint32(body[2:6]); ttl > 0 {
				s.expires.Store(time.Now().Add(time.Duration(ttl) * time.Second).UnixNano())
			} else {
				s.expires.Store(0)
			}
			if !s.configured {
				return s.requestIP()
			}
			s.paused.Store(false)
			return nil
		case fpIPResponse:
			if !s.configuring {
				return errForcepointProtocol
			}
			network, err := parseForcepointNetwork(body)
			if err != nil {
				return err
			}
			if s.configured && !sameForcepointNetwork(s.network, network) {
				return errors.New("Forcepoint network configuration changed; reconnect the tunnel")
			}
			if !s.configured {
				s.network = network
			}
			s.configured, s.configuring = true, false
			s.paused.Store(false)
			return nil
		case fpReauthenticate:
			if !s.configured || s.paused.Load() || len(body) != 0 {
				return errForcepointProtocol
			}
			return s.authenticate()
		case fpReconfigure:
			if !s.configured || s.paused.Load() || len(body) != 0 {
				return errForcepointProtocol
			}
			return s.requestIP()
		}
	case fpClose:
		return errors.New("Forcepoint gateway closed the SSL VPN session")
	}
	return errForcepointProtocol
}

func validForcepointString(body []byte) bool {
	return len(body) >= 2 && int(binary.BigEndian.Uint16(body)) == len(body)-2 && utf8.Valid(body[2:])
}

func parseForcepointNetwork(body []byte) (forcepointNetwork, error) {
	var network forcepointNetwork
	if len(body) < 2 {
		return network, errForcepointProtocol
	}
	count := int(binary.BigEndian.Uint16(body))
	body = body[2:]
	if count > 256 {
		return network, errForcepointProtocol
	}
	for i := 0; i < count; i++ {
		if len(body) < 2 || int(body[1]) > len(body)-2 {
			return network, errForcepointProtocol
		}
		kind, value := body[0], body[2:2+int(body[1])]
		body = body[2+int(body[1]):]
		switch kind {
		case 1, 2, 3, 4, 5: // IPv4 address, netmask, DNS, NBNS, DHCP server
			if len(value) != 4 {
				return network, errForcepointProtocol
			}
			address := netip.AddrFrom4([4]byte(value))
			if kind == 1 {
				if network.address.IsValid() || !validForcepointAddress(address) {
					return network, errForcepointProtocol
				}
				network.address = address
			} else if kind == 3 {
				if !validForcepointAddress(address) || len(network.dns) >= 16 {
					return network, errForcepointProtocol
				}
				network.dns = append(network.dns, address)
			}
		case 6: // protected IPv4 subnet and netmask
			if len(value) != 8 {
				return network, errForcepointProtocol
			}
			prefix, bits := net.IPMask(value[4:]).Size()
			if bits != 32 {
				return network, errForcepointProtocol
			}
			network.routes = append(network.routes, netip.PrefixFrom(netip.AddrFrom4([4]byte(value[:4])), prefix).Masked())
		}
	}
	if len(body) < 4 || int(binary.BigEndian.Uint32(body)) != len(body)-4 {
		return network, errForcepointProtocol
	}
	if err := validateForcepointPolicy(body[4:]); err != nil {
		return network, err
	}
	if !network.address.IsValid() || len(network.routes) == 0 {
		return network, errors.New("Forcepoint did not provide an IPv4 address and protected IPv4 routes")
	}
	return network, nil
}

func validForcepointAddress(address netip.Addr) bool {
	return address.Is4() && address.IsGlobalUnicast()
}

func sameForcepointNetwork(a, b forcepointNetwork) bool {
	if a.address != b.address || len(a.dns) != len(b.dns) || len(a.routes) != len(b.routes) {
		return false
	}
	for i := range a.dns {
		if a.dns[i] != b.dns[i] {
			return false
		}
	}
	for i := range a.routes {
		if a.routes[i] != b.routes[i] {
			return false
		}
	}
	return true
}

func validateForcepointPolicy(body []byte) error {
	if len(body) == 0 {
		return errors.New("Forcepoint SSL policy is missing")
	}
	policy := string(body)
	// Legacy policy files carry newer SSL options inside versioned comments.
	// Interpret the same extension versions as the client rather than overlooking
	// a required security check just because its XML is inside a comment.
	for _, version := range []string{"", "-2", "-3", "-4"} {
		policy = strings.ReplaceAll(policy, "<!--sg-extension"+version+">", "")
		policy = strings.ReplaceAll(policy, "</sg-extension"+version+"-->", "")
	}
	decoder := xml.NewDecoder(strings.NewReader(policy))
	depth, roots, checks := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if roots == 1 && depth == 0 {
				return nil
			}
			return errForcepointProtocol
		}
		if err != nil {
			return errForcepointProtocol
		}
		switch node := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 64 || roots > 1 {
				return errForcepointProtocol
			}
			if node.Name.Local == "security-checks" {
				if checks != 0 {
					return errForcepointProtocol
				}
				checks = depth
			} else if checks > 0 {
				enabled := ""
				seenEnabled := false
				for _, attribute := range node.Attr {
					if attribute.Name.Local == "enabled" {
						if seenEnabled || attribute.Name.Space != "" {
							return errForcepointProtocol
						}
						seenEnabled = true
						enabled = attribute.Value
					}
				}
				if enabled != "0" {
					return errors.New("Forcepoint requires local security checks unsupported by the autonomous tunnel")
				}
			}
			if node.Name.Local == "eca-connection" {
				return errors.New("Forcepoint endpoint control is unsupported by the autonomous tunnel")
			}
		case xml.EndElement:
			if checks == depth {
				checks = 0
			}
			depth--
		case xml.Comment:
			if bytes.Contains(node, []byte("security-checks")) || bytes.Contains(node, []byte("eca-connection")) {
				return errors.New("Forcepoint policy contains an unsupported security extension")
			}
		}
	}
}
