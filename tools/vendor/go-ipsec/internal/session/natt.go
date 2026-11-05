package session

import (
	"context"
	"crypto/hmac"
	"net"
	"net/netip"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/natt"
	"github.com/n0madic/go-ipsec/internal/transport"
)

// sendDatagram sends an IKE message, prepending the non-ESP marker when running
// in NAT-T mode (port 4500).
func (s *Session) sendDatagram(ctx context.Context, ike []byte) error {
	if s.nattMode {
		ike = natt.WrapIKE(ike)
	}
	return s.conn.Send(ctx, ike)
}

// recvDatagram receives the next IKE message, stripping the non-ESP marker and
// skipping keepalives/stray ESP when in NAT-T mode.
func (s *Session) recvDatagram(ctx context.Context) ([]byte, error) {
	for {
		raw, err := s.conn.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if !s.nattMode {
			return raw, nil
		}
		kind, payload := natt.Classify(raw)
		switch kind {
		case natt.KindIKE:
			return payload, nil
		case natt.KindKeepalive:
			continue // NAT keepalive from the server; ignore
		default:
			// Stray ESP before the data plane is wired, or junk: skip.
			continue
		}
	}
}

// appendNATDetection adds NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP
// notifies (RFC 7296 §2.23). The request header carries SPIr = 0.
func (s *Session) appendNATDetection(c *ikemsg.Payloads) {
	localIP, localPort := addrPort(s.conn.LocalAddr())
	remoteIP, remotePort := addrPort(s.conn.RemoteAddr())
	src := natt.DetectionHash(s.initiatorSPI, s.responderSPI, localIP, localPort)
	dst := natt.DetectionHash(s.initiatorSPI, s.responderSPI, remoteIP, remotePort)
	*c = append(*c,
		&ikemsg.NotifyPayload{Type: ikemsg.NotifyNATDetectionSourceIP, Data: src},
		&ikemsg.NotifyPayload{Type: ikemsg.NotifyNATDetectionDestinationIP, Data: dst},
	)
}

// processNATDetection compares the responder's NAT-detection hashes against the
// locally observed addresses to decide whether a NAT lies on either side.
func (s *Session) processNATDetection(notifies []*ikemsg.NotifyPayload) {
	if len(notifies) == 0 {
		return
	}
	localIP, localPort := addrPort(s.conn.LocalAddr())
	remoteIP, remotePort := addrPort(s.conn.RemoteAddr())
	// Peer's source = the server's own address as we see it.
	expectPeerSrc := natt.DetectionHash(s.initiatorSPI, s.responderSPI, remoteIP, remotePort)
	// Our destination = our address as the server sees it.
	expectOurDst := natt.DetectionHash(s.initiatorSPI, s.responderSPI, localIP, localPort)

	for _, n := range notifies {
		switch n.Type {
		case ikemsg.NotifyNATDetectionSourceIP:
			if !hmac.Equal(n.Data, expectPeerSrc) {
				s.natDetected = true // server behind NAT
			}
		case ikemsg.NotifyNATDetectionDestinationIP:
			if !hmac.Equal(n.Data, expectOurDst) {
				s.natDetected = true // we are behind NAT
			}
		}
	}
}

// migrateNATT moves IKE (and later ESP) onto port 4500. A userspace client
// cannot send raw ESP, so it always uses UDP-encapsulation — migration happens
// whether or not a NAT was detected, but the detection result is logged.
func (s *Session) migrateNATT() {
	if m, ok := s.conn.(transport.PortMigrator); ok {
		m.MigrateToPort(natt.Port4500)
		s.nattMode = true
		s.log.Debug("migrated to NAT-T port 4500", "natDetected", s.natDetected)
	} else {
		// Memory transport (tests) has no ports; stay in plain framing.
		s.log.Debug("transport does not support NAT-T migration", "natDetected", s.natDetected)
	}
}

// addrPort extracts the address (IPv4 or IPv6) and port from a net.Addr,
// defaulting to 0.0.0.0 for a non-UDP or unparseable endpoint (which naturally
// trips NAT detection and forces UDP-encapsulation). Returning the real address
// for both families keeps the NAT-detection hash correct on an IPv6 transport.
func addrPort(a net.Addr) (netip.Addr, uint16) {
	zero := netip.AddrFrom4([4]byte{})
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return zero, 0
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return zero, uint16(ua.Port)
	}
	return ip.Unmap(), uint16(ua.Port)
}
