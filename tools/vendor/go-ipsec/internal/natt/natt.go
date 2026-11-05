// Package natt implements the NAT-Traversal pieces a userspace IKEv2 client
// needs (RFC 3948 + RFC 7296 §2.23): NAT-detection hashes, the non-ESP marker
// demux on UDP port 4500, and the NAT keepalive. Because a userspace client
// cannot send raw ESP (IP protocol 50), all ESP is UDP-encapsulated on 4500.
package natt

import (
	"crypto/sha1"
	"encoding/binary"
	"net/netip"
)

// Port4500 is the IKE/ESP NAT-T port; Port500 is the bare IKE port.
const (
	Port500  = 500
	Port4500 = 4500
)

// nonESPMarker is the 4-byte zero prefix that distinguishes an IKE message from
// an ESP packet on port 4500 (RFC 3948 §2.2). ESP packets start with a non-zero
// SPI, so a zero first word unambiguously marks IKE.
var nonESPMarker = []byte{0, 0, 0, 0}

// KeepaliveByte is the NAT keepalive payload (RFC 3948 §2.3): a single 0xFF.
const KeepaliveByte = 0xFF

// DetectionHash computes a NAT-detection payload value (RFC 7296 §2.23):
//
//	SHA1( SPIi | SPIr | IP | Port )
//
// SPIs are 8 bytes big-endian; IP is the 4-byte address for an IPv4 endpoint or
// the 16-byte address for an IPv6 one (so the hash is correct on either transport
// family); Port is 2 bytes.
func DetectionHash(spiI, spiR uint64, ip netip.Addr, port uint16) []byte {
	h := sha1.New()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], spiI)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], spiR)
	h.Write(b[:])
	if ip.Is4() {
		a4 := ip.As4()
		h.Write(a4[:])
	} else {
		a16 := ip.As16()
		h.Write(a16[:])
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum(nil)
}

// WrapIKE prepends the non-ESP marker to an IKE message for port-4500 framing.
func WrapIKE(ike []byte) []byte {
	out := make([]byte, 0, len(nonESPMarker)+len(ike))
	out = append(out, nonESPMarker...)
	out = append(out, ike...)
	return out
}

// Kind classifies a datagram received on port 4500.
type Kind int

const (
	KindUnknown   Kind = iota
	KindIKE            // had the non-ESP marker (already stripped by Classify)
	KindESP            // ESP packet (SPI != 0)
	KindKeepalive      // single 0xFF keepalive
)

// Classify inspects a port-4500 datagram and returns its kind together with the
// payload to process (marker stripped for IKE; the raw packet for ESP).
func Classify(datagram []byte) (Kind, []byte) {
	if len(datagram) == 1 && datagram[0] == KeepaliveByte {
		return KindKeepalive, nil
	}
	if len(datagram) >= 4 {
		if binary.BigEndian.Uint32(datagram[:4]) == 0 {
			return KindIKE, datagram[4:]
		}
		return KindESP, datagram
	}
	return KindUnknown, nil
}
