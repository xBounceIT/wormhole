package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestSummarizeIPPacketIPv4TCPSYN(t *testing.T) {
	pkt := ipv4TCPPacket([4]byte{192, 0, 2, 6}, [4]byte{198, 51, 100, 50}, 49152, 22, tcpFlagSyn)

	got := summarizeIPPacket(pkt)

	assertSummaryContains(t, got, "IPv4 TCP")
	assertSummaryContains(t, got, "192.0.2.6:49152 -> 198.51.100.50:22")
	assertSummaryContains(t, got, "flags=SYN")
}

func TestSummarizeIPPacketIPv4TCPSYNACK(t *testing.T) {
	pkt := ipv4TCPPacket([4]byte{198, 51, 100, 50}, [4]byte{192, 0, 2, 6}, 22, 49152, tcpFlagSyn|tcpFlagAck)

	got := summarizeIPPacket(pkt)

	assertSummaryContains(t, got, "IPv4 TCP")
	assertSummaryContains(t, got, "198.51.100.50:22 -> 192.0.2.6:49152")
	assertSummaryContains(t, got, "flags=SYN,ACK")
}

func TestSummarizeIPPacketIPv4TCPRST(t *testing.T) {
	pkt := ipv4TCPPacket([4]byte{198, 51, 100, 50}, [4]byte{192, 0, 2, 6}, 22, 49152, tcpFlagRst|tcpFlagAck)

	got := summarizeIPPacket(pkt)

	assertSummaryContains(t, got, "IPv4 TCP")
	assertSummaryContains(t, got, "flags=ACK,RST")
}

func TestSummarizeIPPacketIPv4ICMPUnreachable(t *testing.T) {
	pkt := ipv4ICMPPacket([4]byte{198, 51, 100, 1}, [4]byte{192, 0, 2, 6}, 3, 1)

	got := summarizeIPPacket(pkt)

	assertSummaryContains(t, got, "IPv4 ICMP")
	assertSummaryContains(t, got, "198.51.100.1 -> 192.0.2.6")
	assertSummaryContains(t, got, "type=3")
	assertSummaryContains(t, got, "code=1")
}

func TestDialPacketDiagCountsInboundNonIPSeparately(t *testing.T) {
	hub := newPacketDiagHub()
	hub.beginDial(1, "198.51.100.50:22")

	hub.observe(packetDirectionOutbound, ipv4TCPPacket(
		[4]byte{192, 0, 2, 6},
		[4]byte{198, 51, 100, 50},
		49152,
		22,
		tcpFlagSyn))
	hub.observe(packetDirectionInbound, []byte{
		0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07,
		0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48, 0x00,
	})

	summary := hub.endDial(1)

	assertSummaryContains(t, summary, "outbound_packets=1")
	assertSummaryContains(t, summary, "inbound_packets=0")
	assertSummaryContains(t, summary, "inbound_non_ip=1")
	assertSummaryContains(t, summary, `last_inbound_non_ip="unknown_ip_version=2 len=17"`)
}

func assertSummaryContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("summary %q does not contain %q", got, want)
	}
}

func ipv4TCPPacket(src, dst [4]byte, srcPort, dstPort uint16, flags uint8) []byte {
	const headerLen = 20
	const tcpLen = 20
	pkt := make([]byte, headerLen+tcpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 5 << 4
	pkt[33] = flags
	return pkt
}

func ipv4ICMPPacket(src, dst [4]byte, icmpType, icmpCode uint8) []byte {
	const headerLen = 20
	const icmpLen = 8
	pkt := make([]byte, headerLen+icmpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[20] = icmpType
	pkt[21] = icmpCode
	return pkt
}
