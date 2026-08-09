package main

import (
	"encoding/binary"
	"net/netip"
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

func ipv4UDPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

func ipv6Packet(src, dst [16]byte, next uint8, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = next
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	copy(pkt[40:], payload)
	return pkt
}

func TestPacketSummaryMalformedAndUnknownPackets(t *testing.T) {
	tests := []struct {
		packet []byte
		want   string
	}{
		{packet: nil, want: "malformed len=0"},
		{packet: []byte{0x20}, want: "unknown_ip_version=2"},
		{packet: []byte{0x40}, want: "IPv4 malformed"},
		{packet: append([]byte{0x41}, make([]byte, 19)...), want: "ihl=4"},
		{packet: append([]byte{0x4f}, make([]byte, 19)...), want: "ihl=60"},
		{packet: []byte{0x60}, want: "IPv6 malformed"},
	}
	for _, test := range tests {
		assertSummaryContains(t, summarizeIPPacket(test.packet), test.want)
	}
}

func TestPacketSummaryIPv4Protocols(t *testing.T) {
	src := [4]byte{192, 0, 2, 1}
	dst := [4]byte{198, 51, 100, 2}
	assertSummaryContains(t, summarizeIPPacket(ipv4UDPPacket(src, dst, 5353, 53)), "UDP 192.0.2.1:5353 -> 198.51.100.2:53")

	malformedUDP := make([]byte, 24)
	malformedUDP[0] = 0x45
	malformedUDP[9] = 17
	copy(malformedUDP[12:16], src[:])
	copy(malformedUDP[16:20], dst[:])
	assertSummaryContains(t, summarizeIPPacket(malformedUDP), "UDP malformed")

	malformedTCP := append([]byte(nil), malformedUDP...)
	malformedTCP[9] = 6
	assertSummaryContains(t, summarizeIPPacket(malformedTCP), "TCP malformed")

	malformedICMP := append([]byte(nil), malformedUDP[:21]...)
	malformedICMP[9] = 1
	assertSummaryContains(t, summarizeIPPacket(malformedICMP), "ICMP malformed")

	unknown := append([]byte(nil), malformedUDP...)
	unknown[9] = 99
	assertSummaryContains(t, summarizeIPPacket(unknown), "proto=99")
}

func TestPacketSummaryIPv6Protocols(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 1234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[13] = tcpFlagSyn | tcpFlagAck
	assertSummaryContains(t, summarizeIPPacket(ipv6Packet(src, dst, 6, tcp)), "IPv6 TCP [2001:db8::1]:1234 -> [2001:db8::2]:443")

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	assertSummaryContains(t, summarizeIPPacket(ipv6Packet(src, dst, 17, udp)), "IPv6 UDP")
	assertSummaryContains(t, summarizeIPPacket(ipv6Packet(src, dst, 58, []byte{1, 4})), "ICMPv6")
	assertSummaryContains(t, summarizeIPPacket(ipv6Packet(src, dst, 99, nil)), "next=99")
}

func TestPacketSummaryNormalizesHeaderLengths(t *testing.T) {
	pkt := ipv4TCPPacket([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 10, 20, 0)
	binary.BigEndian.PutUint16(pkt[2:4], 10)
	assertSummaryContains(t, summarizeIPPacket(pkt), "flags=none")
	binary.BigEndian.PutUint16(pkt[2:4], 500)
	assertSummaryContains(t, summarizeIPPacket(pkt), "IPv4 TCP")

	v6 := ipv6Packet(netip.MustParseAddr("::1").As16(), netip.MustParseAddr("::2").As16(), 17, make([]byte, 8))
	binary.BigEndian.PutUint16(v6[4:6], 500)
	assertSummaryContains(t, summarizeIPPacket(v6), "IPv6 UDP")
}

func TestTCPFlagStringIncludesEveryFlag(t *testing.T) {
	if got := tcpFlagString(0); got != "none" {
		t.Fatalf("tcpFlagString(0) = %q", got)
	}
	if got := tcpFlagString(0xff); got != "SYN,ACK,RST,FIN,PSH,URG,ECE,CWR" {
		t.Fatalf("tcpFlagString(0xff) = %q", got)
	}
}

func TestPacketDiagHubLifecycleAndMatching(t *testing.T) {
	var nilHub *packetDiagHub
	if nilHub.beginDial(1, "host:22") != nil || nilHub.endDial(1) != "" {
		t.Fatal("nil hub did not remain inert")
	}
	nilHub.observeSummary(packetDirectionInbound, packetSummary{})

	hub := newPacketDiagHub()
	if hub.beginDial(0, "host:22") != nil || hub.endDial(0) != "" || hub.endDial(99) != "" {
		t.Fatal("invalid dial IDs were accepted")
	}
	hub.observeSummary(packetDirectionInbound, packetSummary{valid: true})
	dial := hub.beginDial(7, "not-a-host-port")
	hub.beginDial(7, "host:invalid-port")
	if hub.activeCount.Load() != 1 {
		t.Fatalf("active count = %d", hub.activeCount.Load())
	}
	if dial.hasTargetAddr || dial.targetPort != 0 {
		t.Fatalf("unexpected parsed target: %#v", dial)
	}
	hub.observeSummary(packetDirectionOutbound, packetSummary{valid: true, text: "outbound"})
	summary := hub.endDial(7)
	assertSummaryContains(t, summary, "outbound_packets=1")
}

func TestDialPacketDiagMatchesTCPAndICMP(t *testing.T) {
	dial := &dialPacketDiag{
		hasTargetAddr: true,
		targetAddr:    netip.MustParseAddr("198.51.100.2"),
		targetPort:    443,
	}
	outbound := packetSummary{valid: true, protocol: "TCP", hasPorts: true, srcAddr: netip.MustParseAddr("192.0.2.1"), dstAddr: dial.targetAddr, srcPort: 50000, dstPort: 443}
	if !dial.matchesLocked(packetDirectionOutbound, outbound) {
		t.Fatal("matching outbound packet was rejected")
	}
	dial.observeLocked(packetDirectionOutbound, outbound)
	inbound := packetSummary{valid: true, protocol: "TCP", hasPorts: true, srcAddr: dial.targetAddr, dstAddr: outbound.srcAddr, srcPort: 443, dstPort: 50000, tcpFlags: tcpFlagSyn | tcpFlagAck | tcpFlagRst}
	if !dial.matchesLocked(packetDirectionInbound, inbound) {
		t.Fatal("matching inbound packet was rejected")
	}
	dial.observeLocked(packetDirectionInbound, inbound)
	if dial.matchesLocked(packetDirectionInbound, packetSummary{valid: true, protocol: "TCP", hasPorts: true, srcAddr: netip.MustParseAddr("203.0.113.1"), srcPort: 443}) {
		t.Fatal("wrong inbound source matched")
	}
	if !dial.matchesLocked(packetDirectionInbound, packetSummary{valid: true, protocol: "ICMP"}) {
		t.Fatal("inbound ICMP did not match")
	}
	if dial.matchesLocked(packetDirectionOutbound, packetSummary{valid: false}) {
		t.Fatal("invalid outbound packet matched")
	}
}
