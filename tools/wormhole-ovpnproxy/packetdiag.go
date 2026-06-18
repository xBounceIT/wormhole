package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const packetDiagLogLimit = 12

const (
	packetDirectionInbound  = "inbound"
	packetDirectionOutbound = "outbound"
)

type packetDiagHub struct {
	mu          sync.Mutex
	activeCount atomic.Int64
	active      map[uint64]*dialPacketDiag
}

func newPacketDiagHub() *packetDiagHub {
	return &packetDiagHub{active: make(map[uint64]*dialPacketDiag)}
}

func (h *packetDiagHub) beginDial(id uint64, target string) *dialPacketDiag {
	if h == nil || id == 0 {
		return nil
	}
	d := &dialPacketDiag{id: id, target: target}
	if host, portText, err := net.SplitHostPort(target); err == nil {
		if port, err := strconv.ParseUint(portText, 10, 16); err == nil {
			d.targetPort = uint16(port)
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			d.targetAddr = addr.Unmap()
			d.hasTargetAddr = true
		}
	}

	h.mu.Lock()
	if _, exists := h.active[id]; !exists {
		h.activeCount.Add(1)
	}
	h.active[id] = d
	h.mu.Unlock()
	return d
}

func (h *packetDiagHub) endDial(id uint64) string {
	if h == nil || id == 0 {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.active[id]
	if d == nil {
		return ""
	}
	delete(h.active, id)
	h.activeCount.Add(-1)
	return d.summaryLocked()
}

func (h *packetDiagHub) observe(direction string, pkt []byte) {
	h.observeSummary(direction, parsePacketSummary(pkt))
}

func (h *packetDiagHub) observeSummary(direction string, info packetSummary) {
	if h == nil {
		return
	}
	if h.activeCount.Load() == 0 {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.active) == 0 {
		return
	}
	for _, d := range h.active {
		if d.matchesLocked(direction, info) {
			d.observeLocked(direction, info)
		}
	}
}

type dialPacketDiag struct {
	id     uint64
	target string

	hasTargetAddr bool
	targetAddr    netip.Addr
	targetPort    uint16
	hasLocalAddr  bool
	localAddr     netip.Addr
	localPort     uint16

	loggedPackets int

	outboundPackets int
	outboundSyn     int
	inboundPackets  int
	inboundNonIP    int
	inboundSynAck   int
	inboundRst      int
	inboundIcmp     int

	lastOutbound     string
	lastInbound      string
	lastInboundNonIP string
}

func (d *dialPacketDiag) matchesLocked(direction string, info packetSummary) bool {
	if !info.valid {
		return direction == packetDirectionInbound
	}
	if !d.hasTargetAddr {
		return true
	}
	if info.protocol == "TCP" && info.hasPorts {
		switch direction {
		case packetDirectionOutbound:
			return info.dstAddr == d.targetAddr && info.dstPort == d.targetPort
		case packetDirectionInbound:
			if info.srcAddr != d.targetAddr || info.srcPort != d.targetPort {
				return false
			}
			return !d.hasLocalAddr || (info.dstAddr == d.localAddr && info.dstPort == d.localPort)
		}
	}
	if direction == packetDirectionInbound && strings.HasPrefix(info.protocol, "ICMP") {
		return true
	}
	return false
}

func (d *dialPacketDiag) observeLocked(direction string, info packetSummary) {
	if direction == packetDirectionOutbound {
		d.outboundPackets++
		d.lastOutbound = info.text
		if info.protocol == "TCP" && info.hasPorts {
			d.hasLocalAddr = true
			d.localAddr = info.srcAddr
			d.localPort = info.srcPort
			if info.tcpFlags&tcpFlagSyn != 0 && info.tcpFlags&tcpFlagAck == 0 {
				d.outboundSyn++
			}
		}
	} else {
		if !info.valid {
			d.inboundNonIP++
			d.lastInboundNonIP = info.text
			if d.loggedPackets < packetDiagLogLimit {
				d.loggedPackets++
				logf("openvpn: packet dial_id=%d direction=%s %s", d.id, direction, info.text)
			}
			return
		}
		d.inboundPackets++
		d.lastInbound = info.text
		if info.protocol == "TCP" {
			if info.tcpFlags&tcpFlagSyn != 0 && info.tcpFlags&tcpFlagAck != 0 {
				d.inboundSynAck++
			}
			if info.tcpFlags&tcpFlagRst != 0 {
				d.inboundRst++
			}
		}
		if strings.HasPrefix(info.protocol, "ICMP") {
			d.inboundIcmp++
		}
	}

	if d.loggedPackets < packetDiagLogLimit {
		d.loggedPackets++
		logf("openvpn: packet dial_id=%d direction=%s %s", d.id, direction, info.text)
	}
}

func (d *dialPacketDiag) summaryLocked() string {
	parts := []string{
		fmt.Sprintf("target=%s", d.target),
		fmt.Sprintf("outbound_packets=%d", d.outboundPackets),
		fmt.Sprintf("outbound_syn=%d", d.outboundSyn),
		fmt.Sprintf("inbound_packets=%d", d.inboundPackets),
		fmt.Sprintf("inbound_non_ip=%d", d.inboundNonIP),
		fmt.Sprintf("inbound_synack=%d", d.inboundSynAck),
		fmt.Sprintf("inbound_rst=%d", d.inboundRst),
		fmt.Sprintf("inbound_icmp=%d", d.inboundIcmp),
	}
	if d.lastOutbound != "" {
		parts = append(parts, fmt.Sprintf("last_outbound=%q", d.lastOutbound))
	}
	if d.lastInbound != "" {
		parts = append(parts, fmt.Sprintf("last_inbound=%q", d.lastInbound))
	}
	if d.lastInboundNonIP != "" {
		parts = append(parts, fmt.Sprintf("last_inbound_non_ip=%q", d.lastInboundNonIP))
	}
	return strings.Join(parts, " ")
}

type packetSummary struct {
	valid    bool
	text     string
	version  int
	protocol string

	srcAddr  netip.Addr
	dstAddr  netip.Addr
	hasPorts bool
	srcPort  uint16
	dstPort  uint16

	tcpFlags uint8
	icmpType uint8
	icmpCode uint8
}

const (
	tcpFlagFin uint8 = 0x01
	tcpFlagSyn uint8 = 0x02
	tcpFlagRst uint8 = 0x04
	tcpFlagPsh uint8 = 0x08
	tcpFlagAck uint8 = 0x10
	tcpFlagUrg uint8 = 0x20
	tcpFlagEce uint8 = 0x40
	tcpFlagCwr uint8 = 0x80
)

var tcpFlagNames = [...]struct {
	bit  uint8
	name string
}{
	{tcpFlagSyn, "SYN"},
	{tcpFlagAck, "ACK"},
	{tcpFlagRst, "RST"},
	{tcpFlagFin, "FIN"},
	{tcpFlagPsh, "PSH"},
	{tcpFlagUrg, "URG"},
	{tcpFlagEce, "ECE"},
	{tcpFlagCwr, "CWR"},
}

func summarizeIPPacket(pkt []byte) string {
	return parsePacketSummary(pkt).text
}

func parsePacketSummary(pkt []byte) packetSummary {
	if len(pkt) < 1 {
		return packetSummary{text: "malformed len=0"}
	}
	version := int(pkt[0] >> 4)
	switch version {
	case 4:
		return parseIPv4PacketSummary(pkt)
	case 6:
		return parseIPv6PacketSummary(pkt)
	default:
		return packetSummary{text: fmt.Sprintf("unknown_ip_version=%d len=%d", version, len(pkt))}
	}
}

func parseIPv4PacketSummary(pkt []byte) packetSummary {
	if len(pkt) < 20 {
		return packetSummary{text: fmt.Sprintf("IPv4 malformed len=%d", len(pkt))}
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return packetSummary{text: fmt.Sprintf("IPv4 malformed ihl=%d len=%d", ihl, len(pkt))}
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen == 0 || totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	if totalLen < ihl {
		totalLen = len(pkt)
	}
	info := packetSummary{
		valid:   true,
		version: 4,
		srcAddr: addrFrom4(pkt[12:16]),
		dstAddr: addrFrom4(pkt[16:20]),
	}
	payload := pkt[ihl:totalLen]
	switch proto := pkt[9]; proto {
	case 6:
		fillTCPSummary(&info, payload)
	case 17:
		fillUDPSummary(&info, payload)
	case 1:
		fillICMPSummary(&info, payload, "ICMP")
	default:
		info.protocol = fmt.Sprintf("proto=%d", proto)
		info.text = fmt.Sprintf("IPv4 %s %s -> %s len=%d", info.protocol, info.srcAddr, info.dstAddr, totalLen)
	}
	return info
}

func parseIPv6PacketSummary(pkt []byte) packetSummary {
	if len(pkt) < 40 {
		return packetSummary{text: fmt.Sprintf("IPv6 malformed len=%d", len(pkt))}
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	totalLen := 40 + payloadLen
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	info := packetSummary{
		valid:   true,
		version: 6,
		srcAddr: addrFrom16(pkt[8:24]),
		dstAddr: addrFrom16(pkt[24:40]),
	}
	payload := pkt[40:totalLen]
	switch next := pkt[6]; next {
	case 6:
		fillTCPSummary(&info, payload)
	case 17:
		fillUDPSummary(&info, payload)
	case 58:
		fillICMPSummary(&info, payload, "ICMPv6")
	default:
		info.protocol = fmt.Sprintf("next=%d", next)
		info.text = fmt.Sprintf("IPv6 %s %s -> %s len=%d", info.protocol, info.srcAddr, info.dstAddr, totalLen)
	}
	return info
}

func fillTCPSummary(info *packetSummary, payload []byte) {
	info.protocol = "TCP"
	if len(payload) < 20 {
		info.text = fmt.Sprintf("IPv%d TCP malformed %s -> %s len=%d", info.version, info.srcAddr, info.dstAddr, len(payload))
		return
	}
	info.hasPorts = true
	info.srcPort = binary.BigEndian.Uint16(payload[0:2])
	info.dstPort = binary.BigEndian.Uint16(payload[2:4])
	info.tcpFlags = payload[13]
	info.text = fmt.Sprintf("IPv%d TCP %s -> %s flags=%s len=%d",
		info.version,
		formatEndpoint(info.srcAddr, info.srcPort),
		formatEndpoint(info.dstAddr, info.dstPort),
		tcpFlagString(info.tcpFlags),
		packetLengthFromHeader(info.version, payload))
}

func fillUDPSummary(info *packetSummary, payload []byte) {
	info.protocol = "UDP"
	if len(payload) < 8 {
		info.text = fmt.Sprintf("IPv%d UDP malformed %s -> %s len=%d", info.version, info.srcAddr, info.dstAddr, len(payload))
		return
	}
	info.hasPorts = true
	info.srcPort = binary.BigEndian.Uint16(payload[0:2])
	info.dstPort = binary.BigEndian.Uint16(payload[2:4])
	info.text = fmt.Sprintf("IPv%d UDP %s -> %s len=%d",
		info.version,
		formatEndpoint(info.srcAddr, info.srcPort),
		formatEndpoint(info.dstAddr, info.dstPort),
		packetLengthFromHeader(info.version, payload))
}

func fillICMPSummary(info *packetSummary, payload []byte, protocol string) {
	info.protocol = protocol
	if len(payload) < 2 {
		info.text = fmt.Sprintf("IPv%d %s malformed %s -> %s len=%d", info.version, protocol, info.srcAddr, info.dstAddr, len(payload))
		return
	}
	info.icmpType = payload[0]
	info.icmpCode = payload[1]
	info.text = fmt.Sprintf("IPv%d %s %s -> %s type=%d code=%d len=%d",
		info.version,
		protocol,
		info.srcAddr,
		info.dstAddr,
		info.icmpType,
		info.icmpCode,
		packetLengthFromHeader(info.version, payload))
}

func packetLengthFromHeader(version int, payload []byte) int {
	if version == 4 {
		return len(payload) + 20
	}
	return len(payload) + 40
}

func tcpFlagString(flags uint8) string {
	parts := make([]string, 0, len(tcpFlagNames))
	for _, flag := range tcpFlagNames {
		if flags&flag.bit != 0 {
			parts = append(parts, flag.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func addrFrom4(b []byte) netip.Addr {
	var a [4]byte
	copy(a[:], b)
	return netip.AddrFrom4(a)
}

func addrFrom16(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}

func formatEndpoint(addr netip.Addr, port uint16) string {
	return net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
}
