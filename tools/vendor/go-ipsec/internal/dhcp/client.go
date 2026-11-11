// Package dhcp acquires an RFC 2131 lease entirely inside the authenticated ESP
// data plane. It never opens a host DHCP socket or changes host interface state.
package dhcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Lease struct {
	IP, Netmask, Gateway, Server netip.Addr
	DNS                          []netip.Addr
	Expires, Renew, Rebind       time.Time
}
type Client struct {
	send      func(context.Context, []byte) error
	mac       [6]byte
	mu        sync.Mutex
	xid       [4]byte
	responses chan response
	Retry     time.Duration
}
type response struct {
	kind    byte
	ip      netip.Addr
	options map[byte][]byte
}

var broadcast = netip.MustParseAddr("255.255.255.255")
var zero = netip.MustParseAddr("0.0.0.0")

func New(send func(context.Context, []byte) error) (*Client, error) {
	c := &Client{send: send, responses: make(chan response, 16), Retry: 2 * time.Second}
	if _, err := rand.Read(c.mac[:]); err != nil {
		return nil, err
	}
	c.mac[0] = (c.mac[0] | 2) & 254
	return c, nil
}
func (c *Client) transaction() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := rand.Read(c.xid[:])
	for {
		select {
		case <-c.responses:
		default:
			return err
		}
	}
}

// Handle accepts only a bounded IPv4/UDP BOOTREPLY for this client and current
// transaction. It returns true for DHCP traffic, including malformed replies, so
// it cannot escape into an application socket. The caller has verified ESP.
func (c *Client) Handle(packet []byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return false
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header+8 > len(packet) {
		return false
	}
	u := packet[header:]
	if binary.BigEndian.Uint16(u[:2]) != 67 || binary.BigEndian.Uint16(u[2:4]) != 68 {
		return false
	}
	if len(packet) > 4096 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || checksum(packet[:header]) != 0 {
		return true
	}
	length := int(binary.BigEndian.Uint16(u[4:6]))
	if length < 248 || length > len(u) {
		return true
	}
	u = u[:length]
	if binary.BigEndian.Uint16(u[6:8]) != 0 && udpChecksum(packet[12:16], packet[16:20], u) != 0 {
		return true
	}
	b := u[8:]
	if b[0] != 2 || b[1] != 1 || b[2] != 6 || !bytes.Equal(b[28:34], c.mac[:]) || !bytes.Equal(b[236:240], []byte{99, 130, 83, 99}) {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !bytes.Equal(b[4:8], c.xid[:]) {
		return true
	}
	options, ok := parseOptions(b[240:])
	if !ok || len(options[53]) != 1 {
		return true
	}
	ip := netip.AddrFrom4([4]byte(b[16:20]))
	r := response{options[53][0], ip, options}
	select {
	case c.responses <- r:
	default:
	}
	return true
}
func parseOptions(raw []byte) (map[byte][]byte, bool) {
	out := map[byte][]byte{}
	for len(raw) > 0 {
		code := raw[0]
		raw = raw[1:]
		if code == 255 {
			return out, true
		}
		if code == 0 {
			continue
		}
		if len(raw) < 1 || int(raw[0]) > len(raw)-1 {
			return nil, false
		}
		n := int(raw[0])
		raw = raw[1:]
		if len(out[code])+n > 1024 {
			return nil, false
		}
		out[code] = append(out[code], raw[:n]...)
		raw = raw[n:]
	}
	return nil, false
}
func optionIP(options map[byte][]byte, key byte) netip.Addr {
	v := options[key]
	if len(v) != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(v))
}
func validIP(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && ip != broadcast
}
func seconds(options map[byte][]byte, key byte) time.Duration {
	v := options[key]
	if len(v) != 4 {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint32(v)) * time.Second
}
func lease(r response, previous Lease) (Lease, error) {
	ip := r.ip
	if ip.IsUnspecified() {
		ip = previous.IP
	}
	server := optionIP(r.options, 54)
	if !validIP(ip) || !validIP(server) {
		return Lease{}, errors.New("DHCP reply has invalid address or server")
	}
	ttl := seconds(r.options, 51)
	if ttl <= 0 {
		return Lease{}, errors.New("DHCP reply has no valid lease lifetime")
	}
	mask := optionIP(r.options, 1)
	if !mask.Is4() {
		mask = netip.MustParseAddr("255.255.255.255")
	}
	bits := binary.BigEndian.Uint32(mask.AsSlice())
	inv := ^bits
	if inv&(inv+1) != 0 {
		return Lease{}, errors.New("DHCP reply has invalid subnet mask")
	}
	t1, t2 := seconds(r.options, 58), seconds(r.options, 59)
	if t1 <= 0 || t1 >= ttl {
		t1 = ttl / 2
	}
	if t2 <= t1 || t2 >= ttl {
		t2 = ttl * 7 / 8
	}
	if t2 <= t1 {
		t2 = t1 + (ttl-t1)/2
	}
	now := time.Now()
	l := Lease{IP: ip, Server: server, Netmask: mask, Expires: now.Add(ttl), Renew: now.Add(t1), Rebind: now.Add(t2)}
	if routers := r.options[3]; len(routers) >= 4 && len(routers)%4 == 0 {
		l.Gateway = netip.AddrFrom4([4]byte(routers[:4]))
		if !validIP(l.Gateway) {
			return Lease{}, errors.New("DHCP reply has invalid router")
		}
	}
	dns := r.options[6]
	if len(dns)%4 != 0 || len(dns) > 64 {
		return Lease{}, errors.New("DHCP reply has invalid DNS servers")
	}
	for len(dns) > 0 {
		addr := netip.AddrFrom4([4]byte(dns[:4]))
		if !validIP(addr) {
			return Lease{}, errors.New("DHCP reply has invalid DNS server")
		}
		l.DNS = append(l.DNS, addr)
		dns = dns[4:]
	}
	return l, nil
}
func (c *Client) Acquire(ctx context.Context) (Lease, error) {
	if err := c.transaction(); err != nil {
		return Lease{}, err
	}
	offer, err := c.exchange(ctx, 1, Lease{}, false, func(r response) bool { return r.kind == 2 && validIP(r.ip) && validIP(optionIP(r.options, 54)) })
	if err != nil {
		return Lease{}, err
	}
	selected := Lease{IP: offer.ip, Server: optionIP(offer.options, 54)}
	ack, err := c.exchange(ctx, 3, selected, false, func(r response) bool {
		return (r.kind == 5 || r.kind == 6) && optionIP(r.options, 54) == selected.Server
	})
	if err != nil {
		return Lease{}, err
	}
	if ack.kind == 6 {
		return Lease{}, errors.New("DHCP server rejected address request")
	}
	if ack.ip != selected.IP {
		return Lease{}, errors.New("DHCP server changed the selected address")
	}
	return lease(ack, Lease{})
}
func (c *Client) exchange(ctx context.Context, kind byte, l Lease, renew bool, accept func(response) bool) (response, error) {
	retry := c.Retry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return response{}, ctx.Err()
		case <-timer.C:
			if err := c.send(ctx, c.packet(kind, l, renew)); err != nil {
				return response{}, errors.New("DHCP request could not be sent inside IPsec")
			}
			timer.Reset(retry)
		case r := <-c.responses:
			if accept(r) {
				return r, nil
			}
		}
	}
}

// Maintain renews at T1, broadcasts again at T2, and returns on NAK or expiry.
// The owner must close the VPN on error; an expired address is never retained.
func (c *Client) Maintain(ctx context.Context, l Lease, changed func(Lease)) error {
	for {
		timer := time.NewTimer(time.Until(l.Renew))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := c.transaction(); err != nil {
			return err
		}
		renewCtx, cancel := context.WithDeadline(ctx, l.Expires)
		ack, err := c.exchange(renewCtx, 3, l, true, func(r response) bool {
			return (r.kind == 5 || r.kind == 6) && (time.Now().After(l.Rebind) || optionIP(r.options, 54) == l.Server)
		})
		cancel()
		if err != nil {
			return errors.New("DHCP lease renewal failed or expired")
		}
		if ack.kind == 6 {
			return errors.New("DHCP lease revoked")
		}
		next, err := lease(ack, l)
		if err != nil {
			return err
		}
		l = next
		changed(l)
	}
}
func (c *Client) Release(ctx context.Context, l Lease) { _ = c.send(ctx, c.packet(7, l, true)) }
func (c *Client) packet(kind byte, l Lease, renew bool) []byte {
	b := make([]byte, 240)
	b[0] = 1
	b[1] = 1
	b[2] = 6
	c.mu.Lock()
	copy(b[4:8], c.xid[:])
	c.mu.Unlock()
	copy(b[28:34], c.mac[:])
	copy(b[236:240], []byte{99, 130, 83, 99})
	src, dst := zero, broadcast
	if renew {
		src = l.IP
		copy(b[12:16], src.AsSlice())
		if kind == 7 || time.Now().Before(l.Rebind) {
			dst = l.Server
		}
	} else {
		binary.BigEndian.PutUint16(b[10:12], 0x8000)
	}
	b = append(b, 53, 1, kind, 61, 7, 1)
	b = append(b, c.mac[:]...)
	if !renew && kind == 3 {
		b = append(b, 50, 4)
		b = append(b, l.IP.AsSlice()...)
	}
	if (!renew && kind == 3) || kind == 7 {
		b = append(b, 54, 4)
		b = append(b, l.Server.AsSlice()...)
	}
	b = append(b, 55, 7, 1, 3, 6, 51, 54, 58, 59, 255)
	return wrapUDP(src, dst, 68, 67, b)
}
func wrapUDP(src, dst netip.Addr, source, destination uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	u := p[20:]
	binary.BigEndian.PutUint16(u[:2], source)
	binary.BigEndian.PutUint16(u[2:4], destination)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	sum := udpChecksum(p[12:16], p[16:20], u)
	if sum == 0 {
		sum = 65535
	}
	binary.BigEndian.PutUint16(u[6:8], sum)
	return p
}
func udpChecksum(src, dst, u []byte) uint16 {
	p := append(append(append([]byte{}, src...), dst...), 0, 17, byte(len(u)>>8), byte(len(u)))
	return checksum(append(p, u...))
}
func checksum(p []byte) uint16 {
	sum := uint32(0)
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
