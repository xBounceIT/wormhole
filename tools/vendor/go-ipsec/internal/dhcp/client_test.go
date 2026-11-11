package dhcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

var clientIP = netip.MustParseAddr("10.42.0.9")
var serverIP = netip.MustParseAddr("10.42.0.1")

func reply(c *Client, kind byte, options []byte) []byte {
	b := make([]byte, 240)
	b[0] = 2
	b[1] = 1
	b[2] = 6
	copy(b[4:8], c.xid[:])
	copy(b[28:34], c.mac[:])
	copy(b[16:20], clientIP.AsSlice())
	copy(b[236:240], []byte{99, 130, 83, 99})
	b = append(b, 53, 1, kind, 54, 4, 10, 42, 0, 1, 51, 4, 0, 0, 0, 8, 1, 4, 255, 255, 255, 0, 3, 4, 10, 42, 0, 1, 6, 4, 10, 42, 0, 53)
	b = append(b, options...)
	b = append(b, 255)
	return wrapUDP(serverIP, broadcast, 67, 68, b)
}
func TestAcquireRenewRelease(t *testing.T) {
	for _, rebind := range []bool{false, true} {
		t.Run(map[bool]string{false: "renew", true: "rebind"}[rebind], func(t *testing.T) {
			var c *Client
			sent := 0
			c, _ = New(func(ctx context.Context, p []byte) error {
				sent++
				options, ok := parseOptions(p[268:])
				if !ok {
					t.Fatal("invalid client options")
				}
				kind := options[53][0]
				if checksum(p[:20]) != 0 || udpChecksum(p[12:16], p[16:20], p[20:]) != 0 {
					t.Fatal("invalid outbound checksums")
				}
				switch kind {
				case 1:
					c.Handle(reply(c, 2, nil))
				case 3:
					if sent == 2 {
						if !bytes.Equal(options[50], clientIP.AsSlice()) || !bytes.Equal(options[54], serverIP.AsSlice()) {
							t.Fatal("request did not bind offer")
						}
					} else {
						if len(options[50]) != 0 || len(options[54]) != 0 || !bytes.Equal(p[40:44], clientIP.AsSlice()) {
							t.Fatal("renewal request invalid")
						}
						if rebind && !bytes.Equal(p[16:20], broadcast.AsSlice()) {
							t.Fatal("rebind was not broadcast")
						}
					}
					c.Handle(reply(c, 5, nil))
				case 7:
					if !bytes.Equal(options[54], serverIP.AsSlice()) {
						t.Fatal("release missing server")
					}
				}
				return nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			l, err := c.Acquire(ctx)
			if err != nil || l.IP != clientIP || l.Netmask.String() != "255.255.255.0" || len(l.DNS) != 1 {
				t.Fatal(l, err)
			}
			l.Renew = time.Now().Add(-time.Second)
			if rebind {
				l.Rebind = l.Renew
			}
			maintenance, stop := context.WithCancel(ctx)
			err = c.Maintain(maintenance, l, func(next Lease) {
				if next.Server != serverIP {
					t.Error("server changed")
				}
				stop()
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			c.Release(ctx, l)
			if sent != 4 {
				t.Fatal(sent)
			}
		})
	}
}
func TestAcquireFailures(t *testing.T) {
	for _, mode := range []string{"timeout", "send-error", "nak", "changed-ip", "bad-lease"} {
		t.Run(mode, func(t *testing.T) {
			var c *Client
			c, _ = New(func(ctx context.Context, p []byte) error {
				if mode == "send-error" {
					return errors.New("wire")
				}
				if mode == "timeout" {
					return nil
				}
				options, _ := parseOptions(p[268:])
				kind := byte(2)
				if options[53][0] == 3 {
					kind = 5
					if mode == "nak" {
						kind = 6
					}
				}
				r := reply(c, kind, nil)
				if kind == 5 && mode == "changed-ip" {
					r[47]++
					r[26] = 0
					r[27] = 0
				}
				if kind == 5 && mode == "bad-lease" {
					r[20+8+240+9] = 0
					r[26] = 0
					r[27] = 0
				}
				c.Handle(r)
				return nil
			})
			c.Retry = time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Millisecond)
			defer cancel()
			if _, err := c.Acquire(ctx); err == nil {
				t.Fatal("invalid DHCP accepted")
			}
		})
	}
}
func TestRenewalFailsClosed(t *testing.T) {
	for _, mode := range []string{"nak", "expiry", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			var c *Client
			c, _ = New(func(context.Context, []byte) error {
				if mode == "expiry" {
					return nil
				}
				r := reply(c, 6, nil)
				if mode == "invalid" {
					r = reply(c, 5, []byte{51, 4, 0, 0, 0, 0})
				}
				c.Handle(r)
				return nil
			})
			c.Retry = time.Millisecond
			l := Lease{IP: clientIP, Server: serverIP, Renew: time.Now().Add(-time.Second), Rebind: time.Now().Add(-time.Second), Expires: time.Now().Add(8 * time.Millisecond)}
			if err := c.Maintain(context.Background(), l, func(Lease) { t.Error("bad lease installed") }); err == nil {
				t.Fatal("renewal failure ignored")
			}
		})
	}
}
func TestReplyValidation(t *testing.T) {
	c, _ := New(func(context.Context, []byte) error { return nil })
	_ = c.transaction()
	valid := reply(c, 2, nil)
	for _, mutate := range []func([]byte){func(p []byte) { p[0] = 0x65 }, func(p []byte) { p[9] = 6 }, func(p []byte) { p[22] = 1 }, func(p []byte) { p[2] = 0 }, func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[10] ^= 1 }, func(p []byte) { p[24] = 255 }, func(p []byte) { p[28] = 1 }, func(p []byte) { p[29] = 0 }, func(p []byte) { p[30] = 5 }, func(p []byte) { p[32] ^= 1 }, func(p []byte) { p[56] ^= 1 }, func(p []byte) { p[264] = 0 }, func(p []byte) { p[268] = 254 }, func(p []byte) { p[269] = 255 }} {
		p := append([]byte(nil), valid...)
		mutate(p)
		if p[0] == 0x45 && p[9] == 17 && p[10] == valid[10] {
			p[26] = 0
			p[27] = 0
			p[10] = 0
			p[11] = 0
			binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
		}
		c.Handle(p)
		select {
		case <-c.responses:
			t.Fatal("malformed packet accepted")
		default:
		}
	}
	if c.Handle(nil) {
		t.Fatal("empty packet classified as DHCP")
	}
	for i := 0; i < 20; i++ {
		c.Handle(valid)
	}
	if len(c.responses) != 16 {
		t.Fatal("queue is not bounded")
	}
	_ = c.transaction()
	if len(c.responses) != 0 {
		t.Fatal("old replies survived transaction")
	}
	for _, raw := range [][]byte{{1}, {1, 4, 1}, {53, 1, 2}, append(append([]byte{1, 255}, make([]byte, 255)...), 1, 255)} {
		if _, ok := parseOptions(raw); ok {
			t.Fatal("malformed options accepted")
		}
	}
	if _, ok := parseOptions([]byte{0, 53, 1, 2, 255}); !ok {
		t.Fatal("padding rejected")
	}
}
func TestLeaseValidation(t *testing.T) {
	base := map[byte][]byte{54: serverIP.AsSlice(), 51: {0, 0, 0, 8}, 1: {255, 255, 255, 0}, 58: {0, 0, 0, 1}, 59: {0, 0, 0, 7}}
	for _, key := range []byte{54, 51, 1, 3, 6} {
		options := map[byte][]byte{}
		for k, v := range base {
			options[k] = v
		}
		switch key {
		case 54:
			options[key] = []byte{0, 0, 0, 0}
		case 51:
			options[key] = []byte{0, 0, 0, 0}
		case 1:
			options[key] = []byte{255, 0, 255, 0}
		case 3:
			options[key] = []byte{0, 0, 0, 0}
		case 6:
			options[key] = []byte{1}
		}
		if _, err := lease(response{ip: clientIP, options: options}, Lease{}); err == nil {
			t.Fatal("invalid lease accepted", key)
		}
	}
	l, err := lease(response{ip: zero, options: base}, Lease{IP: clientIP})
	if err != nil || l.IP != clientIP {
		t.Fatal(err)
	}
	delete(base, 1)
	base[58] = []byte{0}
	base[59] = []byte{0}
	if _, err := lease(response{ip: clientIP, options: base}, Lease{}); err != nil {
		t.Fatal(err)
	}
	if validIP(broadcast) || validIP(zero) || validIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("invalid IP accepted")
	}
}
