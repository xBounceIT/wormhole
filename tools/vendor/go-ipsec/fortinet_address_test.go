package ipsec

import (
	"context"
	"encoding/binary"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikev1"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	"github.com/n0madic/go-ipsec/internal/workers"
	"net"
	"net/netip"
	"testing"
	"time"
)

func dhcpServerReply(plain []byte) []byte {
	if len(plain) < 271 {
		return nil
	}
	b := append([]byte(nil), plain[28:268]...)
	b[0] = 2
	copy(b[16:20], []byte{10, 42, 0, 9})
	kind := byte(2)
	for options := plain[268:]; len(options) > 1; {
		code := options[0]
		if code == 255 {
			break
		}
		n := int(options[1])
		if n+2 > len(options) {
			break
		}
		if code == 53 && n == 1 && options[2] == 3 {
			kind = 5
		}
		options = options[n+2:]
	}
	b = append(b, 53, 1, kind, 54, 4, 10, 42, 0, 1, 51, 4, 0, 0, 0, 30, 1, 4, 255, 255, 255, 0, 6, 4, 10, 42, 0, 53, 255)
	p := make([]byte, 28+len(b))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 42, 0, 1})
	copy(p[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(p[20:22], 67)
	binary.BigEndian.PutUint16(p[22:24], 68)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(b)+8))
	copy(p[28:], b)
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func TestDHCPAddressIntegrationBothIKEVersions(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "IKEv2", true: "IKEv1"}[legacy], func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			key := make([]byte, 32)
			peerSA, err := esp.NewSA(0, 1, 2, key, key, key, key, 64)
			if err != nil {
				t.Fatal(err)
			}
			receive := make(chan func([]byte), 1)
			done := make(chan error, 1)
			go func() {
				deliver := <-receive
				buf := make([]byte, 4096)
				for i := 0; i < 2; i++ {
					n, from, err := server.ReadFromUDP(buf)
					if err != nil {
						done <- err
						return
					}
					if n < 4 || binary.BigEndian.Uint32(buf[:4]) != 2 {
						i--
						continue
					}
					plain, err := peerSA.Decrypt(buf[:n])
					if err != nil {
						done <- err
						return
					}
					reply := dhcpServerReply(plain)
					packet, err := peerSA.Encrypt(reply)
					if err != nil {
						done <- err
						return
					}
					_ = from
					deliver(packet)
				}
				done <- nil
			}()
			if legacy {
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				options := DefaultFortinetOptions()
				options.IkeVersion = 1
				options.AddressAssignment = 2
				c := &legacyClient{cfg: Config{FortinetOptions: &options}, conn: conn, peer: server.LocalAddr().(*net.UDPAddr), nattPort: server.LocalAddr().(*net.UDPAddr).Port, done: make(chan struct{}), dialContext: t.Context(), failed: make(chan error, 1)}
				defer c.Close()
				receive <- c.deliverESP
				r := ikev1.Result{EncrID: 12, IntegID: 12, OutSPI: 2, InSPI: 1, OutEncKey: append([]byte(nil), key...), InEncKey: append([]byte(nil), key...), OutIntegKey: append([]byte(nil), key...), InIntegKey: append([]byte(nil), key...)}
				if err = c.install(r); err != nil {
					t.Fatal(err)
				}
				if c.lease == nil || c.tun.Config().LocalIP.String() != "10.42.0.9" || len(c.dns) != 1 {
					t.Fatal("DHCP lease not installed in IKEv1 stack")
				}
				r.OutEncKey = make([]byte, 32)
				r.InEncKey = make([]byte, 32)
				r.OutIntegKey = make([]byte, 32)
				r.InIntegKey = make([]byte, 32)
				if err = c.install(r); err != nil {
					t.Fatal("rekey lost DHCP lease", err)
				}
			} else {
				c := newClient(Config{AddressAssignment: 2, Logger: discardLogger(), MTU: 1400})
				defer c.Close()
				s := session.New(session.Config{Server: server.LocalAddr().String(), LocalID: session.WireID{Type: 2, Data: []byte("client")}, PSK: []byte("test"), RetransmitBase: time.Millisecond, RetransmitTries: 1}) // Open the real UDP transport; the handshake is tested independently in session.
				// Drain the unauthenticated SA_INIT request before the ESP-only fixture starts.
				c.session.Store(s)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
				_ = s.IKESAInit(ctx)
				cancel()
				// Install ESP only after the separate control-plane tests establish its key contract.
				sa, err := esp.NewSA(0, 2, 1, key, key, key, key, 64)
				if err != nil {
					t.Fatal(err)
				}
				c.resetInbound(1, sa)
				c.tun = tunnel.New(sa, c.sendESP, tunConfig(netip.Addr{}, netip.Addr{}))
				c.mgr = workers.NewManager(c.superCtx, c.cfg.Logger)
				receive <- c.deliverESP
				if err = c.prepareDHCP(); err != nil {
					t.Fatal(err)
				}
				if err = c.acquireDHCP(t.Context()); err != nil {
					t.Fatal(err)
				}
				if c.LocalIP().String() != "10.42.0.9" || c.tun.Config().DNS[0].String() != "10.42.0.53" {
					t.Fatal("DHCP lease not installed in IKEv2 stack")
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
