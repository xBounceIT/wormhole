package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikev1"
)

type legacyTestHandler struct {
	ready   chan ikev1.Result
	failure chan error
}

func (h legacyTestHandler) Established(r ikev1.Result) { h.ready <- r }
func (h legacyTestHandler) Failed(err error) {
	select {
	case h.failure <- err:
	default:
	}
}

func legacyTestGateway(t *testing.T) (string, int, <-chan ikev1.Result, <-chan []byte) {
	t.Helper()
	ike, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	natt, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ike.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ike.Close(); natt.Close() })
	ready := make(chan ikev1.Result, 8)
	failure := make(chan error, 1)
	packets := make(chan []byte, 128)
	var mu sync.Mutex
	var client *net.UDPAddr
	session := ikev1.NewSession(ikev1.Config{Role: ikev1.Responder, Mode: ikev1.ModeAggressive, Phase2: ikev1.Phase2RemoteAccess, PSK: []byte("legacy-secret"), ModeCfg: true, LocalIP: net.IPv4(127, 0, 0, 1), PeerIP: net.IPv4(127, 0, 0, 1), LocalPort: uint16(ike.LocalAddr().(*net.UDPAddr).Port), Assign: func() (ikev1.ModeCfgReply, error) {
		return ikev1.ModeCfgReply{Address: net.IPv4(10, 42, 0, 2).To4(), DNS: []net.IP{net.IPv4(10, 42, 0, 1).To4()}}, nil
	}, Handler: legacyTestHandler{ready, failure}, Send: func(p []byte, floated bool) error {
		mu.Lock()
		peer := client
		mu.Unlock()
		socket := ike
		if floated {
			socket = natt
			p = append([]byte{0, 0, 0, 0}, p...)
		}
		_, err := socket.WriteToUDP(p, peer)
		return err
	}})
	t.Cleanup(session.Close)
	for _, socket := range []*net.UDPConn{ike, natt} {
		go func(conn *net.UDPConn) {
			buffer := make([]byte, 65536)
			for {
				n, from, err := conn.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				p := append([]byte(nil), buffer[:n]...)
				mu.Lock()
				client = from
				mu.Unlock()
				if conn == ike {
					session.HandleInbound(p)
				} else if n >= 4 && binary.BigEndian.Uint32(p) == 0 {
					session.HandleInbound(p[4:])
				} else if n > 1 {
					select {
					case packets <- p:
					default:
					}
				}
			}
		}(socket)
	}
	return ike.LocalAddr().String(), natt.LocalAddr().(*net.UDPAddr).Port, ready, packets
}

func TestLegacyFortinetUserspaceTunnel(t *testing.T) {
	gateway, natPort, ready, packets := legacyTestGateway(t)
	options := DefaultFortinetOptions()
	options.IkeVersion = 1
	options.ExchangeMode = 1
	options.Phase1Lifetime = 2
	options.Phase2Lifetime = 1
	options.DhGroups = "14"
	dead := make(chan struct{})
	var once sync.Once
	cfg := Config{Server: gateway, NATTPort: natPort, PSK: "legacy-secret", FortinetOptions: &options, OnDead: func() { once.Do(func() { close(dead) }) }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialFortinet(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := <-ready
	sa, err := esp.NewLegacySA(result.EncrID, result.IntegID, result.OutSPI, result.InSPI, result.OutEncKey, result.OutIntegKey, result.InEncKey, result.InIntegKey, true)
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err = client.DialContext(dialCtx, "tcp", "198.18.0.1:443"); err == nil {
		t.Fatal("unanswered TCP connected")
	}
	select {
	case packet := <-packets:
		plain, err := sa.Decrypt(packet)
		if err != nil || len(plain) < 20 || !net.IP(plain[16:20]).Equal(net.IPv4(198, 18, 0, 1)) {
			t.Fatal("TCP did not travel in ESP", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no ESP data")
	}
	resolverCtx, stopResolver := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stopResolver()
	if _, err = client.Resolver("").LookupHost(resolverCtx, "internal.test"); err == nil {
		t.Fatal("unanswered DNS succeeded")
	}
	select {
	case renewed := <-ready:
		if renewed.InSPI == result.InSPI {
			t.Fatal("Child SA was not renewed")
		}
		deadline := time.Now().Add(time.Second)
		for {
			c := client.(*legacyClient)
			c.mu.RLock()
			spi := c.sa.OutSPI()
			c.mu.RUnlock()
			if spi == renewed.InSPI {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("renewed SA not installed")
			}
			time.Sleep(time.Millisecond)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("key lifetime did not initiate Quick Mode renewal")
	}
	select {
	case <-dead:
	case <-time.After(3 * time.Second):
		t.Fatal("expired key did not tear down tunnel")
	}
	if _, err = client.DialContext(context.Background(), "tcp", "10.42.0.1:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("expired tunnel accepted a connection")
	}
}

func TestFortinetOptionsRejectUnsupportedOrMalformedProfiles(t *testing.T) {
	defaults := DefaultFortinetOptions()
	if _, err := ConfigureFortinet(Config{}, defaults, "", "", ""); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*FortinetOptions){func(o *FortinetOptions) { o.IkeVersion = 3 }, func(o *FortinetOptions) { o.AuthMethod = 2 }, func(o *FortinetOptions) { o.UserAuth = 4 }, func(o *FortinetOptions) { o.ExchangeMode = 2 }, func(o *FortinetOptions) { o.AddressAssignment = 3 }, func(o *FortinetOptions) { o.Phase1Encryption = 4 }, func(o *FortinetOptions) { o.Phase1Authentication = 5 }, func(o *FortinetOptions) { o.Phase1Lifetime = 0 }, func(o *FortinetOptions) { o.Phase2Lifetime = 0 }, func(o *FortinetOptions) { o.Phase2LifetimeKb = 0 }, func(o *FortinetOptions) { o.AddressAssignment = 2 }, func(o *FortinetOptions) { o.DhGroups = "bad" }, func(o *FortinetOptions) { o.DhGroups = "2" }, func(o *FortinetOptions) { o.Phase1Encryption = 3 }, func(o *FortinetOptions) { o.Phase2Encryption = 3 }, func(o *FortinetOptions) { o.Pfs = true; o.PfsGroup = 2 }, func(o *FortinetOptions) { o.ReplayDetection = false }, func(o *FortinetOptions) { o.AuthMethod = 1 }} {
		value := defaults
		mutate(&value)
		if _, err := ConfigureFortinet(Config{}, value, "invalid", "invalid", ""); err == nil {
			t.Fatal("unsupported profile accepted")
		}
	}
	for _, value := range []string{"3", "2,2", "bad"} {
		if _, err := fortinetGroups(value); err == nil {
			t.Fatal("invalid DH groups accepted")
		}
	}
	if groups, err := fortinetGroups(""); err != nil || len(groups) != 1 {
		t.Fatal("default groups invalid")
	}
	for e := 0; e < 4; e++ {
		for a := 0; a < 5; a++ {
			if p := fortinetProposal(e, a, true); p.KeyBits == 0 {
				t.Fatal("invalid proposal mapping")
			}
		}
	}
	options := defaults
	options.IkeVersion = 1
	for _, mutate := range []func(*FortinetOptions){func(o *FortinetOptions) { o.NatTraversal = false }, func(o *FortinetOptions) { o.AddressAssignment = 2 }, func(o *FortinetOptions) { o.EnableLocalLan = true }, func(o *FortinetOptions) { o.DhGroups = "bad" }} {
		value := options
		mutate(&value)
		if _, err := dialLegacy(context.Background(), Config{Server: "127.0.0.1:500", PSK: "secret", FortinetOptions: &value}); err == nil {
			t.Fatal("unsupported legacy profile accepted")
		}
	}
	cfg := Config{Server: "bad address", FortinetOptions: &options}
	if _, err := dialLegacy(context.Background(), cfg); err == nil {
		t.Fatal("invalid server accepted")
	}
}
