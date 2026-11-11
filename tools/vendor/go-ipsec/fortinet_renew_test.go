package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikev1"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	tun2net "github.com/n0madic/go-tun2net"
)

func TestLegacyPhase1RenewalPreservesTCPStream(t *testing.T) {
	gateway, natPort, ready, packets, send := legacyTestGateway(t, true)
	o := DefaultFortinetOptions()
	o.IkeVersion, o.ExchangeMode, o.Phase1Lifetime, o.Phase2Lifetime = 1, 1, 1, 60
	o.DhGroups = "14"
	o.Phase2TimeLifetime = false
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	client, err := dialLegacy(ctx, Config{Server: gateway, NATTPort: natPort, PSK: "legacy-secret", FortinetOptions: &o})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// A failed replacement must leave the established ESP stream usable and retry
	// without consuming the original generation's PSK copy.
	var rejected atomic.Bool
	client.mu.Lock()
	sendControl := client.controlConfig.Send
	client.controlConfig.Send = func(packet []byte, natt bool) error {
		if !rejected.Swap(true) {
			return errors.New("fixture rejected first replacement")
		}
		return sendControl(packet, natt)
	}
	client.mu.Unlock()
	first := <-ready
	makeSA := func(r ikev1.Result) *esp.SA {
		t.Helper()
		sa, err := esp.NewLegacySA(r.EncrID, r.IntegID, r.OutSPI, r.InSPI, r.OutEncKey, r.OutIntegKey, r.InEncKey, r.InIntegKey, true)
		if err != nil {
			t.Fatal(err)
		}
		return sa
	}
	sa := makeSA(first)
	peerTunnel := tunnel.New(sa, func(_ context.Context, p []byte) error { return send(p) }, tun2net.TunConfig{LocalIP: netip.MustParseAddr("10.42.0.1"), MTU: 1400})
	defer peerTunnel.Close()
	peerNet, err := tun2net.New(peerTunnel, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peerNet.Close()
	listener, err := peerNet.ListenTCP(netip.MustParseAddrPort("10.42.0.1:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	updates := make(chan struct{}, 8)
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		keys := map[uint32]*esp.SA{sa.InSPI(): sa}
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-ready:
				fresh, err := esp.NewLegacySA(r.EncrID, r.IntegID, r.OutSPI, r.InSPI, r.OutEncKey, r.OutIntegKey, r.InEncKey, r.InIntegKey, true)
				if err != nil {
					return
				}
				keys[fresh.InSPI()] = fresh
				peerTunnel.SwapSA(fresh)
				updates <- struct{}{}
			case p := <-packets:
				if len(p) < 4 {
					continue
				}
				if key := keys[binary.BigEndian.Uint32(p[:4])]; key != nil {
					if plain, err := key.Decrypt(p); err == nil {
						peerTunnel.DeliverInbound(plain)
					}
				}
			}
		}
	}()
	defer func() { cancel(); <-pumpDone }()
	conn, err := client.DialContext(ctx, "tcp", "10.42.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	originalStack := client.stack
	deadline := time.Now().Add(2400 * time.Millisecond)
	for sequence := byte(1); time.Now().Before(deadline); sequence++ {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte{sequence}); err != nil {
			t.Fatalf("phase-1 expiry dropped live TCP: %v", err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != sequence {
			t.Fatalf("phase-1 renewal interrupted echo: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(updates) < 2 {
		t.Fatal("phase 1 was not renewed repeatedly before expiry")
	}
	if client.stack != originalStack {
		t.Fatal("phase-1 replacement rebuilt the netstack")
	}
}

func TestLegacyControlOwnershipAndRetirement(t *testing.T) {
	cfg := ikev1.Config{PSK: []byte("retained-template"), Send: func([]byte, bool) error { return nil }}
	first, second := newLegacyControl(cfg), newLegacyControl(cfg)
	defer second.close()
	keys := func() ikev1.Result {
		return ikev1.Result{OutEncKey: []byte{1}, InEncKey: []byte{2}, OutIntegKey: []byte{3}, InIntegKey: []byte{4}}
	}
	queued, dropped := keys(), keys()
	first.Established(queued)
	first.Established(dropped)
	if dropped.OutEncKey[0] != 0 || dropped.InIntegKey[0] != 0 {
		t.Fatal("full event queue retained unused keys")
	}
	first.Failed(errors.New("first"))
	first.Failed(errors.New("duplicate"))
	if len(first.failed) != 1 {
		t.Fatal("failure queue is not bounded")
	}
	first.close()
	first.close()
	late := keys()
	first.Established(late)
	if queued.OutEncKey[0] != 0 || late.InEncKey[0] != 0 || len(first.ready) != 0 {
		t.Fatal("retired control retained keys")
	}
	if string(cfg.PSK) != "retained-template" {
		t.Fatal("retiring a generation erased the renewal template")
	}
	var absent *legacyControl
	absent.close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := &legacyClient{conn: conn, control: first, controlConfig: cfg, done: make(chan struct{})}
	c.handleIKE([]byte{1}) // An unpublished generation never accepts packets.
	pending, err := c.beginPhase1Renewal()
	if err != nil {
		t.Fatal(err)
	}
	if same, err := c.beginPhase1Renewal(); err != nil || same != pending {
		t.Fatal("parallel renewal allocated another generation")
	}
	if c.promotePhase1Renewal(second) {
		t.Fatal("unrelated generation was promoted")
	}
	c.discardPhase1Renewal(second)
	if !c.promotePhase1Renewal(pending) {
		t.Fatal("authenticated replacement was not promoted")
	}
	c.Close()
	if c.promotePhase1Renewal(pending) {
		t.Fatal("closed client accepted a replacement")
	}
	if _, err := c.beginPhase1Renewal(); err == nil {
		t.Fatal("closed client started renewal")
	}
	for _, b := range cfg.PSK {
		if b != 0 {
			t.Fatal("closed client retained renewal credentials")
		}
	}
}

func TestLegacyRenewalRejectsAddressChanges(t *testing.T) {
	o := DefaultFortinetOptions()
	o.AddressAssignment = 1
	o.ManualAddress = "10.42.0.9"
	key := make([]byte, 32)
	old, err := esp.NewSA(0, 2, 1, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	tun := tunnel.New(old, func(context.Context, []byte) error { return nil }, tun2net.TunConfig{LocalIP: netip.MustParseAddr("10.42.0.2")})
	defer tun.Close()
	c := &legacyClient{cfg: Config{FortinetOptions: &o}, sa: old, tun: tun}
	result := ikev1.Result{EncrID: 12, IntegID: 12, OutSPI: 4, InSPI: 3, OutEncKey: make([]byte, 32), InEncKey: make([]byte, 32), OutIntegKey: make([]byte, 32), InIntegKey: make([]byte, 32)}
	if err := c.install(result); err == nil {
		t.Fatal("replacement changed a live stream's source address")
	}
	if c.sa != old || tun.Config().LocalIP.String() != "10.42.0.2" {
		t.Fatal("rejected renewal changed current data plane")
	}
}

func TestLegacyCloseBeforeLifecycleStarts(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	o := DefaultFortinetOptions()
	c := &legacyClient{cfg: Config{FortinetOptions: &o}, conn: conn, control: newLegacyControl(ikev1.Config{}), done: make(chan struct{})}
	c.Close()
	// A caller may close immediately after Dial returns, before its lifecycle
	// goroutine has been scheduled. Retain the retired control for that snapshot.
	c.lifecycle()
}
