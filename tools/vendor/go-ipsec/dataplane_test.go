package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/natt"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/transport"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	tun2net "github.com/n0madic/go-tun2net"
)

// TestDataPlaneLoopback is the Phase 2 offline gate: two ESP data planes wired
// back-to-back in memory, each over a real go-tun2net stack. A TCP connection
// dialled through the initiator stack reaches an in-stack listener on the
// responder stack and exchanges data — proving tunnel.Write→ESP→demux→Decrypt→
// DeliverInbound→netstack works end to end. Run under -race.
func TestDataPlaneLoopback(t *testing.T) {
	encrIR := bytes.Repeat([]byte{0x01}, 32)
	integIR := bytes.Repeat([]byte{0x02}, 32)
	encrRI := bytes.Repeat([]byte{0x03}, 32)
	integRI := bytes.Repeat([]byte{0x04}, 32)

	const initSPI, respSPI = 0x1111, 0x2222
	initSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, respSPI, initSPI, encrIR, integIR, encrRI, integRI, 64)
	if err != nil {
		t.Fatal(err)
	}
	respSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, initSPI, respSPI, encrRI, integRI, encrIR, integIR, 64)
	if err != nil {
		t.Fatal(err)
	}

	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })

	initIP := netip.MustParseAddr("10.9.0.1")
	respIP := netip.MustParseAddr("10.9.0.2")
	mask := netip.MustParseAddr("255.255.255.0")

	send := func(c transport.Conn) tunnel.SendFunc {
		return func(ctx context.Context, pkt []byte) error { return c.Send(ctx, pkt) }
	}
	initTun := tunnel.New(initSA, send(initConn), tunConfig(initIP, mask))
	respTun := tunnel.New(respSA, send(respConn), tunConfig(respIP, mask))

	log := slog.New(slog.DiscardHandler)
	initNet, err := tun2net.New(initTun, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { initNet.Close() })
	respNet, err := tun2net.New(respTun, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { respNet.Close() })

	ctx := t.Context()
	go demux(ctx, initConn, initSA, initTun)
	go demux(ctx, respConn, respSA, respTun)

	// In-stack echo listener on the responder netstack.
	ln, err := respNet.ListenTCP(netip.AddrPortFrom(respIP, 80))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		c.Write(append([]byte("pong:"), buf[:n]...))
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := initNet.DialContext(dialCtx, "tcp", net.JoinHostPort(respIP.String(), "80"))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "pong:ping" {
		t.Fatalf("got %q, want %q", got, "pong:ping")
	}
}

// TestDataPlaneLoopbackV6 is the offline gate for inner IPv6: the v6 mirror of
// TestDataPlaneLoopback. Two ESP data planes are wired back-to-back, each over a
// go-tun2net stack configured with only LocalIP6 (no v4, no gateway, no explicit
// routes). go-tun2net's on-link route fallback installs a v6 default, so a TCP
// connection dialled to a literal [v6]:port through the initiator stack reaches
// an in-stack listener on the responder stack — proving ESP carries inner IPv6
// and the netstack routes it. Run under -race.
func TestDataPlaneLoopbackV6(t *testing.T) {
	encrIR := bytes.Repeat([]byte{0x01}, 32)
	integIR := bytes.Repeat([]byte{0x02}, 32)
	encrRI := bytes.Repeat([]byte{0x03}, 32)
	integRI := bytes.Repeat([]byte{0x04}, 32)

	const initSPI, respSPI = 0x1111, 0x2222
	initSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, respSPI, initSPI, encrIR, integIR, encrRI, integRI, 64)
	if err != nil {
		t.Fatal(err)
	}
	respSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, initSPI, respSPI, encrRI, integRI, encrIR, integIR, 64)
	if err != nil {
		t.Fatal(err)
	}

	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })

	initIP := netip.MustParsePrefix("fd00:9::1/64")
	respIP := netip.MustParsePrefix("fd00:9::2/64")

	send := func(c transport.Conn) tunnel.SendFunc {
		return func(ctx context.Context, pkt []byte) error { return c.Send(ctx, pkt) }
	}
	initTun := tunnel.New(initSA, send(initConn), tunConfig6(initIP))
	respTun := tunnel.New(respSA, send(respConn), tunConfig6(respIP))

	log := slog.New(slog.DiscardHandler)
	initNet, err := tun2net.New(initTun, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { initNet.Close() })
	respNet, err := tun2net.New(respTun, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { respNet.Close() })

	ctx := t.Context()
	go demux(ctx, initConn, initSA, initTun)
	go demux(ctx, respConn, respSA, respTun)

	// In-stack echo listener on the responder netstack, bound to its v6 address.
	ln, err := respNet.ListenTCP(netip.AddrPortFrom(respIP.Addr(), 80))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		c.Write(append([]byte("pong:"), buf[:n]...))
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := initNet.DialContext(dialCtx, "tcp", net.JoinHostPort(respIP.Addr().String(), "80"))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping6")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "pong:ping6" {
		t.Fatalf("got %q, want %q", got, "pong:ping6")
	}
}

// demux mirrors the production rx loop: read raw datagrams, decrypt ESP, deliver
// the inner IP packet to the tunnel's fast path.
func demux(ctx context.Context, c transport.Conn, sa *esp.SA, tun *tunnel.Tunnel) {
	demuxReg(ctx, c, func(uint32) *esp.SA { return sa }, tun)
}

// demuxReg is the registry-based variant used by the rekey cutover test: it
// looks up the inbound SA by SPI, mirroring Client.rxDemux.
func demuxReg(ctx context.Context, c transport.Conn, lookup func(spi uint32) *esp.SA, tun *tunnel.Tunnel) {
	for {
		raw, err := c.Recv(ctx)
		if err != nil {
			return
		}
		kind, payload := natt.Classify(raw)
		if kind != natt.KindESP || len(payload) < 4 {
			continue
		}
		sa := lookup(binary.BigEndian.Uint32(payload[:4]))
		if sa == nil {
			continue
		}
		inner, err := sa.Decrypt(payload)
		if err != nil {
			continue
		}
		tun.DeliverInbound(inner)
	}
}

// TestDataPlaneRekeyCutover verifies a TCP connection survives a Child SA
// rekey: mid-stream both ends install a new mirrored SA (new SPIs/keys), add it
// to their inbound registry and swap the outbound SA — the established
// connection keeps flowing (zero-loss cutover).
func TestDataPlaneRekeyCutover(t *testing.T) {
	mkKeys := func(b byte) (enc, integ []byte) {
		return bytes.Repeat([]byte{b}, 32), bytes.Repeat([]byte{b + 1}, 32)
	}
	encIR, intIR := mkKeys(0x01)
	encRI, intRI := mkKeys(0x03)
	const initSPI, respSPI = 0x1111, 0x2222

	initSA, _ := esp.NewSA(esp.SuiteAESCBC256SHA256, respSPI, initSPI, encIR, intIR, encRI, intRI, 64)
	respSA, _ := esp.NewSA(esp.SuiteAESCBC256SHA256, initSPI, respSPI, encRI, intRI, encIR, intIR, 64)

	var initReg, respReg atomic.Pointer[map[uint32]*esp.SA]
	initReg.Store(&map[uint32]*esp.SA{initSPI: initSA})
	respReg.Store(&map[uint32]*esp.SA{respSPI: respSA})

	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })

	initIP := netip.MustParseAddr("10.8.0.1")
	respIP := netip.MustParseAddr("10.8.0.2")
	mask := netip.MustParseAddr("255.255.255.0")
	send := func(c transport.Conn) tunnel.SendFunc {
		return func(ctx context.Context, pkt []byte) error { return c.Send(ctx, pkt) }
	}
	initTun := tunnel.New(initSA, send(initConn), tunConfig(initIP, mask))
	respTun := tunnel.New(respSA, send(respConn), tunConfig(respIP, mask))

	log := slog.New(slog.DiscardHandler)
	initNet, _ := tun2net.New(initTun, log)
	respNet, _ := tun2net.New(respTun, log)
	t.Cleanup(func() { initNet.Close(); respNet.Close() })

	ctx := t.Context()
	go demuxReg(ctx, initConn, func(spi uint32) *esp.SA { return (*initReg.Load())[spi] }, initTun)
	go demuxReg(ctx, respConn, func(spi uint32) *esp.SA { return (*respReg.Load())[spi] }, respTun)

	ln, err := respNet.ListenTCP(netip.AddrPortFrom(respIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c) // echo
	}()

	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	conn, err := initNet.DialContext(dctx, "tcp", net.JoinHostPort(respIP.String(), "7"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	roundTrip := func(msg string) {
		t.Helper()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read %q: %v", msg, err)
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch: %q != %q", buf, msg)
		}
	}

	roundTrip("before-rekey")

	// --- Rekey cutover: install new mirrored SAs (new SPIs/keys) on both ends. ---
	nEncIR, nIntIR := mkKeys(0x21)
	nEncRI, nIntRI := mkKeys(0x23)
	const initSPI2, respSPI2 = 0x3333, 0x4444
	newInitSA, _ := esp.NewSA(esp.SuiteAESCBC256SHA256, respSPI2, initSPI2, nEncIR, nIntIR, nEncRI, nIntRI, 64)
	newRespSA, _ := esp.NewSA(esp.SuiteAESCBC256SHA256, initSPI2, respSPI2, nEncRI, nIntRI, nEncIR, nIntIR, 64)

	initReg.Store(&map[uint32]*esp.SA{initSPI: initSA, initSPI2: newInitSA})
	respReg.Store(&map[uint32]*esp.SA{respSPI: respSA, respSPI2: newRespSA})
	initTun.SwapSA(newInitSA)
	respTun.SwapSA(newRespSA)

	roundTrip("after-rekey-1")
	roundTrip("after-rekey-2")
}

// TestTunnelOutboundSeq checks Tunnel.OutboundSeq reflects how many packets the
// Child SA has sent — the signal the driver uses for volume-based rekey (#6).
func TestTunnelOutboundSeq(t *testing.T) {
	encrIR := bytes.Repeat([]byte{0x01}, 32)
	integIR := bytes.Repeat([]byte{0x02}, 32)
	encrRI := bytes.Repeat([]byte{0x03}, 32)
	integRI := bytes.Repeat([]byte{0x04}, 32)
	sa, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 0x2222, 0x1111, encrIR, integIR, encrRI, integRI, 64)
	if err != nil {
		t.Fatal(err)
	}
	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })
	send := func(ctx context.Context, pkt []byte) error { return initConn.Send(ctx, pkt) }
	tun := tunnel.New(sa, send, tunConfig(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("255.255.255.0")))

	if got := tun.OutboundSeq(); got != 0 {
		t.Fatalf("fresh tunnel OutboundSeq = %d, want 0", got)
	}
	conn := tun.TunnelConn()
	for i := range 3 {
		if _, err := conn.Write([]byte("packet")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := tun.OutboundSeq(); got != 3 {
		t.Fatalf("OutboundSeq after 3 writes = %d, want 3", got)
	}
}

// newBareClient builds a Client with just enough wiring (logger, tunnel, a
// connless session) to drive netstack()/Close() without a live handshake.
func newBareClient(t *testing.T, ip string) *Client {
	t.Helper()
	encrIR := bytes.Repeat([]byte{0x01}, 32)
	integIR := bytes.Repeat([]byte{0x02}, 32)
	encrRI := bytes.Repeat([]byte{0x03}, 32)
	integRI := bytes.Repeat([]byte{0x04}, 32)
	sa, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 0x2222, 0x1111, encrIR, integIR, encrRI, integRI, 64)
	if err != nil {
		t.Fatal(err)
	}
	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })
	send := func(ctx context.Context, pkt []byte) error { return initConn.Send(ctx, pkt) }
	log := slog.New(slog.DiscardHandler)
	c := newClient(Config{Logger: log})
	c.session.Store(session.New(session.Config{Logger: log}))
	c.tun = tunnel.New(sa, send, tunConfig(netip.MustParseAddr(ip), netip.MustParseAddr("255.255.255.0")))
	return c
}

// TestDialContextCloseRace exercises finding #3: DialContext (which lazily builds
// the internal netstack) and Close racing on c.net/c.closed must be data-race
// free. Run under -race.
func TestDialContextCloseRace(t *testing.T) {
	c := newBareClient(t, "10.7.0.1")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		dctx, dcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer dcancel()
		_, _ = c.DialContext(dctx, "tcp", "10.7.0.2:80") // result irrelevant; the race matters
	}()
	go func() {
		defer wg.Done()
		_ = c.Close()
	}()
	wg.Wait()
}

// TestNetstackAfterCloseClosed is the deterministic half of finding #3: a
// netstack built strictly after Close must report the tunnel closed and must not
// be retained (no leaked, never-closed stack).
func TestNetstackAfterCloseClosed(t *testing.T) {
	c := newBareClient(t, "10.7.0.3")
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.netstack(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("netstack after Close: err = %v, want net.ErrClosed", err)
	}
	c.mu.Lock()
	leaked := c.net != nil
	c.mu.Unlock()
	if leaked {
		t.Fatal("a netstack built after Close was retained (leak)")
	}
}

// TestNetstackAfterUseClosedReturnsErr is the build-before-Close half of finding
// #4: a netstack built and used successfully, then torn down by Close, must
// report the tunnel closed on the next netstack() call (rather than handing back
// the stale, already-closed stack). The in-Do check only covers Close-before-
// build; this exercises the post-Do re-check.
func TestNetstackAfterUseClosedReturnsErr(t *testing.T) {
	c := newBareClient(t, "10.7.0.4")
	if _, err := c.netstack(); err != nil {
		t.Fatalf("first netstack(): %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.netstack(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("netstack after use+Close: err = %v, want net.ErrClosed", err)
	}
}

func tunConfig(ip, mask netip.Addr) tun2net.TunConfig {
	return tun2net.TunConfig{LocalIP: ip, Netmask: mask, MTU: 1400}
}

// tunConfig6 mirrors tunConfig for a v6-only assignment: only LocalIP6 is set
// (no v4, no gateway, no RemoteIP6), so go-tun2net's on-link fallback installs
// the v6 default route — the same shape Client.tunConfig produces for inner v6.
func tunConfig6(prefix netip.Prefix) tun2net.TunConfig {
	return tun2net.TunConfig{LocalIP6: prefix, MTU: 1400}
}

// TestRemoveInboundIdentityGuard is finding #4: a superseded SA's grace-removal
// timer must not evict a newer SA that happened to reuse the same (random) inbound
// SPI. removeInbound deletes only when the entry is still the exact pointer it was
// scheduled for.
func TestRemoveInboundIdentityGuard(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	const spi = 0x10
	key := bytes.Repeat([]byte{1}, 32)
	saOld, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 1, spi, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	saNew, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 2, spi, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}

	// A later rekey reused SPI 0x10 for saNew.
	c.resetInbound(spi, saNew)

	// The stale grace timer for the superseded saOld must NOT evict saNew.
	c.removeInbound(spi, saOld)
	if c.lookupInbound(spi) != saNew {
		t.Fatal("stale grace removal evicted the new SA that reused the SPI")
	}

	// A removal matching the current SA still works.
	c.removeInbound(spi, saNew)
	if c.lookupInbound(spi) != nil {
		t.Fatal("matching removal did not delete the SA")
	}
}

// TestDNSAccessorsReturnCopies pins that DNS()/DNS6() hand callers an independent
// copy of the assigned resolvers: mutating the returned slice must not corrupt
// the session's DNS state nor be visible to a later call.
func TestDNSAccessorsReturnCopies(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	s := session.New(session.Config{Logger: discardLogger()})
	v4 := netip.MustParseAddr("10.0.0.53")
	v6 := netip.MustParseAddr("fd00::53")
	s.SetAssigned(session.Assigned{
		DNS:  []netip.Addr{v4},
		DNS6: []netip.Addr{v6},
	})
	c.session.Store(s)

	got4 := c.DNS()
	got4[0] = netip.MustParseAddr("9.9.9.9")
	if c.DNS()[0] != v4 {
		t.Fatalf("DNS() exposed a mutable internal slice: second call = %v, want %v", c.DNS()[0], v4)
	}

	got6 := c.DNS6()
	got6[0] = netip.MustParseAddr("2606:4700:4700::1111")
	if c.DNS6()[0] != v6 {
		t.Fatalf("DNS6() exposed a mutable internal slice: second call = %v, want %v", c.DNS6()[0], v6)
	}
}

// TestInstallChildSAAEADSuite pins that ChildSAUpdate.Suite reaches the ESP
// layer: installing a rekeyed AES-GCM-256 Child SA must produce an outbound SA
// whose packets a partner keyed with the same 36-byte (key+salt) material
// decrypts, and an inbound registry entry that decrypts the partner's packets.
func TestInstallChildSAAEADSuite(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })
	c := newClient(Config{Logger: discardLogger(), ReplayWindow: 64})
	send := func(ctx context.Context, pkt []byte) error { return initConn.Send(ctx, pkt) }

	// Seed the data plane with the first (CBC) Child SA, as after IKE_AUTH.
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	oldSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 2, 1, oldKey, oldKey, oldKey, oldKey, 64)
	if err != nil {
		t.Fatal(err)
	}
	c.resetInbound(1, oldSA)
	c.tun = tunnel.New(oldSA, send, tunConfig(netip.MustParseAddr("10.6.0.1"), netip.MustParseAddr("255.255.255.0")))
	t.Cleanup(func() { c.tun.Close() })
	t.Cleanup(c.stopGraceTimers)

	// Rekey switches the suite to AES-GCM-256 (36-byte key+salt, no integ key).
	keyIR := bytes.Repeat([]byte{0x11}, 36)
	keyRI := bytes.Repeat([]byte{0x22}, 36)
	c.InstallChildSA(session.ChildSAUpdate{
		NewInSPI: 0xAAAA, NewOutSPI: 0xBBBB, OldInSPI: 1,
		Suite:   esp.SuiteAESGCM256,
		OutEncr: keyIR, InEncr: keyRI,
	})

	partner, err := esp.NewSA(esp.SuiteAESGCM256, 0xAAAA, 0xBBBB, keyRI, nil, keyIR, nil, 64)
	if err != nil {
		t.Fatal(err)
	}

	// Outbound: a tunnel write now leaves under the swapped-in GCM SA.
	inner := append([]byte{0x45}, bytes.Repeat([]byte{0xAB}, 27)...)
	if _, err := c.tun.TunnelConn().Write(inner); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := partner.Decrypt(raw)
	if err != nil {
		t.Fatalf("partner could not decrypt our GCM packet: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("outbound GCM round-trip mismatch")
	}

	// Inbound: the registry entry under the new SPI decrypts partner packets.
	inSA := c.lookupInbound(0xAAAA)
	if inSA == nil {
		t.Fatal("new inbound GCM SA not registered")
	}
	inner2 := append([]byte{0x45}, bytes.Repeat([]byte{0xCD}, 19)...)
	pkt, err := partner.Encrypt(inner2)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := inSA.Decrypt(pkt)
	if err != nil {
		t.Fatalf("inbound GCM decrypt: %v", err)
	}
	if !bytes.Equal(got2, inner2) {
		t.Fatal("inbound GCM round-trip mismatch")
	}
}
