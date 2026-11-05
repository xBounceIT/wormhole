// Package ipsec is a pure-Go userspace IKEv2 + ESP VPN client (initiator only).
//
// The IKEv2 control plane and the ESP data plane both run in this process; the
// tunnel is exposed as an ordinary DialContext via the shared go-tun2net
// netstack. There is no kernel XFRM and no strongSwan/charon daemon.
//
// Typical use:
//
//	client, err := ipsec.Dial(ctx, ipsec.Config{
//	    Server:   "vpn.example.com:500",
//	    LocalID:  ipsec.Email("user@example.com"),
//	    EAP:      ipsec.EAPMSCHAPv2{Username: "user", Password: "secret"},
//	})
//	// net, _ := tun2net.New(client.Tunnel(), logger)
//	// conn, _ := net.DialContext(ctx, "tcp", "example.org:80")
package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"github.com/n0madic/go-ipsec/internal/secretmem"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	"github.com/n0madic/go-ipsec/internal/workers"
	tun2net "github.com/n0madic/go-tun2net"
)

// PacketDialer opens the underlying packet socket the tunnel runs over. A nil
// Config.Transport uses the host UDP stack; consumers (e.g. mihomo) inject
// their own dialer to route the outer datagrams.
type PacketDialer interface {
	DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
}

// Client is an established (or establishing) IKEv2 tunnel.
type Client struct {
	cfg Config

	// session is the live IKE session for the current generation. The supervisor
	// swaps it on reconnect; hot-path readers (sendESP, rxDemux) load it lock-free
	// via curSession. It is nil before the first handshake and after Close.
	session atomic.Pointer[session.Session]

	// tun is built once in startDataPlane and never reassigned: a reconnect
	// re-addresses it in place via Reconfigure, so it is safe to read without a lock.
	tun     *tunnel.Tunnel
	rxDrops atomic.Uint64

	// inbound maps an inbound ESP SPI to its Child SA. During a rekey cutover
	// both the old and new SAs are present so in-flight packets on the old SA
	// still decrypt. rxDemux reads it lock-free via the atomic pointer; the
	// copy-on-write writers (InstallChildSA on the driver goroutine, the
	// grace-removal timer, and the reconnect reset) serialize under inboundMu so a
	// concurrent read-modify-write can't lose an update.
	inbound   atomic.Pointer[map[uint32]*esp.SA]
	inboundMu sync.Mutex

	// lastDataInbound is the UnixNano time of the most recent decrypted inbound
	// ESP packet, read by the session driver so DPD counts data-plane liveness
	// and does not tear down a tunnel that is busy on ESP but quiet on IKE.
	lastDataInbound atomic.Int64

	graceMu     sync.Mutex
	graceTimers []*time.Timer

	// netOnce ensures the lazy internal netstack is built at most once.
	netOnce sync.Once

	mu      sync.Mutex
	net     *tun2net.Net     // guarded by mu
	netErr  error            // guarded by mu
	closed  bool             // guarded by mu; set by Close so a netstack() racing it closes its own result
	onRekey []func()         // guarded by mu
	localIP netip.Addr       // guarded by mu
	mgr     *workers.Manager // guarded by mu; swapped each generation by the supervisor

	// Supervisor lifecycle. superCtx parents every generation's worker manager and
	// is derived from context.Background (NOT the Dial ctx), so a cancelled Dial
	// ctx never tears an established tunnel down. superCancel is fired only by
	// Close; superWG tracks the supervisor goroutine; deathSig (cap 1) carries
	// driver death notifications, coalescing duplicates into a single reconnect.
	superCtx    context.Context
	superCancel context.CancelFunc
	superWG     sync.WaitGroup
	deathSig    chan struct{}

	// Test seams, set by newClient to the production implementations. reconnectFn
	// is what the supervisor invokes on each death; dialSession performs one full
	// handshake. Tests substitute these to drive the supervisor deterministically.
	reconnectFn func()
	dialSession func(ctx context.Context) (*session.Session, error)

	closeOnce sync.Once
}

// newClient builds an un-dialed Client with its supervisor lifecycle and the
// production test seams wired. The handshake and data plane are started by Dial.
func newClient(cfg Config) *Client {
	c := &Client{cfg: cfg, deathSig: make(chan struct{}, 1)}
	c.superCtx, c.superCancel = context.WithCancel(context.Background())
	c.dialSession = c.defaultDialSession
	c.reconnectFn = c.reconnect
	return c
}

// Dial brings up a tunnel: IKE_SA_INIT, IKE_AUTH (EAP-MSCHAPv2 or PSK), and the
// first Child SA. It blocks until the Child SA is installed or ctx is cancelled.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := newClient(cfg)
	sess, err := c.dialSession(ctx)
	if err != nil {
		c.superCancel()
		return nil, err
	}
	c.session.Store(sess)
	c.mu.Lock()
	c.localIP = sess.Assigned().IP
	c.mu.Unlock()
	if err := c.startDataPlane(); err != nil {
		_ = sess.Close()
		c.superCancel()
		return nil, err
	}
	return c, nil
}

// defaultDialSession performs a full IKE handshake (IKE_SA_INIT + IKE_AUTH) on a
// fresh socket and returns the established session. It is the production value of
// c.dialSession; tests substitute a scripted dialer through the seam.
func (c *Client) defaultDialSession(ctx context.Context) (*session.Session, error) {
	sess := session.New(toSessionConfig(c.cfg))
	if err := sess.IKESAInit(ctx); err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.IKEAuth(ctx); err != nil {
		_ = sess.Close()
		return nil, err
	}
	return sess, nil
}

// curSession returns the live IKE session for the current generation, or nil
// before the first handshake / after Close. Hot-path readers load it lock-free.
func (c *Client) curSession() *session.Session { return c.session.Load() }

// Tunnel returns the PacketTunnel the netstack runs over. Advanced consumers can
// wire their own go-tun2net stack with tun2net.New(client.Tunnel(), logger);
// most callers should use DialContext, which manages an internal stack. Do not
// mix the two over the same Client.
func (c *Client) Tunnel() tun2net.PacketTunnel { return c.tun }

// DialContext dials through the tunnel using a lazily-created internal netstack.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n, err := c.netstack()
	if err != nil {
		return nil, err
	}
	return n.DialContext(ctx, network, addr)
}

// Net returns the internal go-tun2net stack, creating it on first use.
func (c *Client) Net() (*tun2net.Net, error) { return c.netstack() }

func (c *Client) netstack() (*tun2net.Net, error) {
	c.netOnce.Do(func() {
		// Build outside the lock (tun2net.New can block), then publish under mu so
		// a concurrent Close either observes the stack here or is observed by us.
		n, err := tun2net.New(c.tun, c.cfg.Logger)
		c.mu.Lock()
		if c.closed {
			// Close already ran and won't see this stack — close it here so its
			// goroutines don't leak, and report the tunnel as closed.
			c.netErr = net.ErrClosed
			c.mu.Unlock()
			if n != nil {
				_ = n.Close()
			}
			return
		}
		c.net, c.netErr = n, err
		c.mu.Unlock()
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	// Close may have run after netOnce built and published the stack (the in-Do
	// check only covers Close-before-build). In that ordering Close already closed
	// c.net, so report the tunnel as closed rather than handing back a stale stack.
	if c.closed {
		return nil, net.ErrClosed
	}
	return c.net, c.netErr
}

// RxDrops returns the number of inbound ESP packets dropped by decrypt/replay
// failures.
func (c *Client) RxDrops() uint64 { return c.rxDrops.Load() }

// LocalIP returns the address assigned by the responder's configuration
// payload. It is the zero Addr until the Child SA is established.
func (c *Client) LocalIP() netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localIP
}

// DNS returns the IPv4 resolvers the responder pushed via the configuration
// payload. After a reconnect it reflects the current session's assignment; it is
// empty before the first handshake / after Close.
func (c *Client) DNS() []netip.Addr {
	s := c.curSession()
	if s == nil {
		return nil
	}
	// Clone: Assigned() returns the struct by value but its slice fields still
	// share the session's backing arrays. Hand callers a copy so they cannot
	// mutate live session DNS state or race the driver goroutine.
	return slices.Clone(s.Assigned().DNS)
}

// DNS6 returns the IPv6 resolvers the responder pushed via the configuration
// payload, or nil when none were assigned (e.g. RequestIPv6 disabled or a
// v4-only server). After a reconnect it reflects the current session.
func (c *Client) DNS6() []netip.Addr {
	s := c.curSession()
	if s == nil {
		return nil
	}
	// Clone for the same reason as DNS(): don't expose the session's backing array.
	return slices.Clone(s.Assigned().DNS6)
}

// LocalIP6 returns the inner IPv6 address + prefix the responder assigned via
// the configuration payload, or the zero Prefix when none was assigned (a
// v4-only tunnel). After a reconnect it reflects the current session.
func (c *Client) LocalIP6() netip.Prefix {
	s := c.curSession()
	if s == nil {
		return netip.Prefix{}
	}
	return s.Assigned().IP6
}

// OnRekey registers a callback fired after each successful IKE/Child SA rekey.
func (c *Client) OnRekey(fn func()) {
	if fn == nil {
		return
	}
	c.mu.Lock()
	c.onRekey = append(c.onRekey, fn)
	c.mu.Unlock()
}

// Close tears the tunnel down. The shutdown order is critical: it first cancels
// the supervisor (interrupting any in-flight reconnect backoff/redial) and waits
// for it to exit, so no goroutine swaps the manager or session out from under the
// rest of the teardown; then it stops the current generation's workers (the IKE
// driver sends its graceful DELETE on ctx.Done, while the socket is still open);
// then it closes the netstack, tunnel, grace timers and the IKE session.
func (c *Client) Close() error {
	var errs []error
	c.closeOnce.Do(func() {
		// (1) Mark closed and cancel the supervisor context. This interrupts an
		// in-flight reconnect, cancels every generation's worker manager (so the
		// driver begins its graceful DELETE), and lets a netstack() racing this
		// either observe c.closed or be observed via c.net below.
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.superCancel()

		// (2) Wait for the supervisor to exit. After this no goroutine swaps c.mgr
		// or the session pointer, so the snapshots below are stable.
		c.superWG.Wait()

		// (3) Stop the current generation's workers and wait for the driver's
		// graceful DELETE (it needs the socket, closed in step 4).
		c.mu.Lock()
		mgr := c.mgr
		c.mu.Unlock()
		if mgr != nil {
			mgr.Shutdown()
			mgr.Wait()
		}

		// (4) Tear down the netstack, tunnel, grace timers and session.
		c.mu.Lock()
		n := c.net
		c.mu.Unlock()
		if n != nil {
			if err := n.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.tun != nil {
			if err := c.tun.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		c.stopGraceTimers()
		if s := c.curSession(); s != nil {
			if err := s.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

// toSessionConfig translates the public Config into the internal session form.
// Called per dial (including every reconnect), so each session gets its own
// credential copies and may wipe them on Close without affecting the next one.
func toSessionConfig(cfg Config) session.Config {
	sc := session.Config{
		FortinetSAML:     cfg.FortinetSAML,
		Server:           cfg.Server,
		LocalID:          session.WireID{Type: cfg.LocalID.idType(), Data: cfg.LocalID.idData()},
		RemoteID:         session.WireID{Type: cfg.RemoteID.idType(), Data: cfg.RemoteID.idData()},
		EAPUser:          cfg.EAP.Username,
		RootCAs:          cfg.RootCAs,
		MTU:              cfg.MTU,
		Logger:           cfg.Logger,
		KeepAlive:        cfg.KeepAlive,
		DPDTimeout:       cfg.DPDTimeout,
		RekeyLifetime:    cfg.RekeyLifetime,
		IKERekeyLifetime: cfg.IKERekeyLifetime,
		ReplayWindow:     cfg.ReplayWindow,
		RekeyMaxPackets:  cfg.RekeyMaxPackets,
		ChildSAPFS:       cfg.ChildSAPFS,
		ESPSuites:        espSuitesFromConfig(cfg.ESPCipherSuites),
		IKESuites:        ikeSuitesFromConfig(cfg.IKECipherSuites),
		RequestIPv6:      cfg.requestIPv6Enabled(),
		RetransmitBase:   DefaultRetransmitBase,
		RetransmitMax:    DefaultRetransmitMax,
		RetransmitTries:  DefaultRetransmitTries,
	}
	// Copy the credentials inside secretmem.Do: the session's long-lived
	// byte copies are then runtime-tracked (erased by the GC once the session
	// is dropped) and are additionally wiped by Session.Close. The caller's
	// original strings remain untracked — documented in internal/secretmem.
	secretmem.Do(func() {
		sc.ServerPSK = []byte(cfg.ServerPSK)
		if cfg.PSK != "" {
			sc.PSK = []byte(cfg.PSK)
		}
		if cfg.EAP.Password != "" {
			sc.EAPPass = []byte(cfg.EAP.Password)
		}
	})
	if cfg.Transport != nil {
		sc.Dialer = cfg.Transport.DialPacket
	}
	return sc
}

// espSuitesFromConfig maps the public ESPCipherSuites (already validated) into
// internal ESP suite ids, preserving the preference order; nil stays nil (the
// session then offers its full built-in table).
func espSuitesFromConfig(suites []CipherSuite) []esp.Suite {
	if len(suites) == 0 {
		return nil
	}
	out := make([]esp.Suite, 0, len(suites))
	for _, cs := range suites {
		if id, ok := cs.espSuite(); ok {
			out = append(out, id)
		}
	}
	return out
}

// ikeSuitesFromConfig maps the public IKECipherSuites (already validated) into
// internal IKE SA suite ids, preserving the preference order; nil stays nil
// (the session then offers its full built-in table).
func ikeSuitesFromConfig(suites []CipherSuite) []ikesa.Suite {
	if len(suites) == 0 {
		return nil
	}
	out := make([]ikesa.Suite, 0, len(suites))
	for _, cs := range suites {
		if id, ok := cs.ikeSuite(); ok {
			out = append(out, id)
		}
	}
	return out
}
