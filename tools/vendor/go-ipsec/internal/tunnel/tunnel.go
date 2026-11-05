// Package tunnel adapts the ESP data plane to go-tun2net's PacketTunnel
// contract: one Write == one outbound IP datagram (ESP-encrypted and sent), and
// each decrypted inbound datagram is handed to the registered fast-path handler.
package tunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	tun2net "github.com/n0madic/go-tun2net"
)

// SendFunc transmits a raw ESP datagram to the peer (UDP-encapsulated on 4500,
// no non-ESP marker).
type SendFunc func(ctx context.Context, pkt []byte) error

// Tunnel implements tun2net.PacketTunnel over a Child SA.
type Tunnel struct {
	conn *espConn

	mu          sync.Mutex
	cfg         tun2net.TunConfig
	inbound     func(ip []byte)
	reconfigure map[int]func(tun2net.TunConfig)
	nextHook    int
}

// New builds a Tunnel from an ESP SA, a send function, and the assigned layer-3
// configuration.
func New(sa *esp.SA, send SendFunc, cfg tun2net.TunConfig) *Tunnel {
	return &Tunnel{
		conn:        newESPConn(sa, send),
		cfg:         cfg,
		reconfigure: make(map[int]func(tun2net.TunConfig)),
	}
}

// TunnelConn returns the IP-packet pipe (one Write == one outbound datagram).
func (t *Tunnel) TunnelConn() net.Conn { return t.conn }

// Config returns the current layer-3 assignment.
func (t *Tunnel) Config() tun2net.TunConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// SetInbound registers the fast-path inbound handler and returns a detach func.
func (t *Tunnel) SetInbound(fn func(ip []byte)) (detach func()) {
	t.mu.Lock()
	t.inbound = fn
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		t.inbound = nil
		t.mu.Unlock()
	}
}

// OnReconfigure registers a hook fired when the layer-3 assignment changes.
func (t *Tunnel) OnReconfigure(fn func(tun2net.TunConfig)) (detach func()) {
	t.mu.Lock()
	id := t.nextHook
	t.nextHook++
	t.reconfigure[id] = fn
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.reconfigure, id)
		t.mu.Unlock()
	}
}

// DeliverInbound is called by the rx demux with a decrypted inner IP datagram.
// The slice may be reused after return (go-tun2net copies).
func (t *Tunnel) DeliverInbound(ip []byte) {
	t.mu.Lock()
	h := t.inbound
	t.mu.Unlock()
	if h != nil {
		h(ip)
	}
}

// SwapSA atomically swaps the outbound ESP SA without touching the layer-3
// configuration. Used for SA rekey, where the assigned address is unchanged —
// it must NOT fire OnReconfigure, which the netstack treats as a re-address and
// would tear down every active connection.
func (t *Tunnel) SwapSA(sa *esp.SA) { t.conn.swapSA(sa) }

// OutboundSeq returns the current outbound ESP sequence number of the live SA,
// i.e. how many packets this Child SA has sent. The driver uses it for
// volume-based rekey.
func (t *Tunnel) OutboundSeq() uint32 { return t.conn.sa.load().Seq() }

// Reconfigure swaps the ESP SA AND the assigned config, firing the registered
// OnReconfigure hooks. Use only when the layer-3 assignment actually changes
// (reconnect / MOBIKE), not for a plain SA rekey.
func (t *Tunnel) Reconfigure(sa *esp.SA, cfg tun2net.TunConfig) {
	t.conn.swapSA(sa)
	t.mu.Lock()
	t.cfg = cfg
	hooks := make([]func(tun2net.TunConfig), 0, len(t.reconfigure))
	for _, h := range t.reconfigure {
		hooks = append(hooks, h)
	}
	t.mu.Unlock()
	for _, h := range hooks {
		h(cfg)
	}
}

// Close tears down the conn (unblocking any pending Read).
func (t *Tunnel) Close() error { return t.conn.Close() }

// espConn is the net.Conn handed to the netstack. Write ESP-encrypts and sends;
// Read blocks until the deadline or Close (inbound is delivered out-of-band via
// the tunnel's fast-path handler).
type espConn struct {
	sa   atomicSA
	send SendFunc

	// sendCtx is canceled by Close so a Write blocked inside the transport
	// send (e.g. a custom PacketDialer under backpressure) is interrupted
	// instead of outliving the conn — Close is only checked at Write entry,
	// so without this a blocked send would never observe it.
	sendCtx    context.Context
	sendCancel context.CancelFunc

	mu           sync.Mutex
	readDeadline time.Time
	wake         chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
}

func newESPConn(sa *esp.SA, send SendFunc) *espConn {
	c := &espConn{send: send, closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	c.sendCtx, c.sendCancel = context.WithCancel(context.Background())
	c.sa.store(sa)
	return c
}

func (c *espConn) swapSA(sa *esp.SA) { c.sa.store(sa) }

// Write encrypts one inner IP datagram into an ESP packet and sends it. It never
// reports a partial write and is safe for concurrent callers (only the ESP
// sequence counter is shared, and it is atomic).
func (c *espConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt, err := c.sa.load().Encrypt(p)
	if err != nil {
		return 0, err
	}
	if err := c.send(c.sendCtx, pkt); err != nil {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}
		return 0, err
	}
	return len(p), nil
}

// Read blocks until the read deadline elapses or the conn is closed. Inbound
// datagrams are delivered via Tunnel.DeliverInbound, so Read never yields data;
// it exists to give the netstack readLoop a clean blocking point.
func (c *espConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		dl := c.readDeadline
		c.mu.Unlock()
		if dl.IsZero() {
			select {
			case <-c.closed:
				return 0, net.ErrClosed
			case <-c.wake:
				continue // deadline changed; re-evaluate
			}
		}
		d := time.Until(dl)
		if d <= 0 {
			return 0, timeoutError{}
		}
		// Stop the timer each iteration rather than deferring; this Read blocks
		// for the conn's lifetime, so a deferred Stop would let one timer leak
		// per SetReadDeadline change.
		tm := time.NewTimer(d)
		select {
		case <-c.closed:
			tm.Stop()
			return 0, net.ErrClosed
		case <-tm.C:
			return 0, timeoutError{}
		case <-c.wake:
			tm.Stop() // deadline changed; re-evaluate
		}
	}
}

func (c *espConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.sendCancel()
	})
	return nil
}

func (c *espConn) LocalAddr() net.Addr  { return espAddr{} }
func (c *espConn) RemoteAddr() net.Addr { return espAddr{} }

func (c *espConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return nil
}

func (c *espConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func (c *espConn) SetWriteDeadline(time.Time) error { return nil }

type espAddr struct{}

func (espAddr) Network() string { return "esp" }
func (espAddr) String() string  { return "esp-tunnel" }

type timeoutError struct{}

func (timeoutError) Error() string   { return "esp: read deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// atomicSA is a tiny lock-free holder for the current ESP SA so rekey can swap it
// without locking the hot Write path beyond an atomic pointer load.
type atomicSA struct {
	p atomic.Pointer[esp.SA]
}

func (a *atomicSA) store(sa *esp.SA) { a.p.Store(sa) }
func (a *atomicSA) load() *esp.SA    { return a.p.Load() }

// Compile-time check that Tunnel satisfies the data-plane contract (and
// io.Closer for tun2net.Net.CloseAll).
var (
	_ tun2net.PacketTunnel       = (*Tunnel)(nil)
	_ interface{ Close() error } = (*Tunnel)(nil)
)
