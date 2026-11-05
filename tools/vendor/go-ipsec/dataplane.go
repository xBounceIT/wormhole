package ipsec

import (
	"context"
	"encoding/binary"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/natt"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	"github.com/n0madic/go-ipsec/internal/workers"
	tun2net "github.com/n0madic/go-tun2net"
)

// childSAGrace is how long a superseded inbound Child SA stays installed after a
// rekey cutover, so packets the peer sent on it before switching are still
// accepted (zero-loss rekey).
const childSAGrace = 30 * time.Second

// startDataPlane builds the first ESP SA and the PacketTunnel from the
// established Child SA, then launches the reconnect supervisor (when enabled) and
// the first generation of data-plane workers. It must run after a successful
// IKE_AUTH (the Phase 2 ordering invariant: Config() is populated before
// tun2net.New).
func (c *Client) startDataPlane() error {
	sess := c.curSession()
	child := sess.Child()
	sa, err := c.espSAFromChild(child)
	if err != nil {
		return err
	}
	c.resetInbound(child.InitiatorSPI, sa)
	// The tunnel sends via c.sendESP, an indirection over the current session, so
	// a reconnect can swap the session without rebuilding the tunnel.
	c.tun = tunnel.New(sa, c.sendESP, c.tunConfig())

	// Launch the supervisor before the workers so it is ready to consume a death
	// signal (the cap-1 deathSig would buffer one anyway, but this keeps intent
	// clear). Legacy mode (AutoReconnect disabled) runs no supervisor.
	if c.cfg.autoReconnectEnabled() {
		c.superWG.Add(1)
		go c.supervise()
	}
	c.startWorkers(sess)
	return nil
}

// espSAFromChild builds the bidirectional ESP SA for a Child SA, oriented for the
// initiator (we send to ResponderSPI, the peer sends to InitiatorSPI).
func (c *Client) espSAFromChild(child *session.ChildSA) (*esp.SA, error) {
	return esp.NewSA(
		child.Suite,
		child.ResponderSPI, child.InitiatorSPI,
		child.Keys.EncrIR, child.Keys.IntegIR,
		child.Keys.EncrRI, child.Keys.IntegRI,
		c.cfg.ReplayWindow,
	)
}

// startWorkers wires the session's data plane and starts one generation of
// workers (rx demux, IKE driver, NAT keepalive) under a fresh manager parented by
// superCtx. The manager is published under mu so Close (and the next reconnect)
// can stop it. Each generation gets its own IKE inbox, passed to both the rx
// demux and the driver, so a reconnect's swap never crosses generations on the
// hot path. The driver's death callback re-establishes the tunnel via the
// supervisor when auto-reconnect is enabled, or tears the Client down otherwise.
func (c *Client) startWorkers(sess *session.Session) {
	sess.SetDataPlane(c)
	inbox := make(chan []byte, 16)

	onDead := c.signalDeath
	if !c.cfg.autoReconnectEnabled() {
		// Close must run off the driver goroutine (its mgr.Wait would deadlock
		// waiting on the very goroutine invoking onDead). Log the teardown and
		// any error: with auto-reconnect off this is the only trace of a dead
		// peer — the caller otherwise just starts seeing net.ErrClosed.
		onDead = func() {
			go func() {
				c.cfg.Logger.Warn("IKE SA declared dead, tearing the client down (auto-reconnect disabled)")
				if err := c.Close(); err != nil {
					c.cfg.Logger.Warn("teardown after peer death failed", "err", err)
				}
			}()
		}
	}
	ownerOnDead := onDead
	onDead = func() {
		if c.cfg.OnDead != nil {
			c.cfg.OnDead()
		}
		ownerOnDead()
	}
	// A worker panic is recovered by the manager, which would otherwise only cancel
	// this generation's context — leaving deathSig empty so the supervisor never
	// reconnects and the tunnel stays silently dead. Route the panic into the same
	// death path as a clean death so auto-reconnect (or Close) still fires.
	mgr := workers.NewManager(c.superCtx, c.cfg.Logger,
		workers.WithPanicHandler(func(string, any) { onDead() }))
	c.mu.Lock()
	c.mgr = mgr
	c.mu.Unlock()
	// Go returns false only on a manager that has already been shut down —
	// unreachable today (Close waits out the supervisor before touching the
	// manager), but a silently rejected worker would leave the tunnel
	// half-started with no diagnostic if that invariant ever breaks.
	start := func(name string, fn func(context.Context)) {
		if !mgr.Go(name, fn) {
			c.cfg.Logger.Error("worker rejected by a shut-down manager", "worker", name)
		}
	}
	start("rx-demux", func(ctx context.Context) { c.rxDemux(ctx, inbox) })
	start("ike-driver", func(ctx context.Context) { sess.Driver(ctx, inbox, onDead) })
	if c.cfg.KeepAlive > 0 {
		start("nat-keepalive", c.keepaliveLoop)
	}
}

// sendESP transmits a raw ESP datagram via the current session. The tunnel holds
// this indirection (rather than a session method bound at build time) so a
// reconnect can swap the session in place.
func (c *Client) sendESP(ctx context.Context, pkt []byte) error {
	s := c.curSession()
	if s == nil {
		return net.ErrClosed
	}
	return s.SendESP(ctx, pkt)
}

// resetInbound replaces the inbound registry with a single fresh Child SA,
// serialized under inboundMu with the grace-removal timer so a stale removal from
// a prior generation cannot lose the new entry.
func (c *Client) resetInbound(spi uint32, sa *esp.SA) {
	c.inboundMu.Lock()
	c.inbound.Store(&map[uint32]*esp.SA{spi: sa})
	c.inboundMu.Unlock()
}

// stopGraceTimers stops and forgets every pending grace-removal timer. Called on
// reconnect (before resetting the registry) and on Close.
func (c *Client) stopGraceTimers() {
	c.graceMu.Lock()
	for _, t := range c.graceTimers {
		t.Stop()
	}
	c.graceTimers = nil
	c.graceMu.Unlock()
}

// tunConfig maps the current session's responder-assigned configuration into a
// tun2net.TunConfig.
//
// LocalIP6 is set from the assigned v6 prefix (zero when none → go-tun2net's
// syncFamily removes any v6 address on reconnect). RemoteIP6 is deliberately
// left zero: setting a v6 next-hop adds a v6 gateway route, which makes
// buildRoutes skip its on-link fallback and would drop the v4 default route we
// rely on (go-ipsec never sets Gateway). With RemoteIP6 unset, the fallback
// installs on-link defaults for both families from LocalIP/LocalIP6.
func (c *Client) tunConfig() tun2net.TunConfig {
	a := c.curSession().Assigned()
	return tun2net.TunConfig{
		LocalIP:  a.IP,
		Netmask:  a.Netmask,
		Gateway:  a.Gateway,
		LocalIP6: a.IP6,
		DNS:      append(append([]netip.Addr(nil), a.DNS...), a.DNS6...),
		MTU:      c.cfg.MTU,
	}
}

// rxDemux is the sole reader of the socket on the data plane. It classifies each
// datagram and delivers ESP inline: the inbound SA is looked up by its SPI so
// that, during a rekey cutover, both the old and new Child SAs decrypt. Inbound
// ESP is lossy — a lookup/decrypt/replay failure drops the packet and bumps a
// counter, never blocking the reader. IKE datagrams go to the session driver.
func (c *Client) rxDemux(ctx context.Context, inbox chan<- []byte) {
	for {
		// Load the session once per iteration: a reconnect stops this worker before
		// swapping the session, but loading per-read keeps the read race-free if
		// that ordering ever changes.
		sess := c.curSession()
		if sess == nil {
			return
		}
		raw, err := sess.RecvRaw(ctx)
		if err != nil {
			return // context cancelled or transport closed
		}
		kind, payload := natt.Classify(raw)
		switch kind {
		case natt.KindESP:
			if len(payload) < 4 {
				c.rxDrops.Add(1)
				continue
			}
			spi := binary.BigEndian.Uint32(payload[:4])
			sa := c.lookupInbound(spi)
			if sa == nil {
				c.rxDrops.Add(1)
				continue
			}
			inner, err := sa.Decrypt(payload)
			if err != nil {
				c.rxDrops.Add(1)
				continue
			}
			c.lastDataInbound.Store(time.Now().UnixNano())
			c.tun.DeliverInbound(inner)
		case natt.KindIKE:
			// Hand to this generation's session driver (DPD / DELETE / rekey).
			// Non-blocking: if the driver is busy, drop — IKE control is
			// retransmitted.
			select {
			case inbox <- append([]byte(nil), payload...):
			default:
				c.cfg.Logger.Debug("ike inbox full, dropping IKE datagram")
			}
		case natt.KindKeepalive:
			// server keepalive; nothing to do
		}
	}
}

// LastDataInbound reports when the most recent inbound ESP packet was decrypted,
// or the zero time if none yet. The session driver uses it so DPD treats a
// data-plane-active tunnel as alive. It implements session.DataPlane.
func (c *Client) LastDataInbound() time.Time {
	ns := c.lastDataInbound.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// lookupInbound returns the inbound Child SA registered for an SPI, or nil.
func (c *Client) lookupInbound(spi uint32) *esp.SA {
	m := c.inbound.Load()
	if m == nil {
		return nil
	}
	return (*m)[spi]
}

// ChildSAVolume reports the outbound ESP sequence number of the live Child SA so
// the session driver can rekey on data volume before the counter nears
// exhaustion. It implements session.DataPlane.
func (c *Client) ChildSAVolume() uint32 { return c.tun.OutboundSeq() }

// removeInbound deletes the inbound Child SA registered under spi via a
// copy-on-write swap, serialized under inboundMu with InstallChildSA's add so a
// concurrent read-modify-write can't lose either operation. It deletes only when
// the entry at spi is still the exact want pointer: if a later rekey reused this
// (random) SPI for a fresh SA, a stale grace timer must not evict that new SA. A
// no-op if spi is absent or holds a different SA.
func (c *Client) removeInbound(spi uint32, want *esp.SA) {
	c.inboundMu.Lock()
	defer c.inboundMu.Unlock()
	old := c.inbound.Load()
	if cur, ok := (*old)[spi]; !ok || cur != want {
		return
	}
	next := make(map[uint32]*esp.SA, len(*old))
	for k, v := range *old {
		if k != spi {
			next[k] = v
		}
	}
	c.inbound.Store(&next)
	c.cfg.Logger.Debug("removed inbound Child SA", "spi", spi)
}

// InstallChildSA installs a rekeyed Child SA: it adds the new inbound SA to the
// registry, swaps the outbound SA in the tunnel (atomic cutover), schedules
// removal of the superseded inbound SA after the grace period, and fires the
// rekey hooks. It implements session.DataPlane and is called only from the IKE
// driver goroutine.
func (c *Client) InstallChildSA(u session.ChildSAUpdate) {
	sa, err := esp.NewSA(u.Suite, u.NewOutSPI, u.NewInSPI, u.OutEncr, u.OutInteg, u.InEncr, u.InInteg, c.cfg.ReplayWindow)
	if err != nil {
		c.cfg.Logger.Error("rekey: failed to build new Child SA", "err", err)
		return
	}
	// Copy-on-write add (rxDemux reads the registry lock-free). Serialize with
	// the grace-removal timer so concurrent read-modify-writes can't lose either
	// the add here or a removal.
	c.inboundMu.Lock()
	old := c.inbound.Load()
	superseded := (*old)[u.OldInSPI] // captured for an identity-guarded grace removal
	next := make(map[uint32]*esp.SA, len(*old)+1)
	maps.Copy(next, *old)
	next[u.NewInSPI] = sa
	c.inbound.Store(&next)
	c.inboundMu.Unlock()

	// Atomic outbound cutover. The layer-3 config is unchanged on rekey, so this
	// must NOT fire OnReconfigure (which the netstack treats as a re-address and
	// would tear down active connections).
	c.tun.SwapSA(sa)
	c.fireRekey()
	c.cfg.Logger.Info("Child SA rekeyed",
		"newInSPI", u.NewInSPI, "newOutSPI", u.NewOutSPI, "oldInSPI", u.OldInSPI, "suite", u.Suite)

	// Skip grace-removal when a fresh random NewInSPI collided with OldInSPI:
	// removing it would delete the inbound SA just installed above, black-holing
	// inbound ESP until the next rekey.
	if u.OldInSPI != 0 && u.OldInSPI != u.NewInSPI {
		c.scheduleInboundRemoval(u.OldInSPI, superseded)
	}
}

// scheduleInboundRemoval drops the superseded inbound SA (the exact sa pointer)
// after the grace period; the identity check in removeInbound ensures a later
// rekey reusing the same SPI is not evicted by this timer.
func (c *Client) scheduleInboundRemoval(spi uint32, sa *esp.SA) {
	var t *time.Timer
	t = time.AfterFunc(childSAGrace, func() {
		c.removeInbound(spi, sa)
		// Prune the fired timer so graceTimers doesn't grow without bound over a
		// long-lived tunnel's rekeys (it is otherwise only cleared on Close/reconnect).
		c.graceMu.Lock()
		c.graceTimers = slices.DeleteFunc(c.graceTimers, func(x *time.Timer) bool { return x == t })
		c.graceMu.Unlock()
	})
	c.graceMu.Lock()
	c.graceTimers = append(c.graceTimers, t)
	c.graceMu.Unlock()
}

// fireRekey invokes the registered OnRekey callbacks.
func (c *Client) fireRekey() {
	c.mu.Lock()
	hooks := append([]func(){}, c.onRekey...)
	c.mu.Unlock()
	for _, h := range hooks {
		h()
	}
}

// keepaliveLoop sends NAT keepalives to keep the UDP mapping open.
func (c *Client) keepaliveLoop(ctx context.Context) {
	t := time.NewTicker(c.cfg.KeepAlive)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := c.curSession()
			if s == nil {
				return
			}
			if err := s.SendKeepalive(ctx); err != nil {
				if ctx.Err() != nil {
					return // shutting down
				}
				// A transient send error (a network blip, buffer pressure, a route
				// flap) must not permanently disable keepalives — that would let the
				// NAT mapping expire and the tunnel go one-way dead. Retry next tick.
				c.cfg.Logger.Debug("nat-keepalive: send failed, retrying next tick", "err", err)
			}
		}
	}
}
