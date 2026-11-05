package ipsec

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/n0madic/go-ipsec/internal/session"
)

// errClientClosing is returned by the redial loop when Close cancels superCtx, so
// the supervisor unwinds instead of retrying forever.
var errClientClosing = errors.New("ipsec: client closing")

// supervise is the reconnect supervisor: a single long-lived goroutine that
// re-establishes the tunnel whenever the IKE driver declares the peer dead. It is
// deliberately NOT a worker of the per-generation manager — reconnect calls
// mgr.Wait on the dead generation, so running on a separate goroutine keeps it
// from waiting on itself. It exits when Close cancels superCtx.
func (c *Client) supervise() {
	defer c.superWG.Done()
	for {
		select {
		case <-c.superCtx.Done():
			return
		case <-c.deathSig:
			c.reconnectFn()
		}
	}
}

// signalDeath notifies the supervisor that the current IKE SA is dead. The cap-1
// channel coalesces concurrent or duplicate notifications into a single
// reconnect. It is the IKE driver's onDead callback when auto-reconnect is on.
func (c *Client) signalDeath() {
	select {
	case c.deathSig <- struct{}{}:
	default:
	}
}

// isClosing reports whether Close has begun, so reconnect bails out early.
func (c *Client) isClosing() bool {
	select {
	case <-c.superCtx.Done():
		return true
	default:
		return false
	}
}

// reconnect re-establishes the tunnel in place after the peer is declared dead.
// It runs entirely on the supervisor goroutine, so it is the sole writer of c.mgr
// and the session pointer between generations. The same *tun2net.Net is reused;
// the netstack is re-addressed via Tunnel.Reconfigure, which force-closes stale
// connections (the peer's session is new even when our assigned IP is unchanged).
func (c *Client) reconnect() {
	if c.isClosing() {
		return
	}
	log := c.cfg.Logger
	log.Info("IKE SA declared dead, reconnecting")

	// (1) Stop the dead generation's workers. The driver returned right after
	// onDead; rx-demux and keepalive exit on ctx cancel. mgr.Wait blocks until the
	// socket-using driver has finished (it may send a best-effort DELETE).
	c.mu.Lock()
	oldMgr := c.mgr
	c.mu.Unlock()
	if oldMgr != nil {
		oldMgr.Shutdown()
		oldMgr.Wait()
	}

	// (2) Close the dead session, freeing its UDP socket/port. The redial opens a
	// fresh socket with a new source port, re-punching any stale NAT mapping.
	if old := c.curSession(); old != nil {
		_ = old.Close()
	}

	// (3) Drop the dead generation's grace timers before the inbound registry is
	// reset, so a late removeInbound cannot race the reset.
	c.stopGraceTimers()

	// (4) Redial with capped exponential backoff until success or Close.
	sess, err := c.redialWithBackoff()
	if err != nil {
		return // client closing
	}

	// (5) Build the new outbound ESP SA and swap in the new generation. The
	// inbound registry is reset to the new SPI only.
	child := sess.Child()
	sa, err := c.espSAFromChild(child)
	if err != nil {
		// A keyed handshake that yields an unbuildable SA is not expected; drop the
		// session and re-arm the supervisor to retry from scratch.
		log.Error("reconnect: failed to build Child SA, retrying", "err", err)
		_ = sess.Close()
		c.signalDeath()
		return
	}
	c.resetInbound(child.InitiatorSPI, sa)
	c.session.Store(sess)
	c.mu.Lock()
	c.localIP = sess.Assigned().IP
	c.mu.Unlock()

	// (6) Re-address the netstack in place (force-closing stale connections) and
	// fire the reconnect hooks. Always Reconfigure, never SwapSA: the server
	// session is new even when our assigned IP is unchanged.
	c.tun.Reconfigure(sa, c.tunConfig())
	c.fireRekey()

	// (7) Start the new generation's workers.
	c.startWorkers(sess)
	log.Info("reconnect complete", "localIP", c.LocalIP())
}

// redialWithBackoff repeatedly attempts a fresh handshake, each under a per-
// attempt timeout, with capped exponential backoff between tries. It returns the
// established session, or errClientClosing if Close cancels superCtx first.
func (c *Client) redialWithBackoff() (*session.Session, error) {
	backoff := c.cfg.ReconnectBackoffBase
	for attempt := 1; ; attempt++ {
		if c.isClosing() {
			return nil, errClientClosing
		}
		attemptCtx, cancel := context.WithTimeout(c.superCtx, c.cfg.ReconnectAttemptTimeout)
		sess, err := c.dialSession(attemptCtx)
		cancel()
		if err == nil {
			c.cfg.Logger.Info("reconnect attempt succeeded", "attempt", attempt)
			return sess, nil
		}
		if c.isClosing() {
			return nil, errClientClosing
		}
		c.cfg.Logger.Warn("reconnect attempt failed", "attempt", attempt, "backoff", backoff, "err", err)
		// Jitter each wait so a fleet of clients knocked out by a shared cause
		// (server restart, upstream blip) does not redial in lockstep against a
		// server that just came back — the same de-synchronisation the rekey
		// timers apply via jitteredDeadline in internal/session.
		if !c.sleep(jitterDuration(backoff)) {
			return nil, errClientClosing
		}
		backoff = min(backoff*2, c.cfg.ReconnectBackoffMax)
	}
}

// jitterDuration scales d by a random 0.85–1.0 factor (crypto/rand; falls back
// to the midpoint if the read fails).
func jitterDuration(d time.Duration) time.Duration {
	var b [2]byte
	frac := 0.5
	if _, err := rand.Read(b[:]); err == nil {
		frac = float64(binary.BigEndian.Uint16(b[:])) / 65536.0
	}
	return time.Duration(float64(d) * (0.85 + 0.15*frac))
}

// sleep waits for d or until superCtx is cancelled. It returns false if the
// client is closing, so the caller stops retrying.
func (c *Client) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.superCtx.Done():
		return false
	case <-t.C:
		return true
	}
}
