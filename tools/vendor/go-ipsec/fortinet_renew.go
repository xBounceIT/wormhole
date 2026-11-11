package ipsec

import (
	"errors"
	"slices"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikev1"
)

// Each IKE generation owns its event queues and credential copy. Retired
// callbacks cannot install stale keys or report death for its replacement.
type legacyControl struct {
	session *ikev1.Session
	ready   chan ikev1.Result
	failed  chan error
	started atomic.Bool
	closed  atomic.Bool
}

func newLegacyControl(cfg ikev1.Config) *legacyControl {
	c := &legacyControl{ready: make(chan ikev1.Result, 1), failed: make(chan error, 1)}
	cfg.PSK = slices.Clone(cfg.PSK)
	cfg.Handler = c
	send := cfg.Send
	cfg.Send = func(packet []byte, natt bool) error {
		c.started.Store(true)
		return send(packet, natt)
	}
	c.session = ikev1.NewSession(cfg)
	return c
}

func clearLegacyResult(r ikev1.Result) {
	clear(r.OutEncKey)
	clear(r.InEncKey)
	clear(r.OutIntegKey)
	clear(r.InIntegKey)
}

func (c *legacyControl) Established(r ikev1.Result) {
	if !c.closed.Load() {
		select {
		case c.ready <- r:
			return
		default:
		}
	}
	clearLegacyResult(r)
}
func (c *legacyControl) Failed(err error) {
	select {
	case c.failed <- err:
	default:
	}
}
func (c *legacyControl) close() {
	if c == nil {
		return
	}
	c.closed.Store(true)
	c.session.Close()
	for {
		select {
		case r := <-c.ready:
			clearLegacyResult(r)
		default:
			return
		}
	}
}

func (c *legacyClient) handleIKE(packet []byte) {
	c.mu.RLock()
	active, renewing := c.control, c.renewing
	c.mu.RUnlock()
	for _, control := range []*legacyControl{active, renewing} {
		if control != nil && control.started.Load() {
			control.session.HandleInbound(packet)
		}
	}
}

func (c *legacyClient) beginPhase1Renewal() (*legacyControl, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return nil, errors.New("IPsec client closed during renewal")
	default:
	}
	if c.renewing == nil {
		c.renewing = newLegacyControl(c.controlConfig)
	}
	return c.renewing, nil
}

func (c *legacyClient) discardPhase1Renewal(control *legacyControl) {
	c.mu.Lock()
	if c.renewing == control {
		c.renewing = nil
	}
	c.mu.Unlock()
	control.close()
}

func (c *legacyClient) promotePhase1Renewal(control *legacyControl) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return false
	default:
	}
	if c.renewing != control {
		return false
	}
	c.control, c.renewing = control, nil
	return true
}

// Subtracting the margin avoids overflowing time.Duration at the admitted
// 2147483647-second profile bound (multiplying that duration by nine wraps).
func legacySoftLifetime(lifetime time.Duration) time.Duration {
	return lifetime - lifetime/10
}

func (c *legacyClient) lifecycle() {
	o := c.cfg.FortinetOptions
	phase1Lifetime := time.Duration(o.Phase1Lifetime) * time.Second
	phase1Soft := time.NewTimer(jitterDuration(legacySoftLifetime(phase1Lifetime)))
	phase1Expires := time.Now().Add(phase1Lifetime)
	phase1Hard := time.NewTimer(phase1Lifetime)
	defer phase1Soft.Stop()
	defer phase1Hard.Stop()
	retry := max(time.Millisecond, min(30*time.Second, phase1Lifetime/10))
	childSoft := time.NewTimer(time.Hour)
	childHard := time.NewTimer(time.Hour)
	defer childSoft.Stop()
	defer childHard.Stop()
	var softCh, hardCh <-chan time.Time
	resetChild := func() {
		if o.Phase2TimeLifetime {
			ttl := time.Duration(o.Phase2Lifetime) * time.Second
			childSoft.Reset(legacySoftLifetime(ttl))
			childHard.Reset(ttl)
			softCh, hardCh = childSoft.C, childHard.C
		} else {
			childSoft.Stop()
			childHard.Stop()
			softCh, hardCh = nil, nil
		}
	}
	resetChild()
	c.mu.RLock()
	active := c.control
	c.mu.RUnlock()
	var renewing *legacyControl
	var pendingReady <-chan ikev1.Result
	var pendingFailed <-chan error
	pendingChild := false
	requestChild := func() error {
		if pendingChild {
			return nil
		}
		pendingChild = true
		return active.session.Rekey()
	}
	clearPending := func() {
		c.discardPhase1Renewal(renewing)
		renewing, pendingReady, pendingFailed = nil, nil, nil
		phase1Soft.Reset(max(time.Millisecond, min(retry, time.Until(phase1Expires)/2)))
	}
	// DPD must not block the lifecycle loop while a replacement finishes or a
	// hard lifetime expires. Its acknowledgements have the same select priority.
	dpdTimer := time.NewTimer(time.Hour)
	dpdTimer.Stop()
	defer dpdTimer.Stop()
	var dpdAck <-chan struct{}
	var dpdDeadline <-chan time.Time
	clearDPD := func() { dpdTimer.Stop(); dpdAck, dpdDeadline = nil, nil }
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	defer func() {
		c.Close()
		if c.cfg.OnDead != nil {
			c.cfg.OnDead()
		}
	}()
	for {
		select {
		case <-c.done:
			return
		case <-c.failed:
			return
		case <-active.failed:
			return
		case <-phase1Hard.C:
			return
		case <-hardCh:
			return
		case <-phase1Soft.C:
			var err error
			renewing, err = c.beginPhase1Renewal()
			if err != nil {
				return
			}
			pendingReady, pendingFailed = renewing.ready, renewing.failed
			renewing.session.Start()
		case <-pendingFailed:
			clearPending()
		case result := <-pendingReady:
			if err := c.install(result); err != nil {
				clearPending()
				continue
			}
			if !c.promotePhase1Renewal(renewing) {
				return
			}
			old := active
			active = renewing
			renewing, pendingReady, pendingFailed = nil, nil, nil
			old.close()
			phase1Expires = time.Now().Add(phase1Lifetime)
			phase1Hard.Reset(phase1Lifetime)
			phase1Soft.Reset(jitterDuration(legacySoftLifetime(phase1Lifetime)))
			pendingChild = false
			resetChild()
			clearDPD()
		case <-softCh:
			if err := requestChild(); err != nil {
				return
			}
		case <-c.rekey:
			if err := requestChild(); err != nil {
				return
			}
		case result := <-active.ready:
			if err := c.install(result); err != nil {
				return
			}
			pendingChild = false
			resetChild()
		case <-dpdAck:
			clearDPD()
		case <-dpdDeadline:
			return
		case <-ticker.C:
			peer := *c.peer
			peer.Port = c.nattPort
			if o.NatTraversal {
				_, _ = c.conn.WriteToUDP([]byte{255}, &peer)
			}
			c.mu.RLock()
			volume := c.volume
			c.mu.RUnlock()
			if o.Phase2ByteLifetime && volume >= uint64(o.Phase2LifetimeKb)*1024 {
				return
			}
			if o.DeadPeerDetection && dpdAck == nil && !pendingChild {
				ack, err := active.session.Ping()
				if err != nil {
					return
				}
				dpdAck = ack
				dpdTimer.Reset(15 * time.Second)
				dpdDeadline = dpdTimer.C
			}
		}
	}
}
