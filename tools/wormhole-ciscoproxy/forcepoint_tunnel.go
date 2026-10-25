package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

func startForcepoint(ctx context.Context, outerCancel context.CancelFunc, cfg config) (sockstun.Dialer, func(), func(), error) {
	if outerCancel == nil {
		return nil, nil, nil, errors.New("outerCancel is required")
	}
	sess, err := forcepointLogin(ctx, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = fpDefaultMTU
	}
	netStack, endpoint, err := newNetstack(sess.network.address, mtu)
	if err != nil {
		_ = sess.conn.Close()
		return nil, nil, nil, err
	}
	// These are routes INSIDE the private Go stack. Neither the OS routing table
	// nor host DNS settings change, even when the gateway advertises a full tunnel.
	routes := make([]tcpip.Route, 0, len(sess.network.routes)+len(sess.network.dns))
	for _, prefix := range sess.network.routes {
		routes = append(routes, forcepointRoute(prefix))
	}
	for _, address := range sess.network.dns {
		routes = append(routes, forcepointRoute(netip.PrefixFrom(address, 32)))
	}
	netStack.SetRouteTable(routes)

	loopCtx, cancel := context.WithCancel(ctx)
	done, ready := make(chan struct{}), make(chan struct{})
	var readyOnce, cleanupOnce sync.Once
	arm := func() { readyOnce.Do(func() { close(ready) }) }
	go func() {
		defer close(done)
		runForcepoint(loopCtx, sess, endpoint, 30*time.Second)
	}()
	go func() {
		<-ready
		<-done
		outerCancel()
	}()
	cleanup := func() {
		cleanupOnce.Do(func() {
			arm()
			cancel()
			_ = sess.conn.Close()
			<-done
			netStack.Close()
		})
	}
	return newNetstackDialer(netStack, sess.network.address, sess.network.dns), arm, cleanup, nil
}

func forcepointRoute(prefix netip.Prefix) tcpip.Route {
	address := tcpip.AddressWithPrefix{
		Address: tcpip.AddrFromSlice(prefix.Addr().AsSlice()), PrefixLen: prefix.Bits(),
	}
	return tcpip.Route{Destination: address.Subnet(), NIC: 1}
}

func runForcepoint(ctx context.Context, sess *forcepointSession, endpoint *channel.Endpoint, interval time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		defer cancel()
		for {
			op, payload, err := readForcepointFrame(sess.conn)
			if err != nil {
				return
			}
			if op == fpIPv4 {
				if sess.authenticationExpired(time.Now()) {
					err = errForcepointAuthExpired
				} else if !sess.paused.Load() {
					injectTunnelIPv4(endpoint, payload)
				}
			} else {
				err = sess.handleFrame(op, payload)
			}
			clear(payload)
			if err != nil {
				// Errors are fixed classifications, never server-supplied text.
				logf("forcepoint: %v", err)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer cancel()
		for {
			packet := endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			if sess.paused.Load() {
				packet.DecRef()
				continue
			}
			view := packet.ToView()
			err := sess.write(fpIPv4, view.AsSlice())
			view.Release()
			packet.DecRef()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if now.Sub(time.Unix(0, sess.lastReply.Load())) > 3*interval {
					return
				}
				if sess.authenticationExpired(now) {
					return
				}
				if sess.paused.Load() && now.Sub(time.Unix(0, sess.pauseSince.Load())) >= fpAuthTimeout {
					return
				}
				var token [4]byte
				if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
					return
				}
				if err := sess.write(fpHeartbeat, token[:]); err != nil {
					return
				}
			}
		}
	}()
	<-ctx.Done()
	_ = sess.conn.Close() // unblock TLS reads/writes before waiting for workers
	workers.Wait()
	sess.cfg.Password = ""
}
