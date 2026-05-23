// wormhole-fortiproxy is the userspace Fortinet SSL VPN sidecar that Wormhole launches per
// active connection. It owns a FortiGate SSL VPN session (PPP-over-TLS, v1 wire format)
// running in TUN-less netstack mode (gVisor) and exposes the resulting virtual network
// through a local SOCKS5 listener on 127.0.0.1.
//
// Protocol with the parent:
//
//   - stdin:  one JSON object on the first line, then EOF acts as the shutdown signal.
//   - stdout: a single line "READY <port>\n" once the SOCKS5 listener is up.
//   - stderr: structured log lines (one per event, free-form text).
//
// The process exits when stdin closes (parent died), or when it receives SIGTERM/Ctrl-C.
//
// No OS network interfaces are touched; no admin rights are required.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type config struct {
	Host                   string  `json:"host"`
	Port                   int     `json:"port"`
	Username               string  `json:"username"`
	Password               string  `json:"password"`
	Realm                  *string `json:"realm"`
	TotpSecret             *string `json:"totp_secret"`
	TrustServerCertificate bool    `json:"trust_server_certificate"`
	ServerCertSha256Pin    *string `json:"server_cert_sha256_pin"`
}

// dialer is the abstraction the SOCKS5 server uses to reach the target. In real mode it
// dials through the gVisor netstack fed by the FortiGate PPP stream; in mock mode it
// points at the OS resolver/socket layer.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type osDialer struct{}

func (osDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func main() {
	mock := flag.Bool("mock", false, "skip Fortinet handshake; dial via OS sockets (CI / tests only)")
	flag.Parse()

	if err := run(*mock); err != nil {
		logf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(mock bool) error {
	cfg, err := readConfig()
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Watch for stdin EOF (parent gone). When it fires, cancel the context so the SOCKS5
	// server unblocks and the tunnel tears down.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		logf("stdin closed; shutting down")
		cancel()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			logf("signal received; shutting down")
			cancel()
		case <-ctx.Done():
		}
	}()

	var dial dialer
	var cleanup func()
	arm := func() {} // no-op default; startFortinet supplies the real one

	if mock {
		logf("mock mode: skipping Fortinet handshake, dialing via OS sockets")
		dial = osDialer{}
		cleanup = func() {}
	} else {
		d, a, c, err := startFortinet(ctx, cancel, cfg)
		if err != nil {
			return fmt.Errorf("fortinet start: %w", err)
		}
		dial = d
		arm = a
		cleanup = c
	}
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(os.Stdout, "READY %d\n", port)
	_ = os.Stdout.Sync()
	logf("socks5 listening on 127.0.0.1:%d", port)
	// Arm the PPP-teardown watcher AFTER the listener is published. Until now, a fast PPP
	// exit (gateway RST mid-login) only triggers cleanup() via our defer; armed, it also
	// cancels the outer ctx so the SOCKS5 accept loop exits promptly.
	arm()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			logf("accept: %v", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleSocks5(ctx, c, dial)
		}(c)
	}

	wg.Wait()
	return nil
}

func readConfig() (config, error) {
	dec := json.NewDecoder(os.Stdin)
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	return cfg, nil
}

// startFortinet performs the FortiGate login flow, upgrades the TLS connection to PPP,
// brings up a gVisor netstack endpoint, and returns a dialer that routes through the
// virtual network plus an arm/cleanup pair. The PPP loop runs in a background goroutine
// for the lifetime of the returned cleanup; cleanup waits for it before tearing down the
// gVisor stack so readLoop/writeLoop never touch a closed stack.
//
// outerCancel must be the caller-side cancel that drives the SOCKS5 accept loop. We invoke
// it when the PPP layer dies on its own (gateway Terminate-Request, read error, LCP
// loopback) so the sidecar exits promptly instead of accepting new SOCKS5 connections that
// can never carry traffic.
//
// The returned `arm` func MUST be called by the caller once it is committed to running —
// typically right before publishing READY and entering the accept loop. Without arming,
// PPP exit propagates only through `cleanup`'s explicit teardown; with arming, gateway-
// initiated teardown also cancels the outer ctx so the accept loop exits. Arming after
// READY is what prevents the phantom-READY race where a fast-exiting PPP loop would
// otherwise cancel the outer ctx while we're still on the call stack.
func startFortinet(ctx context.Context, outerCancel context.CancelFunc, cfg config) (dialer, func(), func(), error) {
	if outerCancel == nil {
		// startFortinet propagates gateway-initiated teardown to the outer ctx via a
		// watcher goroutine that calls outerCancel(); a nil here would nil-panic during
		// shutdown. Catch the contract violation at startup instead.
		return nil, nil, nil, errors.New("outerCancel is required")
	}
	if cfg.Host == "" {
		return nil, nil, nil, errors.New("host is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, nil, nil, errors.New("username and password are required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, nil, nil, fmt.Errorf("invalid port %d", cfg.Port)
	}

	// fortiLogin manages its own per-phase deadlines (auth + tunnel-upgrade) rooted in this
	// outer ctx so a slow auth round doesn't burn the budget the tunnel TLS handshake needs.
	session, err := fortiLogin(ctx, cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("login: %w", err)
	}
	logf("fortigate login ok: assigned %s mtu=%d dns=%v", session.AssignedIP, session.MTU, session.DNS)

	stack, channel, err := newNetstack(session.AssignedIP, session.MTU)
	if err != nil {
		_ = session.Conn.Close()
		return nil, nil, nil, fmt.Errorf("netstack: %w", err)
	}

	pppCtx, pppCancel := context.WithCancel(ctx)
	pppDone := make(chan struct{})
	go func() {
		defer close(pppDone)
		runPPP(pppCtx, session, channel)
	}()
	// Propagate gateway-initiated teardown back to the OUTER ctx. Without this, a gateway
	// Terminate-Request would leave the PPP loops exited but the SOCKS5 accept loop in run()
	// still running — new client dials would hang on first byte because no PPP path can
	// drain the netstack. Cancelling pppCtx alone wouldn't reach run()'s ctx (child cancel
	// doesn't propagate up), so we invoke outerCancel directly when pppDone closes.
	//
	// The watcher must NOT fire outerCancel before startFortinet has returned and the
	// caller has had a chance to publish READY and start the SOCKS5 accept loop. Otherwise,
	// if runPPP exits very early (e.g., the gateway RSTs the TLS conn the moment after
	// login), the watcher would cancel ctx while we're still on the stack, run() would
	// print READY, and the listener would be torn down before the parent's first dial — a
	// phantom-READY race with no useful error surfaced. Gate the watcher on a "ready"
	// channel that the caller closes once it considers startup complete.
	ready := make(chan struct{})
	go func() {
		<-pppDone
		// If startFortinet returned an error, the caller never closed `ready`; in that
		// case there is no outer accept loop to cancel and runPPP returned because we
		// closed the conn during cleanup anyway. Bail without invoking outerCancel.
		select {
		case <-ready:
		default:
			return
		}
		logf("ppp loop exited; cancelling outer ctx so run() can shut down")
		outerCancel()
	}()

	cleanup := func() {
		// Cancel and close the TLS conn so the PPP read loop unblocks. Then wait for the
		// runPPP goroutine to exit BEFORE tearing down the gVisor stack — gVisor's stack
		// methods aren't documented as safe against concurrent InjectInbound/ReadContext
		// from a goroutine that hasn't observed the close yet, and process-exit-while-active
		// would leak into background panics on Windows.
		// First mark the watcher as live so a late pppDone close still propagates to the
		// outer ctx even if cleanup races with gateway teardown.
		select {
		case <-ready:
		default:
			close(ready)
		}
		pppCancel()
		_ = session.Conn.Close()
		<-pppDone
		stack.Close()
	}
	// Caller signals "ready" once the SOCKS5 listener is published. The arming separates
	// "PPP died before READY (silent failure, surface via the returned cleanup)" from
	// "PPP died after READY (loud teardown, cancel outer ctx so the parent sees us exit)."
	arm := func() {
		select {
		case <-ready:
		default:
			close(ready)
		}
	}
	return newNetstackDialer(stack, session.AssignedIP, session.DNS), arm, cleanup, nil
}
