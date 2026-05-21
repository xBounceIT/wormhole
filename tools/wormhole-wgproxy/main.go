// wormhole-wgproxy is the userspace WireGuard sidecar that Wormhole launches per active
// connection. It owns a wireguard-go device running in TUN-less netstack mode (gVisor) and
// exposes the resulting virtual network through a local SOCKS5 listener on 127.0.0.1.
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type config struct {
	InterfacePrivateKey string   `json:"interface_private_key"`
	InterfaceAddress    string   `json:"interface_address"`
	Mtu                 *int     `json:"mtu"`
	Dns                 []string `json:"dns"`

	PeerPublicKey              string   `json:"peer_public_key"`
	PeerPresharedKey           *string  `json:"peer_preshared_key"`
	PeerEndpoint               string   `json:"peer_endpoint"`
	AllowedIps                 []string `json:"allowed_ips"`
	PersistentKeepaliveSeconds *int     `json:"persistent_keepalive_s"`
}

// dialer is the abstraction the SOCKS5 server uses to reach the target. In real mode it points
// into the wireguard-go netstack; in mock mode it points at the OS resolver/socket layer.
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
	mock := flag.Bool("mock", false, "skip WireGuard handshake; dial via OS sockets (CI / tests only)")
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
	// server unblocks and the device cleans up.
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

	if mock {
		logf("mock mode: skipping WireGuard, dialing via OS sockets")
		dial = osDialer{}
		cleanup = func() {}
	} else {
		d, c, err := startWireGuard(ctx, cfg)
		if err != nil {
			return fmt.Errorf("wireguard start: %w", err)
		}
		dial = d
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
	if f, ok := os.Stdout.(interface{ Sync() error }); ok {
		_ = f.Sync()
	}
	logf("socks5 listening on 127.0.0.1:%d", port)

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
	return cfg, nil
}

// startWireGuard brings up wireguard-go in netstack mode and returns a dialer that routes
// through the virtual network plus a cleanup function. Address/peer config is provided via
// the UAPI ipcSet contract.
func startWireGuard(ctx context.Context, cfg config) (dialer, func(), error) {
	if cfg.InterfacePrivateKey == "" {
		return nil, nil, errors.New("interface_private_key is required")
	}
	if cfg.InterfaceAddress == "" {
		return nil, nil, errors.New("interface_address is required (e.g. \"10.0.0.2/32\")")
	}
	if cfg.PeerPublicKey == "" {
		return nil, nil, errors.New("peer_public_key is required")
	}
	if cfg.PeerEndpoint == "" {
		return nil, nil, errors.New("peer_endpoint is required (e.g. \"vpn.example.com:51820\")")
	}

	ifaceAddr, err := parseAddrFromCidrOrPlain(cfg.InterfaceAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("interface_address %q: %w", cfg.InterfaceAddress, err)
	}

	var dnsAddrs []netip.Addr
	for _, d := range cfg.Dns {
		a, err := netip.ParseAddr(strings.TrimSpace(d))
		if err != nil {
			return nil, nil, fmt.Errorf("dns %q: %w", d, err)
		}
		dnsAddrs = append(dnsAddrs, a)
	}

	mtu := 1420
	if cfg.Mtu != nil && *cfg.Mtu > 0 {
		mtu = *cfg.Mtu
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{ifaceAddr}, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("netstack: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))

	endpointHostPort, err := resolveEndpoint(ctx, cfg.PeerEndpoint)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("resolve endpoint: %w", err)
	}

	privHex, err := base64KeyToHex(cfg.InterfacePrivateKey)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("interface private key: %w", err)
	}
	pubHex, err := base64KeyToHex(cfg.PeerPublicKey)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("peer public key: %w", err)
	}

	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\n", privHex)
	fmt.Fprintf(&ipc, "public_key=%s\n", pubHex)
	if cfg.PeerPresharedKey != nil && *cfg.PeerPresharedKey != "" {
		pskHex, err := base64KeyToHex(*cfg.PeerPresharedKey)
		if err != nil {
			dev.Close()
			return nil, nil, fmt.Errorf("peer preshared key: %w", err)
		}
		fmt.Fprintf(&ipc, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&ipc, "endpoint=%s\n", endpointHostPort)
	if cfg.PersistentKeepaliveSeconds != nil && *cfg.PersistentKeepaliveSeconds > 0 {
		fmt.Fprintf(&ipc, "persistent_keepalive_interval=%d\n", *cfg.PersistentKeepaliveSeconds)
	}
	if len(cfg.AllowedIps) == 0 {
		// Default routes the entire address space through the peer.
		fmt.Fprintf(&ipc, "allowed_ip=0.0.0.0/0\n")
		fmt.Fprintf(&ipc, "allowed_ip=::/0\n")
	} else {
		for _, a := range cfg.AllowedIps {
			fmt.Fprintf(&ipc, "allowed_ip=%s\n", strings.TrimSpace(a))
		}
	}

	if err := dev.IpcSet(ipc.String()); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("ipcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("device up: %w", err)
	}

	cleanup := func() {
		dev.Close()
	}
	return tnetDialer{tnet}, cleanup, nil
}

type tnetDialer struct{ tnet *netstack.Net }

func (d tnetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tnet.DialContext(ctx, network, address)
}

func parseAddrFromCidrOrPlain(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func resolveEndpoint(parent context.Context, endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	// Use the OS resolver for the WG peer's address (this lookup happens outside the tunnel,
	// which is what wg-quick does too). Inherit the parent ctx so process shutdown during
	// DNS doesn't hang the startup path.
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no IP addresses for %q", host)
	}
	return net.JoinHostPort(addrs[0].Unmap().String(), port), nil
}

func base64KeyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32-byte key, got %d bytes", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// --- SOCKS5 ---

// handleSocks5 implements the minimum RFC 1928 surface the .NET Socks5Client speaks: no-auth
// only, CONNECT command, DOMAINNAME / IPv4 / IPv6 address types. Anything else gets a polite
// error reply.
func handleSocks5(ctx context.Context, c net.Conn, dial dialer) {
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	n := int(hdr[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil {
		return
	}
	if reqHead[0] != 0x05 {
		return
	}
	if reqHead[1] != 0x01 {
		// only CONNECT supported
		writeReply(c, 0x07)
		return
	}

	var host string
	switch reqHead[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03: // DOMAINNAME
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		writeReply(c, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	// Clear deadline before long-lived stream.
	_ = c.SetDeadline(time.Time{})

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := dial.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	cancelDial()
	if err != nil {
		logf("dial %s:%d failed: %v", host, port, err)
		// 0x04 host unreachable is a reasonable generic reply
		writeReply(c, 0x04)
		return
	}
	defer upstream.Close()

	// Success reply with BND.ADDR = 0.0.0.0:0 (we don't expose the bind address).
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	pump(ctx, c, upstream)
}

// pump bidirectionally copies between client and upstream. When one direction's Copy returns
// (EOF or error), half-close the corresponding peer write so the other Copy unblocks at EOF —
// avoids leaking a goroutine until the OS finally tears down a half-open connection. The
// 2-channel pattern (no WaitGroup, no bridge goroutine) keeps per-connection overhead at
// 2 goroutines instead of 3 — material under RDP-through-tunnel load with many sub-streams.
func pump(ctx context.Context, client, upstream net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	done := make(chan struct{}, 2)
	copy1 := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copy1(upstream, client)
	go copy1(client, upstream)

	select {
	case <-done:
	case <-ctx.Done():
		_ = client.Close()
		_ = upstream.Close()
		<-done
	}
	<-done
}

func writeReply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
