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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
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

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// stderrLogger adapts logf to the sockstun.Logger interface so the shared SOCKS5 server
// can emit accept / dial errors through the same stream as the rest of the sidecar.
type stderrLogger struct{}

func (stderrLogger) Logf(format string, args ...any) { logf(format, args...) }

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

	var dial sockstun.Dialer
	var cleanup func()

	if mock {
		logf("mock mode: skipping WireGuard, dialing via OS sockets")
		dial = sockstun.OSDialer{}
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
	// os.Stdout is *os.File, not an interface — calling Sync directly. Best-effort: when
	// stdout is a pipe (the parent's redirected stream) Sync returns an error that's safe
	// to ignore; the Fprintf above has already buffered the line into the OS pipe.
	_ = os.Stdout.Sync()
	logf("socks5 listening on 127.0.0.1:%d", port)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	return sockstun.Serve(ctx, ln, dial, stderrLogger{})
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
func startWireGuard(ctx context.Context, cfg config) (sockstun.Dialer, func(), error) {
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
	// Sort IPv4 first, then IPv6. Resolvers commonly return AAAA records ahead of A per
	// RFC 6724, and WireGuard peer endpoints in the wild are very often IPv4-only — a
	// dual-stack client whose first lookup result is IPv6 then ends up with an unreachable
	// endpoint and an indefinitely-stuck handshake. wireguard-go pins one endpoint per
	// peer and doesn't re-resolve, so the choice we make here is final until the user
	// re-establishes the tunnel. Preferring IPv4 covers the common case; the rare
	// IPv6-only peer still works because the IPv6 candidate is kept as the next-best
	// option.
	sort.SliceStable(addrs, func(i, j int) bool {
		return addrs[i].Is4() && !addrs[j].Is4()
	})
	if len(addrs) > 1 {
		others := make([]string, 0, len(addrs)-1)
		for _, a := range addrs[1:] {
			others = append(others, a.Unmap().String())
		}
		logf("peer %q resolved to %d addresses; using %s (other candidates: %s)",
			host, len(addrs), addrs[0].Unmap().String(), strings.Join(others, ", "))
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
