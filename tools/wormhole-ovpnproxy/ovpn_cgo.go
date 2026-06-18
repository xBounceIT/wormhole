//go:build ovpn3

// CGO bindings to the OpenVPN3 shim (see ovpn_shim/shim.{h,cc}). Plugs the shim's TUN
// queues into a wireguard-go netstack so the SOCKS5 surface can DialContext over the
// tunnel without touching any OS network interface. Built only when `-tags ovpn3` is set;
// production releases ship with the tag, --mock-only CI builds ship without.
//
// We deliberately reuse `golang.zx2c4.com/wireguard/tun/netstack` (the same package the
// wgproxy sidecar uses) for the userspace TCP/IP stack. wireguard-go pins a specific
// gVisor revision and exposes a stable tun.Device / netstack.Net surface — depending on
// it directly lets us share the gVisor version with wgproxy and dodges the gVisor API
// churn around the buffer / packet-buffer packages. The only delta from wgproxy is what
// drives the TUN side of netstack: there it's wireguard-go's device, here it's the
// OpenVPN3 shim plumbed via our C ABI.

package main

// Build note: `go build` keys its cgo link cache on the Go sources + the `#cgo` directive
// strings, NOT on the *content* of the external static archive (libovpn_shim.a) named via
// `-lovpn_shim`. So rebuilding only the C++ shim/OpenVPN3 (changing the .a) does NOT relink
// the Go binary — it silently reuses the previously linked exe. To force a fresh link exactly
// when the archive changes, Fetch-OvpnProxy.ps1 stamps the archive's SHA-256 into a generated
// shim_buildinfo.go (gitignored); a changed hash makes that source change, which busts the
// link cache. If you build the shim by hand without that script, run `go clean -cache` first.

/*
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/ovpn_shim
#cgo LDFLAGS: -L${SRCDIR}/ovpn_shim/build -lovpn_shim -lstdc++
// libovpn_shim.a is a thin static archive of just shim.cc + ovpncli.cpp — it does NOT
// bundle its dependencies. CMake knows the transitive closure (mbedTLS, lz4, and the
// Win32 system libs that OpenVPN3's add_core_dependencies() attaches to the target), but
// a bare `-lovpn_shim` CGO link never sees a static library's link interface, so the
// closure has to be spelled out here or the final go-build link fails with hundreds of
// undefined references. These libs are Windows-specific — the Linux CI best-effort build
// supplies its own via $CGO_LDFLAGS. mbedTLS libs come from the submodule build tree (an
// arch-independent dir); lz4 and jsoncpp from vcpkg, whose lib dir is triplet-specific, so
// the -L for it is keyed off GOARCH below (x64- vs arm64-mingw-static). Today only x64
// builds -tags ovpn3 (arm64 ships the mock stub — no submodules/toolchain on that runner),
// but selecting the vcpkg path by GOARCH avoids silently linking x64 archives into an
// arm64 sidecar if that ever changes. -ljsoncpp mirrors CMake's add_json_library(ovpn_shim):
// the openvpn3 code paths compiled here don't currently pull Json:: symbols, but linking it
// keeps the closure honest against config drift (and ld ignores an unreferenced static
// archive). Order matters for single-pass ld: dependents (ovpn_shim) before dependencies
// (mbedTLS, lz4, jsoncpp), before the Win32 import libs they call into.
// Statically link the MinGW C++/runtime libs so the shipped sidecar is self-contained.
// Without this the .exe imports libstdc++-6.dll + libwinpthread-1.dll, which don't exist
// on a clean end-user machine — the sidecar would fail to start (and the release verify
// gate, which only looks for "binding not linked", would not catch the DLL-load failure).
// System DLLs (kernel32, ws2_32, bcrypt, UCRT) stay dynamic, as they must.
#cgo windows LDFLAGS: -static -static-libgcc -static-libstdc++
#cgo windows LDFLAGS: -L${SRCDIR}/ovpn_shim/build/third_party_mbedtls/library
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/ovpn_shim/build/vcpkg_installed/x64-mingw-static/lib
#cgo windows,arm64 LDFLAGS: -L${SRCDIR}/ovpn_shim/build/vcpkg_installed/arm64-mingw-static/lib
#cgo windows LDFLAGS: -lmbedtls -lmbedx509 -lmbedcrypto -llz4 -ljsoncpp
// -lbcrypt resolves BCryptGenRandom, which mbedTLS 3.6's entropy_poll.c uses for the
// Windows entropy source (modern mbedTLS prefers CNG/bcrypt over the legacy advapi32
// CryptGenRandom). advapi32/ole32/shell32 mirror OpenVPN3's add_core_dependencies set.
#cgo windows LDFLAGS: -lws2_32 -lwsock32 -liphlpapi -lfwpuclnt -lwininet -lsetupapi -lrpcrt4 -lwtsapi32 -ladvapi32 -lbcrypt -lole32 -lshell32

#include "ovpn_shim/shim.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const waitConnectedTimeoutMs = 90000

// lastError pulls the OpenVPN3 fatal/disconnect reason out of the shim so a failed
// connect surfaces "CONNECTION_TIMEOUT" / "AUTH_FAILED" / "TRANSPORT_ERROR" instead of a
// bare numeric code. Returns "" when the shim has no reason recorded.
func lastError(client *C.ovpn_client_t) string {
	buf := make([]byte, 256)
	if rc := C.ovpn_last_error(client, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))); rc != 0 {
		return ""
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(buf[:end]))
}

// connectWithChallenge performs the OpenVPN connect, transparently answering a single
// OpenVPN data-channel dynamic challenge (CRV1) with cfg.ChallengeResponse if the server
// issues one — e.g. WatchGuard AuthPoint 2FA presented at the OpenVPN auth layer rather than
// a web portal. It mirrors the OpenVPN3 ClientAPI pattern of using a FRESH client per attempt:
// attempt 1 sends username/password; if that comes back as a dynamic challenge and we have a
// response, attempt 2 sends username/password + the CRV1 response on a brand-new client.
// Returns a live CONNECTED client (owned by the caller — free with C.ovpn_free) and its
// assigned interface prefix, or an error.
func connectWithChallenge(cfg config) (*C.ovpn_client_t, netip.Prefix, error) {
	cProfile := C.CString(cfg.ProfileOvpn)
	defer C.free(unsafe.Pointer(cProfile))

	// attempt runs ONE connect on a fresh client. response/cookie are empty on the first
	// attempt; on the retry they carry the user's 2FA answer and the CRV1 cookie captured from
	// the first attempt. On a dynamic-challenge failure it returns isChallenge=true + the cookie
	// (retryable); any other failure returns a terminal error (with the OpenVPN3 reason when
	// available). The freshly-created client is freed here unless it actually connected (in
	// which case ownership passes to the caller).
	attempt := func(response, cookie string) (*C.ovpn_client_t, netip.Prefix, bool, string, error) {
		client := C.ovpn_new()
		if client == nil {
			return nil, netip.Prefix{}, false, "", errors.New("ovpn_new returned null (out of memory, or sidecar built without -tags ovpn3 / submodules)")
		}
		connected := false
		defer func() {
			if !connected {
				C.ovpn_stop(client)
				C.ovpn_free(client)
			}
		}()

		if rc := C.ovpn_load_profile(client, cProfile); rc != 0 {
			return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_load_profile failed (code %d) — likely a malformed .ovpn", int(rc))
		}
		if cfg.Username != "" || cfg.Password != "" {
			cU := C.CString(cfg.Username)
			cP := C.CString(cfg.Password)
			rc := C.ovpn_set_creds(client, cU, cP)
			C.free(unsafe.Pointer(cU))
			C.free(unsafe.Pointer(cP))
			if rc != 0 {
				return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_set_creds failed (code %d)", int(rc))
			}
		}
		if response != "" || cookie != "" {
			cR := C.CString(response)
			cC := C.CString(cookie)
			rc := C.ovpn_set_challenge(client, cR, cC)
			C.free(unsafe.Pointer(cR))
			C.free(unsafe.Pointer(cC))
			if rc != 0 {
				return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_set_challenge failed (code %d)", int(rc))
			}
		}
		if rc := C.ovpn_connect_async(client); rc != 0 {
			return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_connect_async failed (code %d)", int(rc))
		}

		// Block until CONNECTED (or a fatal handshake/auth failure / timeout). OpenVPN profiles
		// can list multiple remotes, so keep this wait above one OpenVPN3 connTimeout. The shim
		// returns the assigned interface address as a CIDR string.
		cidrBuf := make([]byte, 64)
		rc := C.ovpn_wait_connected(client, (*C.char)(unsafe.Pointer(&cidrBuf[0])), C.int(len(cidrBuf)), C.int(waitConnectedTimeoutMs))
		if rc != 0 {
			// Distinguish a retryable dynamic challenge from a flat auth/transport failure.
			if C.ovpn_is_dynamic_challenge(client) != 0 {
				ckBuf := make([]byte, 1024)
				C.ovpn_get_dynamic_challenge(client, (*C.char)(unsafe.Pointer(&ckBuf[0])), C.int(len(ckBuf)))
				n := 0
				for n < len(ckBuf) && ckBuf[n] != 0 {
					n++
				}
				return nil, netip.Prefix{}, true, string(ckBuf[:n]), errors.New("server issued an OpenVPN dynamic challenge")
			}
			if reason := lastError(client); reason != "" {
				return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_wait_connected failed (code %d): %s", int(rc), reason)
			}
			return nil, netip.Prefix{}, false, "", fmt.Errorf("ovpn_wait_connected failed (code %d) — handshake/auth failure or timeout", int(rc))
		}

		end := 0
		for end < len(cidrBuf) && cidrBuf[end] != 0 {
			end++
		}
		cidr := strings.TrimSpace(string(cidrBuf[:end]))
		p, perr := netip.ParsePrefix(cidr)
		if perr != nil {
			return nil, netip.Prefix{}, false, "", fmt.Errorf("shim returned invalid interface CIDR %q: %w", cidr, perr)
		}
		connected = true // ownership passes to the caller; defer won't free it
		return client, p, false, "", nil
	}

	// Attempt 1: plain username/password.
	client, pfx, isChallenge, cookie, err := attempt("", "")
	if err == nil {
		return client, pfx, nil
	}
	if !isChallenge {
		return nil, netip.Prefix{}, err
	}
	// The server wants an OpenVPN-layer 2FA response. Retry on a fresh client if we have one.
	if cfg.ChallengeResponse == "" {
		return nil, netip.Prefix{}, errors.New("server requires an OpenVPN dynamic-challenge response but none was provided")
	}
	logf("openvpn: server issued a dynamic challenge; retrying with the provided response")
	client, pfx, isChallenge, _, err = attempt(cfg.ChallengeResponse, cookie)
	if err != nil {
		if isChallenge {
			return nil, netip.Prefix{}, errors.New("openvpn dynamic-challenge response was rejected by the server")
		}
		return nil, netip.Prefix{}, err
	}
	return client, pfx, nil
}

// startOpenVpn boots OpenVPN3 via the shim and returns a Dialer routed through a
// wireguard-go netstack. The cleanup function tears down both — pump goroutines first,
// then the C++ session, then the netstack, then the C++ client object — so no thread
// outlives the objects it dereferences.
func startOpenVpn(ctx context.Context, cfg config) (sockstun.Dialer, func(), error) {
	// Connect, transparently answering one OpenVPN-layer dynamic challenge with
	// cfg.ChallengeResponse if the server issues one (see connectWithChallenge). On success we
	// own a CONNECTED client and its assigned interface prefix.
	client, pfx, err := connectWithChallenge(cfg)
	if err != nil {
		return nil, nil, err
	}
	cleanupClient := func() { C.ovpn_free(client) }

	// nilable family flags: drive the family-aware dialer below and the DNS filter.
	// tnet.HasV4/HasV6 isn't exposed on wireguard-go's *netstack.Net, but we know what
	// we ask for at CreateNetTUN time — pfx.Addr() is the single family we install.
	hasV4 := pfx.Addr().Is4() || pfx.Addr().Is4In6()
	hasV6 := pfx.Addr().Is6() && !pfx.Addr().Is4In6()

	// 4. Spin up a netstack TUN at the pushed address, resolving through the server-
	//    pushed DNS (dhcp-option DNS / --dns server). Servers of a family the tunnel
	//    can't route are dropped — netstack would burn a full query timeout on each.
	//    With an empty list hostname targets fail closed in the dialer below (clear
	//    error instead of netstack's misleading "cannot marshal DNS message", which is
	//    what its zero-server resolver path degenerates to).
	dnsAddrs := pushedDNS(client, hasV4, hasV6)
	if len(dnsAddrs) > 0 {
		logf("openvpn: tunnel DNS via pushed resolver(s) %v", dnsAddrs)
	} else {
		logf("openvpn: server pushed no usable DNS; hostname targets will fail (use IP literals or push dhcp-option DNS)")
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{pfx.Addr()}, dnsAddrs, 1500)
	if err != nil {
		C.ovpn_stop(client)
		cleanupClient()
		return nil, nil, fmt.Errorf("netstack CreateNetTUN: %w", err)
	}

	// 5. Two-way packet pumps. Inbound: shim → tunDev.Write (server-to-client IP packets
	//    appear as if they arrived from a TUN). Outbound: tunDev.Read → shim (packets
	//    written by tnet.DialContext flow out through OpenVPN).
	//
	// Two separate done channels so cleanup() can wait for the INBOUND pump to fully exit
	// BEFORE closing the netstack TUN — pumpInbound's dev.Write concurrent with
	// tunDev.Close() is a known gVisor race (InjectInbound-after-Close is a panic/silent-
	// drop depending on the channel.Endpoint revision). pumpOutbound by contrast only
	// unblocks WHEN tunDev.Close() runs (blocking dev.Read returns ErrClosed), so we close
	// the TUN after inbound has exited, then wait for outbound, then free the C++ client.
	pumpCtx, pumpCancel := context.WithCancel(ctx)
	counters := &ovpnTrafficCounters{}
	packetDiag := newPacketDiagHub()
	inboundDone := make(chan struct{})
	outboundDone := make(chan struct{})
	go func() {
		defer close(inboundDone)
		pumpInbound(pumpCtx, client, tunDev, counters, packetDiag)
	}()
	go func() {
		defer close(outboundDone)
		pumpOutbound(pumpCtx, client, tunDev, counters, packetDiag)
	}()

	// Cleanup sequence (load-bearing ordering):
	//   1. pumpCancel — pumps will return on their next ctx.Err() check after the
	//      currently-blocked recv/Read unblocks.
	//   2. C.ovpn_stop — unblocks pumpInbound's blocking ovpn_tun_recv (returns -1).
	//      We do NOT free the client object yet — ovpn_stop only signals shutdown; the
	//      C++ event loop is still draining and ovpn_free at this point could race with
	//      pumpOutbound holding *client.
	//   3. <-inboundDone — pumpInbound has fully exited, no more dev.Write in flight.
	//   4. tunDev.Close() — safe NOW because no concurrent dev.Write exists. Wakes
	//      pumpOutbound's blocking dev.Read with ErrClosed.
	//   5. <-outboundDone — pumpOutbound has fully exited, no more *client deref.
	//   6. cleanupClient (ovpn_free) — safe because both pumps are gone.
	cleanup := func() {
		pumpCancel()
		C.ovpn_stop(client)
		<-inboundDone
		_ = tunDev.Close()
		<-outboundDone
		cleanupClient()
	}

	return tnetDialer{
		tnet:     tnet,
		hasV4:    hasV4,
		hasV6:    hasV6,
		hasDNS:   len(dnsAddrs) > 0,
		counters: counters,
		client:   client,
		diag:     packetDiag,
	}, cleanup, nil
}

// pushedDNS pulls the server-pushed DNS resolver list out of the shim and parses it
// into netstack-ready addresses, keeping only families the tunnel can route. Entries
// may carry a ":port" suffix (the `dns server <prio> address <ip:port>` form);
// netstack's resolver only speaks plain UDP/TCP 53, so the port is dropped.
func pushedDNS(client *C.ovpn_client_t, hasV4, hasV6 bool) []netip.Addr {
	buf := make([]byte, 1024)
	if rc := C.ovpn_get_dns(client, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))); rc != 0 {
		return nil
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	var out []netip.Addr
	for _, s := range strings.Fields(string(buf[:end])) {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			ap, err2 := netip.ParseAddrPort(s)
			if err2 != nil {
				logf("openvpn: ignoring unparseable pushed DNS server %q", s)
				continue
			}
			addr = ap.Addr()
		}
		addr = addr.Unmap()
		if addr.Is4() && !hasV4 || !addr.Is4() && !hasV6 {
			logf("openvpn: ignoring pushed DNS server %s (family not routable through this tunnel)", addr)
			continue
		}
		out = append(out, addr)
	}
	return out
}

// pumpInbound reads packets out of the OpenVPN3 shim (server → client direction) and
// injects them into the netstack TUN. The shim blocks up to 100 ms per call so we can
// poll pumpCtx cheaply without a dedicated wake-up channel on the C side. The post-recv
// ctx check is belt-and-suspenders against the gVisor InjectInbound-after-Close race:
// even though cleanup() waits for <-inboundDone BEFORE calling tunDev.Close(), the
// extra check ensures a packet that arrived between cancel and recv-return doesn't
// reach dev.Write after the shutdown signal.
func pumpInbound(ctx context.Context, client *C.ovpn_client_t, dev tun.Device, counters *ovpnTrafficCounters, diag *packetDiagHub) {
	buf := make([]byte, 2048)
	bufs := make([][]byte, 1)
	for {
		if ctx.Err() != nil {
			return
		}
		n := int(C.ovpn_tun_recv(client, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), C.int(100)))
		if n < 0 {
			return // shim closed
		}
		if n == 0 {
			continue // timeout, keep polling
		}
		// Re-check ctx between the (potentially long) recv and the write — see comment above.
		if ctx.Err() != nil {
			return
		}
		info := parsePacketSummary(buf[:n])
		if diag != nil {
			diag.observeSummary(packetDirectionInbound, info)
		}
		if !info.valid {
			counters.inNonIPPackets.Add(1)
			counters.inNonIPBytes.Add(uint64(n))
			continue
		}
		bufs[0] = buf[:n]
		if _, err := dev.Write(bufs, 0); err != nil {
			return
		}
		counters.inPackets.Add(1)
		counters.inBytes.Add(uint64(n))
	}
}

// pumpOutbound reads packets from the netstack TUN (i.e. packets that applications wrote
// via tnet.DialContext) and hands them to the shim for delivery into the OpenVPN data
// channel. tunDev.Read blocks until a packet is ready or the device is closed, so this
// loop is naturally driven by the netstack — no busy-spin needed. cleanup() closes the
// TUN to wake this loop after pumpInbound has confirmed it's done.
func pumpOutbound(ctx context.Context, client *C.ovpn_client_t, dev tun.Device, counters *ovpnTrafficCounters, diag *packetDiagHub) {
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			sz := sizes[i]
			if sz == 0 {
				continue
			}
			pkt := bufs[i][:sz]
			diag.observe(packetDirectionOutbound, pkt)
			if rc := C.ovpn_tun_send(client, (*C.char)(unsafe.Pointer(&pkt[0])), C.int(sz)); rc != 0 {
				// rc=1 means the shim is shutting down (tunnel not up, or stopping_).
				// rc=100 means the shim was built without OpenVPN3 (HAVE_OPENVPN3=0).
				// Either way we exit the pump so SOCKS5 surfaces dial failures rather
				// than silently dropping outbound packets while looking healthy.
				return
			}
			counters.outPackets.Add(1)
			counters.outBytes.Add(uint64(sz))
		}
	}
}

// tnetDialer wraps netstack.Net so it satisfies sockstun.Dialer.
//
// Resolution policy (v1): hostnames go straight to tnet.LookupContextHost (i.e. through
// the tunnel via netstack), NOT through the OS resolver. This matters because:
//
//	(a) The OS resolver would leak the hostname to the local network in plaintext DNS
//	    before the tunnel is engaged — same threat model "VPN" is supposed to defeat.
//	(b) wgproxy already routes resolution through the tunnel (it passes the address
//	    string straight to tnet.DialContext, which does internal resolution against the
//	    DNS servers configured at CreateNetTUN); ovpnproxy must match for behavioral
//	    parity across sidecars.
//
// Pushed DNS support: the shim surfaces the server-pushed resolvers (dhcp-option DNS /
// --dns server, see ovpn_get_dns) and startOpenVpn feeds them into CreateNetTUN, so
// LookupContextHost queries them through the tunnel. When the server pushes none,
// hasDNS is false and hostname dials fail closed with a clear error — never a fallback
// to the OS resolver. (Skipping LookupContextHost in that case also matters because
// netstack's zero-server resolver path returns a bogus "cannot marshal DNS message"
// instead of anything actionable.)
//
// Family-aware short-circuit: when netstack only has IPv4 (or only IPv6), dial only
// addresses of the installed family. Without this, an OS resolver returning AAAA-first
// (RFC 6724) on a v4-only tunnel would pay the netstack's full per-address timeout on
// the v6 candidate before falling back to v4. Today the OS resolver isn't used at all,
// but tnet.LookupContextHost can still return both families if the pushed DNS server
// answers AAAA — the same penalty applies, just with different cause.
type tnetDialer struct {
	tnet     *netstack.Net
	hasV4    bool
	hasV6    bool
	hasDNS   bool
	counters *ovpnTrafficCounters
	client   *C.ovpn_client_t
	diag     *packetDiagHub
}

func (d tnetDialer) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	start := time.Now()
	before := d.snapshotCounters()
	shimBefore := d.snapshotShimStats()
	dialID, _ := sockstun.DialIDFromContext(ctx)
	var packetSummary string
	defer func() {
		after := d.snapshotCounters()
		shimAfter := d.snapshotShimStats()
		delta := after.Sub(before)
		if d.diag != nil && dialID != 0 {
			packetSummary = d.diag.endDial(dialID)
		}
		if err != nil {
			err = d.enrichDialError(address, dialID, delta, err)
			logf("openvpn: dial_id=%d target=%s duration=%s result=failed error=%v counters_before=%s counters_after=%s counters_delta=%s shim_before=%s shim_after=%s packet_summary=%s",
				dialID, address, time.Since(start).Round(time.Millisecond), err, before, after, delta, shimBefore, shimAfter, packetSummary)
		} else {
			logf("openvpn: dial_id=%d target=%s duration=%s result=success counters_before=%s counters_after=%s counters_delta=%s shim_before=%s shim_after=%s packet_summary=%s",
				dialID, address, time.Since(start).Round(time.Millisecond), before, after, delta, shimBefore, shimAfter, packetSummary)
		}
	}()

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if d.diag != nil && dialID != 0 {
		d.diag.beginDial(dialID, address)
	}
	if d.client != nil && dialID != 0 {
		C.ovpn_set_dial_id(d.client, C.ulonglong(dialID))
		defer C.ovpn_set_dial_id(d.client, C.ulonglong(0))
	}

	// IP literal: bypass resolution entirely, but enforce the family-installed check so
	// a v4-only tunnel doesn't waste a netstack timeout trying to dial a literal IPv6.
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			if !d.hasV4 {
				return nil, fmt.Errorf("IPv4 destination %s requested but tunnel is IPv6-only", host)
			}
		} else if !d.hasV6 {
			return nil, fmt.Errorf("IPv6 destination %s requested but tunnel is IPv4-only", host)
		}
		return d.tnet.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	// Hostname: resolve via tnet (in-tunnel DNS), filter by installed family, dial in
	// order. We deliberately do NOT fall back to net.DefaultResolver — that would leak
	// the hostname to the local network in plaintext.
	if !d.hasDNS {
		return nil, fmt.Errorf("cannot resolve %s: the VPN server pushed no DNS servers; use an IP literal or push dhcp-option DNS in the profile", host)
	}
	addrs, err := d.tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s through tunnel DNS: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for %s (tunnel DNS may not be configured; use an IP literal or push dhcp-option DNS in the .ovpn)", host)
	}
	var lastErr error
	dialed := false
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		// Skip addresses whose family the netstack can't route — avoids a full per-
		// address timeout inside tnet.DialContext for the mismatched family.
		if ip.To4() != nil {
			if !d.hasV4 {
				continue
			}
		} else if !d.hasV6 {
			continue
		}
		dialed = true
		conn, dialErr := d.tnet.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if !dialed {
		return nil, fmt.Errorf("no addresses of installed family (v4=%v v6=%v) for %s", d.hasV4, d.hasV6, host)
	}
	return nil, lastErr
}

type ovpnTrafficCounters struct {
	inPackets      atomic.Uint64
	inBytes        atomic.Uint64
	outPackets     atomic.Uint64
	outBytes       atomic.Uint64
	inNonIPPackets atomic.Uint64
	inNonIPBytes   atomic.Uint64
}

type ovpnTrafficSnapshot struct {
	inPackets      uint64
	inBytes        uint64
	outPackets     uint64
	outBytes       uint64
	inNonIPPackets uint64
	inNonIPBytes   uint64
}

func (d tnetDialer) snapshotCounters() ovpnTrafficSnapshot {
	if d.counters == nil {
		return ovpnTrafficSnapshot{}
	}
	return ovpnTrafficSnapshot{
		inPackets:      d.counters.inPackets.Load(),
		inBytes:        d.counters.inBytes.Load(),
		outPackets:     d.counters.outPackets.Load(),
		outBytes:       d.counters.outBytes.Load(),
		inNonIPPackets: d.counters.inNonIPPackets.Load(),
		inNonIPBytes:   d.counters.inNonIPBytes.Load(),
	}
}

func (d tnetDialer) snapshotShimStats() string {
	if d.client == nil {
		return "unavailable"
	}
	buf := make([]byte, 512)
	rc := C.ovpn_tun_stats(d.client, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if rc != 0 {
		return fmt.Sprintf("unavailable(rc=%d)", int(rc))
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return string(buf[:end])
}

func (d tnetDialer) enrichDialError(target string, dialID uint64, delta ovpnTrafficSnapshot, err error) error {
	if delta.outPackets > 0 && delta.inPackets == 0 {
		return fmt.Errorf("no data-plane response from tunnel (dial_id=%d target=%s root=%w counters_delta=%s)", dialID, target, err, delta)
	}
	if dialID != 0 {
		return fmt.Errorf("dial_id=%d target=%s: %w", dialID, target, err)
	}
	return err
}

func (s ovpnTrafficSnapshot) String() string {
	return fmt.Sprintf("in_packets=%d in_bytes=%d in_non_ip_packets=%d in_non_ip_bytes=%d out_packets=%d out_bytes=%d",
		s.inPackets, s.inBytes, s.inNonIPPackets, s.inNonIPBytes, s.outPackets, s.outBytes)
}

func (s ovpnTrafficSnapshot) Sub(before ovpnTrafficSnapshot) ovpnTrafficSnapshot {
	return ovpnTrafficSnapshot{
		inPackets:      saturatingSub(s.inPackets, before.inPackets),
		inBytes:        saturatingSub(s.inBytes, before.inBytes),
		outPackets:     saturatingSub(s.outPackets, before.outPackets),
		outBytes:       saturatingSub(s.outBytes, before.outBytes),
		inNonIPPackets: saturatingSub(s.inNonIPPackets, before.inNonIPPackets),
		inNonIPBytes:   saturatingSub(s.inNonIPBytes, before.inNonIPBytes),
	}
}

func saturatingSub(after, before uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}
