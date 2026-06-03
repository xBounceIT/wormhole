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
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startOpenVpn boots OpenVPN3 via the shim and returns a Dialer routed through a
// wireguard-go netstack. The cleanup function tears down both — pump goroutines first,
// then the C++ session, then the netstack, then the C++ client object — so no thread
// outlives the objects it dereferences.
func startOpenVpn(ctx context.Context, cfg config) (sockstun.Dialer, func(), error) {
	// 1. Construct the C++ client and load the profile.
	cProfile := C.CString(cfg.ProfileOvpn)
	defer C.free(unsafe.Pointer(cProfile))
	client := C.ovpn_new()
	if client == nil {
		return nil, nil, errors.New("ovpn_new returned null (out of memory, or sidecar built without -tags ovpn3 / submodules)")
	}
	cleanupClient := func() { C.ovpn_free(client) }

	if rc := C.ovpn_load_profile(client, cProfile); rc != 0 {
		cleanupClient()
		return nil, nil, fmt.Errorf("ovpn_load_profile failed (code %d) — likely a malformed .ovpn", int(rc))
	}

	if cfg.Username != "" || cfg.Password != "" {
		cU := C.CString(cfg.Username)
		cP := C.CString(cfg.Password)
		rc := C.ovpn_set_creds(client, cU, cP)
		C.free(unsafe.Pointer(cU))
		C.free(unsafe.Pointer(cP))
		if rc != 0 {
			cleanupClient()
			return nil, nil, fmt.Errorf("ovpn_set_creds failed (code %d)", int(rc))
		}
	}

	// 2. Kick off the connect in the C++ event loop.
	if rc := C.ovpn_connect_async(client); rc != 0 {
		cleanupClient()
		return nil, nil, fmt.Errorf("ovpn_connect_async failed (code %d)", int(rc))
	}

	// 3. Block until CONNECTED (or a fatal handshake/auth failure / 30s timeout). The
	//    shim returns the assigned interface address as a CIDR string so we can hand it
	//    to netstack.
	cidrBuf := make([]byte, 64)
	if rc := C.ovpn_wait_connected(client, (*C.char)(unsafe.Pointer(&cidrBuf[0])), C.int(len(cidrBuf)), C.int(30000)); rc != 0 {
		C.ovpn_stop(client)
		cleanupClient()
		return nil, nil, fmt.Errorf("ovpn_wait_connected failed (code %d) — handshake/auth failure or timeout", int(rc))
	}
	end := 0
	for end < len(cidrBuf) && cidrBuf[end] != 0 {
		end++
	}
	cidr := strings.TrimSpace(string(cidrBuf[:end]))
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		C.ovpn_stop(client)
		cleanupClient()
		return nil, nil, fmt.Errorf("shim returned invalid interface CIDR %q: %w", cidr, err)
	}

	// 4. Spin up a netstack TUN at the pushed address. nil DNS means hostname targets
	//    fail closed inside netstack.DialContext; pushed DNS support is a v2 feature.
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{pfx.Addr()}, nil, 1500)
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
	inboundDone := make(chan struct{})
	outboundDone := make(chan struct{})
	go func() {
		defer close(inboundDone)
		pumpInbound(pumpCtx, client, tunDev)
	}()
	go func() {
		defer close(outboundDone)
		pumpOutbound(pumpCtx, client, tunDev)
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

	// nilable family flags: drives the family-aware dialer below. tnet.HasV4/HasV6 isn't
	// exposed on wireguard-go's *netstack.Net, but we know what we asked for at CreateNetTUN
	// time — pfx.Addr() is the single family we installed.
	hasV4 := pfx.Addr().Is4() || pfx.Addr().Is4In6()
	hasV6 := pfx.Addr().Is6() && !pfx.Addr().Is4In6()

	return tnetDialer{tnet: tnet, hasV4: hasV4, hasV6: hasV6}, cleanup, nil
}

// pumpInbound reads packets out of the OpenVPN3 shim (server → client direction) and
// injects them into the netstack TUN. The shim blocks up to 100 ms per call so we can
// poll pumpCtx cheaply without a dedicated wake-up channel on the C side. The post-recv
// ctx check is belt-and-suspenders against the gVisor InjectInbound-after-Close race:
// even though cleanup() waits for <-inboundDone BEFORE calling tunDev.Close(), the
// extra check ensures a packet that arrived between cancel and recv-return doesn't
// reach dev.Write after the shutdown signal.
func pumpInbound(ctx context.Context, client *C.ovpn_client_t, dev tun.Device) {
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
		bufs[0] = buf[:n]
		if _, err := dev.Write(bufs, 0); err != nil {
			return
		}
	}
}

// pumpOutbound reads packets from the netstack TUN (i.e. packets that applications wrote
// via tnet.DialContext) and hands them to the shim for delivery into the OpenVPN data
// channel. tunDev.Read blocks until a packet is ready or the device is closed, so this
// loop is naturally driven by the netstack — no busy-spin needed. cleanup() closes the
// TUN to wake this loop after pumpInbound has confirmed it's done.
func pumpOutbound(ctx context.Context, client *C.ovpn_client_t, dev tun.Device) {
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
			if rc := C.ovpn_tun_send(client, (*C.char)(unsafe.Pointer(&pkt[0])), C.int(sz)); rc != 0 {
				// rc=1 means the shim is shutting down (tunnel not up, or stopping_).
				// rc=100 means the shim was built without OpenVPN3 (HAVE_OPENVPN3=0).
				// Either way we exit the pump so SOCKS5 surfaces dial failures rather
				// than silently dropping outbound packets while looking healthy.
				return
			}
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
// Pushed DNS support: CreateNetTUN was called with `nil` DNS servers (the shim doesn't
// surface pushed dhcp-option DNS yet). With no DNS configured, tnet.LookupContextHost
// returns an empty result for hostnames — DialContext will fail with a clear "no such
// host" rather than fall back to the OS resolver. This is the v1 trade-off: hostnames
// require the user to have DNS configured via the OpenVPN profile (push "dhcp-option
// DNS x.y.z.w"), or to use IP literals. A v2 iteration plumbs the pushed DNS into
// CreateNetTUN; the dialer code path here doesn't change.
//
// Family-aware short-circuit: when netstack only has IPv4 (or only IPv6), dial only
// addresses of the installed family. Without this, an OS resolver returning AAAA-first
// (RFC 6724) on a v4-only tunnel would pay the netstack's full per-address timeout on
// the v6 candidate before falling back to v4. Today the OS resolver isn't used at all,
// but tnet.LookupContextHost can still return both families if the pushed DNS server
// answers AAAA — the same penalty applies, just with different cause.
type tnetDialer struct {
	tnet  *netstack.Net
	hasV4 bool
	hasV6 bool
}

func (d tnetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
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
