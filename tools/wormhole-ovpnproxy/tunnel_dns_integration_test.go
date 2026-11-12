package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A userspace packet link stands in for the encrypted OpenVPN transport. Public
// DNS IPs exist only on the peer netstack, so this test cannot use the host route.
func TestTunnelDNSResolvesRemoteResourceThroughNetstack(t *testing.T) {
	clientDev, client, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")},
		[]netip.Addr{netip.MustParseAddr("10.0.0.53")}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	peerDev, peer, err := netstack.CreateNetTUN([]netip.Addr{
		netip.MustParseAddr("10.0.0.53"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("192.0.2.20"),
	}, nil, 1500)
	if err != nil {
		clientDev.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var pumps sync.WaitGroup
	closed := false
	for _, pair := range [][2]tun.Device{{clientDev, peerDev}, {peerDev, clientDev}} {
		pumps.Go(func() {
			packet := make([]byte, 2048)
			sizes := make([]int, 1)
			for {
				if _, err := pair[0].Read([][]byte{packet}, sizes, 0); err != nil {
					return
				}
				mu.Lock()
				if !closed {
					_, _ = pair[1].Write([][]byte{packet[:sizes[0]]}, 0)
				}
				mu.Unlock()
			}
		})
	}
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		clientDev.Close()
		peerDev.Close()
		mu.Unlock()
		pumps.Wait()
	})
	for _, address := range []string{"10.0.0.53:53", "1.1.1.1:53"} {
		listener, err := peer.ListenUDPAddrPort(netip.MustParseAddrPort(address))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			packet := make([]byte, 4096)
			for {
				n, source, err := listener.ReadFrom(packet)
				if err != nil {
					return
				}
				var request dnsmessage.Message
				if err := request.Unpack(packet[:n]); err != nil {
					return
				}
				// The corporate resolver cannot resolve the public image domain.
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true,
					RecursionAvailable: true, RCode: dnsmessage.RCodeNameError}, Questions: request.Questions}
				if address == "1.1.1.1:53" {
					// Force a real UDP -> TCP retry for the public DNS response.
					response.RCode = dnsmessage.RCodeSuccess
					response.Truncated = true
				}
				wire, _ := response.Pack()
				_, _ = listener.WriteTo(wire, source)
			}
		}()
	}
	dnsTCP, err := peer.ListenTCPAddrPort(netip.MustParseAddrPort("1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer dnsTCP.Close()
	dnsDone := make(chan error, 1)
	go func() {
		conn, err := dnsTCP.Accept()
		if err != nil {
			dnsDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var size [2]byte
		_, err = io.ReadFull(conn, size[:])
		if err != nil {
			dnsDone <- err
			return
		}
		wire := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err = io.ReadFull(conn, wire); err != nil {
			dnsDone <- err
			return
		}
		var request dnsmessage.Message
		if err = request.Unpack(wire); err != nil {
			dnsDone <- err
			return
		}
		response := tunnelDNSAnswer(request.Questions[0])
		response.ID, response.Response, response.RecursionAvailable = request.ID, true, true
		response.Questions = request.Questions
		wire, _ = response.Pack()
		binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
		_, err = conn.Write(append(size[:], wire...))
		dnsDone <- err
	}()
	resolver := tunnelDNSResolver{primary: client.LookupContextHost, tunnel: client, fallback: true, hasV4: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupContextHost(ctx, "images.example.com")
	if err != nil || !reflect.DeepEqual(addrs, []string{"192.0.2.20"}) {
		t.Fatalf("resource DNS through packet tunnel = %v, %v", addrs, err)
	}
	if err := <-dnsDone; err != nil {
		t.Fatal(err)
	}
	resource, err := peer.ListenTCPAddrPort(netip.MustParseAddrPort("192.0.2.20:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Close()
	go func() {
		conn, err := resource.Accept()
		if err == nil {
			defer conn.Close()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(conn, "remote resource")
		}
	}()
	conn, err := client.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0], "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := io.ReadAll(conn)
	if err != nil || string(payload) != "remote resource" {
		t.Fatalf("resource stream = %q, %v", payload, err)
	}
}
