package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// A real loopback SOCKS5 relay maps a deliberately unreachable original target
// to the TCP protocol fixture. The destination must arrive intact at the proxy.
func sharedRouteSOCKSFixture(t *testing.T, target, host string, port int) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		var outcome error
		defer func() { done <- outcome }()
		client, err := listener.Accept()
		if err != nil {
			outcome = err
			return
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(client, greeting); err != nil {
			outcome = err
			return
		}
		if !bytes.Equal(greeting, []byte{5, 1, 0}) {
			outcome = fmt.Errorf("invalid SOCKS greeting")
			return
		}
		if _, err := client.Write([]byte{5, 0}); err != nil {
			outcome = err
			return
		}
		header := make([]byte, 4)
		if _, err := io.ReadFull(client, header); err != nil {
			outcome = err
			return
		}
		if !bytes.Equal(header[:3], []byte{5, 1, 0}) || header[3] != 3 {
			outcome = fmt.Errorf("SOCKS must receive the original domain")
			return
		}
		size := []byte{0}
		if _, err := io.ReadFull(client, size); err != nil {
			outcome = err
			return
		}
		destination := make([]byte, int(size[0])+2)
		if _, err := io.ReadFull(client, destination); err != nil {
			outcome = err
			return
		}
		if string(destination[:len(destination)-2]) != host || int(binary.BigEndian.Uint16(destination[len(destination)-2:])) != port {
			outcome = fmt.Errorf("SOCKS destination changed")
			return
		}
		remote, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			outcome = err
			return
		}
		defer remote.Close()
		if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
			outcome = err
			return
		}
		_ = client.SetDeadline(time.Time{})
		bridgeTunnelConnections(client, remote)
	}()
	return listener.Addr().String(), done
}
