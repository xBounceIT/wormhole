package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

// A synthetic sidecar used only by the native Electron relay integration. The
// destination 127.0.0.2 cannot reach the SSH fixture bound to 127.0.0.1 directly.
func init() {
	target := os.Getenv("WORMHOLE_TEST_VPN_SOCKS_TARGET")
	if target == "" {
		return
	}
	_, portText, err := net.SplitHostPort(target)
	if err != nil {
		os.Exit(2)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		os.Exit(2)
	}
	var config map[string]any
	if len(os.Args) != 1 || json.NewDecoder(os.Stdin).Decode(&config) != nil || config["password"] != "route-sidecar-password" {
		os.Exit(3)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(4)
	}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(client, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 1, 0}) {
					return
				}
				if _, err := client.Write([]byte{5, 0}); err != nil {
					return
				}
				request := make([]byte, 10)
				if _, err := io.ReadFull(client, request); err != nil || !bytes.Equal(request[:8], []byte{5, 1, 0, 1, 127, 0, 0, 2}) || int(binary.BigEndian.Uint16(request[8:])) != port {
					return
				}
				remote, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer remote.Close()
				if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
					return
				}
				bridgeTunnelConnections(client, remote)
			}()
		}
	}()
	fmt.Printf("READY %d\n", listener.Addr().(*net.TCPAddr).Port)
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = listener.Close()
	os.Exit(0)
}
