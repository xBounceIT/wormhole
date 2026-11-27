package main

import (
	"net"
	"os"
)

func openTouchIDChannel() (net.Conn, error) {
	f := os.NewFile(3, "vault-touch-id")
	if f == nil {
		return nil, errTouchIDUnavailable
	}
	defer f.Close()
	channel, err := net.FileConn(f)
	if err != nil {
		return nil, errTouchIDUnavailable
	}
	if socket, ok := channel.(*net.UnixConn); !ok || socket.LocalAddr().Network() != "unix" {
		channel.Close()
		return nil, errTouchIDUnavailable
	}
	return channel, nil
}
