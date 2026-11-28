//go:build !darwin

package main

import "net"

func openTouchIDChannel() (net.Conn, error) { return nil, errTouchIDUnavailable }
