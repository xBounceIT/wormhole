//go:build !windows

package main

import "bytes"

func openVaultBitwardenPasswordPipe(frame []byte) (bitwardenPasswordPipe, error) {
	return bitwardenPasswordPipe{
		path: "/dev/stdin", stdin: bytes.NewReader(frame), close: func() {},
	}, nil
}
