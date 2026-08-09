//go:build !windows

package main

import "errors"

func systemRdpClientExecutable() (string, error) {
	return "", errors.New("System Remote Desktop is available only on Windows")
}
