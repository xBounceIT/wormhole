//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func systemRdpClientExecutable() (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil || systemDirectory == "" {
		return "", errors.New("Windows system directory is unavailable")
	}
	executable := filepath.Join(systemDirectory, "mstsc.exe")
	info, err := os.Stat(executable)
	if err != nil || info.IsDir() {
		return "", errors.New("System Remote Desktop client is unavailable")
	}
	return executable, nil
}
