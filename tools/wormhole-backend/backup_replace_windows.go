//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows"
)

func equalBackupPaths(left, right string) bool {
	return strings.EqualFold(left, right)
}

func replaceBackupFile(temporaryPath, targetPath string) error {
	temporary, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		temporary,
		target,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
