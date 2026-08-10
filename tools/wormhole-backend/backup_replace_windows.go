//go:build windows

package main

import (
	"strings"
)

func equalBackupPaths(left, right string) bool {
	return strings.EqualFold(left, right)
}

func replaceBackupFile(temporaryPath, targetPath string) error {
	return replaceFileWithWriteThrough(temporaryPath, targetPath)
}
