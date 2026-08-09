//go:build darwin

package main

import (
	"os"
	"strings"
)

func equalBackupPaths(left, right string) bool {
	return strings.EqualFold(left, right)
}

func replaceBackupFile(temporaryPath, targetPath string) error {
	return os.Rename(temporaryPath, targetPath)
}
