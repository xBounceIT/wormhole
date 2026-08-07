//go:build !windows && !darwin

package main

import "os"

func equalBackupPaths(left, right string) bool {
	return left == right
}

func replaceBackupFile(temporaryPath, targetPath string) error {
	return os.Rename(temporaryPath, targetPath)
}
