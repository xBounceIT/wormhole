//go:build !windows && !darwin

package main

func equalBackupPaths(left, right string) bool {
	return left == right
}

func replaceBackupFile(temporaryPath, targetPath string) error {
	return replaceFileWithWriteThrough(temporaryPath, targetPath)
}
