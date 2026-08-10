//go:build !windows

package main

import "os"

func replaceFileWithWriteThrough(sourcePath, targetPath string) error {
	return os.Rename(sourcePath, targetPath)
}

func syncPrivateFileDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
