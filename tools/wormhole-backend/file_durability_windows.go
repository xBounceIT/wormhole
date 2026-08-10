//go:build windows

package main

import "golang.org/x/sys/windows"

func replaceFileWithWriteThrough(sourcePath, targetPath string) error {
	source, err := windows.UTF16PtrFromString(sourcePath)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		source,
		target,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func syncPrivateFileDirectory(string) error {
	// MOVEFILE_WRITE_THROUGH flushes the rename before replaceFileWithWriteThrough returns.
	return nil
}
