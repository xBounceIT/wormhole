//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows"
)

func replaceFileWithWriteThrough(sourcePath, targetPath string) error {
	return moveWindowsFileWithWriteThrough(sourcePath, targetPath, windows.MOVEFILE_REPLACE_EXISTING)
}

func moveWindowsFileWithWriteThrough(sourcePath, targetPath string, flags uint32) error {
	source, err := windows.UTF16PtrFromString(sourcePath)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}
	return retryWindowsFileMove(func() error {
		return windows.MoveFileEx(source, target, flags|windows.MOVEFILE_WRITE_THROUGH)
	})
}

func retryWindowsFileMove(move func() error) error {
	// Windows can briefly refuse a rename while another component has a file
	// open. Keep the same paths and flags and cap the backoff at 335 ms.
	err := move()
	for _, backoff := range [...]time.Duration{10, 25, 50, 100, 150} {
		if err != windows.ERROR_ACCESS_DENIED && err != windows.ERROR_SHARING_VIOLATION {
			return err
		}
		time.Sleep(backoff * time.Millisecond)
		err = move()
	}
	return err
}

func syncPrivateFileDirectory(string) error {
	// MOVEFILE_WRITE_THROUGH flushes the rename before replaceFileWithWriteThrough returns.
	return nil
}
