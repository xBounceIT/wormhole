//go:build !windows

package main

import "os"

func protectSftpEditDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.ErrPermission
	}
	return os.Chmod(path, 0o700)
}
