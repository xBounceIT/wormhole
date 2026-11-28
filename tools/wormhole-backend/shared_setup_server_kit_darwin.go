//go:build darwin

package main

import "golang.org/x/sys/unix"

func isLocalServerKitCache(path string) bool {
	var fs unix.Statfs_t
	return unix.Statfs(path, &fs) == nil && fs.Flags&unix.MNT_LOCAL != 0
}
