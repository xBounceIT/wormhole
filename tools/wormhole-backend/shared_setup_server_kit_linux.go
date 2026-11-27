//go:build linux

package main

import "golang.org/x/sys/unix"

func isLocalServerKitCache(path string) bool {
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil {
		return false
	}
	switch uint64(fs.Type) {
	case 0x6969, // NFS
		0xff534d42, 0xfe534d42, 0x517b, // CIFS, SMB2, SMB
		0x65735546, // FUSE
		0x01021997, // 9P
		0x00c36400, // Ceph
		0x5346414f: // AFS
		return false
	default:
		return true
	}
}
