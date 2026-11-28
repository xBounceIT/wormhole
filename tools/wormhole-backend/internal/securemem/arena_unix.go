//go:build linux || darwin

package securemem

import "golang.org/x/sys/unix"

func allocate(size int) ([]byte, bool, error) {
	data, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, false, err
	}
	locked := unix.Mlock(data) == nil
	if err := excludeFromDump(data); err != nil {
		if locked {
			_ = unix.Munlock(data)
		}
		_ = unix.Munmap(data)
		return nil, false, err
	}
	return data, locked, nil
}

func release(data []byte, locked bool) error {
	if locked {
		_ = unix.Munlock(data)
	}
	return unix.Munmap(data)
}
