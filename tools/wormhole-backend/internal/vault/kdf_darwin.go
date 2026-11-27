package vault

import (
	"unsafe"

	argon2mem "github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/argon2mem"
	"golang.org/x/sys/unix"
)

// Darwin's Go scavenger marks heap pages reusable. An anonymous mapping lets
// the vault erase and unmap the Argon2 matrix before acknowledging a password.
func passwordKey(password, salt []byte, params KDFParameters) (key []byte, err error) {
	size := int(params.MemoryKiB) * int(unsafe.Sizeof(argon2mem.Block{}))
	mapping, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	defer func() {
		Wipe(mapping)
		if releaseErr := unix.Munmap(mapping); releaseErr != nil {
			Wipe(key)
			key, err = nil, releaseErr
		}
	}()
	blocks := unsafe.Slice((*argon2mem.Block)(unsafe.Pointer(unsafe.SliceData(mapping))), int(params.MemoryKiB))
	key = argon2mem.IDKey(password, salt, params.Iterations, params.Parallelism, blocks)
	if key == nil {
		return nil, ErrFormat
	}
	return key, nil
}
