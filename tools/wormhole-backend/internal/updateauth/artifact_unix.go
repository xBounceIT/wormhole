//go:build darwin || linux

package updateauth

import "golang.org/x/sys/unix"

// A file replaced by a FIFO between Lstat and Open must not block verification.
const artifactNonblocking = unix.O_NONBLOCK
