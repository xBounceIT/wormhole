//go:build darwin

package securemem

import "golang.org/x/sys/unix"

// Darwin has no MADV_DONTDUMP. The vault disables core dumps process-wide.
func excludeFromDump([]byte) error { return nil }

func DisableProcessDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return ErrUnavailable
	}
	return nil
}
