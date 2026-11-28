//go:build linux

package securemem

import "golang.org/x/sys/unix"

func excludeFromDump(data []byte) error {
	return unix.Madvise(data, unix.MADV_DONTDUMP)
}

// DisableProcessDumps is process-wide and irreversible for this vault lifetime.
// Call only in the dedicated vault child, never in protocol/library test hosts.
func DisableProcessDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return ErrUnavailable
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return ErrUnavailable
	}
	return nil
}
