//go:build !windows

package sharedpg

import (
	"os/exec"
	"syscall"
)

func hidePostgresTestProcess(cmd *exec.Cmd) {
	// Without a controlling terminal PostgreSQL's prompt consumes the supplied
	// stdin rather than opening /dev/tty during an interactive local test run.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
