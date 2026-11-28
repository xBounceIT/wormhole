//go:build windows

package sharedpg

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

func hidePostgresTestProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
