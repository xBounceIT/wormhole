//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var shellExecuteW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")

// shellExecuteError converts a ShellExecuteW HINSTANCE return value into a descriptive
// error. Values at or below 32 are SE_ERR_* codes; the x/sys wrapper misreports them as
// GetLastError (often stale), so the call is hand-rolled here to surface the real code.
func shellExecuteError(code uintptr) error {
	switch uint32(code) {
	case 2:
		return errors.New("the system cannot find the specified file")
	case 3:
		return errors.New("the system cannot find the specified path")
	case 5:
		return errors.New("access was denied")
	case 8:
		return errors.New("out of memory")
	case 26:
		return errors.New("a sharing violation occurred")
	case 27:
		return errors.New("the file association is incomplete or invalid")
	case 28:
		return errors.New("the DDE time-out expired")
	case 29:
		return errors.New("the DDE transaction failed")
	case 30:
		return errors.New("the DDE conversation was busy")
	case 31:
		return errors.New("no application is associated with this file")
	case 32:
		return errors.New("the specified DLL was not found")
	default:
		return fmt.Errorf("the shell reported error code %d", code)
	}
}

func openLocalPathWithShell(path string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, _ := syscall.SyscallN(
		shellExecuteW.Addr(),
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		0,
		windows.SW_SHOWNORMAL,
	)
	if result > 32 {
		return nil
	}
	// explorer.exe opens a directory asynchronously and delegates to the running shell, so
	// it is a reliable fallback when the direct ShellExecute call fails. For files, keep the
	// descriptive error so the caller can surface it instead of silently opening the parent.
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		fallback := exec.Command("explorer.exe", path)
		fallback.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if startErr := fallback.Start(); startErr == nil {
			return nil
		}
	}
	return shellExecuteError(result)
}
