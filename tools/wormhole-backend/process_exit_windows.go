//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
)

type processExitAPI struct {
	open  func(uint32, bool, uint32) (windows.Handle, error)
	wait  func(windows.Handle, uint32) (uint32, error)
	close func(windows.Handle) error
}

func nativeProcessTerminated(pid uint32) (bool, error) {
	return windowsProcessTerminated(pid, processExitAPI{windows.OpenProcess, windows.WaitForSingleObject, windows.CloseHandle})
}
func windowsProcessTerminated(pid uint32, api processExitAPI) (terminated bool, result error) {
	if pid == 0 {
		return false, windows.ERROR_INVALID_PARAMETER
	}
	handle, err := api.open(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer func() {
		if err := api.close(handle); err != nil {
			terminated = false
			result = errors.Join(result, err)
		}
	}()
	status, err := api.wait(handle, 0)
	if err != nil {
		return false, err
	}
	switch status {
	case windows.WAIT_OBJECT_0:
		return true, nil
	case uint32(windows.WAIT_TIMEOUT):
		return false, nil
	default:
		return false, windows.ERROR_INVALID_DATA
	}
}
