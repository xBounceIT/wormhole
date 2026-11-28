//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"testing"
)

func TestVaultProcessExitWaitsForKernelSignalAndClosesEveryHandle(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		openErr, waitErr, closeErr error
		status                     uint32
		terminated, wantErr        bool
	}{
		{name: "kernel signaled", status: windows.WAIT_OBJECT_0, terminated: true},
		{name: "exit code zero is insufficient", status: uint32(windows.WAIT_TIMEOUT)},
		{name: "absent PID", openErr: windows.ERROR_INVALID_PARAMETER, terminated: true},
		{name: "access denied", openErr: windows.ERROR_ACCESS_DENIED, wantErr: true},
		{name: "wait failed", waitErr: windows.ERROR_INVALID_HANDLE, wantErr: true},
		{name: "unexpected wait result", status: 42, wantErr: true},
		{name: "unconfirmed handle close", closeErr: windows.ERROR_INVALID_HANDLE, status: windows.WAIT_OBJECT_0, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := 0
			api := processExitAPI{
				open: func(access uint32, inherit bool, pid uint32) (windows.Handle, error) {
					if access != windows.SYNCHRONIZE || inherit || pid != 123 {
						t.Fatal("overprivileged or wrong lookup")
					}
					return 7, tc.openErr
				},
				wait: func(handle windows.Handle, ms uint32) (uint32, error) {
					if handle != 7 || ms != 0 {
						t.Fatal("wrong wait")
					}
					return tc.status, tc.waitErr
				},
				close: func(handle windows.Handle) error {
					closed++
					if handle != 7 {
						t.Fatal("wrong close")
					}
					return tc.closeErr
				},
			}
			got, err := windowsProcessTerminated(123, api)
			if got != tc.terminated || (err != nil) != tc.wantErr {
				t.Fatal(got, err)
			}
			expected := 1
			if tc.openErr != nil {
				expected = 0
			}
			if closed != expected {
				t.Fatal("handle leak", closed)
			}
		})
	}
	if ok, err := windowsProcessTerminated(0, processExitAPI{}); ok || !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatal("PID zero", ok, err)
	}
}
func TestVaultProcessExitRealTerminatedChild(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_PROCESS_EXIT_CHILD") == "1" {
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestVaultProcessExitRealTerminatedChild$")
	cmd.Env = append(os.Environ(), "WORMHOLE_TEST_PROCESS_EXIT_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if ok, err := nativeProcessTerminated(pid); !ok || err != nil {
		t.Fatal("terminated PID not confirmed", ok, err)
	}
}
