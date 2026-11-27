package main

import (
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Keep one non-inheritable handle for the lifetime of this backend. Windows closes
// it even if Electron or the backend crashes before the normal shutdown handshake.
var helperJobMu sync.Mutex
var helperJobHandle windows.Handle

func ownedHelperJob() (windows.Handle, error) {
	helperJobMu.Lock()
	defer helperJobMu.Unlock()
	if helperJobHandle != 0 {
		return helperJobHandle, nil
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	helperJobHandle = job
	return job, nil
}

func startOwnedHelper(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	// Session helpers wait on stdin for configuration until this returns.
	if err := assignOwnedHelper(cmd.Process); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	return nil
}

func assignOwnedHelper(process *os.Process) error {
	job, err := ownedHelperJob()
	if err != nil {
		return err
	}
	var assignErr error
	err = process.WithHandle(func(handle uintptr) {
		child := windows.Handle(handle)
		assignErr = windows.AssignProcessToJobObject(job, child)
		if assignErr != nil {
			// A one-shot credential reader may have already completed.
			if state, _ := windows.WaitForSingleObject(child, 0); state == windows.WAIT_OBJECT_0 {
				assignErr = nil
			}
		}
	})
	if err != nil {
		return err
	}
	return assignErr
}
