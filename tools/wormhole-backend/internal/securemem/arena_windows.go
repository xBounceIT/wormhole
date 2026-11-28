//go:build windows

package securemem

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var workingSetMu sync.Mutex

func allocate(size int) ([]byte, bool, error) {
	address, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return nil, false, err
	}
	// VirtualAlloc returns native memory. No Go pointer is stored there.
	data := unsafe.Slice((*byte)(unsafe.Pointer(address)), size)
	locked := windows.VirtualLock(address, uintptr(size)) == nil
	if !locked {
		workingSetMu.Lock()
		var minimum, maximum uintptr
		var flags uint32
		process := windows.CurrentProcess()
		windows.GetProcessWorkingSetSizeEx(process, &minimum, &maximum, &flags)
		if minimum != 0 && maximum != 0 {
			additional := uintptr(size + 64*1024)
			if minimum+additional > minimum && maximum+additional > maximum {
				if windows.SetProcessWorkingSetSizeEx(process, minimum+additional, maximum+additional, flags) == nil {
					locked = windows.VirtualLock(address, uintptr(size)) == nil
				}
			}
		}
		workingSetMu.Unlock()
	}
	return data, locked, nil
}

func release(data []byte, locked bool) error {
	address := uintptr(unsafe.Pointer(&data[0]))
	if locked {
		_ = windows.VirtualUnlock(address, uintptr(len(data)))
	}
	return windows.VirtualFree(address, 0, windows.MEM_RELEASE)
}
