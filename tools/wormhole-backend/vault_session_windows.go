//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmWtsSessionChange   = 0x02b1
	wmClose              = 0x0010
	wmQuit               = 0x0012
	wtsConsoleDisconnect = 0x02
	wtsRemoteDisconnect  = 0x04
	wtsSessionLogoff     = 0x06
	wtsSessionLock       = 0x07
)

var (
	wtsWindowDLL         = windows.NewLazySystemDLL("user32.dll")
	wtsServiceDLL        = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsCreateWindow      = wtsWindowDLL.NewProc("CreateWindowExW")
	wtsDestroyWindow     = wtsWindowDLL.NewProc("DestroyWindow")
	wtsSetWindowProc     = wtsWindowDLL.NewProc("SetWindowLongPtrW")
	wtsCallWindowProc    = wtsWindowDLL.NewProc("CallWindowProcW")
	wtsWaitForInput      = wtsWindowDLL.NewProc("MsgWaitForMultipleObjectsEx")
	wtsPeekMessage       = wtsWindowDLL.NewProc("PeekMessageW")
	wtsDispatchMessage   = wtsWindowDLL.NewProc("DispatchMessageW")
	wtsPostQuit          = wtsWindowDLL.NewProc("PostQuitMessage")
	wtsRegisterSession   = wtsServiceDLL.NewProc("WTSRegisterSessionNotification")
	wtsUnregisterSession = wtsServiceDLL.NewProc("WTSUnRegisterSessionNotification")
)

type wtsWindowMessage struct {
	window         uintptr
	message        uint32
	wParam, lParam uintptr
	time           uint32
	x, y           int32
	private        uint32
}

func windowsSessionRequiresLock(event, eventSession uintptr, ownSession uint32) bool {
	if eventSession != uintptr(ownSession) {
		return false
	}
	switch event {
	case wtsConsoleDisconnect, wtsRemoteDisconnect, wtsSessionLogoff, wtsSessionLock:
		return true
	default:
		return false
	}
}

type windowsSessionSource func(context.Context, chan<- uintptr, chan<- struct{}) error

func runVaultSessionMonitor(input io.Reader, output io.Writer) int {
	return monitorWindowsVaultSession(input, output, watchWindowsSession)
}

func monitorWindowsVaultSession(input io.Reader, output io.Writer, watch windowsSessionSource) int {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		var lifetime [1]byte
		_, _ = input.Read(lifetime[:])
		cancel()
	}()
	ready := make(chan uintptr, 1)
	locks := make(chan struct{}, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = watch(ctx, ready, locks)
	}()
	defer func() {
		cancel()
		<-finished
	}()
	sourceStopped := func() int {
		if ctx.Err() != nil {
			return 0
		}
		return 1
	}
	select {
	case <-ctx.Done():
		return 0
	case <-finished:
		return sourceStopped()
	case <-ready:
		if _, err := io.WriteString(output, "ready\n"); err != nil {
			return 1
		}
	}
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-finished:
			return sourceStopped()
		case <-locks:
			if _, err := io.WriteString(output, "lock\n"); err != nil {
				return 1
			}
		}
	}
}

func watchWindowsSession(ctx context.Context, ready chan<- uintptr, locks chan<- struct{}) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		return err
	}
	class, _ := windows.UTF16PtrFromString("STATIC")
	const wsPopup = 0x80000000
	// A hidden top-level window receives WTS events without showing any UI.
	window, _, err := wtsCreateWindow.Call(0, uintptr(unsafe.Pointer(class)), 0, wsPopup, 0, 0, 0, 0, 0, 0, 0, 0)
	if window == 0 {
		return err
	}
	defer wtsDestroyWindow.Call(window)
	var previous uintptr
	proc := windows.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
		if msg == wmClose {
			// End the native source and unregister before destroying the HWND.
			wtsPostQuit.Call(0)
			return 0
		}
		if msg == wmWtsSessionChange {
			if windowsSessionRequiresLock(wParam, lParam, session) {
				// WTS may send synchronously while the thread is processing a
				// message. Never wait on the parent pipe from the window proc.
				select {
				case locks <- struct{}{}:
				default:
				}
			}
			return 0
		}
		result, _, _ := wtsCallWindowProc.Call(previous, hwnd, msg, wParam, lParam)
		return result
	})
	const gwlpWndProc = ^uintptr(3)
	previous, _, err = wtsSetWindowProc.Call(window, gwlpWndProc, proc)
	if previous == 0 {
		return err
	}
	defer wtsSetWindowProc.Call(window, gwlpWndProc, previous)
	const notifyForThisSession = 0
	registered, _, err := wtsRegisterSession.Call(window, notifyForThisSession)
	if registered == 0 {
		return err
	}
	defer wtsUnregisterSession.Call(window)

	stopEvent, eventErr := windows.CreateEvent(nil, 1, 0, nil)
	if eventErr != nil {
		return eventErr
	}
	defer windows.CloseHandle(stopEvent)
	signaled := make(chan struct{})
	detach := context.AfterFunc(ctx, func() {
		_ = windows.SetEvent(stopEvent)
		close(signaled)
	})
	defer func() {
		if !detach() {
			<-signaled
		}
	}()
	ready <- window
	return pumpWindowsSessionMessages(stopEvent)
}

func pumpWindowsSessionMessages(stop windows.Handle) error {
	const (
		qsAllInput         = 0x04ff
		mwmoInputAvailable = 4
		pmRemove           = 1
	)
	for {
		result, _, err := wtsWaitForInput.Call(1, uintptr(unsafe.Pointer(&stop)), windows.INFINITE,
			qsAllInput, mwmoInputAvailable)
		switch result {
		case windows.WAIT_OBJECT_0:
			return nil
		case windows.WAIT_OBJECT_0 + 1:
			for range 64 {
				var message wtsWindowMessage
				found, _, _ := wtsPeekMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0, pmRemove)
				if found == 0 {
					break
				}
				if message.message == wmQuit {
					return nil
				}
				wtsDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
			}
		default:
			return err
		}
	}
}
