package secretclipboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fakeWindows struct {
	sequenceValue          Ticket
	owner, opened, changed bool
	failInit, failEmpty    bool
	failFormat             uint32
	busy                   int
	events                 []uint32
	published              []byte
	borrowed               []byte
	pumps, destroys        int
	written                chan struct{}
	resume                 chan struct{}
}

func (a *fakeWindows) initialize() error {
	if a.failInit {
		return ErrUnavailable
	}
	return nil
}
func (a *fakeWindows) pump()    { a.pumps++ }
func (a *fakeWindows) destroy() { a.destroys++ }
func (a *fakeWindows) open() bool {
	if a.busy > 0 {
		a.busy--
		return false
	}
	a.opened = true
	return true
}
func (a *fakeWindows) close() {
	if a.changed {
		a.sequenceValue++
		a.changed = false
	}
	a.opened = false
}
func (a *fakeWindows) empty() bool {
	if !a.opened {
		panic("unlocked empty")
	}
	if a.failEmpty {
		return false
	}
	a.sequenceValue++
	a.changed = true
	a.owner = true
	a.published = nil
	return true
}
func (a *fakeWindows) sequence() Ticket {
	return a.sequenceValue
}
func (a *fakeWindows) owned() bool       { return a.owner }
func (a *fakeWindows) formats() []uint32 { return []uint32{100, 101, 102} }
func (a *fakeWindows) set(format uint32, value []byte) bool {
	if !a.opened {
		panic("unlocked set")
	}
	a.events = append(a.events, format)
	if format == a.failFormat {
		return false
	}
	a.sequenceValue++
	if format == 13 {
		a.published = bytes.Clone(value)
		a.borrowed = value
		if a.written != nil {
			close(a.written)
			<-a.resume
		}
	}
	return true
}
func TestWindowsClipboardAtomicWriteAndOwnership(t *testing.T) {
	a := &fakeWindows{busy: 1}
	ticket, err := windowsWrite(context.Background(), a, []byte("a😀é"))
	if err != nil || ticket == 0 || a.opened || a.pumps != 1 {
		t.Fatal(ticket, err)
	}
	if !bytes.Equal(a.published, []byte{97, 0, 0x3d, 0xd8, 0, 0xde, 0xe9, 0, 0, 0}) {
		t.Fatal("UTF16 encoding")
	}
	if len(a.events) != 4 || a.events[0] != 100 || a.events[1] != 101 || a.events[2] != 102 || a.events[3] != 13 {
		t.Fatal("history marker order")
	}
	if !bytes.Equal(a.borrowed, make([]byte, len(a.borrowed))) {
		t.Fatal("conversion retained plaintext")
	}
	a.owner = false
	if err = windowsClear(context.Background(), a, ticket); err != nil || a.published == nil {
		t.Fatal("foreign owner cleared")
	}
	a.owner = true
	a.sequenceValue++
	if err = windowsClear(context.Background(), a, ticket); err != nil || a.published == nil {
		t.Fatal("newer sequence cleared")
	}
	a.sequenceValue--
	if err = windowsClear(context.Background(), a, ticket); err != nil || a.published != nil || a.opened {
		t.Fatal("clear failed", err)
	}
	a.sequenceValue = 0
	a.open()
	defer a.close()
	if windowsTicket(a) == 0 {
		t.Fatal("zero sequence lost obligation")
	}
}
func TestWindowsClipboardFailurePaths(t *testing.T) {
	for _, format := range []uint32{100, 101, 102, 13} {
		a := &fakeWindows{failFormat: format}
		ticket, err := windowsWrite(context.Background(), a, []byte("synthetic"))
		if err != ErrUnavailable || ticket != 0 || a.opened || a.published != nil {
			t.Fatal(format, ticket, err)
		}
	}
	a := &fakeWindows{failEmpty: true}
	if _, err := windowsWrite(context.Background(), a, []byte("x")); err != ErrUnavailable || a.opened {
		t.Fatal(err)
	}
	a.owner = true
	if err := windowsClear(context.Background(), a, 1<<32); err != ErrUnavailable || a.opened {
		t.Fatal(err)
	}
	if err := windowsClear(context.Background(), a, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := windowsWrite(ctx, a, []byte("x")); err != context.Canceled {
		t.Fatal(err)
	}
	if err := windowsClear(ctx, a, 1); err != context.Canceled {
		t.Fatal(err)
	}
	a.busy = 100
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := windowsOpen(ctx, a); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestWindowsWorkerBorrowsUntilCompletion(t *testing.T) {
	a := &fakeWindows{written: make(chan struct{}), resume: make(chan struct{})}
	d, err := newWindowsDriver(a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := d.Write(ctx, []byte("synthetic")); done <- err }()
	<-a.written
	cancel()
	select {
	case <-done:
		t.Fatal("returned before borrowed data retired")
	default:
	}
	close(a.resume)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil || a.destroys != 1 {
		t.Fatal(err)
	}
	if _, err = d.Write(context.Background(), []byte("x")); err != ErrClosed {
		t.Fatal(err)
	}
	if err = d.Clear(context.Background(), 1); err != ErrClosed {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil || a.destroys != 1 {
		t.Fatal("double close", err)
	}
	if _, err = d.Write(context.Background(), nil); err != ErrInput {
		t.Fatal(err)
	}
	if _, err = newWindowsDriver(&fakeWindows{failInit: true}); err != ErrUnavailable {
		t.Fatal(err)
	}
}
func TestWindowsWorkerConcurrentClose(t *testing.T) {
	a := &fakeWindows{}
	d, err := newWindowsDriver(a)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := d.Write(context.Background(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Clear(context.Background(), ticket); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = d.Write(ctx, []byte("x")); err != context.Canceled {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() { defer group.Done(); d.Close() }()
	}
	group.Wait()
	if a.destroys != 1 {
		t.Fatal("resource lifetime")
	}
}
func winResult(result uintptr) winCall {
	return func(...uintptr) (uintptr, uintptr, error) { return result, 0, nil }
}
func TestWindowsBindingsAndNativeAllocation(t *testing.T) {
	// All clipboard and window writes are faked. Only local GlobalAlloc memory is
	// real: these tests never replace the user's clipboard or access its contents.
	bindings := systemBindings()
	bindings.create = winResult(7)
	bindings.destroy = winResult(1)
	var names []string
	bindings.register = func(args ...uintptr) (uintptr, uintptr, error) {
		runtime.GC()
		names = append(names, clipboardWindowsString(args[0]))
		return uintptr(100 + len(names)), 0, nil
	}
	a := &windowsAPI{calls: bindings}
	if err := a.initialize(); err != nil || len(a.formats()) != 3 || names[0] != "ExcludeClipboardContentFromMonitorProcessing" || names[1] != "CanIncludeInClipboardHistory" || names[2] != "CanUploadToCloudClipboard" {
		t.Fatal(names, err)
	}
	a.calls.open = winResult(1)
	a.calls.close = winResult(1)
	a.calls.empty = winResult(1)
	a.calls.sequence = winResult(42)
	a.calls.owner = winResult(7)
	if !a.open() || !a.empty() || a.sequence() != 42 || !a.owned() {
		t.Fatal("bindings")
	}
	a.close()
	a.calls.owner = winResult(8)
	if a.owned() {
		t.Fatal("owner mismatch")
	}
	var handle uintptr
	a.calls.set = func(args ...uintptr) (uintptr, uintptr, error) {
		handle = args[1]
		pointer, _, _ := a.calls.lock(handle)
		value := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), 4)
		if !bytes.Equal(value, []byte{1, 2, 3, 4}) {
			t.Fatal("native copy")
		}
		a.calls.unlock(handle)
		return handle, 0, nil
	}
	if !a.set(13, []byte{1, 2, 3, 4}) {
		t.Fatal("set")
	}
	a.calls.free(handle)
	a.calls.set = winResult(0)
	originalFree := a.calls.free
	a.calls.free = func(args ...uintptr) (uintptr, uintptr, error) {
		pointer, _, _ := a.calls.lock(args[0])
		if pointer != 0 {
			value := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), 4)
			if !bytes.Equal(value, make([]byte, 4)) {
				t.Fatal("failure did not wipe")
			}
			a.calls.unlock(args[0])
		}
		return originalFree(args...)
	}
	if a.set(13, []byte{1, 2, 3, 4}) {
		t.Fatal("failed set accepted")
	}
	if a.set(13, nil) || a.set(13, make([]byte, 32771)) {
		t.Fatal("size bounds")
	}
	a.calls.allocate = winResult(0)
	if a.set(13, []byte{1}) {
		t.Fatal("allocate error")
	}
	a.calls.allocate = bindings.allocate
	a.calls.lock = winResult(0)
	a.calls.free = originalFree
	if a.set(13, []byte{1}) {
		t.Fatal("lock error")
	}
	a.calls.peek = winResult(1)
	pumped := 0
	a.calls.translate = winResult(1)
	a.calls.dispatch = func(...uintptr) (uintptr, uintptr, error) { pumped++; return 0, 0, nil }
	a.pump()
	if pumped != 64 {
		t.Fatal("unbounded message pump")
	}
	a.calls.peek = winResult(0)
	a.pump()
	if pumped != 64 {
		t.Fatal("empty pump")
	}
	a.destroy()
	a.destroy()
	if a.window != 0 {
		t.Fatal("window lifetime")
	}
	if unsafe.Sizeof(windowsMessage{}) != 48 {
		t.Fatal("MSG ABI")
	}

}
func TestWindowsBindingsInitializationFailures(t *testing.T) {
	a := &windowsAPI{calls: winBindings{create: winResult(0)}}
	if err := a.initialize(); err != ErrUnavailable {
		t.Fatal(err)
	}
	destroyed := false
	a.calls.create = winResult(7)
	a.calls.register = winResult(0)
	a.calls.destroy = func(...uintptr) (uintptr, uintptr, error) { destroyed = true; return 1, 0, nil }
	if err := a.initialize(); err != ErrUnavailable || !destroyed || a.window != 0 {
		t.Fatal(err)
	}
}
func TestNativeClipboardWindowLifecycleWithoutClipboardAccess(t *testing.T) {
	d, err := NewNative()
	if err != nil {
		t.Fatal(err)
	}
	// Allow a pump tick; no clipboard Write/Clear is issued.
	time.Sleep(30 * time.Millisecond)
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClipboardWindowsIsolatedStationInterop(t *testing.T) {
	if os.Getenv("WORMHOLE_CLIPBOARD_STATION_TEST") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^TestClipboardWindowsIsolatedStationInterop$", "-test.v")
		command.Env = append(os.Environ(), "WORMHOLE_CLIPBOARD_STATION_TEST=1")
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated clipboard: %v\n%s", err, output)
		}
		if bytes.Contains(output, []byte("ISOLATION_UNAVAILABLE")) {
			t.Skipf("private Windows station unavailable: %s", output)
		}
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	user := windows.NewLazySystemDLL("user32.dll")
	original, _, _ := user.NewProc("GetProcessWindowStation").Call()
	// CWF_CREATE_ONLY prevents ever reusing an existing station. No clipboard API
	// runs unless a NEW station and its private desktop have both been selected.
	stationName, _ := windows.UTF16PtrFromString(fmt.Sprintf("WormholeClipboardTest-%d-%d", os.Getpid(), time.Now().UnixNano()))
	station, _, err := user.NewProc("CreateWindowStationW").Call(uintptr(unsafe.Pointer(stationName)), 1, 0x37f, 0)
	if station == 0 {
		t.Log("ISOLATION_UNAVAILABLE", err)
		return
	}
	defer user.NewProc("CloseWindowStation").Call(station)
	if ok, _, err := user.NewProc("SetProcessWindowStation").Call(station); ok == 0 {
		t.Fatal("select station", err)
	}
	defer user.NewProc("SetProcessWindowStation").Call(original)
	current, _, _ := user.NewProc("GetProcessWindowStation").Call()
	if current != station {
		t.Fatal("station not isolated")
	}
	threadDesktop, _, _ := user.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	name, _ := windows.UTF16PtrFromString("ClipboardTest")
	desktop, _, err := user.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, 0x1ff, 0)
	if desktop == 0 {
		t.Fatal("create private desktop", err)
	}
	defer user.NewProc("CloseDesktop").Call(desktop)
	if ok, _, err := user.NewProc("SetThreadDesktop").Call(desktop); ok == 0 {
		t.Fatal("select private desktop", err)
	}
	defer user.NewProc("SetThreadDesktop").Call(threadDesktop)
	a := &windowsAPI{calls: systemBindings()}
	if err := a.initialize(); err != nil {
		t.Fatal(err)
	}
	defer a.destroy()
	ticket, err := windowsWrite(context.Background(), a, []byte("synthetic clipboard 😀"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.open() {
		t.Fatal("open private clipboard")
	}
	if windowsTicket(a) != ticket {
		a.close()
		t.Fatal("sequence changed at CloseClipboard")
	}
	for _, format := range a.formats() {
		available, _, _ := user.NewProc("IsClipboardFormatAvailable").Call(uintptr(format))
		if available == 0 {
			a.close()
			t.Fatal("missing exclusion format")
		}
	}
	text, _, _ := user.NewProc("GetClipboardData").Call(13)
	pointer, _, _ := a.calls.lock(text)
	if pointer == 0 {
		a.close()
		t.Fatal("native text missing")
	}
	got := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pointer)))
	a.calls.unlock(text)
	if got != "synthetic clipboard 😀" {
		a.close()
		t.Fatal("native roundtrip")
	}
	// Request a synthesized legacy format: expiry must still recognize our value.
	user.NewProc("GetClipboardData").Call(1)
	a.close()
	if err := windowsClear(context.Background(), a, ticket); err != nil {
		t.Fatal(err)
	}
	available, _, _ := user.NewProc("IsClipboardFormatAvailable").Call(13)
	if available != 0 {
		t.Fatal("expired native text survived")
	}
}

// Test-side Win32 callback: its uintptr names a pointer whose lifetime the
// annotated production syscall wrapper owns; checkptr cannot see that ABI.
//
//go:nocheckptr
func clipboardWindowsString(pointer uintptr) string {
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pointer)))
}
