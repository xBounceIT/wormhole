package secretclipboard

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type winCall func(...uintptr) (uintptr, uintptr, error)

// Preserve Go pointer arguments across the indirect syscall boundary: the
// compiler must move them off movable stacks and retain them until return.
//
//go:uintptrescapes
func callWindows(fn winCall, args ...uintptr) (uintptr, uintptr, error) { return fn(args...) }

type winBindings struct {
	create, destroy, peek, translate, dispatch, register winCall
	open, close, empty, sequence, owner, set             winCall
	allocate, lock, unlock, free                         winCall
}

func systemBindings() winBindings {
	user := windows.NewLazySystemDLL("user32.dll")
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	return winBindings{
		create: user.NewProc("CreateWindowExW").Call, destroy: user.NewProc("DestroyWindow").Call,
		peek: user.NewProc("PeekMessageW").Call, translate: user.NewProc("TranslateMessage").Call, dispatch: user.NewProc("DispatchMessageW").Call,
		register: user.NewProc("RegisterClipboardFormatW").Call,
		open:     user.NewProc("OpenClipboard").Call, close: user.NewProc("CloseClipboard").Call, empty: user.NewProc("EmptyClipboard").Call,
		sequence: user.NewProc("GetClipboardSequenceNumber").Call, owner: user.NewProc("GetClipboardOwner").Call, set: user.NewProc("SetClipboardData").Call,
		allocate: kernel.NewProc("GlobalAlloc").Call, lock: kernel.NewProc("GlobalLock").Call, unlock: kernel.NewProc("GlobalUnlock").Call, free: kernel.NewProc("GlobalFree").Call,
	}
}

type windowsAPI struct {
	calls      winBindings
	window     uintptr
	exclusions []uint32
}

func NewNative() (Driver, error) { return newWindowsDriver(&windowsAPI{calls: systemBindings()}) }
func (a *windowsAPI) initialize() error {
	class, _ := windows.UTF16PtrFromString("STATIC")
	// HWND_MESSAGE = -3: invisible and absent from the user's taskbar.
	a.window, _, _ = callWindows(a.calls.create, 0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, 0, 0)
	if a.window == 0 {
		return ErrUnavailable
	}
	for _, name := range []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		wide, _ := windows.UTF16PtrFromString(name)
		format, _, _ := callWindows(a.calls.register, uintptr(unsafe.Pointer(wide)))
		if format == 0 {
			a.destroy()
			return ErrUnavailable
		}
		a.exclusions = append(a.exclusions, uint32(format))
	}
	return nil
}
func (a *windowsAPI) formats() []uint32 { return a.exclusions }
func (a *windowsAPI) destroy() {
	if a.window != 0 {
		a.calls.destroy(a.window)
		a.window = 0
	}
}
func (a *windowsAPI) open() bool  { value, _, _ := a.calls.open(a.window); return value != 0 }
func (a *windowsAPI) close()      { a.calls.close() }
func (a *windowsAPI) empty() bool { value, _, _ := a.calls.empty(); return value != 0 }
func (a *windowsAPI) sequence() Ticket {
	value, _, _ := a.calls.sequence()
	return Ticket(uint32(value))
}
func (a *windowsAPI) owned() bool {
	value, _, _ := a.calls.owner()
	return value != 0 && value == a.window
}
func (a *windowsAPI) set(format uint32, value []byte) bool {
	if len(value) == 0 || len(value) > 32770 {
		return false
	}
	handle, _, _ := a.calls.allocate(0x42, uintptr(len(value))) // GMEM_MOVEABLE | GMEM_ZEROINIT
	if handle == 0 {
		return false
	}
	pointer, _, _ := a.calls.lock(handle)
	if pointer == 0 {
		a.calls.free(handle)
		return false
	}
	// Native memory belongs to us until SetClipboardData succeeds. A failed write
	// wipes it before release; successful ownership transfer forbids later writes.
	memory := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), len(value))
	copy(memory, value)
	a.calls.unlock(handle)
	result, _, _ := a.calls.set(uintptr(format), handle)
	if result != 0 {
		return true
	}
	pointer, _, _ = a.calls.lock(handle)
	if pointer != 0 {
		clear(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), len(value)))
		a.calls.unlock(handle)
	}
	a.calls.free(handle)
	return false
}

// MSG has native pointer alignment on Windows x64 and arm64.
type windowsMessage struct {
	window  uintptr
	message uint32
	wparam  uintptr
	lparam  uintptr
	time    uint32
	x, y    int32
	private uint32
}

func (a *windowsAPI) pump() {
	var message windowsMessage
	for i := 0; i < 64; i++ {
		found, _, _ := callWindows(a.calls.peek, uintptr(unsafe.Pointer(&message)), a.window, 0, 0, 1)
		if found == 0 {
			return
		}
		callWindows(a.calls.translate, uintptr(unsafe.Pointer(&message)))
		callWindows(a.calls.dispatch, uintptr(unsafe.Pointer(&message)))
	}
}
