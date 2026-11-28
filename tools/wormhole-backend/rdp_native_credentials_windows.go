//go:build windows

package main

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var rdpOle32 = windows.NewLazySystemDLL("ole32.dll")
var rdpOleAut = windows.NewLazySystemDLL("oleaut32.dll")
var rdpIIDDispatch = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var rdpIIDNull windows.GUID
var errRdpNativeCredentials = errors.New("native RDP credentials could not be applied")

type rdpOleVariant struct {
	VT           uint16
	Reserved     [3]uint16
	Value, Extra uintptr
}
type rdpOleParams struct {
	Args                 *rdpOleVariant
	Named                *int32
	ArgCount, NamedCount uint32
}

func rdpComMethod(object unsafe.Pointer, index int) uintptr {
	return (*[7]uintptr)(*(*unsafe.Pointer)(object))[index]
}
func rdpComRelease(object unsafe.Pointer) {
	if object != nil {
		_, _, _ = syscall.SyscallN(rdpComMethod(object, 2), uintptr(object))
	}
}
func rdpComFailed(hr uintptr) bool { return int32(hr) < 0 }

func rdpSecureDispatch(object unsafe.Pointer) error {
	hr, _, _ := rdpOle32.NewProc("CoSetProxyBlanket").Call(uintptr(object), 10, 0, 0, 6, 2, 0, 0)
	if rdpComFailed(hr) {
		return errRdpNativeCredentials
	}
	return nil
}

func rdpDispatchID(object unsafe.Pointer, name string) (int32, error) {
	text, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, errRdpNativeCredentials
	}
	var id int32
	hr, _, _ := syscall.SyscallN(rdpComMethod(object, 5), uintptr(object), uintptr(unsafe.Pointer(&rdpIIDNull)), uintptr(unsafe.Pointer(&text)), 1, 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(text)
	if rdpComFailed(hr) {
		return 0, errRdpNativeCredentials
	}
	return id, nil
}

func rdpDispatchGet(object unsafe.Pointer, name string) (unsafe.Pointer, error) {
	id, err := rdpDispatchID(object, name)
	if err != nil {
		return nil, err
	}
	var params rdpOleParams
	var result rdpOleVariant
	hr, _, _ := syscall.SyscallN(rdpComMethod(object, 6), uintptr(object), uintptr(id), uintptr(unsafe.Pointer(&rdpIIDNull)), 0, 2, uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&result)), 0, 0)
	if rdpComFailed(hr) || result.VT != 9 || result.Value == 0 {
		_, _, _ = rdpOleAut.NewProc("VariantClear").Call(uintptr(unsafe.Pointer(&result)))
		return nil, errRdpNativeCredentials
	}
	// Read the pointer member of the VARIANT union only after checking VT_DISPATCH.
	// Keep the storage integer-typed while Invoke may return a scalar instead.
	return *(*unsafe.Pointer)(unsafe.Pointer(&result.Value)), nil
}

func rdpDispatchSetCredential(object unsafe.Pointer, name string, raw []byte) error {
	value, err := rdpCredentialUTF16(raw)
	if err != nil {
		return err
	}
	defer clear(value)
	var first *uint16
	if len(value) > 0 {
		first = &value[0]
	}
	var bstr unsafe.Pointer
	allocated, _, _ := rdpOleAut.NewProc("SysReAllocStringLen").Call(uintptr(unsafe.Pointer(&bstr)), uintptr(unsafe.Pointer(first)), uintptr(len(value)))
	runtime.KeepAlive(value)
	if allocated == 0 || bstr == nil {
		return errRdpNativeCredentials
	}
	defer func() {
		if len(value) > 0 {
			clear(unsafe.Slice((*uint16)(bstr), len(value)))
		}
		_, _, _ = rdpOleAut.NewProc("SysFreeString").Call(uintptr(bstr))
	}()
	id, err := rdpDispatchID(object, name)
	if err != nil {
		return err
	}
	arg := rdpOleVariant{VT: 8, Value: uintptr(bstr)}
	named := int32(-3)
	params := rdpOleParams{Args: &arg, Named: &named, ArgCount: 1, NamedCount: 1}
	hr, _, _ := syscall.SyscallN(rdpComMethod(object, 6), uintptr(object), uintptr(id), uintptr(unsafe.Pointer(&rdpIIDNull)), 0, 4, uintptr(unsafe.Pointer(&params)), 0, 0, 0)
	runtime.KeepAlive(params)
	if rdpComFailed(hr) {
		return errRdpNativeCredentials
	}
	return nil
}

// Runs only inside Go. The C# adapter exports an opaque IDispatch reference and
// never receives the primary or gateway credential as JSON or a managed string.
func withNativeRdpDispatch(reference []byte, use func(unsafe.Pointer) error) error {
	local, err := localRdpDispatchReference(reference)
	if err != nil {
		return err
	}
	defer clear(local)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := rdpOle32.NewProc("CoInitializeEx").Call(0, 2)
	if rdpComFailed(hr) {
		return errRdpNativeCredentials
	}
	defer rdpOle32.NewProc("CoUninitialize").Call()
	var stream unsafe.Pointer
	hr, _, _ = rdpOle32.NewProc("CreateStreamOnHGlobal").Call(0, 1, uintptr(unsafe.Pointer(&stream)))
	if rdpComFailed(hr) || stream == nil {
		return errRdpNativeCredentials
	}
	defer rdpComRelease(stream)
	var written uint32
	hr, _, _ = syscall.SyscallN(rdpComMethod(stream, 4), uintptr(stream), uintptr(unsafe.Pointer(&local[0])), uintptr(len(local)), uintptr(unsafe.Pointer(&written)))
	runtime.KeepAlive(local)
	if rdpComFailed(hr) || written != uint32(len(local)) {
		return errRdpNativeCredentials
	}
	hr, _, _ = syscall.SyscallN(rdpComMethod(stream, 5), uintptr(stream), 0, 0, 0)
	if rdpComFailed(hr) {
		return errRdpNativeCredentials
	}
	var control unsafe.Pointer
	hr, _, _ = rdpOle32.NewProc("CoUnmarshalInterface").Call(uintptr(stream), uintptr(unsafe.Pointer(&rdpIIDDispatch)), uintptr(unsafe.Pointer(&control)))
	if rdpComFailed(hr) || control == nil {
		return errRdpNativeCredentials
	}
	defer rdpComRelease(control)
	if err := rdpSecureDispatch(control); err != nil {
		return err
	}
	return use(control)
}

func applyNativeRdpCredentials(reference, password, gatewayPassword []byte, passwordProvided, gatewayProvided bool) error {
	return withNativeRdpDispatch(reference, func(control unsafe.Pointer) error {
		if passwordProvided {
			advanced, err := rdpDispatchGet(control, "AdvancedSettings9")
			if err != nil {
				return err
			}
			err = rdpSecureDispatch(advanced)
			if err == nil {
				err = rdpDispatchSetCredential(advanced, "ClearTextPassword", password)
			}
			rdpComRelease(advanced)
			if err != nil {
				return err
			}
		}
		if gatewayProvided {
			transport, err := rdpDispatchGet(control, "TransportSettings2")
			if err != nil {
				return err
			}
			err = rdpSecureDispatch(transport)
			if err == nil {
				err = rdpDispatchSetCredential(transport, "GatewayPassword", gatewayPassword)
			}
			rdpComRelease(transport)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
