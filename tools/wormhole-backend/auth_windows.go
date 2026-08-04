//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

type windowsGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type lastInputInfo struct {
	Size      uint32
	LastInput uint32
}

var (
	combase                = syscall.NewLazyDLL("combase.dll")
	user32                 = syscall.NewLazyDLL("user32.dll")
	roInitialize           = combase.NewProc("RoInitialize")
	roUninitialize         = combase.NewProc("RoUninitialize")
	roGetActivationFactory = combase.NewProc("RoGetActivationFactory")
	windowsCreateString    = combase.NewProc("WindowsCreateString")
	windowsDeleteString    = combase.NewProc("WindowsDeleteString")
	getLastInputInfo       = user32.NewProc("GetLastInputInfo")
	getSystemMetrics       = user32.NewProc("GetSystemMetrics")
	kernel32ForIdle        = syscall.NewLazyDLL("kernel32.dll")
	getTickCount64         = kernel32ForIdle.NewProc("GetTickCount64")
	moveFileEx             = kernel32ForIdle.NewProc("MoveFileExW")
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

func replaceAuthFile(source, destination string) error {
	sourcePath, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return fmt.Errorf("invalid temporary path: %w", err)
	}
	destinationPath, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}
	result, _, callErr := moveFileEx.Call(
		uintptr(unsafe.Pointer(sourcePath)),
		uintptr(unsafe.Pointer(destinationPath)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("Windows atomic file replacement failed: %w", callErr)
		}
		return errors.New("Windows atomic file replacement failed")
	}
	return nil
}

var (
	iidUserConsentVerifierStatics = windowsGUID{
		Data1: 0xAF4F3F91,
		Data2: 0x564C,
		Data3: 0x4DDC,
		Data4: [8]byte{0xB8, 0xB5, 0x97, 0x34, 0x47, 0x62, 0x7C, 0x65},
	}
	iidAsyncInfo = windowsGUID{
		Data1: 0x00000036,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
)

const (
	remoteSessionMetric       = 0x1000
	asyncStarted              = 0
	asyncCompleted            = 1
	asyncCanceled             = 2
	asyncError                = 3
	remoteDesktopHelloMessage = "Remote Desktop session detected. Windows Hello is disabled in remote sessions. Use your configured fallback method to unlock Wormhole."
)

func unqueriedWindowsHelloStatus() authHelloStatus {
	return authHelloStatus{Message: "Windows Hello status has not been checked."}
}

func checkWindowsHello() authHelloStatus {
	if isRemoteSession() {
		return authHelloStatus{Message: remoteDesktopHelloMessage}
	}

	result, err := callWindowsHelloOperation(false, "")
	if err != nil {
		return authHelloStatus{Message: "Windows Hello is unavailable."}
	}
	switch result {
	case 0:
		return authHelloStatus{Available: true, Message: "Windows Hello is available."}
	case 1:
		return authHelloStatus{Message: "No Windows Hello device is present."}
	case 2:
		return authHelloStatus{Message: "Windows Hello is not configured for this Windows user."}
	case 3:
		return authHelloStatus{Message: "Windows Hello is disabled by policy."}
	case 4:
		return authHelloStatus{Message: "Windows Hello is busy."}
	default:
		return authHelloStatus{Message: "Windows Hello is unavailable."}
	}
}

func verifyWindowsHello() authVerificationResponse {
	if isRemoteSession() {
		return authVerificationResponse{Message: remoteDesktopHelloMessage}
	}
	result, err := callWindowsHelloOperation(true, "Unlock Wormhole")
	if err != nil {
		return authVerificationResponse{Message: "Windows Hello is unavailable."}
	}
	switch result {
	case 0:
		return authVerificationResponse{Succeeded: true, Message: "Verified."}
	case 1:
		return authVerificationResponse{Message: "No Windows Hello device is present."}
	case 2:
		return authVerificationResponse{Message: "Windows Hello is not configured for this Windows user."}
	case 3:
		return authVerificationResponse{Message: "Windows Hello is disabled by policy."}
	case 4:
		return authVerificationResponse{Message: "Windows Hello is busy."}
	case 5:
		return authVerificationResponse{Message: "Windows Hello retries were exhausted."}
	case 6:
		return authVerificationResponse{Message: "Windows Hello was canceled."}
	default:
		return authVerificationResponse{Message: "Windows Hello verification failed."}
	}
}

func callWindowsHelloOperation(verify bool, message string) (uint32, error) {
	initialized := false
	result, _, _ := roInitialize.Call(1) // RO_INIT_MULTITHREADED
	if result == 0 || result == 1 {
		initialized = true
	}
	if initialized {
		defer roUninitialize.Call()
	} else {
		return 0, errors.New("Windows Runtime is unavailable")
	}

	className := utf16.Encode([]rune("Windows.Security.Credentials.UI.UserConsentVerifier"))
	var hstring uintptr
	result, _, _ = windowsCreateString.Call(
		uintptr(unsafe.Pointer(&className[0])),
		uintptr(len(className)),
		uintptr(unsafe.Pointer(&hstring)),
	)
	if result != 0 {
		return 0, errors.New("Windows Hello class activation failed")
	}
	defer windowsDeleteString.Call(hstring)

	var factory uintptr
	result, _, _ = roGetActivationFactory.Call(
		hstring,
		uintptr(unsafe.Pointer(&iidUserConsentVerifierStatics)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if result != 0 || factory == 0 {
		return 0, errors.New("Windows Hello activation failed")
	}
	defer comRelease(factory)

	var operation uintptr
	methodSlot := 6
	var arguments []uintptr
	if verify {
		methodSlot = 7
		messageValue := utf16.Encode([]rune(message))
		var messageString uintptr
		result, _, _ = windowsCreateString.Call(
			uintptr(unsafe.Pointer(&messageValue[0])),
			uintptr(len(messageValue)),
			uintptr(unsafe.Pointer(&messageString)),
		)
		if result != 0 {
			return 0, errors.New("Windows Hello message creation failed")
		}
		defer windowsDeleteString.Call(messageString)
		arguments = []uintptr{messageString, uintptr(unsafe.Pointer(&operation))}
	} else {
		arguments = []uintptr{uintptr(unsafe.Pointer(&operation))}
	}
	if _, err := comCall(factory, methodSlot, arguments...); err != nil || operation == 0 {
		if err != nil {
			return 0, err
		}
		return 0, errors.New("Windows Hello did not return an async operation")
	}
	return awaitWindowsHelloResult(operation)
}

func awaitWindowsHelloResult(operation uintptr) (uint32, error) {
	defer comRelease(operation)
	var asyncInfo uintptr
	if _, err := comQueryInterface(operation, &iidAsyncInfo, &asyncInfo); err != nil || asyncInfo == 0 {
		if err != nil {
			return 0, err
		}
		return 0, errors.New("Windows Hello async operation is unavailable")
	}
	defer comRelease(asyncInfo)

	deadline := time.Now().Add(30 * time.Second)
	for {
		var status uint32
		if _, err := comCall(asyncInfo, 7, uintptr(unsafe.Pointer(&status))); err != nil {
			return 0, errors.New("Windows Hello status could not be read")
		}
		switch status {
		case asyncCompleted:
			var value uint32
			if _, err := comCall(operation, 8, uintptr(unsafe.Pointer(&value))); err != nil {
				return 0, errors.New("Windows Hello result could not be read")
			}
			return value, nil
		case asyncCanceled:
			return 6, nil
		case asyncError:
			return 0, errors.New("Windows Hello verification failed")
		case asyncStarted:
			if time.Now().After(deadline) {
				return 0, errors.New("Windows Hello timed out")
			}
			time.Sleep(10 * time.Millisecond)
		default:
			return 0, errors.New("Windows Hello returned an unknown status")
		}
	}
}

func comCall(object uintptr, slot int, arguments ...uintptr) (uintptr, error) {
	if object == 0 {
		return 0, errors.New("invalid COM object")
	}
	// COM returns object addresses through the Win32 ABI as uintptr values. Copy the address
	// through a pointer-sized slot before reading the unmanaged vtable; converting the uintptr
	// directly is rejected by go vet's unsafe-pointer analyzer even though this is the COM ABI.
	objectPointer := *(*unsafe.Pointer)(unsafe.Pointer(&object))
	vtable := *(*[32]uintptr)(objectPointer)
	method := vtable[slot]
	callArguments := make([]uintptr, 0, len(arguments)+1)
	callArguments = append(callArguments, object)
	callArguments = append(callArguments, arguments...)
	result, _, callErr := syscall.SyscallN(method, callArguments...)
	if result != 0 {
		if callErr != syscall.Errno(0) {
			return result, fmt.Errorf("Windows Runtime call failed: %w", callErr)
		}
		return result, errors.New("Windows Runtime call failed")
	}
	return result, nil
}

func comQueryInterface(object uintptr, identifier *windowsGUID, output *uintptr) (uintptr, error) {
	return comCall(object, 0, uintptr(unsafe.Pointer(identifier)), uintptr(unsafe.Pointer(output)))
}

func comRelease(object uintptr) {
	if object != 0 {
		_, _ = comCall(object, 2)
	}
}

func isRemoteSession() bool {
	result, _, _ := getSystemMetrics.Call(remoteSessionMetric)
	if result != 0 {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(os.Getenv("SESSIONNAME")), "RDP-")
}

func systemIdleSeconds() int64 {
	info := lastInputInfo{Size: uint32(unsafe.Sizeof(lastInputInfo{}))}
	result, _, _ := getLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		return 0
	}
	now, _, _ := getTickCount64.Call()
	elapsed := uint32(now) - info.LastInput
	return int64(elapsed / 1000)
}
