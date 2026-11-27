//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"os"
	"runtime"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

const vaultHelloClass = "Windows.Security.Credentials.KeyCredentialManager"

// These interfaces and method slots are from the Windows SDK 10.0.26100.0.
var (
	iidVaultHelloManager       = windowsGUID{0x6AAC468B, 0x0EF1, 0x4CE0, [8]byte{0x82, 0x90, 0x41, 0x06, 0xDA, 0x6A, 0x63, 0xB5}}
	iidVaultHelloWindowManager = windowsGUID{0x30B1B9C9, 0x61EF, 0x43E8, [8]byte{0x88, 0xAC, 0xCC, 0x43, 0x3B, 0x38, 0xD1, 0xA6}}
	iidVaultHelloWindowKey     = windowsGUID{0x050DEB3B, 0xB19C, 0x4635, [8]byte{0x9D, 0xF6, 0x56, 0x50, 0xD6, 0x6C, 0x62, 0xB1}}
	iidVaultCryptoBuffer       = windowsGUID{0x320B7E22, 0x3CB0, 0x4CDF, [8]byte{0x86, 0x63, 0x1D, 0x28, 0x91, 0x00, 0x65, 0xEB}}
	iidVaultBufferBytes        = windowsGUID{0x905A0FEF, 0xBC53, 0x11DF, [8]byte{0x8C, 0x49, 0x00, 0x1E, 0x4F, 0xC6, 0x86, 0xDA}}
	vaultWindowThreadProcessID = windows.NewLazySystemDLL("user32.dll").NewProc("GetWindowThreadProcessId")
	vaultWindowIDFromHandle    = windows.NewLazySystemDLL("Windows.UI.dll").NewProc("GetWindowIdFromWindow")
)

func inVaultHelloApartment(ctx context.Context, run func() error) error {
	if isRemoteSession() {
		return errVaultHelloRemote
	}
	return inVaultCredentialApartment(ctx, run)
}

func inVaultCredentialApartment(ctx context.Context, run func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := roInitialize.Call(1) // RO_INIT_MULTITHREADED
	if hr != 0 && hr != 1 {
		return errVaultHelloUnavailable
	}
	defer roUninitialize.Call()
	return run()
}

func vaultHelloHString(value string) (uintptr, error) {
	encoded := utf16.Encode([]rune(value))
	if len(encoded) == 0 {
		return 0, vault.ErrFormat
	}
	var handle uintptr
	hr, _, _ := windowsCreateString.Call(uintptr(unsafe.Pointer(&encoded[0])), uintptr(len(encoded)), uintptr(unsafe.Pointer(&handle)))
	if hr != 0 || handle == 0 {
		return 0, errVaultHelloUnavailable
	}
	return handle, nil
}

func vaultHelloFactory(class string, iid *windowsGUID) (uintptr, error) {
	name, err := vaultHelloHString(class)
	if err != nil {
		return 0, err
	}
	defer windowsDeleteString.Call(name)
	var factory uintptr
	hr, _, _ := roGetActivationFactory.Call(name, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&factory)))
	if hr != 0 || factory == 0 {
		return 0, errVaultHelloUnavailable
	}
	return factory, nil
}

//go:uintptrescapes
func awaitVaultHello(ctx context.Context, operation uintptr, result ...uintptr) error {
	if operation == 0 {
		return errVaultHelloUnavailable
	}
	defer comRelease(operation)
	var info uintptr
	if _, err := comQueryInterface(operation, &iidAsyncInfo, &info); err != nil || info == 0 {
		return errVaultHelloUnavailable
	}
	defer comRelease(info)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	finished := false
	defer func() {
		if !finished {
			cancelWindowsHelloOperation(info)
		}
	}()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := readWindowsHelloStatus(info)
		if err != nil {
			return errVaultHelloUnavailable
		}
		switch status {
		case asyncCompleted:
			finished = true
			if _, err := comCall(operation, 8, result...); err != nil {
				return errVaultHelloUnavailable
			}
			return nil
		case asyncCanceled:
			finished = true
			return errVaultHelloCanceled
		case asyncStarted:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-tick.C:
			}
		default:
			return errVaultHelloUnavailable
		}
	}
}

func platformVaultHelloAvailable(ctx context.Context) error {
	return inVaultHelloApartment(ctx, func() error {
		manager, err := vaultHelloFactory(vaultHelloClass, &iidVaultHelloManager)
		if err != nil {
			return err
		}
		defer comRelease(manager)
		var operation uintptr
		if _, err := comCall(manager, 6, uintptr(unsafe.Pointer(&operation))); err != nil {
			return errVaultHelloUnavailable
		}
		var supported uint8 // ABI Boolean, not a Win32 BOOL.
		if err := awaitVaultHello(ctx, operation, uintptr(unsafe.Pointer(&supported))); err != nil {
			return err
		}
		if supported != 1 {
			return errVaultHelloUnavailable
		}
		return nil
	})
}

func vaultHelloOwnerWindow(hwnd uintptr) (uintptr, error) {
	var process uint32
	thread, _, _ := vaultWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&process)))
	if thread == 0 || process == 0 || int(process) != os.Getppid() {
		return 0, vault.ErrPolicy
	}
	if windows.RtlGetVersion().BuildNumber < 26100 {
		return 0, nil // Use the original WinRT creation and signing APIs.
	}
	var windowID uintptr // WindowId is a single uint64 on x64 and arm64.
	if err := vaultWindowIDFromHandle.Find(); err != nil {
		return 0, errVaultHelloUnavailable
	}
	hr, _, _ := vaultWindowIDFromHandle.Call(hwnd, uintptr(unsafe.Pointer(&windowID)))
	if hr != 0 || windowID == 0 {
		return 0, errVaultHelloUnavailable
	}
	return windowID, nil
}

func withPlatformVaultHello(ctx context.Context, name string, hwnd uintptr, create bool, use func(vault.HelloCredential) error) error {
	return inVaultHelloApartment(ctx, func() error {
		window, err := vaultHelloOwnerWindow(hwnd)
		if err != nil {
			return err
		}
		manager, err := vaultHelloFactory(vaultHelloClass, &iidVaultHelloManager)
		if err != nil {
			return err
		}
		defer comRelease(manager)
		keyName, err := vaultHelloHString(name)
		if err != nil {
			return err
		}
		defer windowsDeleteString.Call(keyName)
		bufferFactory, err := vaultHelloFactory("Windows.Security.Cryptography.CryptographicBuffer", &iidVaultCryptoBuffer)
		if err != nil {
			return err
		}
		defer comRelease(bufferFactory)
		var operation uintptr
		switch {
		case create && window != 0:
			windowManager, err := vaultHelloFactory(vaultHelloClass, &iidVaultHelloWindowManager)
			if err != nil {
				return err
			}
			defer comRelease(windowManager)
			_, err = comCall(windowManager, 6, window, keyName, 1, uintptr(unsafe.Pointer(&operation))) // FailIfExists
			if err != nil {
				return errVaultHelloUnavailable
			}
		case create:
			_, err = comCall(manager, 8, keyName, 1, uintptr(unsafe.Pointer(&operation))) // FailIfExists
		default:
			_, err = comCall(manager, 9, keyName, uintptr(unsafe.Pointer(&operation)))
		}
		if err != nil {
			return errVaultHelloUnavailable
		}
		var result uintptr
		if err := awaitVaultHello(ctx, operation, uintptr(unsafe.Pointer(&result))); err != nil {
			return err
		}
		defer comRelease(result)
		if err := vaultHelloOperationStatus(result); err != nil {
			return err
		}
		if create {
			// Keep a key when publication may already have replaced the slot file.
			// Password and recovery remain usable even if the key is later lost.
			defer func() {
				if err != nil && !errors.Is(err, errVaultSlotCommitUncertain) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					_ = deleteVaultHelloKey(ctx, manager, keyName)
				}
			}()
		}
		credential := windowsVaultHelloCredential{owner: window, bufferFactory: bufferFactory}
		if _, err = comCall(result, 6, uintptr(unsafe.Pointer(&credential.key))); err != nil || credential.key == 0 {
			err = errVaultHelloUnavailable
			return err
		}
		defer comRelease(credential.key)
		err = use(credential)
		return err
	})
}

func platformRemoveVaultHello(ctx context.Context, name string) bool {
	return inVaultCredentialApartment(ctx, func() error {
		manager, err := vaultHelloFactory(vaultHelloClass, &iidVaultHelloManager)
		if err != nil {
			return err
		}
		defer comRelease(manager)
		keyName, err := vaultHelloHString(name)
		if err != nil {
			return err
		}
		defer windowsDeleteString.Call(keyName)
		var operation, result uintptr
		if _, err := comCall(manager, 9, keyName, uintptr(unsafe.Pointer(&operation))); err != nil {
			return errVaultHelloUnavailable
		}
		if err := awaitVaultHello(ctx, operation, uintptr(unsafe.Pointer(&result))); err != nil {
			return err
		}
		defer comRelease(result)
		var status uint32
		if _, err := comCall(result, 7, uintptr(unsafe.Pointer(&status))); err != nil {
			return errVaultHelloUnavailable
		}
		switch status {
		case 0: // KeyCredentialStatus.Success
			return deleteVaultHelloKey(ctx, manager, keyName)
		case 2: // KeyCredentialStatus.NotFound
			return nil
		default:
			return errVaultHelloUnavailable
		}
	}) == nil
}

func deleteVaultHelloKey(ctx context.Context, manager, name uintptr) error {
	var operation uintptr
	if _, err := comCall(manager, 10, name, uintptr(unsafe.Pointer(&operation))); err != nil || operation == 0 {
		return errVaultHelloUnavailable
	}
	// DeleteAsync is IAsyncAction. Its GetResults is also at slot 8.
	return awaitVaultHello(ctx, operation)
}

func vaultHelloOperationStatus(result uintptr) error {
	var status uint32
	if _, err := comCall(result, 7, uintptr(unsafe.Pointer(&status))); err != nil {
		return errVaultHelloUnavailable
	}
	switch status {
	case 0: // Success
		return nil
	case 3, 4: // UserCanceled or UserPrefersPassword
		return errVaultHelloCanceled
	default:
		return errVaultHelloUnavailable
	}
}

type windowsVaultHelloCredential struct {
	key, owner, bufferFactory uintptr
}

func (c windowsVaultHelloCredential) PublicKey() ([]byte, error) {
	var buffer uintptr
	if _, err := comCall(c.key, 8, 0, uintptr(unsafe.Pointer(&buffer))); err != nil { // X509SubjectPublicKeyInfo
		return nil, errVaultHelloUnavailable
	}
	defer comRelease(buffer)
	return copyVaultHelloBuffer(buffer, 512, false)
}

func (c windowsVaultHelloCredential) Attestation(ctx context.Context, public *rsa.PublicKey) (vault.HelloAttestation, error) {
	var operation, result uintptr
	if _, err := comCall(c.key, 10, uintptr(unsafe.Pointer(&operation))); err != nil {
		return "", errVaultHelloUnavailable
	}
	if err := awaitVaultHello(ctx, operation, uintptr(unsafe.Pointer(&result))); err != nil {
		return "", err
	}
	defer comRelease(result)
	var status uint32
	if _, err := comCall(result, 8, uintptr(unsafe.Pointer(&status))); err != nil {
		return "", errVaultHelloUnavailable
	}
	switch status {
	case 0:
		roots, err := ospolicy.ReadHelloTPMAttestationRoots(ctx)
		if err != nil {
			return "", err
		}
		var evidence [2][]byte
		for i, method := range []int{6, 7} { // Certificate chain and attestation statement.
			var buffer uintptr
			if _, err := comCall(result, method, uintptr(unsafe.Pointer(&buffer))); err != nil || buffer == 0 {
				return "", errVaultHelloUnavailable
			}
			defer comRelease(buffer)
			if length, err := vaultHelloBufferLength(buffer); err != nil || length == 0 || length > 1<<20 {
				return "", errVaultHelloUnavailable
			}
			if roots != nil {
				evidence[i], err = copyVaultHelloBuffer(buffer, 1<<20, false)
				if err != nil {
					return "", err
				}
				defer vault.Wipe(evidence[i])
			}
		}
		if roots != nil {
			certificates, err := decodeWindowsHelloCertificates(evidence[0])
			if err == nil && vault.VerifyHelloTPMAttestation(evidence[1], certificates, roots, public, time.Now()) == nil {
				return vault.HelloAttestationTPMVerified, nil
			}
		}
		return vault.HelloAttestationPresent, nil
	case 2: // NotSupported
		return vault.HelloAttestationUnsupported, nil
	default:
		return "", errVaultHelloUnavailable
	}
}

func (c windowsVaultHelloCredential) Sign(ctx context.Context, challenge []byte) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, vault.ErrFormat
	}
	var buffer uintptr
	if _, err := comCall(c.bufferFactory, 9, 32, uintptr(unsafe.Pointer(&challenge[0])), uintptr(unsafe.Pointer(&buffer))); err != nil || buffer == 0 {
		return nil, errVaultHelloUnavailable
	}
	defer comRelease(buffer)
	var operation uintptr
	var err error
	if c.owner != 0 {
		var windowKey uintptr
		if _, err := comQueryInterface(c.key, &iidVaultHelloWindowKey, &windowKey); err != nil || windowKey == 0 {
			return nil, errVaultHelloUnavailable
		}
		defer comRelease(windowKey)
		_, err = comCall(windowKey, 6, c.owner, buffer, uintptr(unsafe.Pointer(&operation)))
	} else {
		_, err = comCall(c.key, 9, buffer, uintptr(unsafe.Pointer(&operation)))
	}
	if err != nil {
		return nil, errVaultHelloUnavailable
	}
	var result uintptr
	if err := awaitVaultHello(ctx, operation, uintptr(unsafe.Pointer(&result))); err != nil {
		return nil, err
	}
	defer comRelease(result)
	if err := vaultHelloOperationStatus(result); err != nil {
		return nil, err
	}
	var signature uintptr
	if _, err := comCall(result, 6, uintptr(unsafe.Pointer(&signature))); err != nil {
		return nil, errVaultHelloUnavailable
	}
	defer comRelease(signature)
	return copyVaultHelloBuffer(signature, 512, true)
}

func vaultHelloBufferLength(buffer uintptr) (uint32, error) {
	var length uint32
	_, err := comCall(buffer, 7, uintptr(unsafe.Pointer(&length)))
	return length, err
}

func copyVaultHelloBuffer(buffer uintptr, maximum uint32, wipe bool) ([]byte, error) {
	length, err := vaultHelloBufferLength(buffer)
	if err != nil || length == 0 || length > maximum {
		return nil, errVaultHelloUnavailable
	}
	var access uintptr
	if _, err := comQueryInterface(buffer, &iidVaultBufferBytes, &access); err != nil || access == 0 {
		return nil, errVaultHelloUnavailable
	}
	defer comRelease(access)
	var data *byte
	if _, err := comCall(access, 3, uintptr(unsafe.Pointer(&data))); err != nil || data == nil {
		return nil, errVaultHelloUnavailable
	}
	body := unsafe.Slice(data, length)
	if wipe {
		defer vault.Wipe(body)
	}
	return append([]byte(nil), body...), nil
}
