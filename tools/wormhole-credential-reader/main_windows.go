//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	credentialTypeGeneric  = 1
	errorNotFound          = syscall.Errno(1168)
	maxCredentialBlobBytes = 2560
	maxTargetNameUnits     = 256
	maxUserNameUnits       = 513
)

var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	credEnumerateW = advapi32.NewProc("CredEnumerateW")
	credFree       = advapi32.NewProc("CredFree")
	credEnumerate  = callCredEnumerate
	credFreeMemory = callCredFree
)

// credential mirrors the Windows CREDENTIALW layout on both amd64 and arm64. The helper is
// intentionally Windows-only so these pointers never need a cross-platform representation.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type credentialEntry struct {
	Target   string `json:"target"`
	Account  string `json:"account"`
	Password string `json:"password"`
}

func main() {
	entries, err := enumerateCredentials("Wormhole:*")
	if err != nil {
		// Never include credential values in errors. The parent records only this generic failure
		// and leaves the first-launch migration retryable.
		fmt.Fprintln(os.Stderr, "credential enumeration failed:", err)
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(entries); err != nil {
		fmt.Fprintln(os.Stderr, "credential response failed:", err)
		os.Exit(1)
	}
}

func enumerateCredentials(filter string) ([]credentialEntry, error) {
	filterPtr, err := syscall.UTF16PtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter: %w", err)
	}

	var count uint32
	var raw **credential
	result, callErr := credEnumerate(filterPtr, &count, &raw)
	if result == 0 {
		if callErr == errorNotFound {
			return []credentialEntry{}, nil
		}
		return nil, fmt.Errorf("CredEnumerateW: %w", callErr)
	}
	if raw == nil || count == 0 {
		return []credentialEntry{}, nil
	}
	defer credFreeMemory(raw)

	credentials := unsafe.Slice(raw, int(count))
	entries := make([]credentialEntry, 0, len(credentials))
	for _, current := range credentials {
		if current == nil || current.Type != credentialTypeGeneric {
			continue
		}

		target := utf16PointerToString(current.TargetName, maxTargetNameUnits)
		if !strings.HasPrefix(target, "Wormhole:") {
			continue
		}
		account := utf16PointerToString(current.UserName, maxUserNameUnits)
		if account == "" {
			continue
		}

		password, err := decodeCredentialBlob(current.CredentialBlob, current.CredentialBlobSize)
		if err != nil {
			// Only the legacy Wormhole generic entries are relevant. A malformed stale entry should
			// not prevent the valid entries from being migrated.
			continue
		}
		entries = append(entries, credentialEntry{Target: target, Account: account, Password: password})
	}

	return entries, nil
}

func callCredEnumerate(filter *uint16, count *uint32, raw ***credential) (uintptr, error) {
	result, _, callErr := credEnumerateW.Call(
		uintptr(unsafe.Pointer(filter)),
		0,
		uintptr(unsafe.Pointer(count)),
		uintptr(unsafe.Pointer(raw)),
	)
	return result, callErr
}

func callCredFree(raw **credential) {
	credFree.Call(uintptr(unsafe.Pointer(raw)))
}

func decodeCredentialBlob(blob *byte, size uint32) (string, error) {
	if size == 0 {
		return "", nil
	}
	if blob == nil || size%2 != 0 || size > maxCredentialBlobBytes {
		return "", fmt.Errorf("invalid UTF-16LE credential blob")
	}

	bytes := unsafe.Slice(blob, int(size))
	units := make([]uint16, size/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(bytes[index*2 : index*2+2])
	}
	return string(utf16.Decode(units)), nil
}

func utf16PointerToString(value *uint16, maxUnits int) string {
	if value == nil {
		return ""
	}

	units := unsafe.Slice(value, maxUnits)
	for index, unit := range units {
		if unit == 0 {
			return string(utf16.Decode(units[:index]))
		}
	}
	return ""
}
