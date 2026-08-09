//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func utf16Buffer(value string, size int) []uint16 {
	units := utf16.Encode([]rune(value))
	buffer := make([]uint16, size)
	copy(buffer, units)
	return buffer
}

func credentialBlob(value string) []byte {
	units := utf16.Encode([]rune(value))
	blob := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(blob[index*2:index*2+2], unit)
	}
	return blob
}

func TestDecodeCredentialBlobPreservesUnicode(t *testing.T) {
	want := "päss🔐"
	blob := credentialBlob(want)

	got, err := decodeCredentialBlob(&blob[0], uint32(len(blob)))
	if err != nil {
		t.Fatalf("decodeCredentialBlob returned an error: %v", err)
	}
	if got != want {
		t.Fatalf("decodeCredentialBlob returned %q, want %q", got, want)
	}
}

func TestDecodeCredentialBlobAcceptsEmptyValue(t *testing.T) {
	got, err := decodeCredentialBlob(nil, 0)
	if err != nil || got != "" {
		t.Fatalf("decodeCredentialBlob(nil, 0) = %q, %v", got, err)
	}
}

func TestDecodeCredentialBlobRejectsNilBlob(t *testing.T) {
	if _, err := decodeCredentialBlob(nil, 2); err == nil {
		t.Fatal("decodeCredentialBlob accepted a nil non-empty blob")
	}
}

func TestDecodeCredentialBlobRejectsOddLength(t *testing.T) {
	blob := []byte{0x61}
	if _, err := decodeCredentialBlob(&blob[0], uint32(len(blob))); err == nil {
		t.Fatal("decodeCredentialBlob accepted an odd-length blob")
	}
}

func TestDecodeCredentialBlobRejectsOversizedBlob(t *testing.T) {
	blob := []byte{0x61, 0x00}
	if _, err := decodeCredentialBlob(&blob[0], maxCredentialBlobBytes+2); err == nil {
		t.Fatal("decodeCredentialBlob accepted an oversized blob")
	}
}

func TestUTF16PointerToString(t *testing.T) {
	buffer := utf16Buffer("Wormhole:café", maxTargetNameUnits)
	if got := utf16PointerToString(&buffer[0], len(buffer)); got != "Wormhole:café" {
		t.Fatalf("utf16PointerToString returned %q", got)
	}
	if got := utf16PointerToString(nil, maxTargetNameUnits); got != "" {
		t.Fatalf("utf16PointerToString(nil) returned %q", got)
	}

	unterminated := []uint16{'a', 'b'}
	if got := utf16PointerToString(&unterminated[0], len(unterminated)); got != "" {
		t.Fatalf("unterminated value returned %q", got)
	}
}

func TestEnumerateCredentialsRejectsInvalidFilter(t *testing.T) {
	if _, err := enumerateCredentials("Wormhole:\x00invalid"); err == nil {
		t.Fatal("enumerateCredentials accepted an embedded NUL")
	}
}

func TestEnumerateCredentialsHandlesWindowsResults(t *testing.T) {
	originalEnumerate := credEnumerate
	originalFree := credFreeMemory
	t.Cleanup(func() {
		credEnumerate = originalEnumerate
		credFreeMemory = originalFree
	})

	t.Run("not found is empty", func(t *testing.T) {
		credEnumerate = func(*uint16, *uint32, ***credential) (uintptr, error) {
			return 0, errorNotFound
		}
		entries, err := enumerateCredentials("Wormhole:*")
		if err != nil || len(entries) != 0 || entries == nil {
			t.Fatalf("enumerateCredentials = %#v, %v", entries, err)
		}
	})

	t.Run("other Windows error is returned", func(t *testing.T) {
		want := syscall.Errno(5)
		credEnumerate = func(*uint16, *uint32, ***credential) (uintptr, error) {
			return 0, want
		}
		_, err := enumerateCredentials("Wormhole:*")
		if !errors.Is(err, want) {
			t.Fatalf("enumerateCredentials error = %v, want %v", err, want)
		}
	})

	t.Run("successful empty response is empty", func(t *testing.T) {
		credEnumerate = func(_ *uint16, count *uint32, _ ***credential) (uintptr, error) {
			*count = 0
			return 1, nil
		}
		entries, err := enumerateCredentials("Wormhole:*")
		if err != nil || len(entries) != 0 || entries == nil {
			t.Fatalf("enumerateCredentials = %#v, %v", entries, err)
		}
	})
}

func TestEnumerateCredentialsFiltersAndDecodesEntries(t *testing.T) {
	originalEnumerate := credEnumerate
	originalFree := credFreeMemory
	t.Cleanup(func() {
		credEnumerate = originalEnumerate
		credFreeMemory = originalFree
	})

	validTarget := utf16Buffer("Wormhole:server", maxTargetNameUnits)
	validAccount := utf16Buffer("alice", maxUserNameUnits)
	validPassword := credentialBlob("päss🔐")
	wrongTarget := utf16Buffer("Other:server", maxTargetNameUnits)
	emptyAccount := make([]uint16, maxUserNameUnits)
	malformedPassword := []byte{1}

	credentials := []*credential{
		nil,
		{Type: 99},
		{Type: credentialTypeGeneric, TargetName: &wrongTarget[0], UserName: &validAccount[0]},
		{Type: credentialTypeGeneric, TargetName: &validTarget[0], UserName: &emptyAccount[0]},
		{Type: credentialTypeGeneric, TargetName: &validTarget[0], UserName: &validAccount[0], CredentialBlob: &malformedPassword[0], CredentialBlobSize: 1},
		{Type: credentialTypeGeneric, TargetName: &validTarget[0], UserName: &validAccount[0], CredentialBlob: &validPassword[0], CredentialBlobSize: uint32(len(validPassword))},
	}

	credEnumerate = func(_ *uint16, count *uint32, raw ***credential) (uintptr, error) {
		*count = uint32(len(credentials))
		*raw = (**credential)(unsafe.Pointer(&credentials[0]))
		return 1, nil
	}
	freed := false
	credFreeMemory = func(raw **credential) {
		freed = raw == (**credential)(unsafe.Pointer(&credentials[0]))
	}

	entries, err := enumerateCredentials("Wormhole:*")
	if err != nil {
		t.Fatalf("enumerateCredentials returned an error: %v", err)
	}
	want := []credentialEntry{{Target: "Wormhole:server", Account: "alice", Password: "päss🔐"}}
	if len(entries) != len(want) || entries[0] != want[0] {
		t.Fatalf("enumerateCredentials = %#v, want %#v", entries, want)
	}
	if !freed {
		t.Fatal("enumerateCredentials did not free the native result")
	}
}
