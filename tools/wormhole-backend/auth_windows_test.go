//go:build windows

package main

import (
	"strconv"
	"testing"
	"unsafe"
)

func TestParseOwnerWindow(t *testing.T) {
	expected := uintptr(0x1234)
	actual, err := parseOwnerWindow(strconv.FormatUint(uint64(expected), 10))
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("owner window=%#x, want %#x", actual, expected)
	}
}

func TestParseOwnerWindowRejectsMissingOrInvalidHandle(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "not-a-window"} {
		if _, err := parseOwnerWindow(value); err == nil {
			t.Fatalf("owner window %q was accepted", value)
		}
	}
}

func TestComMethodReadsMethodFromInterfaceVtable(t *testing.T) {
	const expectedMethod = uintptr(0x12345678)
	vtable := [32]uintptr{}
	vtable[6] = expectedMethod
	vtablePointer := unsafe.Pointer(&vtable[0])
	object := uintptr(unsafe.Pointer(&vtablePointer))

	method, err := comMethod(object, 6)
	if err != nil {
		t.Fatal(err)
	}
	if method != expectedMethod {
		t.Fatalf("COM method=%#x, want %#x", method, expectedMethod)
	}
}

func TestComMethodRejectsInvalidPointersAndSlots(t *testing.T) {
	if _, err := comMethod(0, 0); err == nil {
		t.Fatal("nil COM object was accepted")
	}
	vtablePointer := unsafe.Pointer(nil)
	object := uintptr(unsafe.Pointer(&vtablePointer))
	if _, err := comMethod(object, 0); err == nil {
		t.Fatal("nil COM vtable was accepted")
	}
	if _, err := comMethod(object, 32); err == nil {
		t.Fatal("out-of-range COM slot was accepted")
	}
}
