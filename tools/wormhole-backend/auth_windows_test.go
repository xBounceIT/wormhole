//go:build windows

package main

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestWindowsHelloStatusAndVerificationMapNativeResults(t *testing.T) {
	previousRemote := windowsHelloRemote
	previousOperation := windowsHelloOperation
	t.Cleanup(func() {
		windowsHelloRemote = previousRemote
		windowsHelloOperation = previousOperation
	})
	windowsHelloRemote = func() bool { return false }

	statusTests := []struct {
		result    uint32
		available bool
		contains  string
	}{
		{result: 0, available: true, contains: "ready"},
		{result: 1, contains: "device"},
		{result: 2, contains: "set up"},
		{result: 3, contains: "organization"},
		{result: 4, contains: "busy"},
		{result: 99, contains: "available"},
	}
	for _, test := range statusTests {
		windowsHelloOperation = func(verify bool, message string, owner uintptr) (uint32, error) {
			if verify || message != "" || owner != 0 {
				t.Fatalf("unexpected availability arguments: %v %q %d", verify, message, owner)
			}
			return test.result, nil
		}
		status := checkWindowsHello()
		if status.Available != test.available || !containsFold(status.Message, test.contains) {
			t.Fatalf("result %d mapped to %#v", test.result, status)
		}
	}
	windowsHelloOperation = func(bool, string, uintptr) (uint32, error) {
		return 0, errors.New("unavailable")
	}
	if status := checkWindowsHello(); status.Available || !containsFold(status.Message, "available") {
		t.Fatalf("operation failure mapped to %#v", status)
	}

	verificationTests := []struct {
		result    uint32
		succeeded bool
		contains  string
	}{
		{result: 0, succeeded: true, contains: "Verified"},
		{result: 1, contains: "device"},
		{result: 2, contains: "set up"},
		{result: 3, contains: "organization"},
		{result: 4, contains: "busy"},
		{result: 5, contains: "attempts"},
		{result: 6, contains: "canceled"},
		{result: 99, contains: "recognize"},
	}
	for _, test := range verificationTests {
		windowsHelloOperation = func(verify bool, message string, owner uintptr) (uint32, error) {
			if !verify || message != "Unlock Wormhole" || owner != 42 {
				t.Fatalf("unexpected verification arguments: %v %q %d", verify, message, owner)
			}
			return test.result, nil
		}
		response := verifyWindowsHello(authHelloVerifyRequest{OwnerWindow: "42"})
		if response.Succeeded != test.succeeded || !containsFold(response.Message, test.contains) {
			t.Fatalf("result %d mapped to %#v", test.result, response)
		}
	}
	windowsHelloOperation = func(bool, string, uintptr) (uint32, error) {
		return 0, errors.New("unavailable")
	}
	if response := verifyWindowsHello(authHelloVerifyRequest{OwnerWindow: "42"}); response.Succeeded || !containsFold(response.Message, "available") {
		t.Fatalf("verification failure mapped to %#v", response)
	}
	if response := verifyWindowsHello(authHelloVerifyRequest{}); response.Succeeded || !containsFold(response.Message, "front") {
		t.Fatalf("invalid owner mapped to %#v", response)
	}

	windowsHelloRemote = func() bool { return true }
	if status := checkWindowsHello(); status.Available || !containsFold(status.Message, "Remote Desktop") {
		t.Fatalf("remote status = %#v", status)
	}
	if response := verifyWindowsHello(authHelloVerifyRequest{OwnerWindow: "42"}); response.Succeeded || !containsFold(response.Message, "Remote Desktop") {
		t.Fatalf("remote verification = %#v", response)
	}
}

func TestAwaitWindowsHelloResultCoversAsyncStates(t *testing.T) {
	previousQuery := windowsHelloQuery
	previousStatus := windowsHelloStatus
	previousResult := windowsHelloResult
	previousRelease := windowsHelloRelease
	previousNow := windowsHelloNow
	previousSleep := windowsHelloSleep
	t.Cleanup(func() {
		windowsHelloQuery = previousQuery
		windowsHelloStatus = previousStatus
		windowsHelloResult = previousResult
		windowsHelloRelease = previousRelease
		windowsHelloNow = previousNow
		windowsHelloSleep = previousSleep
	})

	released := make(map[uintptr]int)
	windowsHelloRelease = func(object uintptr) { released[object]++ }
	windowsHelloQuery = func(_ uintptr, _ *windowsGUID, output *uintptr) (uintptr, error) {
		*output = 22
		return 0, nil
	}
	windowsHelloNow = func() time.Time { return time.Unix(100, 0) }
	windowsHelloSleep = func(time.Duration) {}
	statuses := []uint32{asyncStarted, asyncCompleted}
	windowsHelloStatus = func(uintptr) (uint32, error) {
		status := statuses[0]
		statuses = statuses[1:]
		return status, nil
	}
	windowsHelloResult = func(uintptr) (uint32, error) {
		return 5, nil
	}
	if result, err := awaitWindowsHelloResult(11); err != nil || result != 5 {
		t.Fatalf("completed result = %d, %v", result, err)
	}
	if released[11] != 1 || released[22] != 1 {
		t.Fatalf("released COM objects = %#v", released)
	}

	for _, test := range []struct {
		name   string
		status uint32
		result uint32
		failed bool
	}{
		{name: "cancelled", status: asyncCanceled, result: 6},
		{name: "error", status: asyncError, failed: true},
		{name: "unknown", status: 99, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			windowsHelloStatus = func(uintptr) (uint32, error) {
				return test.status, nil
			}
			result, err := awaitWindowsHelloResult(11)
			if (err != nil) != test.failed || result != test.result {
				t.Fatalf("result = %d, error = %v", result, err)
			}
		})
	}

	windowsHelloQuery = func(uintptr, *windowsGUID, *uintptr) (uintptr, error) {
		return 0, errors.New("query failed")
	}
	if _, err := awaitWindowsHelloResult(11); err == nil {
		t.Fatal("query failure was ignored")
	}
	windowsHelloQuery = func(_ uintptr, _ *windowsGUID, output *uintptr) (uintptr, error) {
		*output = 0
		return 0, nil
	}
	if _, err := awaitWindowsHelloResult(11); err == nil {
		t.Fatal("nil async interface was accepted")
	}

	windowsHelloQuery = func(_ uintptr, _ *windowsGUID, output *uintptr) (uintptr, error) {
		*output = 22
		return 0, nil
	}
	windowsHelloStatus = func(uintptr) (uint32, error) {
		return 0, errors.New("call failed")
	}
	if _, err := awaitWindowsHelloResult(11); err == nil {
		t.Fatal("status read failure was ignored")
	}
	windowsHelloStatus = func(uintptr) (uint32, error) {
		return asyncCompleted, nil
	}
	windowsHelloResult = func(uintptr) (uint32, error) {
		return 0, errors.New("result failed")
	}
	if _, err := awaitWindowsHelloResult(11); err == nil {
		t.Fatal("result read failure was ignored")
	}

	nowCalls := 0
	windowsHelloNow = func() time.Time {
		nowCalls++
		return time.Unix(int64(100+31*(nowCalls-1)), 0)
	}
	windowsHelloStatus = func(uintptr) (uint32, error) {
		return asyncStarted, nil
	}
	if _, err := awaitWindowsHelloResult(11); err == nil {
		t.Fatal("Hello timeout was ignored")
	}
}

func TestComCallsRejectInvalidObjects(t *testing.T) {
	comRelease(0)
	var output uintptr
	if _, err := comQueryInterface(0, &iidAsyncInfo, &output); err == nil {
		t.Fatal("invalid query object was accepted")
	}
	if _, err := readWindowsHelloStatus(0); err == nil {
		t.Fatal("invalid async status object was accepted")
	}
	if _, err := readWindowsHelloResult(0); err == nil {
		t.Fatal("invalid async result object was accepted")
	}
	if _, err := comCall(0, 0); err == nil {
		t.Fatal("invalid COM object was accepted")
	}
}

func containsFold(value, substring string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(substring))
}
