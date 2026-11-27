//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsSessionNotificationsOnlyLockTheOwningSession(t *testing.T) {
	if unsafe.Sizeof(wtsWindowMessage{}) != 48 {
		t.Fatal("incorrect native Windows message layout")
	}
	for _, event := range []uintptr{0, 1, wtsConsoleDisconnect, 3, wtsRemoteDisconnect, 5, wtsSessionLogoff, wtsSessionLock, 8, 9, 15} {
		want := event == wtsConsoleDisconnect || event == wtsRemoteDisconnect || event == wtsSessionLogoff || event == wtsSessionLock
		if got := windowsSessionRequiresLock(event, 123, 123); got != want {
			t.Fatalf("own session event %d = %v, want %v", event, got, want)
		}
		if windowsSessionRequiresLock(event, 124, 123) {
			t.Fatalf("another session triggered a lock with event %d", event)
		}
	}
}

func TestWindowsVaultSessionHiddenWindowReceivesNativeMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ready := make(chan uintptr, 1)
	locks := make(chan struct{}, 1)
	ended := make(chan error, 1)
	go func() { ended <- watchWindowsSession(ctx, ready, locks) }()
	var window uintptr
	select {
	case window = <-ready:
	case err := <-ended:
		t.Fatal("WTS notification window unavailable", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	visible, _, _ := wtsWindowDLL.NewProc("IsWindowVisible").Call(window)
	if visible != 0 {
		t.Fatal("session monitor showed a window")
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		t.Fatal(err)
	}
	send := wtsWindowDLL.NewProc("SendMessageTimeoutW")
	deliver := func(event, owner uintptr) {
		t.Helper()
		var result uintptr
		const smtoAbortIfHung = 2
		if sent, _, err := send.Call(window, wmWtsSessionChange, event, owner, smtoAbortIfHung,
			2000, uintptr(unsafe.Pointer(&result))); sent == 0 {
			t.Fatal("could not reach native window proc", err)
		}
	}
	deliver(wtsRemoteDisconnect, uintptr(session)+1)
	deliver(8, uintptr(session))
	select {
	case <-locks:
		t.Fatal("unrelated session or unlock emitted a lock")
	default:
	}
	deliver(wtsConsoleDisconnect, uintptr(session))
	deliver(wtsRemoteDisconnect, uintptr(session))
	select {
	case <-locks:
	default:
		t.Fatal("synchronous native disconnect did not reach the lock channel")
	}
	select {
	case <-locks:
		t.Fatal("repeated native signals were not bounded while a lock was pending")
	default:
	}
	cancel()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatal("native monitor cancellation failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native thread did not wake on parent cancellation")
	}
	if result, _, _ := wtsWindowDLL.NewProc("IsWindow").Call(window); result != 0 {
		t.Fatal("session monitor leaked its window")
	}
}

func TestWindowsVaultSessionMonitorUsesTheParentPipeForLifetime(t *testing.T) {
	input, parent := io.Pipe()
	defer input.Close()
	defer parent.Close()
	output, child := io.Pipe()
	defer output.Close()
	defer child.Close()
	ended := make(chan int, 1)
	go func() {
		defer child.Close()
		ended <- runVaultSessionMonitor(input, child)
	}()
	if first, err := bufio.NewReader(output).ReadString('\n'); first != "ready\n" || err != nil {
		t.Fatalf("native subscription readiness = %q %v", first, err)
	}
	_ = parent.Close()
	select {
	case result := <-ended:
		if result != 0 {
			t.Fatal("parent EOF ended the monitor with an error", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session monitor outlived its parent pipe")
	}
}

func TestWindowsVaultSessionWindowCloseRetiresTheSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ready := make(chan uintptr, 1)
	ended := make(chan error, 1)
	go func() { ended <- watchWindowsSession(ctx, ready, make(chan struct{}, 1)) }()
	select {
	case window := <-ready:
		post := wtsWindowDLL.NewProc("PostMessageW")
		if result, _, err := post.Call(window, wmClose, 0, 0); result == 0 {
			t.Fatal("could not close session notification window", err)
		}
	case err := <-ended:
		t.Fatal("window did not register", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-ended:
		if err != nil {
			t.Fatal("session window teardown failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closed notification window was left registered")
	}
}

func TestWindowsVaultSessionMonitorReportsLocksAndSourceFailure(t *testing.T) {
	for _, start := range []bool{false, true} {
		input, parent := io.Pipe()
		output, child := io.Pipe()
		defer input.Close()
		defer parent.Close()
		defer output.Close()
		defer child.Close()
		failed := make(chan struct{})
		ended := make(chan int, 1)
		go func() {
			defer child.Close()
			ended <- monitorWindowsVaultSession(input, child, func(ctx context.Context, ready chan<- uintptr, locks chan<- struct{}) error {
				if start {
					ready <- 1
					locks <- struct{}{}
					select {
					case <-ctx.Done():
					case <-failed:
					}
				}
				return errors.New("fixture unavailable")
			})
		}()
		if start {
			reader := bufio.NewReader(output)
			for _, want := range []string{"ready\n", "lock\n"} {
				if line, err := reader.ReadString('\n'); line != want || err != nil {
					t.Fatalf("vault monitor output = %q %v, want %q", line, err, want)
				}
			}
		}
		close(failed)
		if result := <-ended; result != 1 {
			t.Fatal("unexpected source failure was reported as normal termination", result)
		}
		_ = parent.Close()
	}
}
