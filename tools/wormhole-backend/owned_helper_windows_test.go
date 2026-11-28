package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCredentialReaderGetsStartSignal(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "reader.go")
	reader := filepath.Join(dir, "reader.exe")
	const fixture = `package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	var start [1]byte
	if os.Getenv("WORMHOLE_SUPERVISED_CREDENTIAL_READER") != "1" {
		os.Exit(1)
	}
	if _, err := io.ReadFull(os.Stdin, start[:]); err != nil || start[0] != '\n' {
		os.Exit(1)
	}
	fmt.Println("[]")
}`
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", reader, source).CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, out)
	}
	entries, err := readWindowsCredentials(reader)
	if err != nil || len(entries) != 0 {
		t.Fatalf("expected an empty credential inventory, err=%v", err)
	}
}

func TestOwnedHelperSurvivesOnlyWhileBackendIsAlive(t *testing.T) {
	const role = "WORMHOLE_TEST_HELPER_ROLE"
	child := func(ctx context.Context, value string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnedHelperSurvivesOnlyWhileBackendIsAlive$")
		cmd.Env = append(os.Environ(), role+"="+value)
		return cmd
	}
	switch os.Getenv(role) {
	case "sidecar":
		if !bufio.NewScanner(os.Stdin).Scan() {
			t.Fatal("missing sidecar configuration")
		}
		fmt.Println("READY 12345")
		time.Sleep(time.Minute)
		return
	case "worker":
		// Simulate an unresponsive helper which never reads stdin.
		time.Sleep(time.Minute)
		return
	case "backend":
		owned := child(context.Background(), "sidecar")
		if _, err := launchSealedTunnel(t.Context(), owned, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		unmanaged := child(context.Background(), "worker")
		if err := unmanaged.Start(); err != nil {
			t.Fatal(err)
		}
		fmt.Println(owned.Process.Pid, unmanaged.Process.Pid)
		time.Sleep(time.Minute)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := child(ctx, "backend")
	backend.Stderr = os.Stderr
	out, err := backend.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if backend.ProcessState == nil {
			_ = backend.Process.Kill()
			_ = backend.Wait()
		}
	}()
	var ownedPID, unmanagedPID uint32
	if _, err := fmt.Fscan(out, &ownedPID, &unmanagedPID); err != nil {
		t.Fatal(err)
	}
	openWorker := func(pid uint32) windows.Handle {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = windows.TerminateProcess(handle, 1)
			_ = windows.CloseHandle(handle)
		})
		return handle
	}
	owned := openWorker(ownedPID)
	unmanaged := openWorker(unmanagedPID)
	if err := backend.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exited *exec.ExitError
	if err := backend.Wait(); !errors.As(err, &exited) {
		t.Fatalf("expected the simulated backend to have terminated: %v", err)
	}
	if state, err := windows.WaitForSingleObject(owned, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("owned worker survived backend crash: wait=%d err=%v", state, err)
	}
	if state, err := windows.WaitForSingleObject(unmanaged, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("unmanaged worker did not survive: wait=%d err=%v", state, err)
	}
}

func TestVaultBitwardenUnlockOwnedByBackend(t *testing.T) {
	settings := defaultBitwardenCliSettings()
	settings.Path = buildBitwardenUnlockCLI(t)
	job, err := ownedHelperJob()
	if err != nil {
		t.Fatal(err)
	}
	processCount := func() uint32 {
		t.Helper()
		// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION includes exited processes.
		var accounting struct {
			Times              [4]int64
			PageFaults         uint32
			TotalProcesses     uint32
			Active, Terminated uint32
		}
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
			t.Fatal(err)
		}
		return accounting.TotalProcesses
	}
	before := processCount()
	if _, err := unlockVaultBitwardenCLI(t.Context(), settings, []byte("  synthetic rénewal 🔒  ")); err != nil {
		t.Fatal(err)
	}
	if after := processCount(); after != before+1 {
		t.Fatalf("expected one Bitwarden worker in the backend job, got %d", after-before)
	}
}
