//go:build windows

package securemem

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestVaultProcessSuppressesWindowsErrorReporting(t *testing.T) {
	const semFailCriticalErrors = 0x0001
	original, _, _ := getProcessErrorMode.Call()
	t.Cleanup(func() { setProcessErrorMode.Call(original) })
	baseline := (original | semFailCriticalErrors) &^ semNoGPFaultErrorBox
	setProcessErrorMode.Call(baseline)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The actual machine may have a managed policy. Exercise the native wiring
	// without changing that policy or requiring it to have a specific value.
	want := checkWindowsLocalDumps(filepath.Base(exe), openWindowsLocalDumps(registry.LOCAL_MACHINE))
	for range 2 {
		if err := DisableProcessDumps(); err != want {
			t.Fatalf("got startup result %v, want native LocalDumps result %v", err, want)
		}
		if mode, _, _ := getProcessErrorMode.Call(); mode != baseline|semNoGPFaultErrorBox {
			t.Fatalf("process error mode = %#x, want %#x", mode, baseline|semNoGPFaultErrorBox)
		}
	}
}

type testLocalDumpsKey struct {
	values   uint32
	statErr  error
	closeErr error
	closed   int
}

func (key *testLocalDumpsKey) Stat() (*registry.KeyInfo, error) {
	if key.statErr != nil {
		return nil, key.statErr
	}
	return &registry.KeyInfo{ValueCount: key.values}, nil
}

func (key *testLocalDumpsKey) Close() error {
	key.closed++
	return key.closeErr
}

func TestWindowsLocalDumpsAdmission(t *testing.T) {
	const image = "Wormhole-Backend-Renamed.exe"
	privateErr := errors.New("private system configuration")
	for _, test := range []struct {
		name        string
		globalErr   error
		global      testLocalDumpsKey
		searchImage bool
		imageErr    error
		want        error
	}{
		{name: "absent", globalErr: registry.ErrNotExist},
		{name: "unreadable root", globalErr: privateErr, want: ErrUnavailable},
		{name: "global values", global: testLocalDumpsKey{values: 1}, want: ErrUnavailable},
		{name: "unreadable global values", global: testLocalDumpsKey{statErr: privateErr}, want: ErrUnavailable},
		{name: "root close failed", global: testLocalDumpsKey{closeErr: privateErr}, want: ErrUnavailable},
		{name: "only unrelated images", searchImage: true, imageErr: registry.ErrNotExist},
		{name: "default dump settings for this image", searchImage: true, want: ErrUnavailable},
		{name: "unreadable image key", searchImage: true, imageErr: privateErr, want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var queries []string
			var imageKey testLocalDumpsKey
			err := checkWindowsLocalDumps(image, func(path string) (localDumpsKey, error) {
				queries = append(queries, path)
				switch path {
				case localDumpsPath:
					if test.globalErr != nil {
						return nil, test.globalErr
					}
					return &test.global, nil
				case localDumpsPath + `\` + image:
					if test.imageErr != nil {
						return nil, test.imageErr
					}
					return &imageKey, nil
				default:
					t.Fatalf("unexpected registry path %q", path)
					return nil, nil
				}
			})
			wantQueries := []string{localDumpsPath}
			if test.searchImage {
				wantQueries = append(wantQueries, localDumpsPath+`\`+image)
			}
			if err != test.want || !slices.Equal(queries, wantQueries) {
				t.Fatalf("got %v and reads %q, want %v and %q", err, queries, test.want, wantQueries)
			}
			if (test.global.closed == 1) != (test.globalErr == nil) ||
				(imageKey.closed == 1) != (test.searchImage && test.imageErr == nil) {
				t.Fatal("unexpected registry handle lifetime")
			}
		})
	}
}

func privateWindowsCrashRegistry(t *testing.T) (registry.Key, func(string) registry.Key) {
	t.Helper()
	// Exercise the native reads against a private, disposable hive.
	// All fixture writes use its explicit handle and never change HKLM.
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	load := advapi.NewProc("RegLoadAppKeyW")
	file, err := windows.UTF16PtrFromString(filepath.Join(t.TempDir(), "local-dumps.hiv"))
	if err != nil {
		t.Fatal(err)
	}
	const regProcessAppKey = 1
	var hive registry.Key
	status, _, _ := load.Call(uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(&hive)), registry.ALL_ACCESS, regProcessAppKey, 0)
	if status != 0 {
		t.Fatal(syscall.Errno(status))
	}
	t.Cleanup(func() {
		if err := hive.Close(); err != nil {
			t.Error(err)
		}
	})
	create := func(path string) registry.Key {
		t.Helper()
		key, _, err := registry.CreateKey(hive, path, registry.ALL_ACCESS|registry.WOW64_64KEY)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := key.Close(); err != nil {
				t.Error(err)
			}
		})
		return key
	}
	return hive, create
}

func TestWindowsLocalDumpsNativeRegistry(t *testing.T) {
	hive, create := privateWindowsCrashRegistry(t)
	check := func(want error) {
		t.Helper()
		if err := checkWindowsLocalDumps("vault-test.exe", openWindowsLocalDumps(hive)); err != want {
			t.Fatalf("got %v, want %v", err, want)
		}
	}
	check(nil)
	create(localDumpsPath + `\unrelated.exe`)
	check(nil)

	root := create(localDumpsPath)
	if err := root.SetDWordValue("DumpType", 0); err != nil {
		t.Fatal(err)
	}
	check(ErrUnavailable)
	if err := root.DeleteValue("DumpType"); err != nil {
		t.Fatal(err)
	}
	check(nil)

	create(localDumpsPath + `\Vault-Test.EXE`)
	check(ErrUnavailable)
}

func TestWindowsDesktopCrashPolicyRequiresBothProtections(t *testing.T) {
	hive, create := privateWindowsCrashRegistry(t)
	if err := checkWindowsDesktopCrashPolicy(0, hive); err != ErrUnavailable {
		t.Fatal("no image was identified", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image := strings.ToUpper(filepath.Base(executable))
	check := func(want error) {
		t.Helper()
		if err := checkWindowsDesktopCrashPolicy(os.Getpid(), hive); err != want {
			t.Fatalf("desktop crash policy = %v, want %v", err, want)
		}
	}

	check(ErrUnavailable)
	exclusions := create(werExcludedApplicationsPath)
	if err := exclusions.SetDWordValue("unrelated.exe", 1); err != nil {
		t.Fatal(err)
	}
	check(ErrUnavailable)
	for _, write := range []func() error{
		func() error { return exclusions.SetDWordValue(image, 0) },
		func() error { return exclusions.SetBinaryValue(image, []byte{1, 0, 0, 0}) },
		func() error { return exclusions.SetQWordValue(image, 1) },
	} {
		if err := write(); err != nil {
			t.Fatal(err)
		}
		check(ErrUnavailable)
	}
	if err := exclusions.SetDWordValue(image, 1); err != nil {
		t.Fatal(err)
	}
	check(nil)
	create(localDumpsPath + `\` + image)
	check(ErrUnavailable)
}

func TestWindowsProcessLocalDumpsUsesTheKernelImage(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	key := &testLocalDumpsKey{}
	image := &testLocalDumpsKey{}
	check := func(path string) (localDumpsKey, error) {
		switch {
		case path == localDumpsPath:
			return key, nil
		case strings.EqualFold(path, localDumpsPath+`\`+filepath.Base(executable)):
			return image, nil
		default:
			t.Fatalf("queried an unexpected name %q", path)
			return nil, nil
		}
	}
	if err := checkWindowsProcessLocalDumps(os.Getpid(), check); err != ErrUnavailable || key.closed != 1 || image.closed != 1 {
		t.Fatal("did not reject the actual process's image key", err)
	}
	for _, pid := range []int{0, -1, 1<<32 - 1, 1 << 32} {
		if err := checkWindowsProcessLocalDumps(pid, func(string) (localDumpsKey, error) {
			t.Fatal("unresolved process should never query the registry")
			return nil, nil
		}); err != ErrUnavailable {
			t.Fatal("unresolved process was accepted", err)
		}
	}
	want := checkWindowsLocalDumps(filepath.Base(executable), openWindowsLocalDumps(registry.LOCAL_MACHINE))
	if err := CheckWindowsProcessLocalDumps(os.Getpid()); err != want {
		t.Fatalf("machine registry result = %v, want %v", err, want)
	}
}
