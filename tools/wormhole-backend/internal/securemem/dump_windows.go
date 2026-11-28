//go:build windows

package securemem

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const semNoGPFaultErrorBox = 0x0002
const werSettingsPath = `SOFTWARE\Microsoft\Windows\Windows Error Reporting`
const localDumpsPath = werSettingsPath + `\LocalDumps`
const werExcludedApplicationsPath = werSettingsPath + `\ExcludedApplications`
const nativeCrashRegistryAccess = registry.QUERY_VALUE | registry.WOW64_64KEY

var processErrorMode = windows.NewLazySystemDLL("kernel32.dll")
var getProcessErrorMode = processErrorMode.NewProc("GetErrorMode")
var setProcessErrorMode = processErrorMode.NewProc("SetErrorMode")
var processErrorModeMu sync.Mutex

// DisableProcessDumps suppresses ordinary Windows Error Reporting and refuses
// startup when Windows LocalDumps can collect a dump of this process.
func DisableProcessDumps() error {
	if err := disableWindowsErrorReporting(); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return ErrUnavailable
	}
	return checkWindowsLocalDumps(filepath.Base(executable), openWindowsLocalDumps(registry.LOCAL_MACHINE))
}

// CheckWindowsProcessLocalDumps checks the executable name reported by Windows
// for a running process. It never takes a path or image name from a wire request.
func CheckWindowsProcessLocalDumps(pid int) error {
	return checkWindowsProcessLocalDumps(pid, openWindowsLocalDumps(registry.LOCAL_MACHINE))
}

func checkWindowsProcessLocalDumps(pid int, open func(string) (localDumpsKey, error)) error {
	image, err := windowsProcessImageName(pid)
	if err != nil {
		return err
	}
	return checkWindowsLocalDumps(image, open)
}

// CheckWindowsDesktopCrashPolicy verifies both OS-managed crash paths for an
// image whose process error mode cannot be set from the native vault.
func CheckWindowsDesktopCrashPolicy(pid int) error {
	return checkWindowsDesktopCrashPolicy(pid, registry.LOCAL_MACHINE)
}

func checkWindowsDesktopCrashPolicy(pid int, root registry.Key) error {
	image, err := windowsProcessImageName(pid)
	if err != nil {
		return err
	}
	if err := checkWindowsLocalDumps(image, openWindowsLocalDumps(root)); err != nil {
		return err
	}
	key, err := registry.OpenKey(root, werExcludedApplicationsPath, nativeCrashRegistryAccess)
	if err != nil {
		return ErrUnavailable
	}
	// Match the DWORD value emitted by WerAddExcludedApplication. An arbitrary
	// value of the same name is not evidence of a registered exclusion.
	var value [4]byte
	n, kind, err := key.GetValue(image, value[:])
	if closeErr := key.Close(); err != nil || closeErr != nil || n != len(value) ||
		kind != registry.DWORD || binary.LittleEndian.Uint32(value[:]) != 1 {
		return ErrUnavailable
	}
	return nil
}

func windowsProcessImageName(pid int) (string, error) {
	if pid <= 0 || uint64(pid) > math.MaxUint32 {
		return "", ErrUnavailable
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", ErrUnavailable
	}
	defer windows.CloseHandle(process)
	var image [32768]uint16
	size := uint32(len(image))
	if err := windows.QueryFullProcessImageName(process, 0, &image[0], &size); err != nil || size == 0 || size >= uint32(len(image)) {
		return "", ErrUnavailable
	}
	return filepath.Base(windows.UTF16ToString(image[:size])), nil
}

func disableWindowsErrorReporting() error {
	if getProcessErrorMode.Find() != nil || setProcessErrorMode.Find() != nil {
		return ErrUnavailable
	}
	processErrorModeMu.Lock()
	defer processErrorModeMu.Unlock()
	mode, _, _ := getProcessErrorMode.Call()
	if mode&semNoGPFaultErrorBox == 0 {
		setProcessErrorMode.Call(mode | semNoGPFaultErrorBox)
	}
	applied, _, _ := getProcessErrorMode.Call()
	if applied&semNoGPFaultErrorBox == 0 {
		return ErrUnavailable
	}
	return nil
}

type localDumpsKey interface {
	Stat() (*registry.KeyInfo, error)
	Close() error
}

func openWindowsLocalDumps(root registry.Key) func(string) (localDumpsKey, error) {
	// Both packaged Windows architectures use the native 64-bit view.
	return func(path string) (localDumpsKey, error) {
		return registry.OpenKey(root, path, nativeCrashRegistryAccess)
	}
}

func checkWindowsLocalDumps(image string, open func(string) (localDumpsKey, error)) error {
	global, err := open(localDumpsPath)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	info, err := global.Stat()
	// Global values can configure dumps for every process. A parent containing
	// only per-image keys must not make other applications' policies ours.
	if closeErr := global.Close(); err != nil || closeErr != nil || info.ValueCount != 0 {
		return ErrUnavailable
	}

	imageKey, err := open(localDumpsPath + `\` + image)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err == nil {
		// The presence of a key for this image is unsafe even if individual
		// values are omitted, since WER can use defaults.
		_ = imageKey.Close()
	}
	return ErrUnavailable
}
