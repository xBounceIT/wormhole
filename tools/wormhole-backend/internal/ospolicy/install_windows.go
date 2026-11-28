//go:build windows

package ospolicy

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fileDeleteChild = 0x40
const contentRights = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild |
	windows.FILE_WRITE_ATTRIBUTES | windows.GENERIC_ALL | windows.GENERIC_WRITE |
	windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func checkNativeInstallation(ctx context.Context) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", ErrInstallationLocation
	}
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getppid()))
	if err != nil {
		return "", ErrInstallationLocation
	}
	defer windows.CloseHandle(parent)
	var name [32768]uint16
	size := uint32(len(name))
	if windows.QueryFullProcessImageName(parent, 0, &name[0], &size) != nil || size == 0 || size >= uint32(len(name)) {
		return "", ErrInstallationLocation
	}
	return checkWindowsInstallation(ctx, windows.UTF16ToString(name[:size]), executable)
}

func windowsInstallationRoot(frontend, backend string) (string, error) {
	localDrivePath := func(path string) bool {
		volume := filepath.VolumeName(path)
		return len(volume) == 2 && volume[1] == ':' && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path[2:], ':')
	}
	if !localDrivePath(frontend) || !localDrivePath(backend) || !strings.EqualFold(filepath.Base(frontend), "Wormhole.exe") {
		return "", ErrInstallationLocation
	}
	root := filepath.Dir(frontend)
	if len(root) <= 3 {
		return "", ErrInstallationLocation
	}
	directory := filepath.Join(root, "resources", "app", "dist-electron")
	if !strings.EqualFold(directory, filepath.Dir(backend)) {
		return "", ErrInstallationLocation
	}
	name := filepath.Base(backend)
	if !strings.EqualFold(name, "wormhole-backend-x64.exe") && !strings.EqualFold(name, "wormhole-backend-arm64.exe") {
		return "", ErrInstallationLocation
	}
	return root, nil
}

func checkWindowsInstallation(ctx context.Context, frontend, backend string) (string, error) {
	root, err := windowsInstallationRoot(frontend, backend)
	if err != nil {
		return "", err
	}
	volume, err := windows.UTF16PtrFromString(filepath.VolumeName(root) + `\`)
	if err != nil || windows.GetDriveType(volume) != 3 /* DRIVE_FIXED */ {
		return "", ErrInstallationLocation
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return "", ErrInstallationLocation
	}
	if err := checkInstallationTree(ctx, root, frontend, backend, func(path string, directory, volumeRoot bool) error {
		return checkWindowsInstallationEntry(path, directory, volumeRoot, installer)
	}); err != nil {
		return "", err
	}
	return root, nil
}

func checkInstallationTree(ctx context.Context, root, frontend, backend string, inspect func(string, bool, bool) error) error {
	var frontendFound, backendFound bool
	err := walkInstallationTree(ctx, root, func(path string, kind fs.FileMode, volumeRoot bool) error {
		if kind != 0 && kind != fs.ModeDir {
			return ErrInstallationLocation
		}
		if err := inspect(path, kind == fs.ModeDir, volumeRoot); err != nil {
			return err
		}
		if kind == 0 {
			frontendFound = frontendFound || isInstalledExecutable(path, frontend)
			backendFound = backendFound || isInstalledExecutable(path, backend)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !frontendFound || !backendFound {
		return ErrInstallationLocation
	}
	return ctx.Err()
}

func isInstalledExecutable(walked, running string) bool {
	if walked == running {
		return true
	}
	if !strings.EqualFold(walked, running) {
		return false
	}
	// NTFS directories can opt into case sensitivity. Compare the objects
	// whenever the path reported by the OS differs in spelling.
	entry, err := os.Lstat(walked)
	if err != nil {
		return false
	}
	processImage, err := os.Lstat(running)
	return err == nil && entry.Mode().IsRegular() && processImage.Mode().IsRegular() && os.SameFile(entry, processImage)
}

func checkWindowsInstallationEntry(path string, directory, volumeRoot bool, installer *windows.SID) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrInstallationLocation
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return ErrInstallationLocation
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return ErrInstallationLocation
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrInstallationLocation
	}
	return validateWindowsInstallationACL(descriptor, volumeRoot, installer)
}

func validateWindowsInstallationACL(sd *windows.SECURITY_DESCRIPTOR, volumeRoot bool, installer *windows.SID) error {
	if sd == nil {
		return ErrInstallationLocation
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.Equals(installer))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return ErrInstallationLocation
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrInstallationLocation
	}
	mask := windows.ACCESS_MASK(contentRights)
	if volumeRoot {
		// In a directory the append bit allows creating a subdirectory. It
		// does not let a user replace an existing protected child.
		mask &^= windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return ErrInstallationLocation
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Conditional and object ACEs are outside the supported installation DACL.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return ErrInstallationLocation
		}
		if ace.Mask&mask != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrInstallationLocation
		}
	}
	return nil
}
