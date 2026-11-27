package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
	"golang.org/x/sys/windows"
)

func serveWindowsUpdateHandoff(databasePath string, input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 16*1024)
	line, err := reader.ReadSlice('\n')
	var request updateVerifyRequest
	if err != nil || json.Unmarshal(line, &request) != nil {
		return updateauth.ErrArtifact
	}
	suffix := updateInstallerAssetSuffix("windows", updateTargetArchitecture())
	name := request.InstallerFileName
	if suffix == "" || !strings.HasPrefix(strings.ToLower(name), "wormhole-") || !strings.HasSuffix(name, suffix) {
		return updateauth.ErrArtifact
	}
	_, err = withVerifiedUpdate(databasePath, request, func(file *os.File, result updateVerifyResponse) error {
		restart, err := confirmWindowsUpdate(request.updateDownloadRequest, result.PublisherVerified, reader, output)
		if err != nil {
			return err
		}
		return startWindowsInstaller(file, restart)
	})
	return err
}

func confirmWindowsUpdate(request updateDownloadRequest, publisherVerified bool, input io.Reader, output io.Writer) (bool, error) {
	receipt := "V\n"
	if publisherVerified {
		receipt = "P\n"
	}
	if _, err := io.WriteString(output, receipt); err != nil {
		return false, err
	}
	mode, err := io.ReadAll(io.LimitReader(input, 2))
	if err != nil || len(mode) != 1 || (mode[0] != 'R' && mode[0] != 'C') {
		return false, updateauth.ErrArtifact
	}
	if isManagedUpdateURL(strings.TrimSpace(request.InstallerUrl)) {
		if _, err := approvedManagedUpdate(request); err != nil {
			return false, err
		}
	}
	return mode[0] == 'R', nil
}

// Use the final volume path so a redirected cache or drive letter cannot
// change the image selection. Pin each directory before opening its child.
func startWindowsInstaller(file *os.File, restart bool) error {
	var buffer [32768]uint16
	const volumeNameGUID = 1
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), volumeNameGUID)
	if err != nil {
		// SMB has no volume GUID. Only accept the physical UNC spelling here.
		n, err = windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), 0)
		if err != nil || n >= uint32(len(buffer)) || !strings.HasPrefix(windows.UTF16ToString(buffer[:n]), `\\?\UNC\`) {
			return fmt.Errorf("%w: cannot resolve the installer volume", updateauth.ErrArtifact)
		}
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return updateauth.ErrArtifact
	}
	path := windows.UTF16ToString(buffer[:n])
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: invalid resolved installer path", updateauth.ErrArtifact)
	}
	parent := volume + `\`
	locks := []syscall.Handle{syscall.Handle(file.Fd())}
	relative, err := filepath.Rel(parent, filepath.Dir(path))
	if err != nil {
		return updateauth.ErrArtifact
	}
	if relative != "." {
		for _, component := range strings.Split(relative, `\`) {
			parent = filepath.Join(parent, component)
			name, err := windows.UTF16PtrFromString(parent)
			if err != nil {
				return fmt.Errorf("%w: installer directory name", updateauth.ErrArtifact)
			}
			handle, err := windows.CreateFile(name, windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil,
				windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != nil {
				return fmt.Errorf("%w: cannot pin installer directory: %w", updateauth.ErrArtifact, err)
			}
			defer windows.CloseHandle(handle)
			locks = append(locks, syscall.Handle(handle))
			var info windows.ByHandleFileInformation
			if windows.GetFileInformationByHandle(handle, &info) != nil ||
				info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != windows.FILE_ATTRIBUTE_DIRECTORY {
				return updateauth.ErrArtifact
			}
		}
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect the pinned installer path", updateauth.ErrArtifact)
	}
	locked, err := file.Stat()
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(entry, locked) {
		return fmt.Errorf("%w: pinned installer identity changed", updateauth.ErrArtifact)
	}
	// SetupLdr reopens its image and waits for the extracted setup. Give it
	// just the read locks so it can finish after Wormhole and this worker exit.
	// The loader starts the extracted setup with handle inheritance disabled.
	for _, lock := range locks {
		if err := windows.SetHandleInformation(windows.Handle(lock), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return updateauth.ErrArtifact
		}
	}
	args := []string{path, "/SILENT", "/NORESTART", "/NORESTARTAPPLICATIONS"}
	if restart {
		args = []string{path, "/SILENT", "/RESTARTAPP"}
	}
	_, process, err := syscall.StartProcess(path, args, &syscall.ProcAttr{
		Files: []uintptr{0, 0, 0}, Env: bitwardenCliMergeEnv(os.Environ(), nil),
		Sys: &syscall.SysProcAttr{
			HideWindow: true, AdditionalInheritedHandles: locks,
			CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		},
	})
	if err != nil {
		return fmt.Errorf("the verified Windows installer could not be started: %w", err)
	}
	return windows.CloseHandle(windows.Handle(process))
}
