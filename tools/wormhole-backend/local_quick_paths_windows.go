//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func localQuickPathCandidates() ([]localQuickPathCandidate, []localQuickPathCandidate) {
	folders := make([]localQuickPathCandidate, 0, 8)
	profile, err := windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	if err != nil || profile == "" {
		profile, _ = os.UserHomeDir()
	}
	knownFolders := []struct {
		name string
		id   *windows.KNOWNFOLDERID
	}{
		{name: "Desktop", id: windows.FOLDERID_Desktop},
		{name: "Documents", id: windows.FOLDERID_Documents},
		{name: "Pictures", id: windows.FOLDERID_Pictures},
		{name: "Music", id: windows.FOLDERID_Music},
		{name: "Videos", id: windows.FOLDERID_Videos},
	}
	for index, known := range knownFolders {
		path, err := windows.KnownFolderPath(known.id, windows.KF_FLAG_DEFAULT)
		if err == nil {
			folders = append(folders, localQuickPathCandidate{
				DisplayName: known.name,
				Path:        path,
				ProbeExists: true,
			})
		}
		if index == 1 && profile != "" {
			// WinUI intentionally uses the conventional profile-relative Downloads
			// folder, rather than the shell's redirected Downloads known folder.
			// Keep this order and resolution identical so both UIs show the same menu.
			folders = append(folders, localQuickPathCandidate{
				DisplayName: "Downloads",
				Path:        filepath.Join(profile, "Downloads"),
				ProbeExists: true,
			})
		}
	}

	if profile != "" {
		folders = append(folders, localQuickPathCandidate{
			DisplayName: "Home",
			Path:        profile,
			ProbeExists: true,
		})
	}

	drives := make([]localQuickPathCandidate, 0, 4)
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return folders, drives
	}
	for letter := byte('A'); letter <= byte('Z'); letter++ {
		if mask&(1<<uint(letter-'A')) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", letter)
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		driveType := windows.GetDriveType(rootPtr)
		if driveType != windows.DRIVE_FIXED && driveType != windows.DRIVE_REMOVABLE {
			continue
		}
		// GetLogicalDrives/GetDriveType reports configured drives even when a
		// removable volume is not ready. Probe it before exposing the quick path,
		// matching WinUI's DriveInfo.IsReady filter.
		drives = append(drives, localQuickPathCandidate{Path: root, ProbeExists: true})
	}
	return folders, drives
}
