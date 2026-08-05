package main

import (
	"os"
	"path/filepath"
	"strings"
)

type sshSftpQuickPath struct {
	DisplayName string `json:"display_name"`
	Path        string `json:"path"`
	Separator   bool   `json:"is_separator,omitempty"`
}

type localQuickPathCandidate struct {
	DisplayName string
	Path        string
	ProbeExists bool
}

// buildLocalQuickPaths is the backend-owned equivalent of WinUI's
// LocalQuickPaths.Build. The renderer receives the resolved paths rather than
// guessing from the profile, so redirected known folders and drive roots stay
// consistent with the Windows shell.
func buildLocalQuickPaths() []sshSftpQuickPath {
	folders, drives := localQuickPathCandidates()
	return buildLocalQuickPathsFromCandidates(folders, drives, func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.IsDir()
	})
}

func buildLocalQuickPathsFromCandidates(
	folders []localQuickPathCandidate,
	drives []localQuickPathCandidate,
	directoryExists func(string) bool,
) []sshSftpQuickPath {
	probeSafeDriveLetters := make(map[byte]struct{}, len(drives))
	for _, drive := range drives {
		if len(drive.Path) >= 2 && drive.Path[1] == ':' &&
			((drive.Path[0] >= 'a' && drive.Path[0] <= 'z') || (drive.Path[0] >= 'A' && drive.Path[0] <= 'Z')) {
			probeSafeDriveLetters[lowerASCII(drive.Path[0])] = struct{}{}
		}
	}

	result := make([]sshSftpQuickPath, 0, len(folders)+len(drives)+1)
	seen := make(map[string]struct{}, len(folders)+len(drives))
	add := func(candidate localQuickPathCandidate) bool {
		if strings.TrimSpace(candidate.Path) == "" || len([]byte(candidate.Path)) > sshSftpMaxPathBytes {
			return false
		}
		path := filepath.Clean(candidate.Path)
		if !filepath.IsAbs(path) {
			return false
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			return false
		}
		if candidate.ProbeExists && shouldProbeLocalQuickPath(path, probeSafeDriveLetters) {
			if !directoryExists(path) {
				return false
			}
		}
		seen[key] = struct{}{}
		label := candidate.DisplayName
		if label == "" {
			label = path
		}
		result = append(result, sshSftpQuickPath{DisplayName: label, Path: path})
		return true
	}

	folderCount := 0
	for _, folder := range folders {
		if add(folder) {
			folderCount++
		}
	}
	driveCount := 0
	for _, drive := range drives {
		if add(drive) {
			driveCount++
		}
	}
	if folderCount > 0 && driveCount > 0 {
		// Keep the separator as data so the Electron menu has the same grouping as
		// the WinUI MenuFlyout.
		separator := sshSftpQuickPath{Separator: true}
		result = append(result[:folderCount], append([]sshSftpQuickPath{separator}, result[folderCount:]...)...)
	}
	return result
}

func shouldProbeLocalQuickPath(path string, probeSafeDriveLetters map[byte]struct{}) bool {
	if strings.HasPrefix(path, `\\`) {
		return false
	}
	if len(path) >= 2 && path[1] == ':' {
		letter := path[0]
		if letter >= 'A' && letter <= 'Z' {
			letter += 'a' - 'A'
		}
		_, safe := probeSafeDriveLetters[letter]
		return safe
	}
	return true
}

func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}
