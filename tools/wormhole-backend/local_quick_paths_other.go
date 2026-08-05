//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func localQuickPathCandidates() ([]localQuickPathCandidate, []localQuickPathCandidate) {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil, nil
	}
	folders := make([]localQuickPathCandidate, 0, 7)
	for _, name := range []string{"Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"} {
		folders = append(folders, localQuickPathCandidate{
			DisplayName: name,
			Path:        filepath.Join(home, name),
			ProbeExists: true,
		})
	}
	folders = append(folders, localQuickPathCandidate{
		DisplayName: "Home",
		Path:        home,
		ProbeExists: true,
	})
	return folders, nil
}
