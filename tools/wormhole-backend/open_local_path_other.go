//go:build !windows

package main

import "errors"

func openLocalPathWithShell(string) error {
	return errors.New("opening local files is only available on Windows")
}
