//go:build !windows

package main

import "errors"

func nativeProcessTerminated(uint32) (bool, error) {
	return false, errors.New("process_exit_unsupported")
}
