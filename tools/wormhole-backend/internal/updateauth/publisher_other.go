//go:build !windows

package updateauth

import "os"

func LockWindowsInstaller(*os.File) (*os.File, error) { return nil, ErrPublisherUnavailable }

func VerifyWindowsPublisher(*os.File, PublisherPin) error { return ErrPublisherUnavailable }
