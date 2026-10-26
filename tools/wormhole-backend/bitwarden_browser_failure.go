package main

import (
	"errors"
	"strings"
)

func validBitwardenBrowserFailure(code string) bool {
	stage, reason, ok := strings.Cut(code, "/")
	if !ok {
		return false
	}
	switch stage {
	case "prepare", "profile", "migrations", "read", "capture", "restore", "commit", "flush", "marker", "background", "bridge", "checkpoint", "popup":
	default:
		return false
	}
	switch reason {
	case "failed", "timeout", "closed", "unavailable", "conflict":
		return true
	default:
		return false
	}
}

func reportBitwardenBrowserFailure(code string) (map[string]bool, error) {
	if !validBitwardenBrowserFailure(code) {
		return nil, errors.New("Bitwarden browser failure code is invalid")
	}
	logError("Bitwarden browser operation failed (code=%s)", code)
	return map[string]bool{"logged": true}, nil
}
