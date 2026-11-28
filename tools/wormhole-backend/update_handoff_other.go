//go:build !windows

package main

import (
	"io"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func serveWindowsUpdateHandoff(string, io.Reader, io.Writer) error { return updateauth.ErrArtifact }
