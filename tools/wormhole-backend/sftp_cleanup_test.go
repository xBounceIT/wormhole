package main

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

type sftpCleanupTestCommands struct {
	sftp.FileCmder
	remove func()
}

func (commands sftpCleanupTestCommands) Filecmd(request *sftp.Request) error {
	if request.Method == "Remove" && request.Filepath == "/stalled" {
		commands.remove()
	}
	return commands.FileCmder.Filecmd(request)
}

func TestSftpCleanupUsesBoundedIsolatedSubsystem(t *testing.T) {
	release := make(chan struct{})
	handlers := sftp.InMemHandler()
	handlers.FileCmd = sftpCleanupTestCommands{FileCmder: handlers.FileCmd, remove: func() { <-release }}
	transport := newSftpSSHTestClient(t, &handlers)
	browser, err := sftp.NewClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); _ = browser.Close() }()
	if err := writeSftpTestFile(browser, "/stalled", []byte("partial upload")); err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{client: transport, transport: &sshSharedTransport{client: transport, refs: 1}}
	started := time.Now()
	if err := native.cleanupSftpTransferStage("/stalled"); err == nil || time.Since(started) > 3*time.Second {
		t.Fatal("stalled cleanup did not return a bounded failure", err, time.Since(started))
	}
	if _, err := browser.Stat("/stalled"); err != nil {
		t.Fatal("cleanup timeout closed the browser", err)
	}
	if err := native.cleanupSftpTransferStage("/missing"); err != nil {
		t.Fatal("already-removed stage was not treated as clean", err)
	}
	_ = transport.Close()
	if err := native.cleanupSftpTransferStage("/stalled"); err == nil {
		t.Fatal("closed transport accepted cleanup")
	}
}

func TestSftpStageCleanupErrorPreservesOriginalFailure(t *testing.T) {
	err := &sftpTransferStageError{error: io.ErrUnexpectedEOF, path: "/private-stage"}
	if !errors.Is(err, io.ErrUnexpectedEOF) || err.Error() != io.ErrUnexpectedEOF.Error() {
		t.Fatal("stage cleanup hid the transfer failure", err)
	}
}
