package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
)

func TestSftpOverwriteCommitsOnlyAfterSuccessfulCopy(t *testing.T) {
	for _, direction := range []string{"local-to-local", "local-to-remote", "remote-to-local"} {
		for _, cancelCopy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", direction, cancelCopy), func(t *testing.T) {
				client := newSftpTestClient(t)
				root := t.TempDir()
				source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
				incoming := bytes.Repeat([]byte("x"), 2*sshSftpTransferBuffer)
				if err := os.WriteFile(source, incoming, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, []byte("preserved"), 0o600); err != nil {
					t.Fatal(err)
				}
				original, err := os.Stat(destination)
				if err != nil {
					t.Fatal(err)
				}
				plan := sshSftpTransferPlan{sourcePath: source, destinationPath: destination, overwrite: true}
				if direction == "local-to-remote" {
					plan.destinationPath = sftpTestPath(destination)
				} else if direction == "remote-to-local" {
					plan.sourcePath = sftpTestPath(source)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				progress := 0
				err = copyTransferFile(ctx, client, direction, plan, func(int64) {
					progress++
					contents, err := os.ReadFile(destination)
					if err != nil || string(contents) != "preserved" {
						t.Errorf("original changed before commit: %d bytes, %v", len(contents), err)
					}
					if cancelCopy {
						cancel()
					}
				})
				if progress == 0 {
					t.Fatal("copy never started", err)
				}
				want := incoming
				if cancelCopy {
					if !errors.Is(err, context.Canceled) {
						t.Fatal("mid-copy cancellation was ignored", err)
					}
					want = []byte("preserved")
				} else if err != nil {
					t.Fatal(err)
				}
				contents, err := os.ReadFile(destination)
				if err != nil || !bytes.Equal(contents, want) {
					t.Fatalf("destination has %d bytes, want %d: %v", len(contents), len(want), err)
				}
				if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != original.Mode().Perm() {
					t.Fatal("replacement changed the original permissions", info, err)
				}
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 2 {
					t.Fatal("transfer leaked a staged file", entries, err)
				}
			})
		}
	}
}

type sftpTransferFaultWriter struct {
	io.WriterAt
	fault  string
	cancel context.CancelFunc
}

func (writer sftpTransferFaultWriter) WriteAt(data []byte, offset int64) (int, error) {
	if writer.fault == "write" && offset >= 32*1024 {
		return 0, os.ErrPermission
	}
	return writer.WriterAt.WriteAt(data, offset)
}

func (writer sftpTransferFaultWriter) Close() error {
	if closer, ok := writer.WriterAt.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	if writer.fault == "close" {
		return os.ErrPermission
	}
	if writer.fault == "cancel-after-close" {
		writer.cancel()
	}
	return nil
}

type sftpTransferFaultCommands struct {
	sftp.FileCmder
	fault  string
	cancel context.CancelFunc
	chmods atomic.Int32
}

func (commands *sftpTransferFaultCommands) Filecmd(request *sftp.Request) error {
	if request.Method == "Setstat" && strings.Contains(request.Filepath, ".wormhole-transfer-") {
		count := commands.chmods.Add(1)
		if commands.fault == "permissions" {
			return os.ErrPermission
		}
		if commands.fault == "cancel-before-commit" && count == 2 {
			commands.cancel()
		}
	}
	return commands.FileCmder.Filecmd(request)
}

func (commands *sftpTransferFaultCommands) PosixRename(request *sftp.Request) error {
	if commands.fault == "rename" {
		return os.ErrPermission
	}
	return commands.FileCmder.(sftp.PosixRenameFileCmder).PosixRename(request)
}

func TestSftpOverwriteFailuresKeepOriginalAndRemoveStage(t *testing.T) {
	for _, fault := range []string{"open", "permissions", "write", "close", "rename", "stat", "cancel-after-close", "cancel-before-commit"} {
		t.Run(fault, func(t *testing.T) {
			handlers := sftp.InMemHandler()
			put, list := handlers.FilePut, handlers.FileList
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handlers.FilePut = sftpReviewWriter(func(request *sftp.Request) (io.WriterAt, error) {
				if fault == "open" && strings.Contains(request.Filepath, ".wormhole-transfer-") {
					return nil, os.ErrPermission
				}
				writer, err := put.Filewrite(request)
				if err != nil || !strings.Contains(request.Filepath, ".wormhole-transfer-") {
					return writer, err
				}
				return sftpTransferFaultWriter{WriterAt: writer, fault: fault, cancel: cancel}, nil
			})
			handlers.FileCmd = &sftpTransferFaultCommands{FileCmder: handlers.FileCmd, fault: fault, cancel: cancel}
			handlers.FileList = sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
				if fault == "stat" && request.Filepath == "/destination" && (request.Method == "Lstat" || request.Method == "Stat") {
					return nil, os.ErrPermission
				}
				return list.Filelist(request)
			})
			client := newSftpReviewRequestClient(t, handlers)
			if err := writeSftpTestFile(client, "/destination", []byte("preserved")); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, bytes.Repeat([]byte("x"), 2*sshSftpTransferBuffer), 0o644); err != nil {
				t.Fatal(err)
			}
			err := copyTransferFile(ctx, client, "local-to-remote", sshSftpTransferPlan{
				sourcePath: source, destinationPath: "/destination", overwrite: true,
			}, func(int64) {})
			if err == nil {
				t.Fatal("failed overwrite reported success")
			}
			contents, err := readSftpTestFile(client, "/destination")
			if err != nil || string(contents) != "preserved" {
				t.Fatal("failed overwrite changed the original", string(contents), err)
			}
			entries, err := client.ReadDir("/")
			if err != nil || len(entries) != 1 || entries[0].Name() != "destination" {
				t.Fatal("failed overwrite leaked a staging file", entries, err)
			}
		})
	}
}

type sftpTransferFaultReader struct{ io.ReaderAt }

func (reader sftpTransferFaultReader) ReadAt(data []byte, offset int64) (int, error) {
	if offset >= sshSftpTransferBuffer {
		return 0, os.ErrPermission
	}
	return reader.ReaderAt.ReadAt(data, offset)
}

func TestSftpDownloadReadFailurePreservesExistingFile(t *testing.T) {
	handlers := sftp.InMemHandler()
	get := handlers.FileGet
	handlers.FileGet = sftpReviewReader(func(request *sftp.Request) (io.ReaderAt, error) {
		reader, err := get.Fileread(request)
		return sftpTransferFaultReader{reader}, err
	})
	client := newSftpReviewRequestClient(t, handlers)
	if err := writeSftpTestFile(client, "/source", bytes.Repeat([]byte("x"), 2*sshSftpTransferBuffer)); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(destination, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := copyTransferFile(context.Background(), client, "remote-to-local", sshSftpTransferPlan{
		sourcePath: "/source", destinationPath: destination, overwrite: true,
	}, func(int64) {})
	if err == nil {
		t.Fatal("read failure reported success")
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "preserved" {
		t.Fatal("failed download changed the original", string(contents), err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed download leaked a staged file", entries, err)
	}
}

func TestSftpReadOnlyOverwriteDoesNotLeakStage(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("incoming"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("preserved"), 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(destination, 0o600)
	err := copyTransferFile(context.Background(), nil, "local-to-local", sshSftpTransferPlan{
		sourcePath: source, destinationPath: destination, overwrite: true,
	}, func(int64) {})
	// Windows rejects replacing a read-only destination; POSIX permits it when
	// the parent directory is writable. Both outcomes must leave no staged file.
	want := "incoming"
	if err != nil {
		want = "preserved"
	}
	contents, readErr := os.ReadFile(destination)
	if readErr != nil || string(contents) != want {
		t.Fatal("read-only overwrite damaged the destination", string(contents), err, readErr)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		t.Fatal("read-only overwrite leaked a staged file", entries, err)
	}
}

func TestSftpDirectoryOverwriteReplacesFileOnlyAfterApproval(t *testing.T) {
	for _, direction := range []string{"local-to-local", "local-to-remote", "remote-to-local"} {
		for _, decision := range []string{"overwrite", "skip"} {
			t.Run(direction+"/"+decision, func(t *testing.T) {
				server, native, output := newLocalTransferTestServer()
				native.sftpClient = newSftpTestClient(t)
				root, destinationRoot := t.TempDir(), t.TempDir()
				if err := os.WriteFile(filepath.Join(root, "child"), []byte("incoming child"), 0o644); err != nil {
					t.Fatal(err)
				}
				destination := filepath.Join(destinationRoot, "folder")
				if err := os.WriteFile(destination, []byte("existing file"), 0o644); err != nil {
					t.Fatal(err)
				}
				command := sshWireCommand{
					SessionID: native.id, TransferID: "directory-overwrite", Direction: direction,
					DestinationPath: destinationRoot,
					Items:           []sshSftpTransferItem{{SourcePath: root, Name: "folder", IsDirectory: true}},
				}
				if direction == "local-to-remote" {
					command.DestinationPath = sftpTestPath(destinationRoot)
				} else if direction == "remote-to-local" {
					command.Items[0].SourcePath = sftpTestPath(root)
				}
				server.sftpTransfer(command)
				t.Cleanup(func() { server.cancelTransfersForSession(native.id); server.transferWG.Wait() })
				conflict := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.Type == "sftp.conflict" })
				contents, err := os.ReadFile(destination)
				if err != nil || string(contents) != "existing file" || conflict.ExistingIsDirectory {
					t.Fatal("file changed before overwrite approval", string(contents), conflict, err)
				}
				server.sftpTransferDecision(sshWireCommand{
					SessionID: native.id, TransferID: command.TransferID, ItemID: conflict.ItemID, Decision: decision,
				})
				terminal := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return strings.HasPrefix(event.TransferState, "batch-") })
				if terminal.TransferState != "batch-completed" {
					t.Fatal("directory overwrite failed", terminal)
				}
				if decision == "overwrite" {
					contents, err = os.ReadFile(filepath.Join(destination, "child"))
					if err != nil || string(contents) != "incoming child" {
						t.Fatal("approved file-to-directory replacement failed", string(contents), err)
					}
				} else {
					contents, err = os.ReadFile(destination)
					if err != nil || string(contents) != "existing file" {
						t.Fatal("skipped file was replaced", string(contents), err)
					}
				}
			})
		}
	}
}
