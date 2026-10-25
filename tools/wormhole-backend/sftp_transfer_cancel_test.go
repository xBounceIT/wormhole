package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Exercise actual SSH subsystem isolation, including cancellation of pending
// SFTP requests, rather than replacing the production client opener with a fake.
func newSftpSSHTestClient(t *testing.T, handlers *sftp.Handlers) *ssh.Client {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		connection, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			_ = raw.Close()
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		var workers sync.WaitGroup
		defer workers.Wait()
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer channel.Close()
				for request := range requests {
					if request.Type != "subsystem" {
						_ = request.Reply(false, nil)
						continue
					}
					_ = request.Reply(true, nil)
					if handlers != nil {
						server := sftp.NewRequestServer(channel, *handlers)
						_ = server.Serve()
						_ = server.Close()
					} else {
						server, err := sftp.NewServer(channel)
						if err == nil {
							_ = server.Serve()
							_ = server.Close()
						}
					}
					return
				}
			}()
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User: "fixture", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 2 * time.Second,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("SSH subsystem fixture did not stop")
		}
	})
	return client
}

type sftpStalledReader struct {
	io.ReaderAt
	stall func()
}

func (reader sftpStalledReader) ReadAt(data []byte, offset int64) (int, error) {
	reader.stall()
	return reader.ReaderAt.ReadAt(data, offset)
}

type sftpStalledWriter struct {
	io.WriterAt
	stall func()
	phase string
}

func (writer sftpStalledWriter) WriteAt(data []byte, offset int64) (int, error) {
	if writer.phase == "write" {
		writer.stall()
	}
	return writer.WriterAt.WriteAt(data, offset)
}

func (writer sftpStalledWriter) Close() error {
	if writer.phase == "close" {
		writer.stall()
	}
	if closer, ok := writer.WriterAt.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func TestSftpRowCancellationInterruptsIOAndContinuesBatch(t *testing.T) {
	for _, phase := range []string{"open", "read", "write", "close"} {
		t.Run(phase, func(t *testing.T) {
			blocked, release := make(chan struct{}), make(chan struct{})
			var once atomic.Bool
			stall := func() {
				if once.CompareAndSwap(false, true) {
					close(blocked)
					<-release
				}
			}
			handlers := sftp.InMemHandler()
			get, put := handlers.FileGet, handlers.FilePut
			handlers.FileGet = sftpReviewReader(func(request *sftp.Request) (io.ReaderAt, error) {
				if request.Filepath == "/first" && phase == "open" {
					stall()
				}
				reader, err := get.Fileread(request)
				if request.Filepath == "/first" && phase == "read" {
					reader = sftpStalledReader{ReaderAt: reader, stall: stall}
				}
				return reader, err
			})
			handlers.FilePut = sftpReviewWriter(func(request *sftp.Request) (io.WriterAt, error) {
				writer, err := put.Filewrite(request)
				if strings.Contains(request.Filepath, ".wormhole-transfer-") || request.Filepath == "/upload/first" {
					writer = sftpStalledWriter{WriterAt: writer, stall: stall, phase: phase}
				}
				return writer, err
			})
			transport := newSftpSSHTestClient(t, &handlers)
			browser, err := sftp.NewClient(transport)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { close(release); _ = browser.Close() }()
			for _, name := range []string{"first", "second", "healthy"} {
				if err := writeSftpTestFile(browser, "/"+name, []byte(name)); err != nil {
					t.Fatal(err)
				}
			}
			output := &synchronizedBuffer{}
			server := newSSHTestServer(output)
			server.transfers = make(map[string]*sshSftpTransfer)
			native := &sshNativeSession{id: "transfer", server: server, client: transport, sftpClient: browser,
				transport: &sshSharedTransport{client: transport, refs: 1}}
			server.sessions[native.id] = native
			root := t.TempDir()
			command := sshWireCommand{SessionID: native.id, TransferID: "stalled", Direction: "remote-to-local", DestinationPath: root,
				Items: []sshSftpTransferItem{{SourcePath: "/first", Name: "first"}, {SourcePath: "/second", Name: "second"}}}
			if phase == "write" || phase == "close" {
				command.Direction, command.DestinationPath = "local-to-remote", "/upload"
				for index, name := range []string{"first", "second"} {
					source := filepath.Join(root, name)
					if err := os.WriteFile(source, []byte(name), 0o600); err != nil {
						t.Fatal(err)
					}
					command.Items[index].SourcePath = source
				}
			}
			server.sftpTransfer(command)
			t.Cleanup(func() { server.cancelTransfersForSession(native.id); server.transferWG.Wait() })
			select {
			case <-blocked:
			case <-time.After(3 * time.Second):
				t.Fatal("transfer never entered the stalled request")
			}
			server.sftpTransferCancel(sshWireCommand{SessionID: native.id, TransferID: command.TransferID, ItemID: sftpTransferItemID(0)})
			waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.TransferState == "batch-completed" })
			if _, err := browser.Stat("/healthy"); err != nil {
				t.Fatal("row cancellation closed the browser subsystem", err)
			}
			session, err := transport.NewSession()
			if err != nil {
				t.Fatal("row cancellation closed the shared SSH transport", err)
			}
			_ = session.Close()
			var contents []byte
			if command.Direction == "remote-to-local" {
				if _, err := os.Stat(filepath.Join(root, "first")); !os.IsNotExist(err) {
					t.Fatal("cancelled download left a partial final file", err)
				}
				contents, err = os.ReadFile(filepath.Join(root, "second"))
			} else {
				if _, err := browser.Stat("/upload/first"); !os.IsNotExist(err) {
					t.Fatal("cancelled upload published a partial final file", err)
				}
				contents, err = readSftpTestFile(browser, "/upload/second")
				entries, listErr := browser.ReadDir("/upload")
				if listErr != nil || len(entries) != 1 || entries[0].Name() != "second" {
					t.Fatal("cancelled upload leaked a remote stage", entries, listErr)
				}
			}
			if err != nil || string(contents) != "second" {
				t.Fatal("row cancellation did not continue with the next file", string(contents), err)
			}
			if !native.sftpTransferMu.TryLock() {
				t.Fatal("row cancellation did not release the transfer mutex")
			}
			native.sftpTransferMu.Unlock()
		})
	}
}

func TestSftpBatchAndBrowserCloseInterruptPlanning(t *testing.T) {
	for _, action := range []string{"batch", "browser"} {
		t.Run(action, func(t *testing.T) {
			blocked, release := make(chan struct{}), make(chan struct{})
			var once atomic.Bool
			handlers := sftp.InMemHandler()
			list := handlers.FileList
			handlers.FileList = sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
				if request.Filepath == "/source" && once.CompareAndSwap(false, true) {
					close(blocked)
					<-release
				}
				return list.Filelist(request)
			})
			transport := newSftpSSHTestClient(t, &handlers)
			browser, err := sftp.NewClient(transport)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { close(release); _ = browser.Close() }()
			if err := writeSftpTestFile(browser, "/source", []byte("source")); err != nil {
				t.Fatal(err)
			}
			output := &synchronizedBuffer{}
			server := newSSHTestServer(output)
			server.transfers = make(map[string]*sshSftpTransfer)
			native := &sshNativeSession{id: "transfer", server: server, client: transport, sftpClient: browser,
				transport: &sshSharedTransport{client: transport, refs: 1}}
			server.sessions[native.id] = native
			root := t.TempDir()
			command := sshWireCommand{SessionID: native.id, TransferID: "planning", Direction: "remote-to-local", DestinationPath: root,
				Items: []sshSftpTransferItem{{SourcePath: "/source", Name: "source"}}}
			server.sftpTransfer(command)
			t.Cleanup(func() { server.cancelTransfersForSession(native.id); server.transferWG.Wait() })
			select {
			case <-blocked:
			case <-time.After(3 * time.Second):
				t.Fatal("transfer never entered the stalled preflight")
			}
			if action == "browser" {
				native.closeSftp(false)
			} else {
				server.sftpTransferCancel(sshWireCommand{SessionID: native.id, TransferID: command.TransferID})
			}
			waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.TransferState == "batch-cancelled" })
			if action == "batch" {
				if _, err := browser.Stat("/source"); err != nil {
					t.Fatal("batch cancellation closed the browser", err)
				}
			}
			session, err := transport.NewSession()
			if err != nil {
				t.Fatal("planning cancellation closed the shared SSH transport", err)
			}
			_ = session.Close()
			if !native.sftpTransferMu.TryLock() {
				t.Fatal("planning cancellation did not release the mutation queue")
			}
			native.sftpTransferMu.Unlock()
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatal("cancelled planning created destination files", entries, err)
			}
		})
	}
}
