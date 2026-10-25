package main

import (
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestSftpEditPermanentFailureWaitsForNewContentsOrManualRetry(t *testing.T) {
	server, native, _ := newSftpEditFixture(t)
	handlers := sftp.InMemHandler()
	put := handlers.FilePut
	var attempts atomic.Int32
	handlers.FilePut = sftpReviewWriter(func(request *sftp.Request) (io.WriterAt, error) {
		if strings.Contains(request.Filepath, ".wormhole-edit-") {
			attempts.Add(1)
		}
		return put.Filewrite(request)
	})
	handlers.FileCmd = &sftpTransferFaultCommands{FileCmder: handlers.FileCmd, fault: "rename"}
	native.sftpClient = newSftpReviewRequestClient(t, handlers)
	if err := writeSftpTestFile(native.sftpClient, "/original", []byte("original")); err != nil {
		t.Fatal(err)
	}
	record := editFixtureRecord(t, server, native, "/original")
	record.mu.Lock()
	defer record.mu.Unlock()
	if err := os.WriteFile(record.localPath(), []byte("first dirty save"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record.poll(native, now)
	record.poll(native, now.Add(time.Second))
	if attempts.Load() != 1 || record.View.State != "Failed" || !record.View.Pending {
		t.Fatal("fixture did not reach a permanent commit failure", attempts.Load(), record.View)
	}
	for _, delay := range []time.Duration{2, 3, 4, 40} {
		if record.poll(native, now.Add(delay*time.Second)) {
			t.Error("unchanged permanent failure repeated notifications")
		}
	}
	if attempts.Load() != 1 {
		t.Fatal("permanent failure kept uploading unchanged contents", attempts.Load())
	}
	if err := record.upload(native, false); err == nil || attempts.Load() != 2 {
		t.Fatal("explicit manual retry was blocked", attempts.Load(), err)
	}
	// The command handler marks a failed manual attempt, just as poll does for
	// an automatic attempt. The same contents must still remain paused.
	record.View.State = "Failed"
	record.poll(native, now.Add(41*time.Second))
	if attempts.Load() != 2 {
		t.Fatal("manual failure restarted automatic retries", attempts.Load())
	}
	if err := os.WriteFile(record.localPath(), []byte("a different dirty save"), 0o600); err != nil {
		t.Fatal(err)
	}
	record.poll(native, now.Add(42*time.Second))
	record.poll(native, now.Add(43*time.Second))
	if attempts.Load() != 3 {
		t.Fatal("new edited contents did not get a new attempt", attempts.Load())
	}
}

func TestSftpEditDisconnectedRetryBacksOffAndRecovers(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	if err := os.WriteFile(record.localPath(), []byte("save while disconnected"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record.poll(nil, now)
	record.poll(nil, now.Add(time.Second))
	if record.View.State != "Disconnected" || !record.View.Pending {
		t.Fatal("fixture did not reach disconnected state", record.View)
	}
	for _, early := range []time.Duration{1500 * time.Millisecond, 3 * time.Second} {
		previous := record.View
		sftpEditIOMu.Lock()
		changed := record.poll(nil, now.Add(early))
		sftpEditIOMu.Unlock()
		if changed || record.View != previous {
			t.Fatal("backoff retried before its deadline", early, record.View)
		}
		if early == 1500*time.Millisecond {
			record.poll(nil, now.Add(2*time.Second))
		}
	}
	record.poll(native, now.Add(4*time.Second))
	if record.View.Pending || record.View.State != "Uploaded" {
		t.Fatal("backoff did not upload after reconnection", record.View)
	}
	contents, err := readSftpTestFile(native.sftpClient, remote)
	if err != nil || string(contents) != "save while disconnected" {
		t.Fatal(string(contents), err)
	}
}

func TestSftpEditPermanentValidationFailureIsNotQueueWait(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	if err := native.sftpClient.Remove(remote); err != nil {
		t.Fatal(err)
	}
	if err := native.sftpClient.Mkdir(remote); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, Decision: "overwrite"}); err == nil {
		t.Fatal("directory overwrite was accepted as an edited file")
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.View.State != "Failed" || record.failedUploadHash == "" {
		t.Fatal("permanent validation error was treated as a queue wait", record.View)
	}
}

func TestSftpEditRetryBackoffCapsAndNewSaveResetsIt(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	if err := os.WriteFile(record.localPath(), []byte("disconnected save"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record.poll(nil, now)
	for _, second := range []time.Duration{1, 2, 4, 8, 16, 32} {
		record.poll(nil, now.Add(second*time.Second))
	}
	previous := record.View
	sftpEditIOMu.Lock()
	changed := record.poll(nil, now.Add(61*time.Second))
	sftpEditIOMu.Unlock()
	if changed || record.View != previous {
		t.Fatal("backoff did not wait for its capped deadline", record.View)
	}
	if err := os.WriteFile(record.localPath(), []byte("new save resets the backoff"), 0o600); err != nil {
		t.Fatal(err)
	}
	record.poll(nil, now.Add(61*time.Second))
	record.poll(native, now.Add(62*time.Second))
	if record.View.State != "Uploaded" || record.View.Pending {
		t.Fatal("new save remained blocked by the previous backoff", record.View)
	}
}
