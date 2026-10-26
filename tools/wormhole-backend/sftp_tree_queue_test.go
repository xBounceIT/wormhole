package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func newSftpTreeQueueFixture(t *testing.T, client *sftp.Client) (*sshServer, *sshNativeSession, *synchronizedBuffer) {
	t.Helper()
	output := &synchronizedBuffer{}
	server := newSSHTestServer(output)
	native := &sshNativeSession{id: "tree-session", server: server, sftpClient: client, sftpGeneration: 1, done: make(chan struct{})}
	server.sessions[native.id] = native
	t.Cleanup(func() { native.close(false) })
	return server, native, output
}

func waitSftpTreeRequests(t *testing.T, native *sshNativeSession, expected int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		native.sftpMu.Lock()
		pending := native.treeRequests
		native.sftpMu.Unlock()
		if pending == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("tree requests did not drain")
}

func fillSftpTreeTestSlots(native *sshNativeSession) {
	native.treeSlots = make(chan struct{}, sftpTreeConcurrency)
	for index := 0; index < sftpTreeConcurrency; index++ {
		native.treeSlots <- struct{}{}
	}
}

func TestSftpTreeRequestsShareCapacityAcrossPanes(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Stat(filepath.Join(directory, "file"))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan string, 16)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var mu sync.Mutex
	active, maximum := 0, 0
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		defer func() { mu.Lock(); active--; mu.Unlock() }()
		entered <- request.Filepath
		<-release
		return sftpReviewLister{sftpReviewNamedInfo{FileInfo: info, name: "folder"}, file}, nil
	})})
	server, native, output := newSftpTreeQueueFixture(t, client)
	for index := 0; index < 4; index++ {
		server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "remote", Path: fmt.Sprintf("/root-%d", index), RequestID: fmt.Sprintf("active-%d", index)})
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("tree reads did not start")
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(native.treeSlots) != sftpTreeConcurrency && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(native.treeSlots) != sftpTreeConcurrency {
		t.Fatal("tree reads did not reserve all shared slots")
	}
	server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "local", Path: directory, RequestID: "queued-local"})
	server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "remote", Path: "/queued", RequestID: "queued-remote"})
	if output.Len() != 0 {
		t.Fatalf("ordinary tree requests must queue instead of failing: %s", output.String())
	}
	unblock()
	for _, requestID := range []string{"active-0", "active-1", "active-2", "active-3", "queued-local", "queued-remote"} {
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == requestID })
		if event.Error != "" || len(event.Entries) != 1 || !event.Entries[0].IsDirectory {
			t.Fatalf("tree request %s failed: %+v", requestID, event)
		}
	}
	waitSftpTreeRequests(t, native, 0)
	mu.Lock()
	defer mu.Unlock()
	if maximum < 1 || maximum > 4 {
		t.Fatalf("tree reads exceeded the shared limit: %d", maximum)
	}
}

func TestSftpTreeBackpressureBoundsBufferedListings(t *testing.T) {
	writer := &blockingFirstSSHEventWrite{started: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(writer.release) })
	defer unblock()
	entered := make(chan struct{}, sftpTreeConcurrency+2)
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(*sftp.Request) (sftp.ListerAt, error) {
		entered <- struct{}{}
		return sftpReviewLister{}, nil
	})})
	server := newSSHTestServer(writer)
	native := &sshNativeSession{id: "blocked-tree", server: server, sftpClient: client, sftpGeneration: 1, done: make(chan struct{})}
	server.sessions[native.id] = native
	t.Cleanup(func() { native.close(false) })
	for index := 0; index < sftpTreeConcurrency+2; index++ {
		server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "remote", Path: "/root", RequestID: fmt.Sprintf("buffered-%d", index)})
	}
	select {
	case <-writer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("tree event did not reach the blocked writer")
	}
	for index := 0; index < sftpTreeConcurrency; index++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("directory reads did not fill the available slots")
		}
	}
	select {
	case <-entered:
		t.Fatal("blocked event publication allowed more than four buffered directory listings")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	waitSftpTreeRequests(t, native, 0)
	for index := 0; index < sftpTreeConcurrency+2; index++ {
		waitSftpTestEvent(t, &writer.output, func(event sshWireEvent) bool { return event.RequestID == fmt.Sprintf("buffered-%d", index) })
	}
}

func TestSftpTreeQueuedRequestsCancelWithSession(t *testing.T) {
	server, native, output := newSftpTreeQueueFixture(t, nil)
	fillSftpTreeTestSlots(native)
	for _, pane := range []string{"local", "remote"} {
		server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: pane, Path: t.TempDir(), RequestID: pane})
	}
	native.close(false)
	for _, pane := range []string{"local", "remote"} {
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == pane })
		expectedType := "sftp.error"
		if pane == "local" {
			expectedType = "sftp.local.error"
		}
		if event.Type != expectedType {
			t.Fatal(event)
		}
		if event.Error == "" {
			t.Fatal("cancelled queued read succeeded")
		}
	}
	waitSftpTreeRequests(t, native, 0)
	if len(native.treeSlots) != sftpTreeConcurrency {
		t.Fatal("cancelled queued read acquired a slot")
	}
}

func TestSftpTreeQueuedRequestsRejectOldGeneration(t *testing.T) {
	server, native, output := newSftpTreeQueueFixture(t, nil)
	fillSftpTreeTestSlots(native)
	for _, pane := range []string{"local", "remote"} {
		server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: pane, Path: t.TempDir(), RequestID: pane})
	}
	native.sftpMu.Lock()
	native.sftpGeneration++
	native.sftpMu.Unlock()
	<-native.treeSlots
	for _, pane := range []string{"local", "remote"} {
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == pane })
		if event.Error != errSSHSftpClosed.Error() {
			t.Fatalf("stale queued read crossed its SFTP generation: %+v", event)
		}
	}
	waitSftpTreeRequests(t, native, 0)
	if len(native.treeSlots) != sftpTreeConcurrency-1 {
		t.Fatal("stale queued read leaked its slot")
	}
}

func TestSftpTreeRejectsGenerationChangeDuringRead(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(*sftp.Request) (sftp.ListerAt, error) {
		close(entered)
		<-release
		return sftpReviewLister{}, nil
	})})
	server, native, output := newSftpTreeQueueFixture(t, client)
	server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "remote", Path: "/root", RequestID: "stale"})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("tree read did not start")
	}
	native.sftpMu.Lock()
	native.sftpGeneration++
	native.sftpMu.Unlock()
	unblock()
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "stale" })
	if event.Error != errSSHSftpClosed.Error() {
		t.Fatal(event)
	}
	waitSftpTreeRequests(t, native, 0)
	if len(native.treeSlots) != 0 {
		t.Fatal("stale read leaked its slot")
	}
}

func TestSftpTreeErrorsReleaseCapacity(t *testing.T) {
	server, native, output := newSftpTreeQueueFixture(t, nil)
	for index, command := range []sshWireCommand{
		{Pane: "remote", Path: "/missing-client"},
		{Pane: "local", Path: filepath.Join(t.TempDir(), "missing")},
	} {
		command.SessionID, command.RequestID = native.id, fmt.Sprintf("error-%d", index)
		server.sftpTreeList(command)
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == command.RequestID })
		if event.Error == "" || strings.Contains(event.Error, "too many") {
			t.Fatal(event)
		}
		waitSftpTreeRequests(t, native, 0)
		if len(native.treeSlots) != 0 {
			t.Fatal("failed directory read leaked its slot")
		}
	}
	server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "local", Path: t.TempDir(), RequestID: "recovered"})
	if event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "recovered" }); event.Error != "" {
		t.Fatal(event)
	}
	waitSftpTreeRequests(t, native, 0)
}

func TestSftpTreeRemoteErrorsReleaseCapacity(t *testing.T) {
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
		if request.Filepath == "/denied" {
			return nil, os.ErrPermission
		}
		return sftpReviewLister{}, nil
	})})
	server, native, output := newSftpTreeQueueFixture(t, client)
	for _, path := range []string{"/denied", "/allowed"} {
		server.sftpTreeList(sshWireCommand{SessionID: native.id, Pane: "remote", Path: path, RequestID: path})
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == path })
		if (event.Error != "") != (path == "/denied") {
			t.Fatal(event)
		}
		waitSftpTreeRequests(t, native, 0)
		if len(native.treeSlots) != 0 {
			t.Fatal("remote directory error leaked capacity")
		}
	}
}
