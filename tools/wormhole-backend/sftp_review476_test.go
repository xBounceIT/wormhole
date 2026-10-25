package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type editCommitHook struct {
	sftp.FileCmder
	beforeCommit func()
	afterCommit  func()
	chmods       int
}

func (hook *editCommitHook) Filecmd(request *sftp.Request) error {
	if request.Method == "Setstat" && strings.Contains(request.Filepath, ".wormhole-edit-") {
		hook.chmods++
		if hook.chmods%2 == 0 && hook.beforeCommit != nil {
			hook.beforeCommit()
		}
	}
	return hook.FileCmder.Filecmd(request)
}

func (hook *editCommitHook) PosixRename(request *sftp.Request) error {
	err := hook.FileCmder.(sftp.PosixRenameFileCmder).PosixRename(request)
	if err == nil && hook.afterCommit != nil {
		hook.afterCommit()
	}
	return err
}

func TestSftpEditDetectsRemoteWriterDuringAndAfterUpload(t *testing.T) {
	server, native, _ := newSftpEditFixture(t)
	handlers := sftp.InMemHandler()
	hook := &editCommitHook{FileCmder: handlers.FileCmd}
	handlers.FileCmd = hook
	client := newSftpReviewRequestClient(t, handlers)
	previous := native.sftpClient
	native.sftpClient = client
	defer previous.Close()
	remote := "/original.conf"
	if err := writeSftpTestFile(client, remote, []byte("original")); err != nil {
		t.Fatal(err)
	}
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	changeRemote := func() {
		writer, err := handlers.FilePut.Filewrite(&sftp.Request{Method: "Put", Filepath: remote, Flags: 2 | 8 | 16})
		if err != nil {
			t.Error(err)
			return
		}
		_, err = writer.WriteAt([]byte("independent remote writer"), 0)
		if err != nil {
			t.Error(err)
		}
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if err := os.WriteFile(record.localPath(), []byte("local save"), 0o600); err != nil {
		t.Fatal(err)
	}
	hook.beforeCommit = changeRemote
	if err := record.upload(native, false); err == nil || record.View.State != "Conflict" {
		t.Fatal("concurrent remote save was overwritten", err)
	}
	contents, err := readSftpTestFile(client, remote)
	if err != nil || string(contents) != "independent remote writer" {
		t.Fatal(string(contents), err)
	}
	hook.beforeCommit, hook.afterCommit = nil, changeRemote
	if err := record.upload(native, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("next save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := record.upload(native, false); err == nil || record.View.State != "Conflict" {
		t.Fatal("post-rename writer was accepted as our baseline", err)
	}
}

func TestSftpSharedSubsystemCancellationClosesOnlyNewChannel(t *testing.T) {
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
	defer listener.Close()
	requested := make(chan struct{}, 1)
	go func() {
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
		go func() {
			for request := range requests {
				_ = request.Reply(true, nil)
			}
		}()
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for range requests {
					requested <- struct{}{} /* deliberately no reply */
				}
			}()
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := &sshSharedTransport{client: client, refs: 1}
	source := &sshNativeSession{client: client, transport: transport}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := newSharedSftpClient(ctx, source); done <- err }()
	<-requested
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent subsystem succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("subsystem cancellation stalled")
	}
	deadline := time.Now().Add(time.Second)
	for {
		transport.mu.Lock()
		pending := transport.opening
		transport.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subsystem goroutine/channel leaked after cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	if ok, _, err := client.SendRequest("sibling-still-alive", true, nil); err != nil || !ok {
		t.Fatal("cancelled sibling closed source transport", err)
	}
	transport.opening = 4
	if _, err := newSharedSftpClient(context.Background(), source); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatal(err)
	}
}

func TestSftpEditDispatchBoundsAndDeadline(t *testing.T) {
	server, native, _ := newSftpEditFixture(t)
	output := &synchronizedBuffer{}
	server.output = &sshEventWriter{encoder: json.NewEncoder(output)}
	for i := 0; i < cap(server.editWorkers); i++ {
		server.editWorkers <- struct{}{}
	}
	server.handleSftpEdit(sshWireCommand{SessionID: native.id, Operation: "list", RequestID: "bounded"})
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "bounded" })
	if !strings.Contains(event.Error, "too many") {
		t.Fatal(event)
	}
	for len(server.editWorkers) > 0 {
		<-server.editWorkers
	}
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(*sftp.Request) (sftp.ListerAt, error) {
		close(started)
		<-release
		return nil, os.ErrNotExist
	})})
	native.sftpMu.Lock()
	previous := native.sftpClient
	native.sftpClient = client
	native.sftpMu.Unlock()
	defer previous.Close()
	stop := native.sftpEditDeadline(client, 20*time.Millisecond)
	defer stop()
	done := make(chan error, 1)
	go func() { _, err := client.Lstat("/blocked"); done <- err }()
	<-started
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled file request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("file request deadline did not close subsystem")
	}
	if _, err := native.editClient(); err == nil {
		t.Fatal("timed out subsystem remained usable")
	}
	// Already-cancelled shared requests must not consume a pending-open slot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newSharedSftpClient(ctx, native); err == nil {
		t.Fatal("cancelled subsystem accepted")
	}
}

func TestSftpEditSaveAsCommitsOnlyAfterCreatingDestination(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	copyPath := remote + ".unchanged"
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: copyPath}); err != nil {
		t.Fatal(err)
	}
	contents, err := readSftpTestFile(native.sftpClient, copyPath)
	if err != nil || string(contents) != "original\r\n" {
		t.Fatalf("save-as reported success without creating unchanged contents: %q, %v", contents, err)
	}
	if err := os.WriteFile(record.localPath(), []byte("pending save"), 0o600); err != nil {
		t.Fatal(err)
	}
	queuedPath := remote + ".queued"
	native.sftpTransferMu.Lock()
	err = server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: queuedPath})
	native.sftpTransferMu.Unlock()
	if err == nil || record.View.RemotePath != copyPath {
		t.Fatalf("queued save-as changed the watched destination: %s, %v", record.View.RemotePath, err)
	}
	failedPath := remote + "/missing-parent/file"
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: failedPath}); err == nil || record.View.RemotePath != copyPath {
		t.Fatalf("failed save-as changed destination: %s, %v", record.View.RemotePath, err)
	}
}

func TestSftpEditRecoveryRequiresOriginalRoute(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	native.sftpEditRoute = "vpn:original"
	record := editFixtureRecord(t, server, native, remote)
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close", Decision: "keep"}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"direct", "vpn:other"} {
		native.sftpEditRoute = route
		if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "recover", EditID: record.View.ID}); err == nil {
			t.Fatalf("recovery accepted different route %s", route)
		}
	}
	native.sftpEditRoute = "vpn:original"
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "recover", EditID: record.View.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestSftpEditRouteIdentityUsesResolvedVPNBeforeRuntimeDisable(t *testing.T) {
	disabled, enabled := false, true
	for _, test := range []struct {
		name, config, endpoint string
		enabled                *bool
		want                   string
	}{
		{"direct", "", "", nil, "direct"},
		{"Go VPN", "original", "", nil, "vpn:original"},
		{"enabled VPN", "original", "", &enabled, "vpn:original"},
		{"disabled direct", "original", "", &disabled, "direct"},
		{"delegated VPN", "original", "127.0.0.1:41001", &disabled, "vpn:original"},
		{"restarted delegated VPN", "original", "127.0.0.1:42002", &disabled, "vpn:original"},
		{"unknown proxy", "", "127.0.0.1:41001", &disabled, "proxy:127.0.0.1:41001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sftpEditRouteIdentity(test.config, test.endpoint, test.enabled); got != test.want {
				t.Fatalf("identity = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSftpRecoveredEditUploadsAfterVPNProxyPortChanges(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	disabled := false
	native.sftpEditRoute = sftpEditRouteIdentity("original", "127.0.0.1:41001", &disabled)
	record := editFixtureRecord(t, server, native, remote)
	if err := os.WriteFile(record.localPath(), []byte("save pending across application restart"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close", Decision: "keep"}); err != nil {
		t.Fatal(err)
	}
	recovered := newSSHTestServer(io.Discard)
	recovered.electronUserDataPath, recovered.databasePath = server.electronUserDataPath, server.databasePath
	if err := recovered.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	copy := recovered.edits[record.View.ID]
	if copy == nil || copy.Route != "vpn:original" {
		t.Fatal("journal did not retain stable VPN identity")
	}
	for _, route := range []string{"direct", "vpn:other"} {
		native.sftpEditRoute = route
		if copy.matches(native) {
			t.Fatal("recovered copy accepted another route", route)
		}
	}
	native.sftpEditRoute = sftpEditRouteIdentity("original", "127.0.0.1:42002", &disabled)
	recovered.sessions[native.id] = native
	if err := recovered.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "recover", EditID: copy.View.ID}); err != nil {
		t.Fatal(err)
	}
	defer func() { copy.mu.Lock(); copy.stopped = true; copy.mu.Unlock() }()
	if err := recovered.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: copy.View.ID}); err != nil {
		t.Fatal(err)
	}
	contents, err := readSftpTestFile(native.sftpClient, remote)
	if err != nil || string(contents) != "save pending across application restart" {
		t.Fatal(string(contents), err)
	}
}

func TestSftpEditCloseRetainsCleanCopyForLaterEditorSave(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close", Decision: "keep"}); err != nil {
		t.Fatal(err)
	}
	if !record.View.Recovered {
		t.Fatal("clean file may still be open in the external editor")
	}
	if err := os.WriteFile(record.localPath(), []byte("editor saved after tab closed"), 0o600); err != nil {
		t.Fatal("late editor save target was deleted", err)
	}
	recovered := newSSHTestServer(io.Discard)
	recovered.electronUserDataPath = server.electronUserDataPath
	if err := recovered.ensureSftpEdits(); err != nil || len(recovered.edits) != 1 {
		t.Fatal("late save cannot be recovered", err)
	}
}

func TestSftpEditRecoveryRejectsOutOfContractMetadata(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	record.View.RemotePath = strings.Repeat("x", sshSftpMaxPathBytes+1)
	if err := record.save(); err != nil {
		t.Fatal(err)
	}
	record.mu.Unlock()
	recovered := newSSHTestServer(io.Discard)
	recovered.electronUserDataPath = server.electronUserDataPath
	if err := recovered.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	if len(recovered.edits) != 0 {
		t.Fatal("malformed manifest can poison every edit response")
	}
}

func TestSftpEditRecoveryManifestValidation(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	contents, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*sftpEditRecord){
		"name":             func(r *sftpEditRecord) { r.View.Name = "../escape" },
		"nul":              func(r *sftpEditRecord) { r.View.Editor = "editor\x00" },
		"oversized editor": func(r *sftpEditRecord) { r.View.Editor = strings.Repeat("x", 257) },
		"relative":         func(r *sftpEditRecord) { r.View.RemotePath = "relative" },
		"empty":            func(r *sftpEditRecord) { r.View.RemotePath = "" },
		"unclean":          func(r *sftpEditRecord) { r.View.RemotePath = "/parent/../file" },
		"hash":             func(r *sftpEditRecord) { r.UploadedHash = "not-a-hash" },
		"port":             func(r *sftpEditRecord) { r.Port = 65536 },
		"route":            func(r *sftpEditRecord) { r.Route = "" },
		"size":             func(r *sftpEditRecord) { r.BaseSize = -2 },
		"permissions":      func(r *sftpEditRecord) { r.Mode = 0o7777 },
	} {
		t.Run(name, func(t *testing.T) {
			var parsed sftpEditRecord
			if err := json.Unmarshal(contents, &parsed); err != nil {
				t.Fatal(err)
			}
			if !validSftpEditManifest(&parsed) {
				t.Fatal("valid journal rejected")
			}
			change(&parsed)
			if validSftpEditManifest(&parsed) {
				t.Fatal("invalid journal accepted")
			}
		})
	}
}

func TestSftpEditRecoveryRejectsLinkedFilesDirectory(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	directory := filepath.Join(record.directory, "files")
	if err := os.Rename(directory, directory+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), directory); err != nil {
		t.Skip("creating symbolic links requires local OS permission: ", err)
	}
	recovered := newSSHTestServer(io.Discard)
	recovered.electronUserDataPath = server.electronUserDataPath
	if err := recovered.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	if len(recovered.edits) != 0 {
		t.Fatal("linked recovery directory was followed")
	}
}

func TestSftpEditNativeClosePreventsLateLaunchAndRetainsCopy(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	server.close(native.id)
	server.editCleanupWG.Wait()
	record.mu.Lock()
	defer record.mu.Unlock()
	if !record.View.Recovered {
		t.Fatal("native close did not freeze editor copy")
	}
	if err := native.launchFileEditor(sftpEditor{}, record.localPath()); err == nil {
		t.Fatal("editor launched after its connection closed")
	}
	if _, err := os.Stat(record.localPath()); err != nil {
		t.Fatal("copy deleted during native close", err)
	}
}

func TestSftpEditRecoveryRestartsWatcherAfterPreviousWatcherExits(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	waitWatching := func(want bool) {
		deadline := time.Now().Add(2 * time.Second)
		for {
			record.mu.Lock()
			watching := record.watching
			record.mu.Unlock()
			if watching == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("watch ownership = %v, want %v", watching, want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitWatching(true)
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close", Decision: "keep"}); err != nil {
		t.Fatal(err)
	}
	waitWatching(false)
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "recover", EditID: record.View.ID}); err != nil {
		t.Fatal(err)
	}
	waitWatching(true)
	if err := os.WriteFile(record.localPath(), []byte("saved after watcher handoff"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record.mu.Lock()
		uploaded := record.View.State == "Uploaded"
		record.mu.Unlock()
		if uploaded {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recovered working copy was not watched")
}

func TestSftpEditPollSkipsUnchangedContentsAndReportsOnlyChanges(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	now := time.Now()
	if changed := record.poll(native, now); changed {
		t.Fatal("unchanged poll published state")
	}
	firstHashRead := record.hashReadAt
	if record.poll(native, now.Add(time.Second)) || !record.hashReadAt.Equal(firstHashRead) {
		t.Fatal("unchanged file was read and hashed again")
	}
	if err := os.WriteFile(record.localPath(), []byte("another save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !record.poll(native, now.Add(2*time.Second)) || !record.View.Pending {
		t.Fatal("changed save was not detected")
	}
	if !record.poll(native, now.Add(3*time.Second)) || record.View.Pending {
		t.Fatal("debounced save was not uploaded")
	}
	if record.poll(native, now.Add(4*time.Second)) {
		t.Fatal("unchanged uploaded status was repeated")
	}
	if record.poll(native, now.Add(40*time.Second)) || record.hashReadAt.Before(now.Add(40*time.Second)) {
		t.Fatal("periodic integrity check did not run")
	}
}

func TestSftpEditHashStreamsAndMemoryWorkIsBounded(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	contents := []byte(strings.Repeat("unchanged", 8192))
	if err := os.WriteFile(record.localPath(), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := sftpEditFileHash(record.localPath(), record.maxSize)
	if err != nil || hash != sftpEditHash(contents) {
		t.Fatal(hash, err)
	}
	prefix, err := sftpEditPrefix(record.localPath(), record.maxSize)
	if err != nil || len(prefix) != 8192 {
		t.Fatal(len(prefix), err)
	}
	for _, filename := range []string{record.localPath(), record.localPath() + ".missing", record.directory} {
		if _, err := sftpEditFileHash(filename, 1); err == nil {
			t.Fatal("unsafe hash input accepted", filename)
		}
		if _, err := sftpEditPrefix(filename, 1); err == nil {
			t.Fatal("unsafe prefix input accepted", filename)
		}
	}
	sftpEditIOMu.Lock()
	err = record.upload(native, false)
	if err == nil || record.View.State != "Waiting for transfer queue" {
		t.Error("unbounded concurrent edit upload", err)
	}
	err = record.download(native)
	sftpEditIOMu.Unlock()
	if err == nil {
		t.Fatal("unbounded concurrent edit download")
	}
}

func TestSftpEditWaitingRetriesDoNotRepeatNotifications(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	record.mu.Lock()
	defer record.mu.Unlock()
	if err := os.WriteFile(record.localPath(), []byte("waiting for another transfer"), 0o600); err != nil {
		t.Fatal(err)
	}
	notices := 0
	record.notify = func(sftpEditView) { notices++ }
	native.sftpTransferMu.Lock()
	defer native.sftpTransferMu.Unlock()
	for i := 0; i < 3; i++ {
		if err := record.upload(native, false); err == nil {
			t.Fatal("transfer lock bypassed")
		}
	}
	if notices != 1 {
		t.Fatalf("unchanged queue state emitted %d notices", notices)
	}
}

func TestSftpEditorAppArgumentsAreNotDropped(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "original file.conf")
	executable, args, err := sftpEditorArgv("darwin", sftpEditor{Executable: "/Applications/Code.app", Arguments: []string{"--reuse-window", "{file}", "--wait"}}, filename)
	want := []string{"-a", "/Applications/Code.app", filename, "--args", "--reuse-window", filename, "--wait"}
	if err != nil || executable != "/usr/bin/open" || !reflect.DeepEqual(args, want) {
		t.Fatal(executable, args, err)
	}
	if _, _, err := sftpEditorArgv("darwin", sftpEditor{Executable: "/Applications/Code.app", Arguments: []string{"--file={file}"}}, filename); err == nil {
		t.Fatal("invalid placeholder accepted for app bundle")
	}
}

func TestSftpEditorsNeverInheritBitwardenSecrets(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "original file.conf")
	for _, goos := range []string{"windows", "darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			environment := sftpEditorEnvironment(goos, []string{"PATH=/usr/bin", "KEEP=value", "BW_SESSION=upper-secret", "bw_session=lower-secret", "WORMHOLE_BW_PASSWORD=upper-password", "wormhole_bw_password=lower-password"})
			if !reflect.DeepEqual(environment, []string{"PATH=/usr/bin", "KEEP=value"}) {
				t.Fatal("editor inherited private environment", environment)
			}
			executable, args, err := sftpEditorArgv(goos, sftpEditor{ID: "system"}, filename)
			wantExecutable, wantArgs := externalOpenCommand(goos, filename)
			if err != nil || executable != wantExecutable || !reflect.DeepEqual(args, wantArgs) {
				t.Fatal("system editor bypasses sanitized launcher", executable, args, err)
			}
		})
	}
}

func TestSftpEditorChildProcess(t *testing.T) {
	if os.Getenv("WORMHOLE_SFTP_EDITOR_CHILD") != "1" {
		return
	}
	contents, err := json.Marshal(map[string]string{"session": os.Getenv("BW_SESSION"), "password": os.Getenv("WORMHOLE_BW_PASSWORD"), "keep": os.Getenv("WORMHOLE_SFTP_EDITOR_CHILD")})
	if err != nil {
		t.Fatal(err)
	}
	filename := os.Args[len(os.Args)-1]
	if err := os.WriteFile(filename+".tmp", contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filename+".tmp", filename); err != nil {
		t.Fatal(err)
	}
}

func TestSftpEditorLaunchScrubsActualChildEnvironment(t *testing.T) {
	t.Setenv("WORMHOLE_SFTP_EDITOR_CHILD", "1")
	t.Setenv("BW_SESSION", "fixture-session-not-for-editor")
	t.Setenv("WORMHOLE_BW_PASSWORD", "fixture-password-not-for-editor")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "original file with spaces.conf")
	if err := launchSftpEditor(sftpEditor{ID: "fixture", Executable: executable, Arguments: []string{"-test.run=TestSftpEditorChildProcess", "{file}"}}, filename); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(filename)
		if err == nil {
			var environment map[string]string
			if err := json.Unmarshal(contents, &environment); err != nil {
				t.Fatal(err)
			}
			if environment["session"] != "" || environment["password"] != "" || environment["keep"] != "1" {
				t.Fatal("editor environment was not sanitized correctly")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("configured editor child did not receive its intact file argument")
}

func TestSftpEditManifestSurvivesFailedRetarget(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	native.sftpTransferMu.Lock()
	_ = server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: remote + ".new"})
	native.sftpTransferMu.Unlock()
	contents, err := os.ReadFile(filepath.Join(record.directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved sftpEditRecord
	if err := json.Unmarshal(contents, &saved); err != nil || saved.View.RemotePath != record.View.RemotePath {
		t.Fatal("memory and recovery journal disagree", err)
	}
}
