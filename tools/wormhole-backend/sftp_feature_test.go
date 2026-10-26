package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSftpSavedConnectionsReuseInheritedSshCredentialsAndBackupProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	credential := "20000000-0000-4000-8000-000000000001"
	if _, err := database.Exec("INSERT INTO CredentialProfiles (Id, Protocol, Kind) VALUES (?,0,1)", credential); err != nil {
		t.Fatal(err)
	}
	folder, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "SSH defaults", Kind: "folder", CredentialMode: 2, CredentialID: credential})
	if err != nil {
		t.Fatal(err)
	}
	id, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "File transfer", Kind: "connection", Protocol: "sftp", Host: "sftp.example", ParentID: folder, CredentialMode: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{ID: id, Name: "Edited transfer", Kind: "connection", Protocol: "sftp", Host: "sftp.example", ParentID: folder, CredentialMode: 0}); err != nil {
		t.Fatal(err)
	}
	actual, err := resolveNodeCredentialID(database, id, 0)
	if err != nil || actual != credential {
		t.Fatal(actual, err)
	}
	var protocol int64
	if err := database.QueryRow("SELECT Protocol FROM Nodes WHERE Id=?", id).Scan(&protocol); err != nil || protocol != 7 {
		t.Fatal(protocol, err)
	}
	sshProtocol, sftpProtocol, port := int64(0), int64(7), int64(2222)
	nodes := map[string]*sshNode{"leaf": {id: "leaf", kind: 1, parentID: "parent", protocol: &sftpProtocol}, "parent": {id: "parent", protocol: &sshProtocol, host: "sftp.example", port: &port}}
	endpoint, err := resolveSSHNodeEndpoint(nodes, "leaf")
	if err != nil || endpoint.port != 2222 {
		t.Fatal(endpoint, err)
	}
	object := backupObject{"name": json.RawMessage(`"File transfer"`), "protocol": json.RawMessage(`7`)}
	result := &backupImportResult{}
	scrubBackupNodeReferences(object, &backupImportState{}, result)
	if value, _ := backupObjectInteger(object, "protocol"); value != 7 {
		t.Fatal("backup restore changed SFTP to SSH")
	}
}

func TestSftpEditDispatchAndCrashScanRejectMalformedCopies(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	output := &synchronizedBuffer{}
	server.output = &sshEventWriter{encoder: json.NewEncoder(output)}
	server.handleSftpEdit(sshWireCommand{SessionID: native.id, Operation: "list", RequestID: "list-edits"})
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "list-edits" })
	if len(event.Edits) != 1 || event.Error != "" {
		t.Fatal(event)
	}
	server.handleSftpEdit(sshWireCommand{SessionID: native.id, Operation: "unsupported", EditID: record.View.ID, RequestID: "bad-edit"})
	if event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "bad-edit" }); event.Error == "" {
		t.Fatal(event)
	}
	root := filepath.Join(server.electronUserDataPath, "sftp-edit")
	for _, name := range []string{"not-an-id", "20000000-0000-4000-8000-000000000002", "20000000-0000-4000-8000-000000000003"} {
		directory := filepath.Join(root, name)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if name != "not-an-id" {
			if err := os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(`{"view":{"id":"wrong","name":"../../secret"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "ordinary-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovery := newSSHTestServer(io.Discard)
	recovery.electronUserDataPath = server.electronUserDataPath
	if err := recovery.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	if len(recovery.edits) != 1 {
		t.Fatal("invalid recovery manifest accepted")
	}
	if err := protectSftpEditDirectory(filepath.Join(root, "ordinary-file")); err == nil {
		t.Fatal("non-directory protected root accepted")
	}
	if err := protectSftpEditDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing protected root accepted")
	}
}

func TestSftpProtocolAndEditorSettings(t *testing.T) {
	if value, ok := workspaceProtocolValue("sftp"); !ok || value != 7 || protocolName(sql.NullInt64{Int64: 7, Valid: true}) != "sftp" {
		t.Fatal("SFTP protocol did not round trip")
	}
	if !workspaceCredentialProtocolMatches(7, 0) || !workspaceCredentialKindSupportsProtocol(1, 7) || workspaceCredentialProtocolMatches(7, 1) {
		t.Fatal("SFTP must accept SSH credentials only")
	}
	database := filepath.Join(t.TempDir(), "workspace.db")
	settings, err := readSftpEditorSettings(database)
	if err != nil || settings.MaxFileSize != 50*1024*1024 {
		t.Fatal(settings, err)
	}
	settings.Editors = []sftpEditor{{ID: "code", Name: "Code", Executable: "code", Arguments: []string{"--reuse-window", "{file}"}, Patterns: "*.conf;*.yml"}}
	settings.DefaultEditor, settings.SwapPanels = "code", true
	if err := writeSftpEditorSettings(database, settings); err != nil {
		t.Fatal(err)
	}
	read, err := readSftpEditorSettings(database)
	if err != nil || !reflect.DeepEqual(read, settings) {
		t.Fatal(read, err)
	}
	editor, err := resolveSftpEditor(settings, "", "server.conf")
	if err != nil || editor.ID != "code" {
		t.Fatal(editor, err)
	}
	if _, err := resolveSftpEditor(settings, "missing", "file"); err == nil {
		t.Fatal("accepted unknown editor")
	}
	if editor, err := resolveSftpEditor(settings, "system", "file"); err != nil || editor.ID != "system" {
		t.Fatal(editor, err)
	}
	if editor, err := resolveSftpEditor(settings, "auto", "file"); err != nil || editor.Name == "" {
		t.Fatal(editor, err)
	}
	for _, bad := range []sftpEditorSettings{
		{MaxFileSize: 0}, {MaxFileSize: 1, DefaultEditor: "missing"},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "auto", Name: "x", Executable: "code"}}},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "id", Name: "", Executable: "code"}}},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "id", Name: "x", Executable: "relative/path"}}},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "id", Name: "x", Executable: "code", Arguments: []string{"--file={file}"}}}},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "id", Name: "x", Executable: "code", Arguments: []string{"{file}", "{file}"}}}},
		{MaxFileSize: 1, DefaultEditor: "auto", Editors: []sftpEditor{{ID: "id", Name: "x", Executable: "code", Patterns: "["}}},
	} {
		if err := writeSftpEditorSettings(database, bad); err == nil {
			t.Fatal("accepted invalid editor settings", bad)
		}
	}
	_, settingsPath := authPaths(database)
	for _, contents := range []string{`invalid`, `{"fileTransfer":{"maxFileSize":0}}`, `{"fileTransfer":"invalid"}`} {
		if err := os.WriteFile(settingsPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		read, err := readSftpEditorSettings(database)
		if err != nil || read.DefaultEditor != "auto" {
			t.Fatal(read, err)
		}
	}
}

func TestSftpEditorArgvAndEnvironment(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "space Unicode è 🔑.conf")
	for _, args := range [][]string{nil, {"{file}"}, {"--reuse-window", "{file}"}, {"--wait"}} {
		executable, actual, err := sftpEditorArgv("windows", sftpEditor{Executable: "editor", Arguments: args}, filename)
		if err != nil || executable != "editor" || actual[len(actual)-1] != filename {
			t.Fatal(executable, actual, err)
		}
	}
	if _, _, err := sftpEditorArgv("linux", sftpEditor{Arguments: []string{"--file={file}"}}, filename); err == nil {
		t.Fatal("accepted split file placeholder")
	}
	if _, _, err := sftpEditorArgv("linux", sftpEditor{}, "relative"); err == nil {
		t.Fatal("accepted relative editor file")
	}
	executable, args, err := sftpEditorArgv("darwin", sftpEditor{Executable: "/Applications/Code.app"}, filename)
	if err != nil || executable != "/usr/bin/open" || !reflect.DeepEqual(args, []string{"-a", "/Applications/Code.app", filename}) {
		t.Fatal(executable, args, err)
	}
	env := []string{"APPDIR=/bundle", "APPIMAGE=x", "LD_LIBRARY_PATH=x", "LD_PRELOAD=x", "PATH=/bundle", "HOME=/home/me", "DISPLAY=:1"}
	if actual := sftpEditorEnvironment("linux", env); !reflect.DeepEqual(actual, []string{"HOME=/home/me", "DISPLAY=:1", "PATH=/usr/local/bin:/usr/bin:/bin"}) {
		t.Fatal(actual)
	}
	if actual := sftpEditorEnvironment("darwin", env); !reflect.DeepEqual(actual, env) {
		t.Fatal(actual)
	}
	if actual := sftpEditorEnvironment("linux", []string{"PATH=/home/me/bin:/usr/bin"}); !reflect.DeepEqual(actual, []string{"PATH=/home/me/bin:/usr/bin"}) {
		t.Fatal("ordinary desktop PATH was lost", actual)
	}
	selected, err := sftpEditorExecutable("linux", "code", []string{"PATH=.:/usr/local/bin:/usr/bin"}, func(candidate string) (string, error) {
		if candidate == "/usr/bin/code" {
			return candidate, nil
		}
		return "", os.ErrNotExist
	})
	if err != nil || selected != "/usr/bin/code" {
		t.Fatal(selected, err)
	}
	if _, err := sftpEditorExecutable("linux", "missing", []string{"PATH=relative"}, func(string) (string, error) { return "", os.ErrNotExist }); err == nil {
		t.Fatal("relative editor PATH accepted")
	}
	if selected, err := sftpEditorExecutable("darwin", "open", nil, nil); err != nil || selected != "open" {
		t.Fatal(selected, err)
	}
	missing := func(string) (string, error) { return "", os.ErrNotExist }
	for _, goos := range []string{"windows", "darwin", "linux"} {
		value := automaticSftpEditor(goos, missing, func(string) bool { return false }, "C:/Program Files")
		if value.Name == "" {
			t.Fatal(value)
		}
	}
	if value := automaticSftpEditor("windows", missing, func(string) bool { return true }, "C:/Program Files"); value.Name != "Notepad++" {
		t.Fatal(value)
	}
	if value := automaticSftpEditor("linux", func(name string) (string, error) {
		if name == "kate" {
			return "/usr/bin/kate", nil
		}
		return "", os.ErrNotExist
	}, nil, ""); value.Name != "kate" {
		t.Fatal(value)
	}
}

func newSftpEditFixture(t *testing.T) (*sshServer, *sshNativeSession, string) {
	t.Helper()
	server := newSSHTestServer(io.Discard)
	server.electronUserDataPath = t.TempDir()
	server.databasePath = filepath.Join(t.TempDir(), "workspace.db")
	if err := server.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{id: "edit-session", server: server, done: make(chan struct{}), sftpClient: newSftpTestClient(t), sftpGeneration: 1, fingerprint: "fixture-key", mcpSession: mcpSessionInfo{Host: "fixture", Port: 22, Username: "me"}}
	server.sessions[native.id] = native
	server.lifecycles[native.id] = &sshReconnectState{command: sshWireCommand{SessionID: native.id, NodeID: "fixture-node"}}
	remote := filepath.Join(t.TempDir(), "original.conf")
	if err := os.WriteFile(remote, []byte("original\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := launchSftpEditor
	launchSftpEditor = func(editor sftpEditor, filename string) error { return nil }
	t.Cleanup(func() {
		launchSftpEditor = previous
		server.editMu.Lock()
		records := make([]*sftpEditRecord, 0, len(server.edits))
		for _, record := range server.edits {
			records = append(records, record)
		}
		server.editMu.Unlock()
		for _, record := range records {
			record.mu.Lock()
			record.stopped = true
			record.mu.Unlock()
		}
		native.close(false)
	})
	normalized, err := normalizeSftpPath(sftpTestPath(remote))
	if err != nil {
		t.Fatal(err)
	}
	return server, native, normalized
}

func editFixtureRecord(t *testing.T, server *sshServer, native *sshNativeSession, remote string) *sftpEditRecord {
	t.Helper()
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "start", Pane: "remote", Path: remote}); err != nil {
		t.Fatal(err)
	}
	for _, record := range server.edits {
		if record.View.RemotePath == remote {
			return record
		}
	}
	t.Fatal("missing edit record")
	return nil
}

func TestSftpEditDownloadUploadConflictAndRecovery(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	if record.View.NodeID != "fixture-node" {
		t.Fatal(record.View)
	}
	record.mu.Lock()
	if contents, err := os.ReadFile(record.localPath()); err != nil || string(contents) != "original\r\n" {
		t.Fatal(string(contents), err)
	}
	if err := os.WriteFile(record.localPath(), []byte("saved\nUnicode è"), 0o600); err != nil {
		t.Fatal(err)
	}
	native.sftpTransferMu.Lock()
	if err := record.upload(native, false); err == nil || record.View.State != "Waiting for transfer queue" {
		t.Fatal(record.View, err)
	}
	native.sftpTransferMu.Unlock()
	if err := record.upload(native, false); err != nil {
		t.Fatal(err)
	}
	contents, err := readSftpTestFile(native.sftpClient, remote)
	if err != nil || string(contents) != "saved\nUnicode è" {
		t.Fatal(string(contents), err)
	}
	if err := record.upload(native, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("local change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSftpTestFile(native.sftpClient, remote, []byte("remote independent change")); err != nil {
		t.Fatal(err)
	}
	if err := record.upload(native, false); err == nil || record.View.State != "Conflict" || !record.View.Pending {
		t.Fatal(record.View, err)
	}
	if err := record.upload(native, true); err != nil {
		t.Fatal(err)
	}
	if err := record.download(native); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("pending crash recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	record.mu.Unlock()
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "prepare-close"}); err != nil {
		t.Fatal(err)
	}
	if !server.sftpEditSnapshot(native.id)[0].Pending {
		t.Fatal("pending save lost")
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close"}); err == nil {
		t.Fatal("silently discarded pending save")
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "finish-close", Decision: "keep"}); err != nil {
		t.Fatal(err)
	}
	recovered := newSSHTestServer(io.Discard)
	recovered.electronUserDataPath = server.electronUserDataPath
	if err := recovered.ensureSftpEdits(); err != nil {
		t.Fatal(err)
	}
	views := recovered.sftpEditSnapshot("sftp-recovery")
	if len(views) != 1 || !views[0].Recovered {
		t.Fatal(views)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: "wrong", Operation: "recover", EditID: record.View.ID}); err == nil {
		t.Fatal("recovery uploaded to another server")
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "recover", EditID: record.View.ID}); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "reload", EditID: record.View.ID}); err == nil {
		t.Fatal("reload discarded without confirmation")
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "reload", EditID: record.View.ID, Decision: "discard"}); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "stop", EditID: record.View.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.directory); !os.IsNotExist(err) {
		t.Fatal("finished copy was not removed", err)
	}
}

func TestSftpEditWatcherDebouncesAndSurvivesEditorHandoff(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	record := editFixtureRecord(t, server, native, remote)
	if err := os.WriteFile(record.localPath(), []byte("first save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("second save, editor process already exited"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		record.mu.Lock()
		uploaded := record.View.State == "Uploaded"
		record.mu.Unlock()
		if uploaded {
			contents, err := readSftpTestFile(native.sftpClient, remote)
			if err != nil || string(contents) != "second save, editor process already exited" {
				t.Fatal(string(contents), err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("watcher did not upload")
}

func TestSftpEditValidationAndErrorPaths(t *testing.T) {
	server, native, remote := newSftpEditFixture(t)
	for _, command := range []sshWireCommand{{Operation: "start"}, {Operation: "start", SessionID: native.id, Pane: "invalid"}, {Operation: "start", SessionID: native.id, Pane: "remote", Path: "\x00"}, {Operation: "upload", SessionID: native.id, EditID: "missing"}} {
		if err := server.runSftpEdit(command); err == nil {
			t.Fatal("invalid edit accepted", command)
		}
	}
	local := filepath.Join(t.TempDir(), "local.conf")
	if err := os.WriteFile(local, []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.startSftpEdit(native, sshWireCommand{Pane: "local", Path: local}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.startSftpEdit(native, sshWireCommand{Pane: "local", Path: local}); err == nil || !strings.Contains(err.Error(), "binary-file") {
		t.Fatal(err)
	}
	if err := server.startSftpEdit(native, sshWireCommand{Pane: "local", Path: local, AllowBinary: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sftpEditBytes(local, 1); err == nil {
		t.Fatal("size limit ignored")
	}
	if _, err := sftpEditBytes(filepath.Dir(local), 1024); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := sftpEditBytes(local+"missing", 1024); err == nil {
		t.Fatal("missing file accepted")
	}
	record := editFixtureRecord(t, server, native, remote)
	if err := server.startSftpEdit(native, sshWireCommand{Pane: "remote", Path: remote}); err == nil {
		t.Fatal("duplicate edit accepted")
	}
	for _, command := range []sshWireCommand{{Operation: "discard"}, {Operation: "unsupported"}, {Operation: "upload", SessionID: "other"}} {
		if command.SessionID == "" {
			command.SessionID = native.id
		}
		command.EditID = record.View.ID
		if err := server.runSftpEdit(command); err == nil {
			t.Fatal("unsafe edit action accepted", command)
		}
	}
	record.mu.Lock()
	if err := os.WriteFile(record.localPath(), []byte("offline change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := record.upload(nil, false); !errors.Is(err, errSSHSessionClosed) {
		t.Fatal(err)
	}
	native.sftpMu.Lock()
	native.sftpClosed = true
	native.sftpMu.Unlock()
	if err := record.upload(native, false); err == nil {
		t.Fatal("closed client upload accepted")
	}
	native.sftpMu.Lock()
	native.sftpClosed = false
	native.sftpMu.Unlock()
	record.mu.Unlock()
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: remote}); err == nil {
		t.Fatal("save-as replaced existing file")
	}
	saveAs := remote + ".copy"
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID, DestinationPath: saveAs}); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "discard", EditID: record.View.ID, Decision: "discard"}); err != nil {
		t.Fatal(err)
	}
	if err := server.runSftpEdit(sshWireCommand{SessionID: native.id, Operation: "upload", EditID: record.View.ID}); err == nil {
		t.Fatal("stopped record accepted")
	}
	if err := server.runSftpEdit(sshWireCommand{Operation: "list"}); err != nil {
		t.Fatal(err)
	}
	if err := (&sshServer{}).ensureSftpEdits(); err == nil {
		t.Fatal("missing private root accepted")
	}
}

func TestSftpOnlyTransportHasNoShellAndSurvivesSiblingClose(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	var mu sync.Mutex
	requestsSeen := []string{}
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		connection, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for request := range requests {
					mu.Lock()
					requestsSeen = append(requestsSeen, request.Type)
					mu.Unlock()
					if request.Type != "subsystem" {
						_ = request.Reply(false, nil)
						continue
					}
					_ = request.Reply(true, nil)
					server, err := sftp.NewServer(channel)
					if err == nil {
						_ = server.Serve()
						_ = server.Close()
					}
					return
				}
			}()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	goTunnelDisabled := false
	target := &sshTarget{host: "127.0.0.1", port: address.Port, username: "fixture", password: "test", tunnelConfigID: "disabled-vpn"}
	native, openedTarget, err := openNativeSSH(context.Background(), "", "", "", target, "", "", &goTunnelDisabled, "", "", false, false, "", 80, 24, "sftp")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := openedTarget.knownHostFingerprint
	defer native.close(false)
	if native.sftpEditRoute != "direct" || openedTarget.tunnelConfigID != "" {
		t.Fatal("native open did not capture the actual direct route before clearing disabled VPN configuration")
	}
	if native.terminal != nil || native.session != nil || native.inputQueue != nil || native.shellWaitDone != nil || fingerprint == "" {
		t.Fatal("SFTP allocated terminal resources")
	}

	output := &synchronizedBuffer{}
	backend := newSSHTestServer(output)
	native.id, native.server, native.fingerprint = "source", backend, fingerprint
	native.mcpSession = mcpSessionInfo{Host: "127.0.0.1", Port: address.Port, Username: "fixture", ID: "source"}
	backend.sessions[native.id] = native
	backend.lifecycles[native.id] = &sshReconnectState{command: sshWireCommand{SessionID: native.id, Host: "127.0.0.1", Username: "fixture", Password: "test"}}
	defer backend.shutdown()
	backend.openSharedSftp(sshWireCommand{SessionID: "bad", SourceSessionID: native.id, Mode: "terminal"})
	backend.openSharedSftp(sshWireCommand{SessionID: "bad", SourceSessionID: "missing", Mode: "sftp"})
	backend.openSharedSftp(sshWireCommand{SessionID: "shared", SourceSessionID: native.id, Mode: "sftp"})
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.SessionID == "shared" && event.Type == "connected" })
	if event.Fingerprint != fingerprint {
		t.Fatal("shared connection lost host-key identity")
	}
	sibling := backend.session("shared")
	if sibling == nil || !sibling.sftpOnly {
		t.Fatal("missing SFTP sibling")
	}
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pane := range []string{"local", "remote"} {
		listingPath := directory
		if pane == "remote" {
			listingPath = sftpTestPath(directory)
		}
		backend.sftpTreeList(sshWireCommand{SessionID: sibling.id, Pane: pane, Path: listingPath, RequestID: "tree-" + pane})
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "tree-"+pane })
		if event.Error != "" || len(event.Entries) != 1 || !event.Entries[0].IsDirectory {
			t.Fatal(event)
		}
	}
	if sibling.sftpListSeq != 0 {
		t.Fatal("tree expansion invalidated the file listing")
	}
	waitSftpTreeRequests(t, sibling, 0)
	sibling.sftpMu.Lock()
	sibling.treeRequests = sftpTreeConcurrency + sftpTreeQueueLimit
	sibling.sftpMu.Unlock()
	backend.sftpTreeList(sshWireCommand{SessionID: sibling.id, Pane: "local", Path: directory, RequestID: "busy"})
	if event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "busy" }); event.Error == "" {
		t.Fatal("tree queue limit ignored")
	}
	sibling.sftpMu.Lock()
	sibling.treeRequests = 0
	sibling.sftpMu.Unlock()
	for index, command := range []sshWireCommand{
		{SessionID: "missing", Pane: "remote", Path: "/"},
		{SessionID: sibling.id, Pane: "invalid", Path: "/"},
		{SessionID: sibling.id, Pane: "remote", Path: "\x00"},
		{SessionID: sibling.id, Pane: "local", Path: "relative"},
	} {
		command.RequestID = fmt.Sprintf("bad-%d", index)
		backend.sftpTreeList(command)
		event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == command.RequestID })
		if event.Error == "" {
			t.Fatal(event)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if client, err := newSharedSftpClient(cancelled, native); err == nil {
		_ = client.Close()
		t.Fatal("cancelled subsystem open succeeded")
	}
	client, err := newSharedSftpClient(context.Background(), native)
	if err != nil {
		t.Fatal(err)
	}
	if !native.transport.retain() {
		t.Fatal("transport retain failed")
	}
	native.close(false)
	if _, err := client.Getwd(); err != nil {
		t.Fatal("closing one tab closed the shared transport", err)
	}
	_ = client.Close()
	sibling.close(false)
	native.transport.release()
	native.transport.release()
	if native.transport.retain() {
		t.Fatal("retained closed transport")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requestsSeen) < 3 || strings.Join(requestsSeen, ",") != strings.TrimSuffix(strings.Repeat("subsystem,", len(requestsSeen)), ",") {
		t.Fatal("SFTP requested a shell/PTY", requestsSeen)
	}
}
