package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

// Only one editor download/upload retains a full immutable file buffer. Hash
// polling streams small chunks, independently of the number of watched files.
var sftpEditIOMu sync.Mutex

type sftpEditView struct {
	ID         string `json:"id"`
	SessionID  string `json:"sessionId"`
	NodeID     string `json:"nodeId"`
	Name       string `json:"name"`
	RemotePath string `json:"remotePath"`
	Editor     string `json:"editor"`
	State      string `json:"state"`
	Pending    bool   `json:"pending"`
	Recovered  bool   `json:"recovered"`
	Error      string `json:"error,omitempty"`
	UploadedAt string `json:"uploadedAt,omitempty"`
}

type sftpEditRecord struct {
	mu               sync.Mutex
	View             sftpEditView `json:"view"`
	Host             string       `json:"host"`
	Port             int          `json:"port"`
	Username         string       `json:"username"`
	Fingerprint      string       `json:"fingerprint"`
	Route            string       `json:"route"`
	BaseSize         int64        `json:"baseSize"`
	BaseMtime        int64        `json:"baseMtime"`
	Mode             uint32       `json:"mode"`
	UploadedHash     string       `json:"uploadedHash"`
	directory        string
	lastHash         string
	changedAt        time.Time
	stopped          bool
	maxSize          int64
	notify           func(sftpEditView)
	watching         bool
	hashReadAt       time.Time
	lastFileInfo     os.FileInfo
	failedUploadHash string
	nextUploadAt     time.Time
	uploadRetryDelay time.Duration
}

func (record *sftpEditRecord) resetUploadRetry() {
	record.failedUploadHash = ""
	record.nextUploadAt, record.uploadRetryDelay = time.Time{}, 0
}

func (record *sftpEditRecord) localPath() string {
	return filepath.Join(record.directory, "files", record.View.Name)
}

func sftpEditReader(filename string, limit int64) (*os.File, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("editing requires a regular file within the configured size limit")
	}
	return os.Open(filename)
}

func sftpEditBytes(filename string, limit int64) ([]byte, error) {
	file, err := sftpEditReader(filename, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(contents)) > limit {
		err = errors.New("edited file exceeds the configured size limit")
	}
	return contents, err
}

func sftpEditPrefix(filename string, limit int64) ([]byte, error) {
	file, err := sftpEditReader(filename, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 8192))
}

func sftpEditFileHash(filename string, limit int64) (string, error) {
	file, err := sftpEditReader(filename, limit)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if count > limit {
		return "", errors.New("edited file exceeds the configured size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sftpEditHash(contents []byte) string {
	hash := sha256.Sum256(contents)
	return hex.EncodeToString(hash[:])
}
func sftpLooksBinary(contents []byte) bool {
	return bytes.ContainsRune(contents[:min(len(contents), 8192)], 0)
}

func (record *sftpEditRecord) save() error {
	contents, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary := filepath.Join(record.directory, "manifest.tmp")
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	return replaceBackupFile(temporary, filepath.Join(record.directory, "manifest.json"))
}

func (server *sshServer) ensureSftpEdits() error {
	server.editOnce.Do(func() {
		server.edits = make(map[string]*sftpEditRecord)
		server.editWorkers = make(chan struct{}, 16)
		root := filepath.Join(server.electronUserDataPath, "sftp-edit")
		if server.electronUserDataPath == "" {
			server.editError = errors.New("the private editing directory is unavailable")
			return
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			server.editError = err
			return
		}
		if err := protectSftpEditDirectory(root); err != nil {
			server.editError = err
			return
		}
		settings, settingsErr := readSftpEditorSettings(server.databasePath)
		if settingsErr != nil {
			server.editError = settingsErr
			return
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			server.editError = err
			return
		}
		for _, entry := range entries {
			if len(server.edits) >= 256 {
				break
			}
			if !entry.IsDir() || !validCredentialID(entry.Name()) {
				continue
			}
			directory := filepath.Join(root, entry.Name())
			info, err := os.Lstat(directory)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			contents, err := sftpEditBytes(filepath.Join(directory, "manifest.json"), 64*1024)
			if err != nil {
				continue
			}
			record := &sftpEditRecord{}
			if json.Unmarshal(contents, record) != nil || record.View.ID != entry.Name() || !validSftpEditManifest(record) {
				continue
			}
			if protectSftpEditDirectory(directory) != nil || protectSftpEditDirectory(filepath.Join(directory, "files")) != nil {
				continue
			}
			record.directory, record.maxSize = directory, settings.MaxFileSize
			record.notify = server.notifySftpEdit
			record.View.Recovered, record.View.State = true, "Recovered"
			server.edits[record.View.ID] = record
		}
	})
	return server.editError
}

func validLocalSftpName(name string) bool {
	return isSafeLocalSftpName(name) && filepath.Base(name) == name
}

func validSftpEditManifest(record *sftpEditRecord) bool {
	view := record.View
	for _, field := range []struct {
		value string
		limit int
	}{
		{view.SessionID, 128}, {view.NodeID, 128}, {view.Name, sshSftpMaxNameBytes},
		{view.RemotePath, sshSftpMaxPathBytes}, {view.Editor, 256}, {view.State, 128},
		{view.Error, 8192}, {view.UploadedAt, 128}, {record.Host, 4096},
		{record.Username, 512}, {record.Fingerprint, 512}, {record.Route, 4096},
	} {
		if len(field.value) > field.limit || strings.ContainsRune(field.value, 0) {
			return false
		}
	}
	remote, err := normalizeSftpPath(view.RemotePath)
	hash, hashErr := hex.DecodeString(record.UploadedHash)
	return err == nil && remote != "" && remote == view.RemotePath && validLocalSftpName(view.Name) &&
		hashErr == nil && len(hash) == sha256.Size && record.Port > 0 && record.Port <= 65535 &&
		record.Host != "" && record.Username != "" && record.Fingerprint != "" && record.Route != "" &&
		record.BaseSize >= -1 && record.Mode & ^uint32(0o777) == 0
}

func (server *sshServer) sftpEditSnapshot(sessionID string) []sftpEditView {
	server.editMu.Lock()
	records := make([]*sftpEditRecord, 0, len(server.edits))
	for _, record := range server.edits {
		records = append(records, record)
	}
	server.editMu.Unlock()
	views := make([]sftpEditView, 0, len(records))
	for _, record := range records {
		record.mu.Lock()
		if !record.stopped && (sessionID == "sftp-recovery" || record.View.SessionID == sessionID || record.View.Recovered) {
			views = append(views, record.View)
		}
		record.mu.Unlock()
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	return views
}

func (server *sshServer) handleSftpEdit(command sshWireCommand) {
	if err := server.ensureSftpEdits(); err != nil {
		server.output.write(sshWireEvent{Type: "sftp.edit", SessionID: command.SessionID, RequestID: command.RequestID, Error: safeSftpError(err)})
		return
	}
	select {
	case server.editWorkers <- struct{}{}:
	default:
		server.output.write(sshWireEvent{Type: "sftp.edit", SessionID: command.SessionID, RequestID: command.RequestID, Error: "too many file edit operations; retry after the current operation"})
		return
	}
	go func() {
		defer func() { <-server.editWorkers }()
		err := server.runSftpEdit(command)
		event := sshWireEvent{Type: "sftp.edit", SessionID: command.SessionID, RequestID: command.RequestID, Edits: server.sftpEditSnapshot(command.SessionID)}
		if err != nil {
			event.Error = safeSftpError(err)
		}
		server.output.write(event)
		server.editMu.Lock()
		for id, record := range server.edits {
			record.mu.Lock()
			stopped := record.stopped
			record.mu.Unlock()
			if stopped {
				delete(server.edits, id)
			}
		}
		server.editMu.Unlock()
	}()
}

func (server *sshServer) runSftpEdit(command sshWireCommand) error {
	if command.Operation == "list" {
		return nil
	}
	if command.Operation == "prepare-close" || command.Operation == "finish-close" {
		server.editMu.Lock()
		records := make([]*sftpEditRecord, 0, len(server.edits))
		for _, record := range server.edits {
			records = append(records, record)
		}
		server.editMu.Unlock()
		for _, record := range records {
			record.mu.Lock()
			if !record.stopped && !record.View.Recovered && (command.SessionID == "sftp-recovery" || record.View.SessionID == command.SessionID) {
				if command.Operation == "prepare-close" || command.Decision != "keep" {
					hash, err := sftpEditFileHash(record.localPath(), record.maxSize)
					record.View.Pending = err != nil || hash != record.UploadedHash
				}
				if command.Operation == "finish-close" {
					if record.View.Pending && command.Decision != "keep" {
						record.mu.Unlock()
						return errors.New("unsaved working copies require confirmation")
					}
					// An editor may still hold even a clean copy open and save after close.
					// Only explicit Stop editing/Discard removes its working directory.
					record.View.Recovered, record.View.State = true, "Recovered"
					if err := record.save(); err != nil {
						record.mu.Unlock()
						return err
					}
				}
			}
			record.mu.Unlock()
		}
		return nil
	}

	native := server.session(command.SessionID)
	if command.Operation == "start" {
		return server.startSftpEdit(native, command)
	}
	server.editMu.Lock()
	record := server.edits[command.EditID]
	server.editMu.Unlock()
	if record == nil {
		return errors.New("edited file was not found")
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.stopped {
		return errors.New("editing has finished")
	}
	if command.Operation == "reveal" {
		return openLocalPathWithShell(filepath.Join(record.directory, "files"))
	}
	if command.Operation == "discard" {
		if command.Decision != "discard" {
			return errors.New("discarding a working copy requires confirmation")
		}
		return record.remove()
	}
	if command.Operation == "recover" {
		if !record.View.Recovered {
			return errors.New("this file is already being watched")
		}
		if !record.matches(native) {
			return errors.New("reconnect to the original server, account and VPN route before recovering this file")
		}
		previous := record.View
		record.View.SessionID, record.View.Recovered, record.View.State = native.id, false, "Watching"
		if err := record.save(); err != nil {
			record.View = previous
			return err
		}
		record.resetUploadRetry()
		go server.watchSftpEdit(record)
		return nil
	}
	if record.View.Recovered || record.View.SessionID != command.SessionID || !record.matches(native) {
		return errors.New("edited file belongs to another connection")
	}
	switch command.Operation {
	case "reload":
		if command.Decision != "discard" {
			return errors.New("reloading requires confirmation to discard local changes")
		}
		return record.download(native)
	case "upload", "stop":
		record.resetUploadRetry()
		if err := record.uploadTo(native, command.Decision == "overwrite", command.DestinationPath); err != nil {
			record.View.Error = safeSftpError(err)
			if record.View.State != "Conflict" && record.View.State != "Disconnected" && record.View.State != "Waiting for transfer queue" {
				record.View.State = "Failed"
			}
			return err
		}
		if command.Operation == "stop" {
			latest, err := sftpEditFileHash(record.localPath(), record.maxSize)
			unchanged := err == nil && latest == record.UploadedHash
			if !unchanged {
				record.View.Pending = true
				return errors.New("the editor saved again during upload; finish uploading before stopping")
			}
			return record.remove()
		}
		return nil
	default:
		return errors.New("unsupported edit action")
	}
}

func (record *sftpEditRecord) matches(native *sshNativeSession) bool {
	return native != nil && !native.isClosed() && record.Host == native.mcpSession.Host && record.Port == native.mcpSession.Port && record.Username == native.mcpSession.Username && record.Fingerprint == native.fingerprint && record.Route == native.editRoute()
}

func (native *sshNativeSession) editRoute() string {
	if native.sftpEditRoute == "" {
		return "direct"
	}
	return native.sftpEditRoute
}

func (native *sshNativeSession) editClient() (*sftp.Client, error) {
	if native == nil || native.isClosed() {
		return nil, errSSHSessionClosed
	}
	native.sftpMu.Lock()
	defer native.sftpMu.Unlock()
	if native.sftpClosed || native.sftpClient == nil {
		return nil, errSSHSftpClosed
	}
	return native.sftpClient, nil
}

func (server *sshServer) startSftpEdit(native *sshNativeSession, command sshWireCommand) error {
	if native == nil || native.isClosed() {
		return errSSHSessionClosed
	}
	settings, err := readSftpEditorSettings(server.databasePath)
	if err != nil {
		return err
	}
	editor, err := resolveSftpEditor(settings, command.EditorID, path.Base(command.Path))
	if err != nil {
		return err
	}
	if command.Pane == "local" {
		filename, err := normalizeLocalPath(command.Path)
		if err != nil {
			return err
		}
		contents, err := sftpEditPrefix(filename, settings.MaxFileSize)
		if err != nil {
			return err
		}
		defer clear(contents)
		if sftpLooksBinary(contents) && !command.AllowBinary {
			return errors.New("binary-file-confirmation-required")
		}
		return native.launchFileEditor(editor, filename)
	}
	if command.Pane != "remote" {
		return errors.New("invalid editing pane")
	}
	remote, err := normalizeSftpPath(command.Path)
	if err != nil || remote == "" {
		return errors.New("invalid remote file path")
	}
	name := path.Base(remote)
	if !validLocalSftpName(name) {
		return errors.New("this filename cannot be used for a private working copy")
	}
	server.editMu.Lock()
	if len(server.edits) >= 256 {
		server.editMu.Unlock()
		return errors.New("too many edited files; finish or discard an existing working copy")
	}
	for _, record := range server.edits {
		record.mu.Lock()
		duplicate := !record.stopped && record.View.SessionID == native.id && record.View.RemotePath == remote
		record.mu.Unlock()
		if duplicate {
			server.editMu.Unlock()
			return errors.New("this remote file is already being edited")
		}
	}
	id, err := newCredentialID()
	if err != nil {
		server.editMu.Unlock()
		return err
	}
	record := &sftpEditRecord{View: sftpEditView{ID: id, SessionID: native.id, Name: name, RemotePath: remote, Editor: editor.Name, State: "Opening"}, Host: native.mcpSession.Host, Port: native.mcpSession.Port, Username: native.mcpSession.Username, Fingerprint: native.fingerprint, Route: native.editRoute(), maxSize: settings.MaxFileSize}
	if state := server.reconnectState(native.id); state != nil {
		record.View.NodeID = state.commandSnapshot().NodeID
	}
	record.directory = filepath.Join(server.electronUserDataPath, "sftp-edit", id)
	record.notify = server.notifySftpEdit
	// Publish only after taking the record lock, so close cannot retire a half-open edit.
	record.mu.Lock()
	server.edits[id] = record
	server.editMu.Unlock()
	defer record.mu.Unlock()
	if err := os.Mkdir(record.directory, 0o700); err != nil {
		record.stopped = true
		return err
	}
	if err := protectSftpEditDirectory(record.directory); err != nil {
		record.stopped = true
		_ = os.Remove(record.directory)
		return err
	}
	if err := os.Mkdir(filepath.Join(record.directory, "files"), 0o700); err != nil {
		_ = record.remove()
		return err
	}
	if err := record.download(native); err != nil {
		_ = record.remove()
		return err
	}
	contents, err := sftpEditPrefix(record.localPath(), settings.MaxFileSize)
	if err != nil {
		return err
	}
	binary := sftpLooksBinary(contents)
	clear(contents)
	if binary && !command.AllowBinary {
		_ = record.remove()
		return errors.New("binary-file-confirmation-required")
	}
	if err := native.launchFileEditor(editor, record.localPath()); err != nil {
		record.View.State, record.View.Error = "Failed", safeSftpError(err)
		return err
	}
	record.View.State = "Watching"
	go server.watchSftpEdit(record)
	return nil
}

func (native *sshNativeSession) launchFileEditor(editor sftpEditor, filename string) error {
	native.lifecycleMu.Lock()
	defer native.lifecycleMu.Unlock()
	if native.closed {
		return errSSHSessionClosed
	}
	return launchSftpEditor(editor, filename)
}

func (server *sshServer) reconnectState(id string) *sshReconnectState {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.lifecycles[id]
}

func (record *sftpEditRecord) download(native *sshNativeSession) error {
	if !sftpEditIOMu.TryLock() {
		return errors.New("waiting for another file edit operation; retry when it finishes")
	}
	defer sftpEditIOMu.Unlock()
	client, err := native.editClient()
	if err != nil {
		return err
	}
	stopDeadline := native.sftpEditDeadline(client, sshSftpListTimeout)
	defer stopDeadline()
	info, err := client.Lstat(record.View.RemotePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > record.maxSize {
		return errors.New("remote file is not regular or exceeds the editing size limit")
	}
	input, err := client.Open(record.View.RemotePath)
	if err != nil {
		return err
	}
	defer input.Close()
	contents, err := io.ReadAll(io.LimitReader(input, record.maxSize+1))
	if err != nil {
		return err
	}
	defer clear(contents)
	if int64(len(contents)) > record.maxSize {
		return errors.New("remote file exceeds the editing size limit")
	}
	// Editors commonly replace files themselves. Stage our re-download in the same
	// private directory, preserving the previous copy if a write cannot finish.
	temporary := filepath.Join(record.directory, "download.tmp")
	defer os.Remove(temporary)
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	if err := replaceBackupFile(temporary, record.localPath()); err != nil {
		return err
	}
	record.BaseSize, record.BaseMtime, record.Mode = info.Size(), info.ModTime().UnixNano(), uint32(info.Mode().Perm())
	record.UploadedHash = sftpEditHash(contents)
	record.lastHash = record.UploadedHash
	record.lastFileInfo, _ = os.Stat(record.localPath())
	record.hashReadAt = time.Now()
	record.View.State, record.View.Pending, record.View.Error = "Watching", false, ""
	record.resetUploadRetry()
	return record.save()
}

func sftpRemoteChanged(info os.FileInfo, err error, size, mtime int64) bool {
	if size == -1 {
		return !os.IsNotExist(err)
	}
	return err != nil || info.Size() != size || info.ModTime().UnixNano() != mtime
}

func (record *sftpEditRecord) upload(native *sshNativeSession, overwrite bool) error {
	return record.uploadTo(native, overwrite, "")
}

func (record *sftpEditRecord) uploadTo(native *sshNativeSession, overwrite bool, destination string) (resultErr error) {
	target := record.View.RemotePath
	baseSize, baseMtime := record.BaseSize, record.BaseMtime
	saveAs := destination != ""
	if saveAs {
		var err error
		target, err = normalizeSftpPath(destination)
		if err != nil || target == "" {
			return errors.New("invalid save-as destination")
		}
		baseSize, baseMtime = -1, 0
		overwrite = false
	}
	if !sftpEditIOMu.TryLock() {
		record.View.State = "Waiting for transfer queue"
		return errors.New("waiting for another file edit operation")
	}
	defer sftpEditIOMu.Unlock()
	contents, err := sftpEditBytes(record.localPath(), record.maxSize)
	if err != nil {
		return err
	}
	defer clear(contents)
	hash := sftpEditHash(contents)
	defer func() {
		if resultErr == nil {
			record.resetUploadRetry()
		} else if record.View.State != "Conflict" && record.View.State != "Disconnected" && record.View.State != "Waiting for transfer queue" {
			// Retry these contents only after a new edit or an explicit action.
			record.failedUploadHash = hash
		}
	}()
	if !saveAs && hash == record.UploadedHash {
		record.View.Pending = false
		return nil
	}
	if !record.View.Pending || record.View.State != "Waiting for transfer queue" {
		record.View.Pending, record.View.State = true, "Waiting for transfer queue"
		if record.notify != nil {
			record.notify(record.View)
		}
	}
	if !record.matches(native) {
		record.View.State = "Disconnected"
		return errSSHSessionClosed
	}
	if !native.sftpTransferMu.TryLock() {
		return errors.New("waiting for transfer queue")
	}
	defer native.sftpTransferMu.Unlock()
	record.View.State = "Uploading"
	client, err := native.editClient()
	if err != nil {
		record.View.State = "Disconnected"
		return err
	}
	stopDeadline := native.sftpEditDeadline(client, sshSftpListTimeout)
	defer stopDeadline()
	info, statErr := client.Lstat(target)
	if !overwrite && sftpRemoteChanged(info, statErr, baseSize, baseMtime) {
		record.View.State = "Conflict"
		return errors.New("remote file changed; choose overwrite, save as, or re-download")
	}
	if statErr == nil && !info.Mode().IsRegular() {
		return errors.New("remote destination is not a regular file")
	}
	if record.notify != nil {
		record.notify(record.View)
	}
	attempt, err := newCredentialID()
	if err != nil {
		return err
	}
	temporary := path.Join(path.Dir(target), ".wormhole-edit-"+attempt)
	output, err := client.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer client.Remove(temporary)
	if err := client.Chmod(temporary, 0o600); err != nil {
		_ = output.Close()
		return err
	}
	_, copyErr := io.Copy(output, bytes.NewReader(contents))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := client.Chmod(temporary, os.FileMode(record.Mode)); err != nil {
		return err
	}
	// The upload may take seconds. Recheck immediately before committing so a
	// remote save during transfer is not silently overwritten.
	current, currentErr := client.Lstat(target)
	if !overwrite && sftpRemoteChanged(current, currentErr, baseSize, baseMtime) {
		record.View.State = "Conflict"
		return errors.New("remote file changed during upload; choose overwrite, save as, or re-download")
	}
	info, err = client.Lstat(temporary)
	if err != nil {
		return err
	}
	if _, supported := client.HasExtension("posix-rename@openssh.com"); supported && !saveAs {
		err = client.PosixRename(temporary, target)
	} else {
		// SFTP v3 RENAME must fail when the new name already exists. Save-as
		// deliberately avoids the replace extension, including a concurrent create.
		err = client.Rename(temporary, target)
	}
	// A server without replace-rename support keeps the original and the working copy.
	if err != nil {
		return fmt.Errorf("server could not atomically replace the remote file: %w", err)
	}
	// Take the baseline from our staged file, never from another writer's file
	// that might have replaced the destination just after our rename.
	record.BaseSize, record.BaseMtime = info.Size(), info.ModTime().UnixNano()
	record.View.RemotePath = target
	record.UploadedHash = hash
	record.View.Pending, record.View.State, record.View.Error, record.View.UploadedAt = false, "Uploaded", "", time.Now().UTC().Format(time.RFC3339)
	return record.save()
}

// A stuck file request must not hold the record lock or a close RPC forever.
// Closing this tab's subsystem interrupts reads without closing sibling tabs.
func (native *sshNativeSession) sftpEditDeadline(client *sftp.Client, timeout time.Duration) func() {
	var mu sync.Mutex
	finished := false
	timer := time.AfterFunc(timeout, func() {
		mu.Lock()
		defer mu.Unlock()
		if finished {
			return
		}
		native.sftpMu.Lock()
		if native.sftpClient == client {
			native.sftpClosed = true
			native.sftpClient = nil
			native.sftpGeneration++
		}
		native.sftpMu.Unlock()
		_ = client.Close()
	})
	return func() { mu.Lock(); finished = true; mu.Unlock(); timer.Stop() }
}

func (record *sftpEditRecord) remove() error {
	if err := os.RemoveAll(record.directory); err != nil {
		return err
	}
	record.stopped = true
	return nil
}

func (server *sshServer) watchSftpEdit(record *sftpEditRecord) {
	record.mu.Lock()
	if record.watching {
		record.mu.Unlock()
		return
	}
	record.watching = true
	record.mu.Unlock()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		record.mu.Lock()
		if record.stopped || record.View.Recovered {
			// Clear ownership before unlocking. A recover racing with this exit
			// must either retain this watcher or be able to start its replacement.
			record.watching = false
			record.mu.Unlock()
			return
		}
		changed := record.poll(server.session(record.View.SessionID), time.Now())
		view := record.View
		record.mu.Unlock()
		if changed {
			server.notifySftpEdit(view)
		}
	}
}

func (record *sftpEditRecord) poll(native *sshNativeSession, now time.Time) bool {
	previous := record.View
	info, err := os.Lstat(record.localPath())
	changed := err != nil || record.lastFileInfo == nil || !os.SameFile(info, record.lastFileInfo) ||
		info.Size() != record.lastFileInfo.Size() || !info.ModTime().Equal(record.lastFileInfo.ModTime())
	// Rehash periodically as a fallback for editors preserving timestamps.
	if changed || now.Sub(record.hashReadAt) >= 30*time.Second {
		var hash string
		hash, err = sftpEditFileHash(record.localPath(), record.maxSize)
		if err == nil {
			if hash != record.lastHash {
				record.lastHash, record.changedAt = hash, now
				record.nextUploadAt, record.uploadRetryDelay = time.Time{}, 0
			}
			record.View.Pending = hash != record.UploadedHash
			record.lastFileInfo, record.hashReadAt = info, now
		}
	}
	if err != nil {
		record.View.Pending, record.View.State, record.View.Error = true, "Failed", safeSftpError(err)
	} else if record.View.Pending && now.Sub(record.changedAt) >= 750*time.Millisecond && record.View.State != "Conflict" &&
		record.lastHash != record.failedUploadHash && !now.Before(record.nextUploadAt) {
		if err := record.upload(native, false); err != nil {
			record.View.Error = safeSftpError(err)
			if record.View.State != "Conflict" && record.View.State != "Disconnected" && record.View.State != "Waiting for transfer queue" {
				record.View.State = "Failed"
			}
			if record.View.State == "Disconnected" || record.View.State == "Waiting for transfer queue" {
				if record.uploadRetryDelay == 0 {
					record.uploadRetryDelay = time.Second
				} else {
					record.uploadRetryDelay = min(2*record.uploadRetryDelay, 30*time.Second)
				}
				record.nextUploadAt = now.Add(record.uploadRetryDelay)
			}
		}
	}
	return previous != record.View
}

func (server *sshServer) notifySftpEdit(view sftpEditView) {
	server.output.write(sshWireEvent{Type: "sftp.edit", SessionID: view.SessionID, Edits: []sftpEditView{view}})
}
