package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// These paths are supplied by the trusted process owner, never by a file command.
// The workspace/node scope comes from the authenticated credential handoff.
type sealedSFTPEditOptions struct {
	UserDataPath string
	SettingsPath string
}

type sealedSFTPEdits struct {
	options             sealedSFTPEditOptions
	workspaceID, nodeID string
	mu                  sync.Mutex
	release             func()
	stop                chan struct{}
	watchers            sync.WaitGroup
	closed              bool
}

var errSealedSFTPEditsUnavailable = errors.New("private file editing is unavailable")

func (edits *sealedSFTPEdits) prepare(server *sshServer) error {
	edits.mu.Lock()
	defer edits.mu.Unlock()
	if edits.closed || !filepath.IsAbs(edits.options.UserDataPath) || !filepath.IsAbs(edits.options.SettingsPath) ||
		!vaultCredentialID(edits.workspaceID) || !vaultCredentialID(edits.nodeID) {
		return errSealedSFTPEditsUnavailable
	}
	if edits.release != nil {
		return nil
	}
	root := edits.options.UserDataPath
	// Create and validate one component at a time; do not traverse an existing
	// symlink/junction or tighten permissions on the user's data directory itself.
	for _, component := range []string{"vault-sftp-edit", edits.workspaceID, edits.nodeID} {
		root = filepath.Join(root, component)
		if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errSealedSFTPEditsUnavailable
		}
		if protectPrivateDirectory(root) != nil {
			return errSealedSFTPEditsUnavailable
		}
	}
	lockPath := filepath.Join(root, ".owner.lock")
	if info, err := os.Lstat(lockPath); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return errSealedSFTPEditsUnavailable
	}
	release, err := tryAcquireExclusiveFileLock(lockPath)
	if err != nil {
		return errSealedSFTPEditsUnavailable
	}
	edits.release = release
	server.electronUserDataPath = root
	return nil
}

func (server *sshServer) readEditSettings() (sftpEditorSettings, error) {
	if server.sealedEdits != nil {
		return readSftpEditorSettingsFile(server.sealedEdits.options.SettingsPath)
	}
	return readSftpEditorSettings(server.databasePath)
}

func (server *sshServer) startEditWatcher(record *sftpEditRecord) {
	edits := server.sealedEdits
	if edits == nil {
		go server.watchSftpEdit(record)
		return
	}
	edits.mu.Lock()
	defer edits.mu.Unlock()
	if edits.closed {
		return
	}
	edits.watchers.Add(1)
	go func() {
		defer edits.watchers.Done()
		server.watchSftpEdit(record)
	}()
}

// Call after closing file-work admission and joining operations. The lease is
// retained until every watcher has stopped and recovery manifests are saved.
func (server *sshServer) closeSealedEdits() {
	edits := server.sealedEdits
	if edits == nil {
		return
	}
	edits.mu.Lock()
	if edits.closed {
		edits.mu.Unlock()
		return
	}
	edits.closed = true
	close(edits.stop)
	edits.mu.Unlock()
	edits.watchers.Wait()
	_ = server.runSftpEdit(sshWireCommand{SessionID: "sftp-recovery", Operation: "finish-close", Decision: "keep"})
	edits.mu.Lock()
	defer edits.mu.Unlock()
	if edits.release != nil {
		edits.release()
		edits.release = nil
	}
}

// Recovery follows the authenticated configuration, not the transient SOCKS
// listener. A new configuration version must never silently resume an upload.
func sealedSFTPEditRoute(route *vault.TunnelBundleBinding) string {
	if route == nil {
		return "direct"
	}
	return fmt.Sprintf("vault-vpn:%s:%s:%d:%d", route.FileID, route.TunnelConfigID, route.Kind, route.ConfigurationVersion)
}
