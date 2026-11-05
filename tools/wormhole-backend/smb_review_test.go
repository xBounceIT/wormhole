package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

type smbRacingFS struct {
	smbFilesystem
	root string
	once *sync.Once
}

func (fs smbRacingFS) WithContext(ctx context.Context) smbFilesystem {
	fs.smbFilesystem = fs.smbFilesystem.WithContext(ctx)
	return fs
}
func (fs smbRacingFS) Lstat(name string) (os.FileInfo, error) {
	info, err := fs.smbFilesystem.Lstat(name)
	if name == "target.txt" && os.IsNotExist(err) {
		fs.once.Do(func() { _ = os.WriteFile(filepath.Join(fs.root, name), []byte("other writer"), 0o600) })
	}
	return info, err
}

func (fs smbRacingFS) RenameNoReplace(source, destination string) error {
	fs.once.Do(func() { _ = os.WriteFile(filepath.Join(fs.root, destination), []byte("other writer"), 0o600) })
	return fs.smbFilesystem.RenameNoReplace(source, destination)
}

func TestSMBReviewNoReplaceSurvivesDestinationRace(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "source.txt"), []byte("upload"), 0o600))
	handler := smbFileHandler{fs: smbRacingFS{smbFilesystem: smbTestFS{root: root}, root: root, once: &sync.Once{}}}
	request := sftp.NewRequest("Rename", "/source.txt")
	request.Target = "/target.txt"
	require.Error(t, handler.Filecmd(request))
	data, err := os.ReadFile(filepath.Join(root, "target.txt"))
	require.NoError(t, err)
	require.Equal(t, "other writer", string(data))
	require.FileExists(t, filepath.Join(root, "source.txt"))
}

type smbContextFS struct {
	smbFilesystem
	ctx    context.Context
	opened chan *smbContextFile
	list   bool
}

func (fs smbContextFS) WithContext(ctx context.Context) smbFilesystem {
	fs.ctx = ctx
	fs.smbFilesystem = fs.smbFilesystem.WithContext(ctx)
	return fs
}
func (fs smbContextFS) OpenFile(name string, flags int, mode os.FileMode) (smbFile, error) {
	file, err := fs.smbFilesystem.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	wrapped := &smbContextFile{smbFile: file, ctx: fs.ctx, closed: make(chan error, 1), list: fs.list}
	fs.opened <- wrapped
	return wrapped, nil
}

type smbContextFile struct {
	smbFile
	ctx    context.Context
	closed chan error
	list   bool
}

func (file *smbContextFile) Close() error {
	err := file.ctx.Err()
	if err == nil {
		err = file.smbFile.Close()
	}
	file.closed <- err
	return err
}
func (file *smbContextFile) CloseContext(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		err = file.smbFile.CloseContext(ctx)
	}
	file.closed <- err
	return err
}
func (file *smbContextFile) Readdir(n int) ([]os.FileInfo, error) {
	if !file.list {
		return file.smbFile.Readdir(n)
	}
	<-file.ctx.Done()
	return nil, file.ctx.Err()
}

func TestSMBReviewBridgeCancellationClosesOutstandingFiles(t *testing.T) {
	transport := smbTestTransport(t, smbTestFS{root: t.TempDir()})
	opened := make(chan *smbContextFile, 1)
	transport.fs = smbContextFS{smbFilesystem: transport.fs, opened: opened}
	client, err := transport.newClient(context.Background())
	require.NoError(t, err)
	_, err = client.OpenFile("/stage.txt", os.O_CREATE|os.O_WRONLY)
	require.NoError(t, err)
	file := <-opened
	t.Cleanup(func() { _ = file.smbFile.Close() })
	require.NoError(t, client.Close())
	select {
	case err := <-file.closed:
		require.NoError(t, err, "remote handles must close even after request cancellation")
	case <-time.After(time.Second):
		t.Fatal("outstanding remote handle was not closed")
	}
}

func TestSMBReviewDirectoryHonorsRequestCancellation(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan *smbContextFile, 1)
	fs := smbContextFS{smbFilesystem: smbTestFS{root: t.TempDir()}, ctx: lifetime, opened: opened, list: true}
	handler := smbFileHandler{fs: fs}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	finished := make(chan error, 1)
	go func() { _, err := handler.Filelist(sftp.NewRequest("List", "/").WithContext(ctx)); finished <- err }()
	file := <-opened
	defer func() { cancel(); _ = file.smbFile.Close() }()
	deadline, bounded := file.ctx.Deadline()
	require.True(t, bounded)
	require.LessOrEqual(t, time.Until(deadline), sshSftpListTimeout)
	stop()
	select {
	case err := <-finished:
		require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled), err)
	case <-time.After(2 * time.Second):
		cancel()
		<-finished
		t.Fatal("a cancelled directory request retained its SMB worker")
	}
}

func TestSMBReviewLiteralUNCPaths(t *testing.T) {
	for _, test := range []struct{ input, directory string }{
		{`\\server\share\reports#2026`, "/reports#2026"},
		{`\\server\share\100%`, "/100%"},
		{`server/share/literal%20name`, "/literal%20name"},
	} {
		address, err := parseSMBAddress(test.input, 0)
		require.NoError(t, err, test.input)
		require.Equal(t, test.directory, address.directory)
	}
}

func TestSMBReviewBlankPortInheritsFolderPort(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Folder", Kind: "folder"})
	require.NoError(t, err)
	database, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	defer database.Close()
	_, err = database.Exec("UPDATE Nodes SET Protocol=8, Port=1445 WHERE Id=?", folderID)
	require.NoError(t, err)
	id, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{ParentID: folderID, Name: "Share", Kind: "connection", Protocol: "smb", Host: "server/share", Username: "user"})
	require.NoError(t, err)
	nodes, err := loadSSHNodes(database)
	require.NoError(t, err)
	endpoint, err := resolveFileNodeEndpoint(nodes, id, true)
	require.NoError(t, err)
	require.Equal(t, 1445, endpoint.port)
	for _, item := range []struct {
		host           string
		port, expected int
	}{
		{"server/share", 445, 445},
		{"smb://server:2445/share", 0, 2445},
	} {
		next, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{ParentID: folderID, Name: "Explicit", Kind: "connection", Protocol: "smb", Host: item.host, Port: item.port, Username: "user"})
		require.NoError(t, err)
		nodes, err = loadSSHNodes(database)
		require.NoError(t, err)
		resolved, err := resolveFileNodeEndpoint(nodes, next, true)
		require.NoError(t, err)
		require.Equal(t, item.expected, resolved.port)
	}
}

type smbFailedCloseFile struct{ smbFile }

func (file smbFailedCloseFile) CloseContext(context.Context) error { return os.ErrPermission }

func TestSMBReviewFailedHandleCleanupRetiresTransport(t *testing.T) {
	transport := smbTestTransport(t, smbTestFS{root: t.TempDir()})
	client, err := transport.newClient(context.Background())
	require.NoError(t, err)
	base, err := transport.fs.OpenFile("file", os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	defer base.Close()
	file := &smbCleanupFile{smbFile: smbFailedCloseFile{smbFile: base}, onFailure: transport.close}
	require.ErrorIs(t, file.Close(), os.ErrPermission)
	require.ErrorIs(t, transport.ctx.Err(), context.Canceled)
	require.Error(t, client.Wait())
}

func TestSMBReviewRequestsCannotReviveCancelledContexts(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		owner, cancel := context.WithCancel(context.Background())
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		if cancelOwner {
			cancel()
		} else {
			cancelRequest()
		}
		handler := smbFileHandler{fs: smbTestFS{root: t.TempDir()}, ctx: owner}
		operation, release := handler.forRequest(sftp.NewRequest("Mkdir", "/new").WithContext(requestCtx))
		err := operation.fs.(smbTestFS).ctx.Err()
		release()
		cancel()
		cancelRequest()
		require.ErrorIs(t, err, context.Canceled, "an already cancelled context must be inherited synchronously")
	}
}

func TestSMBReviewCancelledPathOperationsRetireUnknownHandles(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		transport := smbTestTransport(t, smbTestFS{root: t.TempDir()})
		client, err := transport.newClient(context.Background())
		require.NoError(t, err)
		defer client.Close()
		handler := smbFileHandler{fs: transport.fs, ctx: transport.ctx, closeTransport: transport.close}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, release := handler.forRequest(sftp.NewRequest("Mkdir", "/new").WithContext(ctx))
		if cancelled {
			cancel()
		}
		release()
		if cancelled {
			require.ErrorIs(t, transport.ctx.Err(), context.Canceled)
		} else {
			require.NoError(t, transport.ctx.Err(), "successful requests must not retire the shared session")
			cancel()
			require.NoError(t, transport.ctx.Err(), "request cleanup must detach retirement callbacks")
		}
	}
	transport := smbTestTransport(t, smbTestFS{root: t.TempDir()})
	handler := smbFileHandler{fs: transport.fs, closeTransport: transport.close}
	handler.retireUncertainOpen(os.ErrPermission)
	require.NoError(t, transport.ctx.Err())
	handler.retireUncertainOpen(context.Canceled)
	require.ErrorIs(t, transport.ctx.Err(), context.Canceled)
}

func TestSMBReviewStoredPasswordProfilesRemainEditable(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	draft := credentialCreateRequest{Name: "SMB account", Protocol: "smb", Kind: "password", Username: "user", Domain: "CORP", Password: "original-secret", Provider: "Local"}
	credential, err := createCredential(databasePath, draft)
	require.NoError(t, err)
	workspace, err := loadWorkspace(databasePath)
	require.NoError(t, err)
	require.Len(t, workspace.Credentials, 1)
	require.True(t, workspace.Credentials[0].CanEdit, "reloaded SMB profiles must keep the Edit action")

	draft.Name, draft.Username, draft.Domain, draft.Password = "Renamed SMB", "updated-user", "UPDATED", ""
	updated, err := updateCredential(databasePath, credentialUpdateRequest{ID: credential.ID, credentialCreateRequest: draft})
	require.NoError(t, err)
	require.True(t, updated.CanEdit)
	workspace, err = loadWorkspace(databasePath)
	require.NoError(t, err)
	require.Equal(t, draft.Name, workspace.Credentials[0].Name)
	require.True(t, workspace.Credentials[0].CanEdit)
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Share", Kind: "connection", Protocol: "smb", Host: "server/share", CredentialMode: 2, CredentialID: credential.ID})
	require.NoError(t, err)
	target, err := loadFileTargetWithCredentialOverrides(databasePath, nodeID, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, `UPDATED\updated-user`, target.username)
	require.Equal(t, "original-secret", target.password, "metadata edits preserve the protected password")
	draft.Password = "updated-secret"
	_, err = updateCredential(databasePath, credentialUpdateRequest{ID: credential.ID, credentialCreateRequest: draft})
	require.NoError(t, err)
	target, err = loadFileTargetWithCredentialOverrides(databasePath, nodeID, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, draft.Password, target.password)
}

func TestSMBReviewWorkspaceCredentialReveals(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	credential, err := createCredential(databasePath, credentialCreateRequest{Name: "SMB account", Protocol: "smb", Kind: "password", Username: "user", Domain: "CORP", Password: "profile-secret", Provider: "Local"})
	require.NoError(t, err)
	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Folder", Kind: "folder", CredentialMode: 2, CredentialID: credential.ID})
	require.NoError(t, err)
	var savedID, inlineID string
	for _, item := range []struct {
		name, parent, credentialID, username, password string
		mode                                           int
	}{
		{"Saved", "", credential.ID, "", "", 2},
		{"Inherited", folderID, "", "", "", 0},
		{"Inline", "", "", `LOCAL\inline-user`, "inline-secret", 1},
	} {
		action := "clear"
		if item.password != "" {
			action = "set"
		}
		id, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: item.name, Kind: "connection", Protocol: "smb", Host: "server/share", ParentID: item.parent, CredentialMode: item.mode, CredentialID: item.credentialID, Username: item.username, InlinePasswordAction: action, InlinePassword: item.password})
		require.NoError(t, err)
		result, err := showWorkspaceNodeCredentials(databasePath, workspaceNodeRequest{NodeID: id}, filepath.Dir(databasePath))
		require.NoError(t, err)
		require.True(t, result.Found, item.name)
		require.Equal(t, "Password", result.SecretLabel)
		if item.password == "" {
			require.Equal(t, "profile-secret", result.Secret)
			require.Equal(t, "user", result.Username)
			require.Equal(t, "CORP", result.Domain)
			savedID = id
		} else {
			require.Equal(t, item.password, result.Secret)
			require.Equal(t, item.username, result.Username)
			inlineID = id
		}
	}
	database, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	defer database.Close()
	for _, item := range []struct{ name, query, nodeID string }{
		{"wrong credential protocol", "UPDATE CredentialProfiles SET Protocol=0", savedID},
		{"vault-owned secret", "UPDATE CredentialProfiles SET Protocol=8, SecretProvider=1", savedID},
		{"unsupported key kind", "UPDATE CredentialProfiles SET SecretProvider=0, Kind=1", savedID},
		{"unsupported connection protocol", "UPDATE Nodes SET Protocol=99 WHERE UseInlinePassword=1", inlineID},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, err := database.Exec(item.query)
			require.NoError(t, err)
			result, err := showWorkspaceNodeCredentials(databasePath, workspaceNodeRequest{NodeID: item.nodeID}, filepath.Dir(databasePath))
			require.NoError(t, err)
			require.False(t, result.Found)
			require.Empty(t, result.Secret)
		})
	}
}
