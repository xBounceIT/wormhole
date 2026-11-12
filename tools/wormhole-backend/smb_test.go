package main

import (
	"context"
	"database/sql"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestSMBAddress(t *testing.T) {
	for _, item := range []struct {
		input, host, share, directory string
		port                          int
	}{
		{`\\server\share`, "server", "share", "/", 445},
		{"server/share", "server", "share", "/", 445},
		{"smb://server/share/sub%20folder/", "server", "share", "/sub folder", 445},
		{"smb://[::1]:1445/share", "::1", "share", "/", 1445},
	} {
		t.Run(item.input, func(t *testing.T) {
			address, err := parseSMBAddress(item.input, 0)
			require.NoError(t, err)
			require.Equal(t, item.host, address.host)
			require.Equal(t, item.share, address.share)
			require.Equal(t, item.directory, address.directory)
			require.Equal(t, item.port, address.port)
		})
	}
	for _, input := range []string{"", "server", "smb://server", "smb://server/", "https://server/share", "smb://user:password@server/share", "smb://server/share?token=x", "smb://server/share#secret", "smb://server/share?", "smb://server/share/../other", "smb://server/share/%2e%2e", "smb://server/share/file:stream", "smb://server/share/a%5cb", "smb://server/share/a%00b", "smb://server/share/a.", "smb://server/share/a%20", "smb://server/share/a//b", "smb://server:abc/share", "smb://server:65536/share", "smb://server:0/share", "smb://server/sh%xx", "smb://bad%20host/share", "smb://server/share\n", strings.Repeat("a", 4097)} {
		_, err := parseSMBAddress(input, 0)
		require.Error(t, err, input)
	}
	_, err := parseSMBAddress("smb://server:1445/share", 445)
	require.Error(t, err)
	_, err = parseSMBAddress("server/share", -1)
	require.Error(t, err)
	for _, input := range []string{"relative", "/../file", "/a/b:c", "/a\\b", "/a//b", "/a/", "/a/.", "/a/*", "/a/?", "/a/\x00", "/" + strings.Repeat("a", sshSftpMaxPathBytes)} {
		_, err := smbRelativePath(input)
		require.Error(t, err, input)
	}
	name, err := smbRelativePath("/a/b")
	require.NoError(t, err)
	require.Equal(t, `a\b`, name)
}

type smbTestFS struct {
	root    string
	ctx     context.Context
	failure string
	link    string
}

func (fs smbTestFS) WithContext(ctx context.Context) smbFilesystem { fs.ctx = ctx; return fs }
func (fs smbTestFS) local(name string) string {
	return filepath.Join(fs.root, strings.ReplaceAll(name, `\`, "/"))
}
func (fs smbTestFS) check(method string) error {
	if fs.ctx != nil && fs.ctx.Err() != nil {
		return fs.ctx.Err()
	}
	if fs.failure == method {
		return os.ErrPermission
	}
	return nil
}
func (fs smbTestFS) OpenFile(name string, flags int, mode os.FileMode) (smbFile, error) {
	if err := fs.check("open"); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fs.local(name), flags, mode)
	if err != nil {
		return nil, err
	}
	return &smbTestFile{File: file}, nil
}

type smbTestFile struct{ *os.File }

func (file *smbTestFile) CloseContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return file.File.Close()
}

type smbLinkInfo struct{ os.FileInfo }

func (info smbLinkInfo) Mode() os.FileMode { return os.ModeSymlink | 0o777 }
func (fs smbTestFS) Lstat(name string) (os.FileInfo, error) {
	if err := fs.check("stat"); err != nil {
		return nil, err
	}
	info, err := os.Lstat(fs.local(name))
	if err == nil && name == fs.link {
		return smbLinkInfo{info}, nil
	}
	return info, err
}
func (fs smbTestFS) Mkdir(name string, mode os.FileMode) error { return os.Mkdir(fs.local(name), mode) }
func (fs smbTestFS) Remove(name string) error                  { return os.Remove(fs.local(name)) }
func (fs smbTestFS) Rename(source, destination string) error {
	return os.Rename(fs.local(source), fs.local(destination))
}

func (fs smbTestFS) RenameNoReplace(source, destination string) error {
	// An exclusive hard-link creation models the server's atomic collision
	// check for files. The native request flags are pinned separately.
	if err := os.Link(fs.local(source), fs.local(destination)); err != nil {
		return err
	}
	return os.Remove(fs.local(source))
}

func smbTestTransport(t *testing.T, fs smbTestFS) *smbTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	transport := &smbTransport{fs: fs, ctx: ctx, cancel: cancel, directory: "/", echo: func(ctx context.Context) error { return ctx.Err() }}
	t.Cleanup(transport.close)
	return transport
}

func TestSMBBrowserAndTransfers(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "existing.txt"), []byte("original"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(root, "folder"), 0o700))
	transport := smbTestTransport(t, smbTestFS{root: root})
	native := &sshNativeSession{smb: transport}
	client, err := newSharedSftpClient(context.Background(), native)
	require.NoError(t, err)
	defer client.Close()
	home, err := client.Getwd()
	require.NoError(t, err)
	require.Equal(t, "/", home)
	resolved, entries, truncated, err := readSftpDirectory(client, "")
	require.NoError(t, err)
	require.Equal(t, "/", resolved)
	require.Len(t, entries, 2)
	require.False(t, truncated)
	require.NoError(t, client.Mkdir("/new"))
	file, err := client.OpenFile("/new/data.txt", os.O_CREATE|os.O_EXCL|os.O_RDWR)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte("payload"), 0)
	require.NoError(t, err)
	data := make([]byte, 7)
	_, err = file.ReadAt(data, 0)
	require.NoError(t, err)
	require.Equal(t, "payload", string(data))
	require.NoError(t, file.Close())
	require.Error(t, client.Rename("/new/data.txt", "/existing.txt"), "ordinary rename must preserve existing files")
	data, err = os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
	require.NoError(t, client.Rename("/new/data.txt", "/new/renamed.txt"))
	local := filepath.Join(t.TempDir(), "upload.txt")
	require.NoError(t, os.WriteFile(local, []byte("uploaded"), 0o600))
	require.NoError(t, copyTransferFile(context.Background(), client, "local-to-remote", sshSftpTransferPlan{sourcePath: local, destinationPath: "/uploaded.txt"}, func(int64) {}))
	download := filepath.Join(t.TempDir(), "download.txt")
	require.NoError(t, copyTransferFile(context.Background(), client, "remote-to-local", sshSftpTransferPlan{sourcePath: "/uploaded.txt", destinationPath: download}, func(int64) {}))
	data, err = os.ReadFile(download)
	require.NoError(t, err)
	require.Equal(t, "uploaded", string(data))
	require.NoError(t, commitTransferFile(context.Background(), client, "local-to-remote", "/uploaded.txt", "/existing.txt", true))
	data, err = os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "uploaded", string(data))
	require.NoError(t, client.Remove("/new/renamed.txt"))
	require.NoError(t, client.RemoveDirectory("/new"))
	require.Error(t, client.RemoveDirectory("/"))
	require.Error(t, client.Mkdir("/bad:stream"))
	require.NoError(t, transport.checkAlive())
	transport.close()
	transport.close()
	require.Error(t, transport.checkAlive())
	require.Error(t, client.Wait())
}

func TestSMBHandlerErrorsAndBounds(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "link"), 0o700))
	fs := smbTestFS{root: root, link: "link"}
	handler := smbFileHandler{fs: fs, directory: "/link"}
	_, err := handler.checkedPath("/link/child", true)
	require.Error(t, err)
	_, err = handler.checkedPath("/missing/child", true)
	require.Error(t, err)
	_, err = handler.checkedPath("/../child", true)
	require.Error(t, err)
	_, err = handler.RealPath("relative")
	require.Error(t, err)
	for _, method := range []string{"Readlink", "unknown"} {
		_, err = handler.Filelist(sftp.NewRequest(method, "/link"))
		require.Error(t, err)
		require.Error(t, handler.Filecmd(sftp.NewRequest(method, "/link")))
	}
	require.Error(t, handler.Filecmd(sftp.NewRequest("Setstat", "/link")))
	require.Error(t, handler.Filecmd(sftp.NewRequest("Setstat", "/")))
	require.Error(t, handler.Filecmd(sftp.NewRequest("Setstat", "/bad:stream")))
	for _, method := range []string{"Remove", "Rmdir", "Rename", "Mkdir"} {
		require.Error(t, handler.Filecmd(sftp.NewRequest(method, "/")))
	}
	for _, failure := range []string{"stat", "open"} {
		transport := smbTestTransport(t, smbTestFS{root: root, failure: failure})
		client, err := transport.newClient(context.Background())
		require.NoError(t, err)
		_, err = client.ReadDir("/")
		require.Error(t, err)
		_, err = client.Stat("/missing")
		require.Error(t, err)
		_, err = client.Open("/missing")
		require.Error(t, err)
		_, err = client.OpenFile("/missing", os.O_RDWR)
		require.Error(t, err)
		_ = client.Close()
	}
	for _, paths := range [][2]string{{"/bad:stream", "/ok"}, {"/ok", "/bad:stream"}, {"/", "/ok"}, {"/ok", "/"}} {
		r := sftp.NewRequest("Rename", paths[0])
		r.Target = paths[1]
		require.Error(t, handler.PosixRename(r))
		require.Error(t, handler.Filecmd(r))
	}
	list := smbFileList{}
	_, err = list.ListAt(nil, -1)
	require.Error(t, err)
	_, err = list.ListAt(nil, 0)
	require.ErrorIs(t, err, io.EOF)
	info, err := os.Stat(root)
	require.NoError(t, err)
	list = smbFileList{info, info}
	n, err := list.ListAt(make([]os.FileInfo, 1), 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = list.ListAt(make([]os.FileInfo, 2), 1)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 1, n)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = smbTestTransport(t, fs).newClient(ctx)
	require.ErrorIs(t, err, context.Canceled)
	// Directory replies are bounded even when the share contains more entries.
	for i := 0; i < sshSftpMaxEntryCount+5; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(root, strconv.Itoa(i)), nil, 0o600))
	}
	transport := smbTestTransport(t, smbTestFS{root: root})
	client, err := transport.newClient(context.Background())
	require.NoError(t, err)
	defer client.Close()
	_, entries, truncated, err := readSftpDirectory(client, "/")
	require.NoError(t, err)
	require.True(t, truncated)
	require.Len(t, entries, sshSftpMaxEntryCount)
}

func TestSMBDialLifecycleAndFailClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		for {
			select {
			case conn := <-accepted:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	old := openSMBShare
	t.Cleanup(func() { openSMBShare = old })
	root := t.TempDir()
	openSMBShare = func(ctx context.Context, conn net.Conn, address smbAddress, username, password string) (smbFilesystem, func(context.Context) error, error) {
		require.Equal(t, "share", address.share)
		require.Equal(t, `CORP\user`, username)
		require.Equal(t, "test-password", password)
		return smbTestFS{root: root}, func(ctx context.Context) error { return ctx.Err() }, nil
	}
	target := sshTarget{credentialProtocol: smbProtocolValue, host: "smb://127.0.0.1/share", port: port, username: `CORP\user`, password: "test-password"}
	native, _, err := openNativeSSH(context.Background(), "", "", "", &target, "", "", nil, "", "", false, false, "", 80, 24, nil, "smb")
	require.NoError(t, err)
	require.NotNil(t, native.smb)
	require.NoError(t, native.smb.checkAlive())
	native.close(false)
	require.Error(t, native.smb.checkAlive())
	_, _, err = openNativeSSH(context.Background(), "", "", "", &target, "", "", nil, "", "", false, false, "", 80, 24, nil, "terminal")
	require.ErrorContains(t, err, "protocol")
	target.socksEndpoint = "127.0.0.1:1"
	_, err = dialNativeSMB(context.Background(), target, nil)
	require.Error(t, err)
	target.socksEndpoint = ""
	target.host = "smb://server"
	_, err = dialNativeSMB(context.Background(), target, nil)
	require.Error(t, err)
	target.host = "smb://127.0.0.1/share"
	openSMBShare = func(context.Context, net.Conn, smbAddress, string, string) (smbFilesystem, func(context.Context) error, error) {
		return nil, nil, os.ErrPermission
	}
	_, err = dialNativeSMB(context.Background(), target, nil)
	require.ErrorIs(t, err, os.ErrPermission)
	openSMBShare = old
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = dialNativeSMB(ctx, target, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "test-password")
}

func TestSMBWorkspaceCredentialsAndBitwarden(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	credential, err := createCredential(databasePath, credentialCreateRequest{Name: "SMB account", Protocol: "smb", Kind: "password", Username: "user", Domain: "CORP", Password: "test-password", Provider: "Local"})
	require.NoError(t, err)
	require.Equal(t, "smb", credential.Protocol)
	request := workspaceNodeWriteRequest{Name: "Share", Kind: "connection", Protocol: "smb", Host: `\\server\share`, CredentialMode: 2, CredentialID: credential.ID}
	id, err := createWorkspaceNode(databasePath, request)
	require.NoError(t, err)
	target, err := loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, 445, target.port)
	require.Equal(t, `CORP\user`, target.username)
	require.Equal(t, "test-password", target.password)
	_, err = loadSSHTarget(databasePath, id)
	require.Error(t, err, "SMB nodes must not become SSH jump hosts")
	request.ID = id
	request.Host = "smb://other/share/subdir"
	request.Port = 1445
	require.NoError(t, updateWorkspaceNode(databasePath, request))
	workspace, err := loadWorkspace(databasePath)
	require.NoError(t, err)
	require.Equal(t, "smb", workspace.Tree[0].Protocol)
	require.Equal(t, 1445, workspace.Tree[0].Port)
	require.Len(t, workspace.CredentialOptions["smb"], 1)
	databaseForMCP, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	connection, err := resolveMcpConnectionTarget(databaseForMCP, mcpConnectionInfo{ID: id, Protocol: "smb"})
	require.NoError(t, err)
	require.Equal(t, 1445, connection.Port)
	require.Equal(t, request.Host, connection.Host)
	require.NoError(t, databaseForMCP.Close())
	request.Host = "smb://other/share/../secret"
	_, err = createWorkspaceNode(databasePath, request)
	require.Error(t, err)
	request.Host = "smb://other/share"
	request.CredentialMode = 1
	request.CredentialID = ""
	request.Username = `LOCAL\user`
	request.InlinePasswordAction = "set"
	request.InlinePassword = "inline-password"
	require.NoError(t, updateWorkspaceNode(databasePath, request))
	target, err = loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, "inline-password", target.password)
	require.NoError(t, updateWorkspaceNodeInlineCredential(databasePath, workspaceNodeInlineCredentialRequest{NodeID: id, Protocol: "smb", Username: "new-user", Password: "new-password"}))
	_, err = replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{{ID: "vault-item", Name: "Vault", Username: `VAULT\user`}}, time.Now())
	require.NoError(t, err)
	database, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	defer database.Close()
	virtualID := bitwardenVirtualCredentialID("vault-item", smbProtocolValue)
	ref, found, err := resolveBitwardenCredentialReference(database, virtualID, smbProtocolValue)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ref.Virtual)
	require.Equal(t, `VAULT\user`, ref.Username)
	metadata, found, err := credentialMetadataByID(database, virtualID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, smbProtocolValue, metadata.protocol)
	require.Equal(t, smbProtocolValue, bitwardenProtocolValue("smb"))
	require.Equal(t, "smb", protocolName(sql.NullInt64{Int64: smbProtocolValue, Valid: true}))
	_, found, err = resolveBitwardenCredentialReference(database, bitwardenVirtualCredentialID("missing", smbProtocolValue), smbProtocolValue)
	require.NoError(t, err)
	require.False(t, found)
	for _, input := range []credentialCreateRequest{{Name: "Missing", Protocol: "smb", Kind: "password", Provider: "Local"}, {Name: "Key", Protocol: "smb", Kind: "sshKey", Username: "user", Provider: "Local"}} {
		_, err = createCredential(databasePath, input)
		require.Error(t, err)
	}
	_, err = resolveDirectSSHTarget(sshWireCommand{Mode: "smb", Host: "server/share", Username: "user"})
	require.NoError(t, err)
	_, err = resolveDirectSSHTarget(sshWireCommand{Mode: "smb", Host: "server", Username: "user"})
	require.Error(t, err)
}

func TestSMBCredentialProtocolMismatchAndRetry(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "workspace.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	smbCredential, err := createCredential(databasePath, credentialCreateRequest{Name: "Share", Protocol: "smb", Kind: "password", Username: "user", Domain: "CORP", Password: "test-password", Provider: "Local"})
	require.NoError(t, err)
	sshCredential, err := createCredential(databasePath, credentialCreateRequest{Name: "Shell", Protocol: "ssh", Kind: "password", Username: "shell", Password: "ssh-password", Provider: "Local"})
	require.NoError(t, err)
	id, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Share", Kind: "connection", Protocol: "smb", Host: "server/share", CredentialMode: 2, CredentialID: smbCredential.ID})
	require.NoError(t, err)
	// An explicit runtime selection must still enforce SMB's credential protocol.
	_, err = loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, sshCredential.ID, true)
	require.EqualError(t, err, "the selected credential is not an SMB credential")
	// Older/imported nodes can also retain an incompatible saved binding.
	database, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	defer database.Close()
	_, err = database.Exec("UPDATE Nodes SET CredentialId=? WHERE Id=?", sshCredential.ID, id)
	require.NoError(t, err)
	_, err = loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, "", true)
	require.EqualError(t, err, "the selected credential is not an SMB credential")
	// A replacement SMB profile recovers the same node without altering its binding.
	target, err := loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, smbCredential.ID, true)
	require.NoError(t, err)
	require.Equal(t, `CORP\user`, target.username)
	require.Equal(t, "test-password", target.password)
	require.Equal(t, smbProtocolValue, target.credentialProtocol)
	// SSH must continue rejecting SMB profiles instead of accepting their password.
	err = loadSSHCredential(database, databasePath, smbCredential.ID, &sshTarget{}, "", "", false, false)
	require.EqualError(t, err, "the selected credential is not an SSH credential")
}

func TestSMBBackupAndCredentialInheritance(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "source.db")
	require.NoError(t, ensureElectronWorkspaceSchema(databasePath))
	credential, err := createCredential(databasePath, credentialCreateRequest{Name: "SMB", Protocol: "smb", Kind: "password", Username: "user", Domain: "CORP", Password: "test-password", Provider: "Local"})
	require.NoError(t, err)
	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Folder", Kind: "folder", CredentialMode: 2, CredentialID: credential.ID})
	require.NoError(t, err)
	id, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{ParentID: folderID, Name: "Inherited", Kind: "connection", Protocol: "smb", Host: "server/share"})
	require.NoError(t, err)
	target, err := loadFileTargetWithCredentialOverrides(databasePath, id, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, `CORP\user`, target.username)
	_, err = replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{{ID: "vault-item", Name: "Vault", Username: "vault-user"}}, time.Now())
	require.NoError(t, err)
	virtualID := bitwardenVirtualCredentialID("vault-item", smbProtocolValue)
	virtualNodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Vault share", Kind: "connection", Protocol: "smb", Host: "server/vault", CredentialMode: 2, CredentialID: virtualID})
	require.NoError(t, err)
	backupPath := filepath.Join(t.TempDir(), "encrypted.json")
	_, err = exportBackup(databasePath, backupRequest{Path: backupPath, Password: "backup-test-password"})
	require.NoError(t, err)
	destination := filepath.Join(t.TempDir(), "restored.db")
	result, err := importBackup(destination, backupRequest{Path: backupPath, Password: "backup-test-password"})
	require.NoError(t, err)
	require.Empty(t, result.Warnings)
	target, err = loadFileTargetWithCredentialOverrides(destination, id, "", "", false, false, "", true)
	require.NoError(t, err)
	require.Equal(t, "test-password", target.password)
	database, err := openDatabase(destination, false)
	require.NoError(t, err)
	defer database.Close()
	resolved, err := resolveNodeCredentialID(database, virtualNodeID, smbProtocolValue)
	require.NoError(t, err)
	require.Equal(t, virtualID, resolved)
	ref, found, err := resolveBitwardenCredentialReference(database, resolved, smbProtocolValue)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "vault-item", ref.ItemID)
}
