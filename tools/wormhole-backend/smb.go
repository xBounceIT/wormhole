package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/pkg/sftp"
)

const smbProtocolValue = int64(8)

type smbAddress struct {
	host, share, directory string
	port                   int
	explicitPort           bool
}

// SMB addresses identify one share. Credentials never belong in an address.
func parseSMBAddress(address string, port int) (smbAddress, error) {
	invalid := errors.New("SMB address must be smb://server/share or \\\\server\\share, without credentials")
	if len(address) > sshMaxHostLength || strings.IndexFunc(address, unicode.IsControl) >= 0 {
		return smbAddress{}, invalid
	}
	address = strings.ReplaceAll(strings.TrimSpace(address), `\`, "/")
	if !strings.Contains(address, "://") {
		// UNC and plain share paths contain literal filename characters; only
		// smb:// URLs percent-decode names or interpret query/fragment syntax.
		authority, tail, found := strings.Cut(strings.TrimPrefix(address, "//"), "/")
		if !found {
			return smbAddress{}, invalid
		}
		address = (&url.URL{Scheme: "smb", Host: authority, Path: "/" + tail}).String()
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "smb" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Hostname(), " /\\@%") {
		return smbAddress{}, invalid
	}
	explicitPort := port != 0 || u.Port() != ""
	if u.Port() != "" {
		addressPort, err := strconv.Atoi(u.Port())
		if err != nil || addressPort < 1 || addressPort > 65535 || (port != 0 && port != addressPort) {
			return smbAddress{}, errors.New("SMB address and port do not match")
		}
		port = addressPort
	}
	if port == 0 {
		port = 445
	}
	if port < 1 || port > 65535 {
		return smbAddress{}, errors.New("SMB port is invalid")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, part := range parts {
		if !safeSMBName(part) {
			return smbAddress{}, invalid
		}
	}
	return smbAddress{host: u.Hostname(), share: parts[0], directory: "/" + strings.Join(parts[1:], "/"), port: port, explicitPort: explicitPort}, nil
}

func safeSMBName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255*4 &&
		!strings.ContainsAny(name, `\/:*?"<>|`) && strings.IndexFunc(name, unicode.IsControl) < 0 &&
		!strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ")
}

// Only share-relative names reach the SMB library, including rename targets.
func smbRelativePath(value string) (string, error) {
	if value == "/" {
		return ".", nil
	}
	if len(value) > sshSftpMaxPathBytes || !strings.HasPrefix(value, "/") {
		return "", os.ErrInvalid
	}
	parts := strings.Split(strings.TrimPrefix(value, "/"), "/")
	for _, part := range parts {
		if !safeSMBName(part) {
			return "", os.ErrInvalid
		}
	}
	return strings.Join(parts, `\`), nil
}

type smbFile interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Readdir(int) ([]os.FileInfo, error)
	Stat() (os.FileInfo, error)
	CloseContext(context.Context) error
}

type smbFilesystem interface {
	OpenFile(string, int, os.FileMode) (smbFile, error)
	Lstat(string) (os.FileInfo, error)
	Mkdir(string, os.FileMode) error
	Remove(string) error
	Rename(string, string) error
	RenameNoReplace(string, string) error
	WithContext(context.Context) smbFilesystem
}

type smbShare struct{ *smb2.Share }

func (share smbShare) WithContext(ctx context.Context) smbFilesystem {
	return smbShare{share.Share.WithContext(ctx)}
}

func (share smbShare) OpenFile(name string, flags int, mode os.FileMode) (smbFile, error) {
	return share.Share.OpenFile(name, flags, mode)
}

type smbTransport struct {
	fs        smbFilesystem
	directory string
	ctx       context.Context
	cancel    context.CancelFunc
	conn      net.Conn
	echo      func(context.Context) error
	once      sync.Once
}

func (transport *smbTransport) close() {
	transport.once.Do(func() {
		transport.cancel()
		if transport.conn != nil {
			// Closing TCP invalidates the session and all tree/file handles without
			// waiting for an unresponsive server to acknowledge logoff.
			_ = transport.conn.Close()
		}
	})
}

func dialNativeSMB(ctx context.Context, target sshTarget, tunnel *tunnelRuntime) (*sshNativeSession, error) {
	address, err := parseSMBAddress(target.host, target.port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, sshConnectTimeout)
	defer cancel()
	endpoint := net.JoinHostPort(address.host, strconv.Itoa(address.port))
	var conn net.Conn
	switch {
	case target.socksEndpoint != "":
		conn, err = dialSocks5(ctx, target.socksEndpoint, "tcp", endpoint)
	case tunnel != nil:
		conn, err = tunnel.dialContext(ctx, "tcp", endpoint)
	default:
		conn, err = (&net.Dialer{Timeout: sshConnectTimeout}).DialContext(ctx, "tcp", endpoint)
	}
	if err != nil {
		return nil, errors.New("could not connect to the SMB server")
	}
	owned := false
	defer func() {
		if !owned {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	fs, echo, err := openSMBShare(ctx, conn, address, target.username, target.password)
	if err != nil {
		return nil, err
	}
	lifetime, release := context.WithCancel(context.Background())
	transport := &smbTransport{fs: fs, directory: address.directory, ctx: lifetime, cancel: release, conn: conn, echo: echo}
	client, err := transport.newClient(ctx)
	if err != nil {
		transport.close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = client.Close()
		transport.close()
		return nil, err
	}
	owned = true
	return &sshNativeSession{smb: transport, sftpOnly: true, sftpClient: client, done: make(chan struct{})}, nil
}

// The native authentication boundary is replaceable in tests; all browser and
// transfer integration tests still exercise the production in-memory bridge.
var openSMBShare = func(ctx context.Context, conn net.Conn, address smbAddress, username, password string) (smbFilesystem, func(context.Context) error, error) {
	user, domain := splitRdpDomainUsername(username)
	dialer := smb2.Dialer{Negotiator: smb2.Negotiator{RequireMessageSigning: true}, Initiator: &smb2.NTLMInitiator{User: user, Domain: domain, Password: password}}
	session, err := dialer.DialConn(ctx, conn, address.host)
	if err != nil {
		return nil, nil, errors.New("SMB authentication or negotiation failed; check username and password")
	}
	share, err := session.WithContext(ctx).Mount(address.share)
	if err != nil {
		return nil, nil, errors.New("could not open the SMB share; check its name and permissions")
	}
	return smbShare{share}, func(ctx context.Context) error { return session.WithContext(ctx).Echo() }, nil
}

func (transport *smbTransport) checkAlive() error {
	ctx, cancel := context.WithTimeout(transport.ctx, 10*time.Second)
	defer cancel()
	return transport.echo(ctx)
}

// Adapt SMB file operations to the existing file-browser engine in memory. No
// SSH connection, listener, mount, external process or credentials file is used.
func (transport *smbTransport) newClient(ctx context.Context) (*sftp.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(transport.ctx)
	clientPipe, serverPipe := net.Pipe()
	stop := context.AfterFunc(lifetime, func() { _ = serverPipe.Close() })
	handler := &smbFileHandler{fs: transport.fs.WithContext(lifetime), ctx: lifetime, directory: transport.directory, closeTransport: transport.close}
	server := sftp.NewRequestServer(serverPipe, sftp.Handlers{FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler})
	go func() { defer cancel(); defer stop(); defer server.Close(); _ = server.Serve() }()
	stopOpening := context.AfterFunc(ctx, func() { cancel(); _ = clientPipe.Close() })
	client, err := sftp.NewClientPipe(clientPipe, &smbClientPipe{Conn: clientPipe, cancel: cancel})
	stopOpening()
	if err != nil {
		cancel()
		_ = clientPipe.Close()
	}
	return client, err
}

type smbClientPipe struct {
	net.Conn
	cancel context.CancelFunc
}

func (pipe *smbClientPipe) Close() error { pipe.cancel(); return pipe.Conn.Close() }

type smbFileHandler struct {
	fs             smbFilesystem
	directory      string
	ctx            context.Context
	closeTransport func()
}

// Short requests must not outlive the browser's listing timeout. Streaming
// file handles retain the bridge lifetime and are interrupted by its owner.
func (handler *smbFileHandler) forRequest(request *sftp.Request) (*smbFileHandler, func()) {
	parent := handler.ctx
	if parent == nil {
		parent = request.Context()
	}
	ctx, cancel := context.WithTimeout(parent, sshSftpListTimeout)
	stop := context.AfterFunc(request.Context(), cancel)
	if request.Context().Err() != nil {
		cancel()
	}
	stopRetirement := func() bool { return true }
	if handler.closeTransport != nil {
		stopRetirement = context.AfterFunc(ctx, handler.closeTransport)
	}
	copy := *handler
	copy.ctx = ctx
	copy.fs = handler.fs.WithContext(ctx)
	return &copy, func() {
		stop()
		if request.Context().Err() != nil {
			cancel()
		}
		stopRetirement()
		if ctx.Err() != nil && handler.closeTransport != nil {
			handler.closeTransport()
		}
		cancel()
	}
}

func (handler *smbFileHandler) retireUncertainOpen(err error) {
	// A cancelled CREATE may have allocated a handle before its reply arrived.
	// Without that handle ID, closing the connection is the only reliable cleanup.
	if handler.closeTransport != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		handler.closeTransport()
	}
}

type smbCleanupFile struct {
	smbFile
	onFailure func()
}

func (file *smbCleanupFile) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := file.CloseContext(ctx)
	if err != nil && file.onFailure != nil {
		file.onFailure()
	}
	return err
}

func (handler *smbFileHandler) RealPath(value string) (string, error) {
	if value == "." || value == "" {
		value = handler.directory
	}
	if _, err := smbRelativePath(value); err != nil {
		return "", err
	}
	return value, nil
}

// Reject reparse points in ancestors; a remote link must never change the
// selected share or cause another connection outside the acquired VPN route.
func (handler *smbFileHandler) checkedPath(value string, includeLeaf bool) (string, error) {
	name, err := smbRelativePath(value)
	if err != nil {
		return "", err
	}
	parts := strings.Split(name, `\`)
	if !includeLeaf {
		parts = parts[:len(parts)-1]
	}
	for index := range parts {
		info, err := handler.fs.Lstat(strings.Join(parts[:index+1], `\`))
		if os.IsNotExist(err) && includeLeaf && index == len(parts)-1 {
			break
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return "", errors.New("SMB symbolic links and reparse points are not supported")
		}
	}
	return name, nil
}

func (handler *smbFileHandler) open(request *sftp.Request, flags int) (smbFile, error) {
	name, err := handler.checkedPath(request.Filepath, true)
	if err != nil || name == "." && flags != os.O_RDONLY {
		if err == nil {
			err = os.ErrPermission
		}
		handler.retireUncertainOpen(err)
		return nil, err
	}
	file, err := handler.fs.OpenFile(name, flags, 0o600)
	if err != nil {
		handler.retireUncertainOpen(err)
		return nil, err
	}
	return &smbCleanupFile{smbFile: file, onFailure: handler.closeTransport}, nil
}

func (handler *smbFileHandler) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	return handler.open(request, os.O_RDONLY)
}

func (handler *smbFileHandler) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	flags := request.Pflags()
	value := os.O_WRONLY
	if flags.Read {
		value = os.O_RDWR
	}
	if flags.Creat {
		value |= os.O_CREATE
	}
	if flags.Trunc {
		value |= os.O_TRUNC
	}
	if flags.Excl {
		value |= os.O_EXCL
	}
	return handler.open(request, value)
}

func (handler *smbFileHandler) OpenFile(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	file, err := handler.Filewrite(request)
	if err != nil {
		return nil, err
	}
	return file.(smbFile), nil
}

func (handler *smbFileHandler) Filecmd(request *sftp.Request) error {
	handler, release := handler.forRequest(request)
	defer release()
	name, err := handler.checkedPath(request.Filepath, request.Method == "Setstat")
	if err != nil {
		return err
	}
	if name == "." {
		return os.ErrPermission
	}
	switch request.Method {
	case "Mkdir":
		return handler.fs.Mkdir(name, 0o755)
	case "Remove", "Rmdir":
		return handler.fs.Remove(name)
	case "Rename":
		destination, err := handler.checkedPath(request.Target, false)
		if err != nil {
			return err
		}
		if destination == "." {
			return os.ErrPermission
		}
		return handler.fs.RenameNoReplace(name, destination)
	case "Setstat":
		// The shared transfer engine applies POSIX permissions to staged files.
		// SMB access is controlled by server ACLs; retain those inherited ACLs.
		if request.AttrFlags().Permissions && !request.AttrFlags().Size && !request.AttrFlags().UidGid && !request.AttrFlags().Acmodtime {
			return nil
		}
	}
	return sftp.ErrSSHFxOpUnsupported
}

func (handler *smbFileHandler) PosixRename(request *sftp.Request) error {
	handler, release := handler.forRequest(request)
	defer release()
	source, err := handler.checkedPath(request.Filepath, false)
	if err != nil {
		return err
	}
	destination, err := handler.checkedPath(request.Target, false)
	if err != nil {
		return err
	}
	if source == "." || destination == "." {
		return os.ErrPermission
	}
	return handler.fs.Rename(source, destination)
}

func (handler *smbFileHandler) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	handler, release := handler.forRequest(request)
	defer release()
	if request.Method == "Stat" {
		return handler.Lstat(request)
	}
	if request.Method != "List" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	file, err := handler.open(request, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.Readdir(sshSftpMaxEntryCount + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return smbFileList(entries), nil
}

func (handler *smbFileHandler) Lstat(request *sftp.Request) (sftp.ListerAt, error) {
	handler, release := handler.forRequest(request)
	defer release()
	name, err := handler.checkedPath(request.Filepath, false)
	if err != nil {
		return nil, err
	}
	info, err := handler.fs.Lstat(name)
	if err != nil {
		return nil, err
	}
	return smbFileList{info}, nil
}

type smbFileList []os.FileInfo

func (files smbFileList) ListAt(destination []os.FileInfo, offset int64) (int, error) {
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if offset >= int64(len(files)) {
		return 0, io.EOF
	}
	n := copy(destination, files[offset:])
	if int(offset)+n == len(files) {
		return n, io.EOF
	}
	return n, nil
}
