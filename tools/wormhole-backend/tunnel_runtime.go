package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tunnelStartTimeout             = 5 * time.Minute
	tunnelDialTimeout              = 45 * time.Second
	tunnelSidecarStderrLimit       = 4 * 1024
	tunnelSidecarStderrWaitTimeout = 500 * time.Millisecond
)

// tunnelRuntime is a ref-counted lease over a process-local shared VPN sidecar. Every long-lived
// Go backend coalesces concurrent sessions for the same config and closes the sidecar when its
// final lease closes. No route or VPN secret crosses the Go/renderer boundary.
type tunnelRuntime struct {
	entry       *sharedTunnelEntry
	pool        *tunnelRuntimePool
	releaseOnce sync.Once
}

type tunnelProcess struct {
	stdin     io.WriteCloser
	command   *exec.Cmd
	socks     string
	exited    chan struct{}
	closeOnce sync.Once
}

type tunnelConfigSnapshot struct {
	databasePath string
	id           string
	name         string
	updatedAt    string
	kind         int64
	settings     json.RawMessage
	prompt       tunnelPromptHandler
	progress     tunnelProgressHandler
}

type tunnelPrompt struct {
	Title                   string
	Message                 string
	Secret                  bool
	Browser                 bool
	URLs                    []string
	IgnoreCertificateErrors bool
	Completion              string
	RedirectPrefix          string
	ExpectedState           string
	CookieName              string
	RequireHTTPOnly         bool
	Confirmation            bool
	AcceptLabel             string
}

type tunnelPromptHandler func(context.Context, tunnelPrompt) (string, error)

type tunnelProgressHandler func(context.Context, string, string) error

type tunnelPromptContextKey struct{}

func withTunnelPromptHandler(ctx context.Context, handler tunnelPromptHandler) context.Context {
	return context.WithValue(ctx, tunnelPromptContextKey{}, handler)
}

func tunnelPromptHandlerFromContext(ctx context.Context) tunnelPromptHandler {
	handler, _ := ctx.Value(tunnelPromptContextKey{}).(tunnelPromptHandler)
	return handler
}

func requestTunnelPrompt(ctx context.Context, prompt tunnelPrompt) (string, error) {
	handler := tunnelPromptHandlerFromContext(ctx)
	if handler == nil {
		return "", errors.New("this VPN tunnel requires interactive authentication")
	}
	return handler(ctx, prompt)
}

type tunnelProgressContextKey struct{}

func withTunnelProgressHandler(ctx context.Context, handler tunnelProgressHandler) context.Context {
	return context.WithValue(ctx, tunnelProgressContextKey{}, handler)
}

func tunnelProgressHandlerFromContext(ctx context.Context) tunnelProgressHandler {
	handler, _ := ctx.Value(tunnelProgressContextKey{}).(tunnelProgressHandler)
	return handler
}

func reportTunnelProgress(ctx context.Context, phase, detail string) error {
	handler := tunnelProgressHandlerFromContext(ctx)
	if handler == nil {
		return nil
	}
	return handler(ctx, phase, detail)
}

type sharedTunnelEntry struct {
	key              string
	updatedAt        string
	ready            chan struct{}
	settled          chan struct{}
	process          *tunnelProcess
	err              error
	refs             int
	cancel           context.CancelFunc
	establish        context.Context
	progressHandlers []tunnelProgressSubscription
	promptHandlers   []tunnelPromptSubscription
	lastPhase        string
	lastDetail       string
	hasProgress      bool
}

type tunnelProgressSubscription struct {
	id      uint64
	handler tunnelProgressHandler
}

type tunnelPromptSubscription struct {
	id      uint64
	ctx     context.Context
	handler tunnelPromptHandler
}

type tunnelRuntimePool struct {
	mu             sync.Mutex
	entries        map[string]*sharedTunnelEntry
	nextProgressID uint64
	nextPromptID   uint64
	loadSettings   bool
	probe          func(context.Context, *tunnelProcess) error
	start          func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error)
}

var processTunnelPool = func() *tunnelRuntimePool {
	pool := newTunnelRuntimePool(startTunnelProcess)
	pool.loadSettings = true
	pool.probe = probeTunnelProcess
	return pool
}()

func newTunnelRuntimePool(
	start func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error),
) *tunnelRuntimePool {
	return &tunnelRuntimePool{entries: make(map[string]*sharedTunnelEntry), start: start}
}

type tunnelForwarder struct {
	listener  net.Listener
	tunnel    *tunnelRuntime
	socks     string
	target    string
	closed    chan struct{}
	closeOnce sync.Once
}

func startSocksForwarder(socksEndpoint, target string) (*tunnelForwarder, error) {
	if !isLoopbackSocksEndpoint(socksEndpoint) {
		return nil, errors.New("VPN proxy endpoint is invalid")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("could not bind the VPN tunnel forwarder")
	}
	forwarder := &tunnelForwarder{
		listener: listener, socks: socksEndpoint, target: target, closed: make(chan struct{}),
	}
	go forwarder.serve()
	return forwarder, nil
}

func startTunnelForwarder(tunnel *tunnelRuntime, target string) (*tunnelForwarder, error) {
	if tunnel == nil {
		return nil, errors.New("VPN tunnel is not ready")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("could not bind the VPN tunnel forwarder")
	}
	forwarder := &tunnelForwarder{listener: listener, tunnel: tunnel, target: target, closed: make(chan struct{})}
	go forwarder.serve()
	return forwarder, nil
}

func (forwarder *tunnelForwarder) address() (string, int) {
	address := forwarder.listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", address.Port
}

func (forwarder *tunnelForwarder) serve() {
	for {
		client, err := forwarder.listener.Accept()
		if err != nil {
			return
		}
		go forwardTunnelConnection(forwarder, client)
	}
}

func forwardTunnelConnection(forwarder *tunnelForwarder, client net.Conn) {
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
	defer cancel()
	var remote net.Conn
	var err error
	if forwarder.socks != "" {
		remote, err = dialSocks5(ctx, forwarder.socks, "tcp", forwarder.target)
	} else {
		remote, err = forwarder.tunnel.dialContext(ctx, "tcp", forwarder.target)
	}
	if err != nil {
		return
	}
	defer remote.Close()
	bridgeTunnelConnections(client, remote)
}

func bridgeTunnelConnections(client, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, client)
		close(done)
	}()
	_, _ = io.Copy(client, remote)
	// Either half finishing must tear down both sockets. Waiting before closing them can
	// deadlock forever when (for example) the client stops reading but keeps its upload half
	// open, leaving the opposite io.Copy blocked with no peer activity.
	_ = remote.Close()
	_ = client.Close()
	<-done
}

func (forwarder *tunnelForwarder) close() {
	if forwarder == nil {
		return
	}
	forwarder.closeOnce.Do(func() {
		close(forwarder.closed)
		_ = forwarder.listener.Close()
	})
}

func startTunnelRuntime(ctx context.Context, databasePath, id string) (*tunnelRuntime, error) {
	return startTunnelRuntimeScoped(ctx, databasePath, id, "")
}

// startTunnelRuntimeScoped uses the normal shared config key unless scope is non-empty. A scoped
// runtime is still lifecycle-managed by the same pool, but cannot join an already-live tunnel.
// Diagnostics use this to prove that the saved config can establish from scratch.
func startTunnelRuntimeScoped(ctx context.Context, databasePath, id, scope string) (*tunnelRuntime, error) {
	tunnelMutationMu.RLock()
	snapshot, err := loadTunnelSnapshot(databasePath, id)
	if err != nil {
		tunnelMutationMu.RUnlock()
		return nil, err
	}
	if processTunnelPool.loadSettings {
		database, openErr := openDatabase(databasePath, true)
		if openErr == nil && database != nil {
			snapshot.settings, openErr = readTunnelSettings(database, databasePath, snapshot.id)
			_ = database.Close()
		} else if openErr == nil {
			openErr = errors.New("VPN tunnel was not found")
		}
		err = openErr
	}
	tunnelMutationMu.RUnlock()
	if err != nil {
		return nil, err
	}
	absoluteDatabasePath, err := filepath.Abs(databasePath)
	if err != nil {
		absoluteDatabasePath = databasePath
	}
	snapshot.prompt = tunnelPromptHandlerFromContext(ctx)
	snapshot.progress = tunnelProgressHandlerFromContext(ctx)
	key := strings.ToLower(filepath.Clean(absoluteDatabasePath)) + "\x00" + snapshot.id
	if scope != "" {
		key += "\x00dedicated\x00" + scope
	}
	return processTunnelPool.acquire(ctx, key, snapshot)
}

func loadTunnelSnapshot(databasePath, id string) (tunnelConfigSnapshot, error) {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return tunnelConfigSnapshot{}, err
	}
	if database == nil {
		return tunnelConfigSnapshot{}, errors.New("VPN tunnel was not found")
	}
	defer database.Close()
	var snapshot tunnelConfigSnapshot
	snapshot.databasePath = databasePath
	if err := database.QueryRow("SELECT Id, Name, Kind, UpdatedAt FROM TunnelConfigs WHERE lower(Id) = lower(?);", id).
		Scan(&snapshot.id, &snapshot.name, &snapshot.kind, &snapshot.updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tunnelConfigSnapshot{}, errors.New("VPN tunnel was not found")
		}
		return tunnelConfigSnapshot{}, errors.New("could not read VPN tunnel")
	}
	snapshot.id = normalizeTunnelID(snapshot.id)
	return snapshot, nil
}

func (pool *tunnelRuntimePool) acquire(
	ctx context.Context,
	key string,
	snapshot tunnelConfigSnapshot,
) (*tunnelRuntime, error) {
	pool.mu.Lock()
	entry := pool.entries[key]
	var subscriptionID uint64
	var promptSubscriptionID uint64
	var replayPhase, replayDetail string
	reusedReady := false
	joinedEstablishment := false
	if entry != nil && (entry.updatedAt != snapshot.updatedAt || (entry.process != nil && !entry.process.alive())) {
		delete(pool.entries, key)
		entry = nil
	}
	if entry == nil {
		establish, cancel := context.WithTimeout(context.Background(), tunnelStartTimeout)
		entry = &sharedTunnelEntry{
			key: key, updatedAt: snapshot.updatedAt, ready: make(chan struct{}), settled: make(chan struct{}), refs: 1,
			cancel: cancel,
		}
		entry.establish = withTunnelProgressHandler(establish, pool.progress(entry))
		entry.establish = withTunnelPromptHandler(entry.establish, pool.prompt(entry))
		if snapshot.progress != nil {
			subscriptionID = pool.subscribeProgressLocked(entry, snapshot.progress)
		}
		if snapshot.prompt != nil {
			promptSubscriptionID = pool.subscribePromptLocked(entry, ctx, snapshot.prompt)
		}
		snapshot.prompt = pool.prompt(entry)
		pool.entries[key] = entry
		go pool.establish(entry, snapshot)
	} else {
		entry.refs++
		if snapshot.progress != nil {
			if entry.process != nil && entry.err == nil {
				replayPhase = "ready"
			} else {
				subscriptionID = pool.subscribeProgressLocked(entry, snapshot.progress)
				if entry.hasProgress {
					replayPhase, replayDetail = entry.lastPhase, entry.lastDetail
				}
			}
		}
		if snapshot.prompt != nil && entry.process == nil && entry.err == nil {
			promptSubscriptionID = pool.subscribePromptLocked(entry, ctx, snapshot.prompt)
		}
		reusedReady = entry.process != nil && entry.err == nil
		joinedEstablishment = !reusedReady
	}
	pool.mu.Unlock()
	if joinedEstablishment {
		clearBytes(snapshot.settings)
		snapshot.settings = nil
	}
	if reusedReady && pool.probe != nil {
		if err := pool.probe(ctx, entry.process); err != nil {
			pool.evict(entry)
			pool.release(entry)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return pool.acquire(ctx, key, snapshot)
		}
	}
	if reusedReady {
		clearBytes(snapshot.settings)
		snapshot.settings = nil
	}
	if replayPhase != "" && snapshot.progress != nil {
		_ = snapshot.progress(ctx, replayPhase, replayDetail)
	}

	select {
	case <-entry.ready:
		pool.unsubscribeProgress(entry, subscriptionID)
		pool.unsubscribePrompt(entry, promptSubscriptionID)
		if entry.err != nil {
			pool.release(entry)
			return nil, entry.err
		}
		return &tunnelRuntime{entry: entry, pool: pool}, nil
	case <-ctx.Done():
		pool.unsubscribeProgress(entry, subscriptionID)
		pool.unsubscribePrompt(entry, promptSubscriptionID)
		pool.release(entry)
		return nil, ctx.Err()
	}
}

func (pool *tunnelRuntimePool) evict(entry *sharedTunnelEntry) {
	pool.mu.Lock()
	if current := pool.entries[entry.key]; current == entry {
		delete(pool.entries, entry.key)
	}
	pool.mu.Unlock()
}

func probeTunnelProcess(ctx context.Context, process *tunnelProcess) error {
	if process == nil || !process.alive() || !isLoopbackSocksEndpoint(process.socks) {
		return errors.New("VPN tunnel is not healthy")
	}
	probeContext, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(probeContext, "tcp", process.socks)
	if err != nil {
		return err
	}
	_ = connection.Close()
	return nil
}

func (pool *tunnelRuntimePool) subscribeProgressLocked(
	entry *sharedTunnelEntry,
	handler tunnelProgressHandler,
) uint64 {
	pool.nextProgressID++
	id := pool.nextProgressID
	entry.progressHandlers = append(entry.progressHandlers, tunnelProgressSubscription{id: id, handler: handler})
	return id
}

func (pool *tunnelRuntimePool) unsubscribeProgress(entry *sharedTunnelEntry, id uint64) {
	if id == 0 {
		return
	}
	pool.mu.Lock()
	for index, subscription := range entry.progressHandlers {
		if subscription.id == id {
			entry.progressHandlers = append(entry.progressHandlers[:index], entry.progressHandlers[index+1:]...)
			break
		}
	}
	pool.mu.Unlock()
}

func (pool *tunnelRuntimePool) subscribePromptLocked(
	entry *sharedTunnelEntry,
	ctx context.Context,
	handler tunnelPromptHandler,
) uint64 {
	pool.nextPromptID++
	id := pool.nextPromptID
	entry.promptHandlers = append(entry.promptHandlers, tunnelPromptSubscription{id: id, ctx: ctx, handler: handler})
	return id
}

func (pool *tunnelRuntimePool) unsubscribePrompt(entry *sharedTunnelEntry, id uint64) {
	if id == 0 {
		return
	}
	pool.mu.Lock()
	for index, subscription := range entry.promptHandlers {
		if subscription.id == id {
			entry.promptHandlers = append(entry.promptHandlers[:index], entry.promptHandlers[index+1:]...)
			break
		}
	}
	pool.mu.Unlock()
}

func (pool *tunnelRuntimePool) prompt(entry *sharedTunnelEntry) tunnelPromptHandler {
	return func(_ context.Context, prompt tunnelPrompt) (string, error) {
		tried := make(map[uint64]struct{})
		for {
			pool.mu.Lock()
			var selected tunnelPromptSubscription
			for _, subscription := range entry.promptHandlers {
				if _, alreadyTried := tried[subscription.id]; alreadyTried || subscription.ctx.Err() != nil {
					continue
				}
				selected = subscription
				break
			}
			pool.mu.Unlock()
			if selected.handler == nil {
				return "", errors.New("this VPN tunnel requires interactive authentication")
			}

			value, err := selected.handler(selected.ctx, prompt)
			if err == nil {
				return value, nil
			}
			if selected.ctx.Err() == nil {
				return "", err
			}
			// The connection that owned this prompt disappeared while a second connection was
			// joining the same establishment. Retry through another live subscriber without starting
			// a second sidecar.
			tried[selected.id] = struct{}{}
			pool.unsubscribePrompt(entry, selected.id)
		}
	}
}

func (pool *tunnelRuntimePool) progress(entry *sharedTunnelEntry) tunnelProgressHandler {
	return func(ctx context.Context, phase, detail string) error {
		pool.mu.Lock()
		entry.lastPhase, entry.lastDetail, entry.hasProgress = phase, detail, true
		handlers := append([]tunnelProgressSubscription(nil), entry.progressHandlers...)
		pool.mu.Unlock()
		for _, subscription := range handlers {
			if err := subscription.handler(ctx, phase, detail); err != nil {
				pool.unsubscribeProgress(entry, subscription.id)
			}
		}
		// A broken progress consumer must never abort the shared VPN establishment for every
		// other waiter. Failed subscriptions are detached above, matching the .NET fan-out.
		return nil
	}
}

func (pool *tunnelRuntimePool) establish(entry *sharedTunnelEntry, snapshot tunnelConfigSnapshot) {
	process, err := pool.start(entry.establish, snapshot)
	if err == nil {
		_ = pool.progress(entry)(entry.establish, "ready", "")
	}
	pool.mu.Lock()
	entry.cancel()
	entry.process = process
	entry.err = err
	entry.progressHandlers = nil
	entry.promptHandlers = nil
	if err != nil {
		if current := pool.entries[entry.key]; current == entry {
			delete(pool.entries, entry.key)
		}
	}
	orphaned := entry.refs == 0
	close(entry.ready)
	pool.mu.Unlock()
	if orphaned && process != nil {
		process.close()
	}
	close(entry.settled)
}

func (pool *tunnelRuntimePool) release(entry *sharedTunnelEntry) {
	pool.mu.Lock()
	entry.refs--
	if entry.refs > 0 {
		pool.mu.Unlock()
		return
	}
	if current := pool.entries[entry.key]; current == entry {
		delete(pool.entries, entry.key)
	}
	process := entry.process
	settled := entry.settled
	if process == nil {
		entry.cancel()
	}
	pool.mu.Unlock()
	if process != nil {
		process.close()
	} else if settled != nil {
		select {
		case <-settled:
		case <-time.After(7 * time.Second):
			// A custom or future starter that ignores cancellation must not deadlock shutdown.
		}
	}
}

func startTunnelProcess(ctx context.Context, snapshot tunnelConfigSnapshot) (*tunnelProcess, error) {
	if err := reportTunnelProgress(ctx, "preparing", ""); err != nil {
		return nil, err
	}
	if snapshot.prompt != nil {
		ctx = withTunnelPromptHandler(ctx, snapshot.prompt)
	}
	if snapshot.settings == nil {
		database, err := openDatabase(snapshot.databasePath, true)
		if err != nil {
			return nil, err
		}
		if database == nil {
			return nil, errors.New("VPN tunnel was not found")
		}
		defer database.Close()
		snapshot.settings, err = readTunnelSettings(database, snapshot.databasePath, snapshot.id)
		if err != nil {
			return nil, err
		}
	}
	defer clearBytes(snapshot.settings)
	if err := reportTunnelProgress(ctx, "authenticating", ""); err != nil {
		return nil, err
	}
	settings, err := prepareTunnelAuthentication(ctx, snapshot.kind, snapshot.settings, snapshot)
	if err != nil {
		return nil, err
	}
	defer clearBytes(settings)
	executable, config, err := tunnelSidecarCommand(snapshot.kind, settings)
	if err != nil {
		return nil, err
	}
	defer clearBytes(config)
	path, err := findTunnelSidecar(executable)
	if err != nil {
		return nil, err
	}

	command := exec.Command(path)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errors.New("could not start VPN tunnel")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("could not start VPN tunnel")
	}
	stderrPipe, err := command.StderrPipe()
	if err != nil {
		return nil, errors.New("could not start VPN tunnel")
	}
	if err := reportTunnelProgress(ctx, "starting", ""); err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, errors.New("could not start VPN tunnel")
	}
	process := &tunnelProcess{stdin: stdin, command: command, exited: make(chan struct{})}
	stderrDone := make(chan struct{})
	diagnostics := &boundedStderrBuilder{limit: tunnelSidecarStderrLimit}
	go func() {
		defer close(stderrDone)
		defer stderrPipe.Close()
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 1024), tunnelSidecarStderrLimit)
		for scanner.Scan() && diagnostics.append(scanner.Text()) {
		}
	}()
	go func() {
		_ = command.Wait()
		close(process.exited)
	}()
	if _, err := stdin.Write(config); err != nil {
		process.close()
		return nil, errors.New("could not configure VPN tunnel")
	}
	if _, err := stdin.Write([]byte("\n")); err != nil {
		process.close()
		return nil, errors.New("could not configure VPN tunnel")
	}

	ready := make(chan string, 1)
	readErr := make(chan error, 1)
	go readTunnelReady(bufio.NewReaderSize(stdout, 1024), ready, readErr)
	select {
	case port := <-ready:
		process.socks = net.JoinHostPort("127.0.0.1", port)
		return process, nil
	case <-ctx.Done():
		process.close()
		return nil, ctx.Err()
	case <-process.exited:
		process.close()
		select {
		case <-stderrDone:
		case <-time.After(tunnelSidecarStderrWaitTimeout):
		}
		return nil, tunnelSidecarStartupFailure(snapshot, settings, executable, diagnostics.text(), process.command.ProcessState.ExitCode())
	case err := <-readErr:
		process.close()
		select {
		case <-process.exited:
			// The sidecar died before reporting readiness. Surface the classified startup
			// failure instead of the raw pipe EOF, which would leak to the UI as "EOF".
			select {
			case <-stderrDone:
			case <-time.After(tunnelSidecarStderrWaitTimeout):
			}
			return nil, tunnelSidecarStartupFailure(snapshot, settings, executable, diagnostics.text(), process.command.ProcessState.ExitCode())
		default:
			return nil, err
		}
	}
}

func tunnelSidecarStartupFailure(
	snapshot tunnelConfigSnapshot,
	settings json.RawMessage,
	executable string,
	stderr string,
	exitCode int,
) error {
	var values map[string]json.RawMessage
	_ = json.Unmarshal(settings, &values)
	defer clearTunnelSettingsMap(values)
	lower := strings.ToLower(stderr)
	authFailure := strings.Contains(lower, "auth_failed") || strings.Contains(lower, "auth failed") ||
		strings.Contains(lower, "authentication failed") || strings.Contains(lower, "authentication rejected") ||
		strings.Contains(lower, "login failed")
	transientTransport := strings.Contains(lower, "connection_timeout") || strings.Contains(lower, "transport_error") ||
		strings.Contains(lower, "network_recv") || strings.Contains(lower, "eof_error") ||
		strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host")

	if snapshot.id != "" {
		switch snapshot.kind {
		case 3:
			if tunnelSettingBool(values, "_WormholeWatchguardTypedOTP") && (authFailure || transientTransport) {
				return errors.New("WatchGuard couldn't complete the connection with the one-time code; AuthPoint may be rate-limiting a recent login or push approval, so wait about 30 seconds and retry with a fresh code (or type 'p' to approve with a push)")
			}
			if tunnelSettingBool(values, "_WormholeWatchguardCacheHit") && !authFailure &&
				!strings.Contains(lower, "dynamic-challenge") && !transientTransport {
				removeProtectedTunnelFileIfCurrent(snapshot, watchguardCachePath(snapshot))
				return errors.New("couldn't start the VPN tunnel: the cached WatchGuard profile was rejected and has been cleared; reconnect to download a fresh profile")
			}
		case 4:
			if tunnelSettingBool(values, "_WormholeStormshieldOptimisticCache") {
				removeProtectedTunnelFileIfCurrent(snapshot, stormshieldCachePath(snapshot))
				return errors.New("couldn't start the VPN tunnel: the unverified Stormshield profile cache has been cleared; reconnect with a fresh one-time code to download the current profile")
			}
			if tunnelSettingNumber(values, "Mode") == 0 && tunnelSettingBool(values, "UseOtp") {
				base := tunnelSidecarFailureMessage(executable, stderr, exitCode)
				return fmt.Errorf("%s; the Stormshield one-time code may have been used or expired during this attempt, so retry with a new code", base)
			}
		case 5:
			if authFailure {
				removeProtectedTunnelFileIfCurrent(snapshot, azureRefreshPath(snapshot))
				return errors.New("couldn't start the VPN tunnel: Azure rejected the Microsoft access token; cached sign-in was cleared, so reconnect to authenticate again")
			}
		}
	}
	return tunnelSidecarFailureMessage(executable, stderr, exitCode)
}

type boundedStderrBuilder struct {
	limit   int
	builder strings.Builder
}

func (b *boundedStderrBuilder) append(line string) bool {
	if b.builder.Len() >= b.limit {
		return false
	}
	if b.builder.Len() > 0 {
		b.builder.WriteByte('\n')
	}
	remaining := b.limit - b.builder.Len()
	if len(line) > remaining {
		line = line[:remaining]
	}
	b.builder.WriteString(line)
	return true
}

func (b *boundedStderrBuilder) text() string {
	return b.builder.String()
}

// tunnelSidecarFailureMessage turns sidecar startup stderr into a safe, actionable error for the
// UI. Raw diagnostics are deliberately kept out of the IPC stream: they can carry gateway
// details, and a build that lacks the OpenVPN3 engine already tells us the one thing the user
// needs to fix. Set WORMHOLE_TUNNEL_DEBUG=1 in the Electron environment to opt in to the raw
// first line for one-shot support captures.
func tunnelSidecarFailureMessage(executable, stderr string, exitCode int) error {
	detail := strings.TrimSpace(stderr)
	if debug := strings.TrimSpace(os.Getenv("WORMHOLE_TUNNEL_DEBUG")); debug != "" && debug != "0" {
		if detail != "" {
			return fmt.Errorf("VPN sidecar %s failed during startup: %s", executable, truncateTunnelDiagnostic(detail))
		}
		return fmt.Errorf("VPN sidecar %s exited during startup (exit code %d)", executable, exitCode)
	}

	lower := strings.ToLower(detail)
	var message string
	switch {
	case strings.Contains(lower, "binding not linked"):
		message = "this build is missing the OpenVPN engine, so OpenVPN-based tunnels can't start. Rebuild the sidecar with scripts/Fetch-OvpnProxy.ps1 -RequireReal"
	case strings.Contains(lower, "no such host"):
		message = "we couldn't resolve the VPN gateway host — double-check the server address"
	case strings.Contains(lower, "connection refused"):
		message = "the VPN gateway refused the connection — it may be offline or blocking this client"
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out"):
		message = "the VPN gateway didn't respond in time — it may be unreachable or overloaded"
	case strings.Contains(lower, "authentication") || strings.Contains(lower, "login"):
		if strings.Contains(lower, "fail") || strings.Contains(lower, "reject") ||
			strings.Contains(lower, "denied") || strings.Contains(lower, "invalid") {
			message = "the VPN gateway rejected the username, password, or authentication step"
		}
	case strings.Contains(lower, "profile_ovpn is required") ||
		strings.Contains(lower, "profile is missing") || strings.Contains(lower, "is missing"):
		message = "the VPN profile is incomplete or missing — check the profile and its key material"
	}
	if message != "" {
		return fmt.Errorf("couldn't start the VPN tunnel: %s", message)
	}
	return fmt.Errorf("couldn't start the VPN tunnel. Check the gateway settings and try again")
}

func truncateTunnelDiagnostic(value string) string {
	const max = 1024
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

func prepareTunnelAuthentication(
	ctx context.Context,
	kind int64,
	raw json.RawMessage,
	snapshots ...tunnelConfigSnapshot,
) (json.RawMessage, error) {
	if kind == 4 {
		return prepareStormshieldProfile(ctx, raw, snapshots...)
	}
	if kind == 3 {
		return prepareWatchguardProfile(ctx, raw, snapshots...)
	}
	if kind == 5 {
		return prepareAzureVPN(ctx, raw, snapshots...)
	}
	if kind != 2 {
		return raw, nil
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if !tunnelSettingBool(settings, "UseSingleSignOn") {
		return raw, nil
	}
	useExternalBrowser := tunnelSettingBool(settings, "UseExternalBrowser")
	if useExternalBrowser && strings.TrimSpace(tunnelSettingString(settings, "Realm")) != "" {
		return nil, errors.New("external-browser Fortinet single sign-on does not support realms")
	}
	callbackPort := int(tunnelSettingNumber(settings, "SamlRedirectPort"))
	if callbackPort == 0 {
		callbackPort = fortinetSAMLDefaultCallbackPort
	}
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	if !useExternalBrowser {
		base, err := buildWebURL("https", tunnelSettingString(settings, "Host"), port)
		if err != nil {
			return nil, errors.New("Fortinet SAML gateway is invalid")
		}
		start, _ := url.Parse(base)
		start.Path = "/remote/saml/start"
		if realm := strings.TrimSpace(tunnelSettingString(settings, "Realm")); realm != "" {
			start.RawQuery = url.Values{"realm": {realm}}.Encode()
		}
		cookie, err := requestTunnelPrompt(ctx, tunnelPrompt{
			Title: "Fortinet SAML sign-in", Browser: true, URLs: []string{start.String()},
			Completion: "cookie", CookieName: "SVPNCOOKIE", RequireHTTPOnly: true,
			IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate"),
		})
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(cookie) == "" || len(cookie) > 16*1024 {
			return nil, errors.New("Fortinet SAML returned no VPN cookie")
		}
		settings["SvpnCookie"], _ = json.Marshal(cookie)
		return json.Marshal(settings)
	}
	authID, err := authenticateFortinetExternalSAML(ctx, tunnelSettingString(settings, "Host"), port, callbackPort)
	if err != nil {
		return nil, err
	}
	encodedAuthID, err := json.Marshal(authID)
	if err != nil {
		return nil, errors.New("Fortinet SAML response was invalid")
	}
	settings["SamlAuthId"] = encodedAuthID
	return json.Marshal(settings)
}

func readTunnelReady(reader *bufio.Reader, ready chan<- string, failures chan<- error) {
	lineBytes, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			failures <- errors.New("VPN sidecar exited before reporting readiness")
			return
		}
		failures <- errors.New("VPN sidecar readiness check failed")
		return
	}
	line := string(lineBytes)
	parts := strings.Fields(line)
	if len(parts) != 2 || parts[0] != "READY" {
		failures <- errors.New("VPN sidecar returned an invalid readiness response")
		return
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		failures <- errors.New("VPN sidecar returned an invalid readiness response")
		return
	}
	ready <- strconv.Itoa(port)
}

func (runtime *tunnelRuntime) close() {
	if runtime == nil {
		return
	}
	runtime.releaseOnce.Do(func() { runtime.pool.release(runtime.entry) })
}

func (runtime *tunnelRuntime) socksEndpoint() string {
	if runtime == nil || runtime.entry == nil || runtime.entry.process == nil {
		return ""
	}
	return runtime.entry.process.socks
}

func (runtime *tunnelRuntime) exited() <-chan struct{} {
	if runtime == nil || runtime.entry == nil || runtime.entry.process == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return runtime.entry.process.exited
}

func (runtime *tunnelRuntime) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if runtime == nil || runtime.entry == nil || runtime.entry.process == nil || runtime.entry.process.socks == "" {
		return nil, errors.New("VPN tunnel is not ready")
	}
	return dialSocks5(ctx, runtime.entry.process.socks, network, address)
}

func isLoopbackSocksEndpoint(endpoint string) bool {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}

func (process *tunnelProcess) alive() bool {
	if process == nil {
		return false
	}
	select {
	case <-process.exited:
		return false
	default:
		return true
	}
}

func (process *tunnelProcess) close() {
	if process == nil {
		return
	}
	process.closeOnce.Do(func() {
		if process.stdin != nil {
			_ = process.stdin.Close()
		}
		if process.exited == nil {
			return
		}
		select {
		case <-process.exited:
		case <-time.After(3 * time.Second):
			if process.command != nil && process.command.Process != nil {
				_ = process.command.Process.Kill()
			}
			select {
			case <-process.exited:
			case <-time.After(3 * time.Second):
				// A failed OS-level kill must not deadlock application shutdown forever.
			}
		}
	})
}

func tunnelSidecarCommand(kind int64, raw json.RawMessage) (string, []byte, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", nil, errors.New("VPN tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	stringValue := func(key string) string { return tunnelSettingString(settings, key) }
	numberValue := func(key string, fallback int64) int64 {
		value := tunnelSettingNumber(settings, key)
		if value < 1 || value > 65535 {
			return fallback
		}
		return value
	}
	encode := func(value any) ([]byte, error) {
		payload, err := json.Marshal(value)
		if err != nil {
			return nil, errors.New("VPN tunnel settings are invalid")
		}
		return payload, nil
	}

	switch kind {
	case 0:
		payload, err := encode(map[string]any{
			"interface_private_key":  stringValue("InterfacePrivateKey"),
			"interface_address":      stringValue("InterfaceAddress"),
			"mtu":                    optionalJSONNumber(settings, "Mtu"),
			"dns":                    stringListSetting(settings, "Dns"),
			"peer_public_key":        stringValue("PeerPublicKey"),
			"peer_preshared_key":     optionalJSONString(settings, "PeerPresharedKey"),
			"peer_endpoint":          stringValue("PeerEndpoint"),
			"allowed_ips":            stringListSetting(settings, "AllowedIps"),
			"persistent_keepalive_s": optionalJSONNumber(settings, "PersistentKeepaliveSeconds"),
		})
		return "wormhole-wgproxy", payload, err
	case 1:
		payload, err := encode(openVPNConfig(stringValue("ProfileOvpn"), stringValue("Username"), stringValue("Password")))
		return "wormhole-ovpnproxy", payload, err
	case 2:
		useSSO := tunnelSettingBool(settings, "UseSingleSignOn")
		if useSSO && strings.TrimSpace(stringValue("SamlAuthId")) == "" && strings.TrimSpace(stringValue("SvpnCookie")) == "" {
			return "", nil, errors.New("Fortinet single sign-on did not return an authentication token")
		}
		payload, err := encode(map[string]any{
			"host":                     stringValue("Host"),
			"port":                     numberValue("Port", 443),
			"username":                 valueUnless(useSSO, stringValue("Username")),
			"password":                 valueUnless(useSSO, stringValue("Password")),
			"realm":                    valueUnless(useSSO, optionalJSONString(settings, "Realm")),
			"totp_secret":              valueUnless(useSSO, optionalJSONString(settings, "TotpSecret")),
			"saml_auth_id":             optionalJSONString(settings, "SamlAuthId"),
			"svpn_cookie":              optionalJSONString(settings, "SvpnCookie"),
			"trust_server_certificate": tunnelSettingBool(settings, "TrustServerCertificate"),
			"server_cert_sha256_pin":   optionalJSONString(settings, "ServerCertSha256Pin"),
		})
		return "wormhole-fortiproxy", payload, err
	case 3:
		profile := stringValue("ProfileOvpn")
		if strings.TrimSpace(profile) == "" {
			return "", nil, errors.New("WatchGuard did not return an OpenVPN profile")
		}
		config := openVPNConfig(profile, stringValue("Username"), stringValue("Password"))
		if challenge := strings.TrimSpace(stringValue("ChallengeResponse")); challenge != "" {
			config["challenge_response"] = challenge
		}
		payload, err := encode(config)
		return "wormhole-ovpnproxy", payload, err
	case 4:
		profile := stringValue("ProfileOvpn")
		if strings.TrimSpace(profile) == "" {
			return "", nil, errors.New("Stormshield OpenVPN profile is missing")
		}
		adapters, err := physicalTransportAdapterIDs()
		if err != nil {
			return "", nil, err
		}
		config := openVPNConfig(profile, stringValue("Username"), stringValue("Password"))
		if len(adapters) > 0 {
			remotes := extractOpenVPNTransportRemotes(profile)
			if len(remotes) == 0 {
				return "", nil, errors.New("Stormshield OpenVPN profile contains no transport remote")
			}
			config["transport_adapter_ids"] = adapters
			config["transport_remotes"] = remotes
		}
		payload, err := encode(config)
		return "wormhole-ovpnproxy", payload, err
	case 5:
		profile := stringValue("ProfileOvpn")
		if strings.TrimSpace(profile) == "" || strings.TrimSpace(stringValue("Password")) == "" {
			return "", nil, errors.New("Azure VPN authentication is incomplete")
		}
		payload, err := encode(openVPNConfig(profile, "AzureAD", stringValue("Password")))
		return "wormhole-ovpnproxy", payload, err
	case 6:
		payload, err := encode(map[string]any{
			"host":                     stringValue("Host"),
			"port":                     numberValue("Port", 443),
			"username":                 stringValue("Username"),
			"password":                 stringValue("Password"),
			"group":                    optionalJSONString(settings, "Group"),
			"secondary_password":       optionalJSONString(settings, "SecondaryPassword"),
			"totp_secret":              optionalJSONString(settings, "TotpSecret"),
			"trust_server_certificate": tunnelSettingBool(settings, "TrustServerCertificate"),
			"server_cert_sha256_pin":   optionalJSONString(settings, "ServerCertSha256Pin"),
		})
		return "wormhole-ciscoproxy", payload, err
	default:
		return "", nil, errors.New("VPN tunnel type is unsupported")
	}
}

func valueUnless(condition bool, value any) any {
	if condition {
		return nil
	}
	return value
}

func openVPNConfig(profile, username, password string) map[string]any {
	return map[string]any{"profile_ovpn": profile, "username": username, "password": password}
}

func optionalJSONString(settings map[string]json.RawMessage, key string) any {
	if value := strings.TrimSpace(tunnelSettingString(settings, key)); value != "" {
		return value
	}
	return nil
}

func optionalJSONNumber(settings map[string]json.RawMessage, key string) any {
	if value := tunnelSettingNumber(settings, key); value > 0 {
		return value
	}
	return nil
}

func stringListSetting(settings map[string]json.RawMessage, key string) []string {
	var values []string
	if err := json.Unmarshal(settings[key], &values); err == nil {
		return values
	}
	value := strings.TrimSpace(tunnelSettingString(settings, key))
	if value == "" {
		return []string{}
	}
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == '\n' })
}

func findTunnelSidecar(name string) (string, error) {
	providerName := strings.TrimPrefix(name, "wormhole-")
	override := strings.TrimSpace(os.Getenv("WORMHOLE_" + strings.ToUpper(strings.ReplaceAll(providerName, "-", "_")) + "_PATH"))
	if override != "" {
		if info, err := os.Stat(override); err == nil && !info.IsDir() {
			return override, nil
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return "", errors.New("VPN sidecar is unavailable")
	}
	file := name
	if filepath.Ext(executable) == ".exe" {
		file += ".exe"
	}
	path := filepath.Join(filepath.Dir(executable), file)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path, nil
	}
	return "", fmt.Errorf("VPN sidecar %s is unavailable", file)
}

func dialSocks5(ctx context.Context, proxyAddress, network, targetAddress string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("VPN tunnel only supports TCP connections")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(tunnelStartTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(cancellationDone)
	})
	var stopCancellationOnce sync.Once
	stopCancellationAndWait := func() {
		stopCancellationOnce.Do(func() {
			if !stopCancellation() {
				<-cancellationDone
			}
		})
	}
	defer stopCancellationAndWait()
	fail := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 5 || response[1] != 0 {
		return fail(errors.New("VPN SOCKS5 authentication failed"))
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fail(err)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fail(errors.New("VPN target host is invalid"))
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	if _, err := connection.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[1] != 0 {
		return fail(errors.New("VPN SOCKS5 connection failed"))
	}
	remaining := 0
	switch header[3] {
	case 1:
		remaining = 4
	case 4:
		remaining = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return fail(err)
		}
		remaining = int(length[0])
		if remaining == 0 {
			return fail(errors.New("VPN SOCKS5 response is invalid"))
		}
	default:
		return fail(errors.New("VPN SOCKS5 response is invalid"))
	}
	if _, err := io.ReadFull(connection, make([]byte, remaining+2)); err != nil {
		return fail(err)
	}
	stopCancellationAndWait()
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}
