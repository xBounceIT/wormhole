package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// The RDP controller is intentionally a small process supervisor rather than an RDP
// implementation. Windows uses the existing mstscax ActiveX host in a native helper process;
// Linux and macOS use the FreeRDP client installed by the host OS. Keeping the supervisor in Go
// gives Electron one platform-neutral session contract and keeps process/secret handling out of
// the renderer.

const (
	rdpMaxCommandBytes = 256 * 1024
	rdpMaxHostLength   = 253
	rdpDefaultPort     = 3389
)

type rdpBounds struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

func (b rdpBounds) valid() bool {
	return b.Width >= 1 && b.Height >= 1 && b.Width <= 16384 && b.Height <= 16384
}

type rdpProfile struct {
	NodeID               string `json:"nodeId,omitempty"`
	Name                 string `json:"name,omitempty"`
	Host                 string `json:"host"`
	Port                 int    `json:"port,omitempty"`
	Username             string `json:"username,omitempty"`
	Domain               string `json:"domain,omitempty"`
	Password             string `json:"password,omitempty"`
	GatewayHostname      string `json:"gatewayHostname,omitempty"`
	GatewayUsername      string `json:"gatewayUsername,omitempty"`
	GatewayPassword      string `json:"gatewayPassword,omitempty"`
	ScreenSize           string `json:"screenSize,omitempty"`
	FullScreen           bool   `json:"fullScreen,omitempty"`
	ColorDepth           int    `json:"colorDepth,omitempty"`
	UseAllMonitors       bool   `json:"useAllMonitors,omitempty"`
	AudioMode            int    `json:"audioMode,omitempty"`
	AudioCaptureMode     int    `json:"audioCaptureMode,omitempty"`
	KeyboardHookMode     int    `json:"keyboardHookMode,omitempty"`
	RedirectClipboard    bool   `json:"redirectClipboard"`
	RedirectPrinters     bool   `json:"redirectPrinters,omitempty"`
	RedirectSmartCards   bool   `json:"redirectSmartCards,omitempty"`
	RedirectPorts        bool   `json:"redirectPorts,omitempty"`
	RedirectDevices      bool   `json:"redirectDevices,omitempty"`
	RedirectDrives       string `json:"redirectDrives,omitempty"`
	ConnectionSpeed      int    `json:"connectionSpeed,omitempty"`
	DesktopBackground    bool   `json:"desktopBackground,omitempty"`
	FontSmoothing        bool   `json:"fontSmoothing,omitempty"`
	DesktopComposition   bool   `json:"desktopComposition,omitempty"`
	WindowDrag           bool   `json:"windowDrag,omitempty"`
	MenuAnimation        bool   `json:"menuAnimation,omitempty"`
	VisualStyles         bool   `json:"visualStyles,omitempty"`
	BitmapCaching        bool   `json:"bitmapCaching,omitempty"`
	AutoReconnect        bool   `json:"autoReconnect,omitempty"`
	ServerAuthentication *int   `json:"serverAuthentication,omitempty"`
	GatewayUsageMethod   int    `json:"gatewayUsageMethod,omitempty"`
	GatewayBypassLocal   bool   `json:"gatewayBypassLocal,omitempty"`
	GatewayUseSameCreds  bool   `json:"gatewayUseSameCreds,omitempty"`
	UseExternalClient    bool   `json:"useExternalClient,omitempty"`
	SocksEndpoint        string `json:"socksEndpoint,omitempty"`
	TunnelEnabled        *bool  `json:"tunnelEnabled,omitempty"`
}

type rdpCommand struct {
	Op          string     `json:"op"`
	RequestID   string     `json:"requestId,omitempty"`
	SessionID   string     `json:"sessionId"`
	OwnerWindow string     `json:"ownerWindow,omitempty"`
	Bounds      rdpBounds  `json:"bounds,omitempty"`
	Profile     rdpProfile `json:"profile,omitempty"`
	tunnel      *tunnelRuntime
	forwarder   *tunnelForwarder
}

type rdpEvent struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	Backend   string `json:"backend,omitempty"`
	Code      int    `json:"code,omitempty"`
	Attempt   int    `json:"attempt,omitempty"`
	Max       int    `json:"max,omitempty"`
	Message   string `json:"message,omitempty"`
}

type rdpProcess struct {
	sessionID string
	backend   string
	process   *exec.Cmd
	stdin     io.WriteCloser
	stdinMu   sync.Mutex
	stopOnce  sync.Once
	terminal  bool
	tunnel    *tunnelRuntime
	forwarder *tunnelForwarder
}

type rdpController struct {
	databasePath   string
	nativeHostPath string
	freerdpPath    string
	processes      map[string]*rdpProcess
	mu             sync.Mutex
}

func runRdpController(databasePath, nativeHostPath, freerdpPath string) error {
	controller := &rdpController{
		databasePath:   databasePath,
		nativeHostPath: strings.TrimSpace(nativeHostPath),
		freerdpPath:    strings.TrimSpace(freerdpPath),
		processes:      make(map[string]*rdpProcess),
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 32*1024), rdpMaxCommandBytes)
	for scanner.Scan() {
		var command rdpCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			requestID, sessionID := rdpRequestMetadata(scanner.Bytes())
			writeRdpEvent(rdpEvent{Type: "error", RequestID: requestID, SessionID: sessionID, Message: "invalid RDP command"})
			continue
		}
		controller.handle(command)
	}
	controller.closeAll()
	return scanner.Err()
}

func (c *rdpController) handle(command rdpCommand) {
	switch command.Op {
	case "start":
		c.start(command)
	case "resize":
		c.forward(command)
	case "show", "hide", "focus", "disconnect":
		c.forward(command)
	case "shutdown":
		c.closeAll()
		writeRdpEvent(rdpEvent{Type: "ack", RequestID: command.RequestID})
	default:
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: "unsupported RDP command"})
	}
}

func (c *rdpController) start(command rdpCommand) {
	if strings.TrimSpace(command.SessionID) == "" {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, Message: "RDP session ID is required"})
		return
	}
	if strings.TrimSpace(command.Profile.Host) == "" || len([]rune(strings.TrimSpace(command.Profile.Host))) > rdpMaxHostLength {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: "RDP host is invalid"})
		return
	}
	host, port, err := normalizeRdpTarget(command.Profile.Host, command.Profile.Port)
	if err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: err.Error()})
		return
	}
	// Normalize once before dispatch so the ActiveX host receives a clean Server value and the
	// same host:port parsing rules as FreeRDP. This also lets the Electron host field accept the
	// familiar `server:3390` form without needing a second port editor in the first UI slice.
	command.Profile.Host = host
	command.Profile.Port = port
	if command.Bounds.Width == 0 || command.Bounds.Height == 0 {
		// The first surface measurement can arrive after the start request. A one-pixel seed keeps
		// the native host alive until the renderer sends its first real resize.
		command.Bounds = rdpBounds{Width: 1, Height: 1}
	}
	if !command.Bounds.valid() && !(command.Bounds.Width == 1 && command.Bounds.Height == 1) {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: "RDP surface bounds are invalid"})
		return
	}

	c.mu.Lock()
	existing := c.processes[command.SessionID]
	if existing != nil && !existing.terminal {
		c.mu.Unlock()
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: "RDP session is already running"})
		return
	}
	if existing != nil {
		// A native ActiveX host exits after a terminal disconnect/fatal error. Replace the old
		// process immediately so Retry is not lost in the small interval before Wait returns.
		delete(c.processes, command.SessionID)
	}
	c.mu.Unlock()
	if existing != nil {
		stopRdpProcess(existing)
	}
	// Establish only after every validation/duplicate-session return above. From this point the
	// selected launcher owns command.tunnel/forwarder and closes them on every failure path.
	if err := c.routeRdpThroughTunnel(&command, host, port); err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: err.Error()})
		return
	}

	if runtime.GOOS == "windows" {
		c.startNative(command)
		return
	}
	c.startFreeRdp(command)
}

func (c *rdpController) routeRdpThroughTunnel(command *rdpCommand, host string, port int) error {
	if command.Profile.TunnelEnabled != nil && !*command.Profile.TunnelEnabled {
		return nil
	}
	if strings.TrimSpace(command.Profile.NodeID) == "" {
		return nil
	}
	tunnelID, enabled, err := resolveNodeTunnel(c.databasePath, command.Profile.NodeID)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if tunnelID == "" {
		return errors.New("RDP connection enables a VPN tunnel but no tunnel is configured")
	}
	if command.Profile.SocksEndpoint != "" && !isLoopbackSocksEndpoint(command.Profile.SocksEndpoint) {
		return errors.New("RDP VPN proxy endpoint is invalid")
	}
	if command.Profile.UseExternalClient {
		return errors.New("RDP external client cannot be used with a VPN tunnel")
	}
	if command.Profile.GatewayHostname != "" && command.Profile.GatewayUsageMethod != 0 {
		return errors.New("RDP Gateway cannot be used with a VPN tunnel")
	}
	if command.Profile.ServerAuthentication != nil && *command.Profile.ServerAuthentication == 1 {
		return errors.New("strict RDP server authentication cannot be used with a VPN tunnel")
	}
	var runtime *tunnelRuntime
	var forwarder *tunnelForwarder
	if command.Profile.SocksEndpoint != "" {
		forwarder, err = startSocksForwarder(
			command.Profile.SocksEndpoint, net.JoinHostPort(host, strconv.Itoa(port)),
		)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), tunnelStartTimeout)
		defer cancel()
		runtime, err = startTunnelRuntime(ctx, c.databasePath, tunnelID)
		if err == nil {
			forwarder, err = startTunnelForwarder(runtime, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	if err != nil {
		runtime.close()
		return err
	}
	command.tunnel = runtime
	command.forwarder = forwarder
	command.Profile.Host, command.Profile.Port = forwarder.address()
	return nil
}

func resolveNodeTunnel(databasePath, nodeID string) (string, bool, error) {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return "", false, err
	}
	if database == nil {
		return "", false, errors.New("RDP connection was not found")
	}
	defer database.Close()
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return "", false, err
	}
	if _, ok := columns["TunnelEnabled"]; !ok {
		return "", false, nil
	}
	column := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	current := normalizeID(nodeID)
	seen := map[string]struct{}{}
	resolved := false
	enabled := false
	tunnelID := ""
	leaf := true
	for current != "" {
		if _, duplicate := seen[current]; duplicate {
			return "", false, errors.New("RDP connection tree contains a cycle")
		}
		seen[current] = struct{}{}
		var parent, config sql.NullString
		var enabledValue sql.NullInt64
		err := database.QueryRow("SELECT "+column("ParentId")+", "+column("TunnelEnabled")+", "+column("TunnelConfigId")+" FROM Nodes WHERE lower(Id) = lower(?);", current).Scan(&parent, &enabledValue, &config)
		if errors.Is(err, sql.ErrNoRows) {
			if leaf {
				return "", false, errors.New("RDP connection was not found")
			}
			break
		}
		if err != nil {
			return "", false, errors.New("could not resolve RDP VPN tunnel")
		}
		if !resolved && enabledValue.Valid {
			resolved = true
			enabled = enabledValue.Int64 != 0
		}
		if tunnelID == "" && config.Valid {
			tunnelID = normalizeTunnelID(config.String)
		}
		if !parent.Valid {
			break
		}
		current = normalizeID(parent.String)
		leaf = false
	}
	return tunnelID, resolved && enabled, nil
}

// resolveNodeDisplayName walks the node tree from nodeID upward and returns the first non-empty
// Name. It is only used for the "ask whether to use the tunnel" dialog, so any failure falls
// back to a neutral label.
func resolveNodeDisplayName(databasePath, nodeID string) string {
	database, err := openDatabase(databasePath, true)
	if err != nil || database == nil {
		return "the target"
	}
	defer database.Close()
	columns, err := tableColumns(database, "Nodes")
	if err != nil || len(columns) == 0 {
		return "the target"
	}
	column := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	current := normalizeID(nodeID)
	seen := map[string]struct{}{}
	leaf := true
	for current != "" {
		if _, duplicate := seen[current]; duplicate {
			return "the target"
		}
		seen[current] = struct{}{}
		var parent, name sql.NullString
		err := database.QueryRow(
			"SELECT "+column("ParentId")+", "+column("Name")+" FROM Nodes WHERE lower(Id) = lower(?);",
			current,
		).Scan(&parent, &name)
		if errors.Is(err, sql.ErrNoRows) {
			if leaf {
				return "the target"
			}
			break
		}
		if err != nil {
			return "the target"
		}
		if name.Valid && strings.TrimSpace(name.String) != "" {
			return strings.TrimSpace(name.String)
		}
		if !parent.Valid {
			break
		}
		current = normalizeID(parent.String)
		leaf = false
	}
	return "the target"
}

// tunnelConfigName returns the human-readable name of a tunnel configuration, falling back to a
// neutral label when the row cannot be read.
func tunnelConfigName(databasePath, id string) string {
	if id == "" {
		return "the configured VPN tunnel"
	}
	database, err := openDatabase(databasePath, true)
	if err != nil || database == nil {
		return "the configured VPN tunnel"
	}
	defer database.Close()
	var name sql.NullString
	if err := database.QueryRow(
		"SELECT Name FROM TunnelConfigs WHERE lower(Id) = lower(?);",
		id,
	).Scan(&name); err != nil || !name.Valid || strings.TrimSpace(name.String) == "" {
		return "the configured VPN tunnel"
	}
	return strings.TrimSpace(name.String)
}

func (c *rdpController) startNative(command rdpCommand) {
	handoff := false
	defer func() {
		if !handoff {
			command.forwarder.close()
			command.tunnel.close()
		}
	}()
	hostPath := c.nativeHostPath
	if hostPath == "" {
		hostPath = bundledSibling("wormhole-rdp-host-" + architectureName() + executableSuffix())
	}
	if hostPath == "" {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex", Message: "Windows native RDP host is missing"})
		return
	}

	cmd := exec.Command(hostPath)
	process, err := cmd.StdinPipe()
	if err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex", Message: "could not open the Windows native RDP host"})
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = process.Close()
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex", Message: "could not attach to the Windows native RDP host"})
		return
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = process.Close()
		_ = stdout.Close()
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex", Message: "could not start the Windows native RDP host"})
		return
	}

	running := &rdpProcess{sessionID: command.SessionID, backend: "activex", process: cmd, stdin: process, tunnel: command.tunnel, forwarder: command.forwarder}
	c.mu.Lock()
	c.processes[command.SessionID] = running
	c.mu.Unlock()
	handoff = true
	if err := running.write(command); err != nil {
		c.mu.Lock()
		if current, ok := c.processes[command.SessionID]; ok && current == running {
			delete(c.processes, command.SessionID)
		}
		c.mu.Unlock()
		stopRdpProcess(running)
		_ = stdout.Close()
		_ = cmd.Wait()
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex", Message: "could not initialize the Windows native RDP host"})
		return
	}
	writeRdpEvent(rdpEvent{Type: "started", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "activex"})

	go c.readNativeEvents(running, stdout)
	go c.waitForExit(running)
}

func (c *rdpController) readNativeEvents(process *rdpProcess, stdout io.ReadCloser) {
	defer stdout.Close()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 8*1024), 64*1024)
	for scanner.Scan() {
		var event rdpEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		event.SessionID = process.sessionID
		event.Backend = process.backend
		if event.Type == "disconnected" || event.Type == "fatalError" {
			c.markProcessTerminal(process)
		}
		// The helper may include a request id for command acknowledgements, but it must never
		// echo profile or password fields across this boundary.
		writeRdpEvent(event)
	}
}

func (c *rdpController) startFreeRdp(command rdpCommand) {
	handoff := false
	defer func() {
		if !handoff {
			command.forwarder.close()
			command.tunnel.close()
		}
	}()
	client, err := locateFreeRdp(c.freerdpPath)
	if err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "freerdp", Message: err.Error()})
		return
	}
	args, err := buildFreeRdpArguments(command)
	if err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "freerdp", Message: err.Error()})
		return
	}

	cmd := exec.Command(client, args...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "freerdp", Message: "could not start FreeRDP"})
		return
	}
	running := &rdpProcess{sessionID: command.SessionID, backend: "freerdp", process: cmd, tunnel: command.tunnel, forwarder: command.forwarder}
	c.mu.Lock()
	c.processes[command.SessionID] = running
	c.mu.Unlock()
	handoff = true
	writeRdpEvent(rdpEvent{Type: "started", RequestID: command.RequestID, SessionID: command.SessionID, Backend: "freerdp"})
	// FreeRDP's X11/SDL clients do not expose a stable machine-readable connected event across
	// versions. Treat successful process launch as surface readiness; a non-zero exit still turns
	// the session into a failure, while a normal exit becomes a clean disconnect.
	writeRdpEvent(rdpEvent{Type: "connected", SessionID: command.SessionID, Backend: "freerdp"})
	go c.waitForExit(running)
}

func (c *rdpController) waitForExit(process *rdpProcess) {
	err := process.process.Wait()
	c.mu.Lock()
	wasCurrent := false
	if current, ok := c.processes[process.sessionID]; ok && current == process {
		delete(c.processes, process.sessionID)
		wasCurrent = true
	}
	c.mu.Unlock()
	if process.stdin != nil {
		_ = process.stdin.Close()
	}
	process.forwarder.close()
	process.tunnel.close()
	if !wasCurrent {
		// A terminal native event may have been replaced by a fast Retry. Do not emit a stale
		// exited event that could overwrite the new attempt's UI state.
		return
	}
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		} else {
			code = -1
		}
	}
	writeRdpEvent(rdpEvent{Type: "exited", SessionID: process.sessionID, Backend: process.backend, Code: code})
}

func (c *rdpController) forward(command rdpCommand) {
	c.mu.Lock()
	process := c.processes[command.SessionID]
	c.mu.Unlock()
	if process == nil {
		if isRdpNoopWithoutProcess(command.Op) {
			writeRdpEvent(rdpEvent{Type: "ack", RequestID: command.RequestID, SessionID: command.SessionID})
			return
		}
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Message: "RDP session is not running"})
		return
	}
	if process.backend == "freerdp" {
		if command.Op == "disconnect" {
			c.markProcessTerminal(process)
			c.stop(command.SessionID)
		}
		writeRdpEvent(rdpEvent{Type: "ack", RequestID: command.RequestID, SessionID: command.SessionID, Backend: process.backend})
		return
	}
	if command.Op == "disconnect" {
		// Allow an immediate Retry to replace this process while the native helper performs its
		// orderly STA teardown and before waitForExit observes the closed pipe.
		c.markProcessTerminal(process)
	}
	if err := process.write(command); err != nil {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, Backend: process.backend, Message: "native RDP host is not responding"})
		return
	}
	if process.backend == "activex" {
		// The native helper acknowledges after the STA command has completed. Do not synthesize a
		// second acknowledgement here; duplicate request IDs can otherwise race the real helper
		// response across the Go/Electron boundary.
		return
	}
	writeRdpEvent(rdpEvent{Type: "ack", RequestID: command.RequestID, SessionID: command.SessionID, Backend: process.backend})
}

func (c *rdpController) markProcessTerminal(process *rdpProcess) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, ok := c.processes[process.sessionID]; ok && current == process {
		process.terminal = true
	}
}

func (c *rdpController) stop(sessionID string) {
	c.mu.Lock()
	process := c.processes[sessionID]
	c.mu.Unlock()
	if process == nil {
		return
	}
	process.stopOnce.Do(func() {
		stopRdpProcess(process)
	})
}

func stopRdpProcess(process *rdpProcess) {
	if process.stdin != nil {
		_ = process.stdin.Close()
	}
	if process.process != nil && process.process.Process != nil {
		_ = process.process.Process.Kill()
	}
	process.forwarder.close()
	process.tunnel.close()
}

func (c *rdpController) closeAll() {
	c.mu.Lock()
	ids := make([]string, 0, len(c.processes))
	for id := range c.processes {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.stop(id)
	}
}

func (p *rdpProcess) write(command rdpCommand) error {
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()
	if p.stdin == nil {
		return errors.New("RDP host stdin is closed")
	}
	data, err := json.Marshal(command)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = p.stdin.Write(data)
	return err
}

func writeRdpEvent(event rdpEvent) {
	rdpOutputMu.Lock()
	defer rdpOutputMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(event)
}

func rdpRequestMetadata(data []byte) (string, string) {
	var envelope struct {
		RequestID string `json:"requestId"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", ""
	}
	return envelope.RequestID, envelope.SessionID
}

func locateFreeRdp(explicit string) (string, error) {
	if explicit != "" {
		if path, err := exec.LookPath(explicit); err == nil {
			return path, nil
		}
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit, nil
		}
		return "", errors.New("configured FreeRDP client was not found")
	}
	for _, candidate := range freeRdpCandidates() {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", errors.New("FreeRDP is not installed; install xfreerdp (FreeRDP 2 or 3) and try again")
}

func freeRdpCandidates() []string {
	return freeRdpCandidatesForOS(runtime.GOOS)
}

func freeRdpCandidatesForOS(goos string) []string {
	if goos == "darwin" {
		return []string{
			"sdl-freerdp",
			"sdl-freerdp3",
			"xfreerdp",
			"xfreerdp3",
			"/opt/homebrew/bin/sdl-freerdp",
			"/opt/homebrew/bin/sdl-freerdp3",
			"/opt/homebrew/bin/xfreerdp",
			"/opt/homebrew/bin/xfreerdp3",
			"/usr/local/bin/sdl-freerdp",
			"/usr/local/bin/sdl-freerdp3",
			"/usr/local/bin/xfreerdp",
			"/usr/local/bin/xfreerdp3",
		}
	}
	return []string{"xfreerdp", "xfreerdp3"}
}

func isRdpNoopWithoutProcess(operation string) bool {
	return operation == "resize" || operation == "hide" || operation == "disconnect"
}

func buildFreeRdpArguments(command rdpCommand) ([]string, error) {
	profile := command.Profile
	host, port, err := normalizeRdpTarget(profile.Host, profile.Port)
	if err != nil {
		return nil, err
	}
	args := []string{"/v:" + formatRdpTarget(host, port)}
	width, height := freeRdpSize(profile, command.Bounds)
	args = append(args, "/w:"+strconv.Itoa(width), "/h:"+strconv.Itoa(height))
	if profile.ColorDepth == 15 {
		profile.ColorDepth = 16
	}
	if profile.ColorDepth == 16 || profile.ColorDepth == 24 || profile.ColorDepth == 32 {
		args = append(args, "/bpp:"+strconv.Itoa(profile.ColorDepth))
	}
	if profile.Username != "" {
		args = append(args, "/u:"+profile.Username)
	}
	if profile.Domain != "" {
		args = append(args, "/d:"+profile.Domain)
	}
	if profile.Password != "" {
		// FreeRDP masks /p values in its own process display. Keeping the value in the
		// argv passed directly to the client also avoids writing it to a temporary file.
		args = append(args, "/p:"+profile.Password)
	}
	if profile.GatewayHostname != "" && profile.GatewayUsageMethod != 0 {
		args = append(args, "/g:"+profile.GatewayHostname)
		if profile.GatewayUsername != "" {
			args = append(args, "/gu:"+profile.GatewayUsername)
		}
		if profile.GatewayPassword != "" {
			args = append(args, "/gp:"+profile.GatewayPassword)
		}
	}
	if profile.UseAllMonitors {
		args = append(args, "/multimon")
	}
	if !profile.FullScreen && isDynamicRdpScreenSize(profile.ScreenSize) {
		// Let the X11/SDL client renegotiate the remote desktop when its parent/window size
		// changes. The initial /w and /h still make the first frame match the measured surface.
		args = append(args, "+dynamic-resolution")
	}
	if profile.AutoReconnect {
		args = append(args, "+auto-reconnect")
	}
	args = appendToggle(args, "clipboard", profile.RedirectClipboard)
	args = appendToggle(args, "wallpaper", profile.DesktopBackground)
	args = appendToggle(args, "fonts", profile.FontSmoothing)
	args = appendToggle(args, "aero", profile.DesktopComposition)
	args = appendToggle(args, "window-drag", profile.WindowDrag)
	args = appendToggle(args, "menu-anims", profile.MenuAnimation)
	args = appendToggle(args, "themes", profile.VisualStyles)
	if profile.RedirectDrives != "" {
		if strings.EqualFold(strings.TrimSpace(profile.RedirectDrives), "all") {
			args = append(args, "/drives")
		}
	}
	usesParentWindow := freeRdpUsesParentWindow(runtime.GOOS, command.OwnerWindow)
	if usesParentWindow {
		args = append(args, "/parent-window:"+command.OwnerWindow)
	}
	if profile.FullScreen && !usesParentWindow {
		args = append(args, "/f")
	}
	serverAuthentication := 2
	if profile.ServerAuthentication != nil {
		serverAuthentication = *profile.ServerAuthentication
	}
	if serverAuthentication == 0 {
		// /cert-ignore is supported by both the FreeRDP 2 and 3 command-line clients.
		args = append(args, "/cert-ignore")
	}
	return args, nil
}

func freeRdpUsesParentWindow(goos, ownerWindow string) bool {
	return goos == "linux" && ownerWindow != ""
}

func appendToggle(args []string, name string, enabled bool) []string {
	prefix := "-"
	if enabled {
		prefix = "+"
	}
	return append(args, prefix+name)
}

func freeRdpSize(profile rdpProfile, bounds rdpBounds) (int, int) {
	if !profile.FullScreen && isDynamicRdpScreenSize(profile.ScreenSize) && bounds.Width >= 640 && bounds.Height >= 480 {
		return bounds.Width, bounds.Height
	}
	if size := strings.TrimSpace(profile.ScreenSize); size != "" {
		parts := strings.FieldsFunc(size, func(r rune) bool { return r == 'x' || r == 'X' })
		if len(parts) == 2 {
			width, widthErr := strconv.Atoi(strings.TrimSpace(parts[0]))
			height, heightErr := strconv.Atoi(strings.TrimSpace(parts[1]))
			if widthErr == nil && heightErr == nil && width >= 640 && height >= 480 {
				return width, height
			}
		}
	}
	return 1280, 800
}

func isDynamicRdpScreenSize(screenSize string) bool {
	switch strings.ToLower(strings.TrimSpace(screenSize)) {
	case "", "full connection content", "full screen", "fittowindow":
		return true
	default:
		return false
	}
}

func normalizeRdpTarget(rawHost string, rawPort int) (string, int, error) {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return "", 0, errors.New("RDP host is empty")
	}
	port := rawPort
	if port == 0 {
		port = rdpDefaultPort
	}
	if port < 1 || port > 65535 {
		return "", 0, errors.New("RDP port is invalid")
	}
	if strings.HasPrefix(host, "[") {
		close := strings.IndexByte(host, ']')
		if close < 0 || close == 1 {
			return "", 0, errors.New("RDP host is invalid")
		}
		remainder := host[close+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") {
				return "", 0, errors.New("RDP host is invalid")
			}
			parsed, err := parseRdpPort(remainder[1:])
			if err != nil {
				return "", 0, err
			}
			if rawPort == 0 {
				port = parsed
			}
		}
		host = host[1:close]
	} else if strings.Count(host, ":") == 1 {
		parts := strings.SplitN(host, ":", 2)
		if parts[0] == "" {
			return "", 0, errors.New("RDP host is invalid")
		}
		parsed, err := parseRdpPort(parts[1])
		if err != nil {
			return "", 0, err
		}
		host = parts[0]
		if rawPort == 0 {
			port = parsed
		}
	} else if strings.Count(host, ":") > 1 && net.ParseIP(host) == nil {
		return "", 0, errors.New("RDP host is invalid")
	}
	if host == "" {
		return "", 0, errors.New("RDP host is invalid")
	}
	return host, port, nil
}

func parseRdpPort(rawPort string) (int, error) {
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("RDP port is invalid")
	}
	return port, nil
}

func formatRdpTarget(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func bundledSibling(name string) string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(executable), name)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	return ""
}

func architectureName() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "x64"
}

func executableSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
