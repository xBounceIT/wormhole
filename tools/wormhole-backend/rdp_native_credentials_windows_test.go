//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Opt-in integration: no RDP server/account is needed. A native ActiveX control
// exports a local COM reference, Go sets synthetic write-only credentials, then
// a loopback listener observes the initial RDP negotiation and closes the socket.
func TestNativeRdpCOMCredentialBridge(t *testing.T) {
	for _, mode := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) { testNativeRdpCOMFixture(t, mode) })
	}
}

func testNativeRdpCOMFixture(t *testing.T, mode int) {
	path := os.Getenv("WORMHOLE_TEST_RDP_HOST")
	if path == "" {
		t.Skip("set WORMHOLE_TEST_RDP_HOST for native ActiveX bridge verification")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("native helper path must be absolute")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	user := windows.NewLazySystemDLL("user32.dll")
	class, _ := windows.UTF16PtrFromString("STATIC")
	hwnd, _, err := user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), 0, 0x80000000, 0, 0, 1, 1, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatal("hidden owner unavailable", err)
	}
	defer user.NewProc("DestroyWindow").Call(hwnd)
	type windowMessage struct {
		Window         uintptr
		Message        uint32
		WParam, LParam uintptr
		Time           uint32
		X, Y           int32
		Private        uint32
	}
	pump := func() {
		for i := 0; i < 32; i++ {
			var message windowMessage
			n, _, _ := user.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0, 1)
			if n == 0 {
				return
			}
			_, _, _ = user.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
			_, _, _ = user.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
		}
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	traffic := make(chan error, 1)
	closedTraffic := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			traffic <- e
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 4)
		_, e = io.ReadFull(conn, b)
		if e == nil && (b[0] != 3 || b[1] != 0) {
			e = fmt.Errorf("invalid RDP negotiation")
		}
		traffic <- e
		if mode >= 2 && e == nil {
			_, e = io.Copy(io.Discard, conn)
			closedTraffic <- e
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if mode >= 2 {
		standalone := mode == 4 || mode == 5 || (mode >= 8 && mode != 10)
		testNativeSealedRDPFixture(t, path, hwnd, pump, tick.C, ctx, listener, traffic, closedTraffic, mode%2 == 1, standalone, mode >= 6, mode >= 10)
		return
	}
	if mode == 1 {
		var applied atomic.Bool
		c := &rdpController{nativeHostPath: path, processes: make(map[string]*rdpProcess), nativeCredentialApply: func(ref, p, g []byte, primary, gateway bool) error {
			if string(p) != "synthetic-supervisor-password" || !primary || gateway {
				t.Error("Go supervisor credential context")
			}
			err := applyNativeRdpCredentials(ref, p, g, primary, gateway)
			if err == nil {
				applied.Store(true)
			}
			return err
		}}
		defer c.closeAll()
		c.startNative(rdpCommand{Op: "start", RequestID: "native-supervisor", SessionID: "native-probe", LifecycleID: "native-attempt", OwnerWindow: strconv.FormatUint(uint64(hwnd), 10), Bounds: rdpBounds{X: -50000, Y: -50000, Width: 1, Height: 1}, Profile: rdpProfile{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Username: "synthetic", Password: "synthetic-supervisor-password"}}, validateNativeRdpCrashPolicy)
		c.mu.Lock()
		process := c.processes["native-probe"]
		c.mu.Unlock()
		if process == nil || process.nativeHandoff == nil {
			t.Fatal("supervisor did not prepare credentials")
		}
		received := false
		for !received {
			select {
			case e := <-traffic:
				if e != nil {
					t.Fatal(e)
				}
				received = true
			case <-tick.C:
				pump()
			case <-ctx.Done():
				t.Fatal("supervisor never connected")
			}
		}
		if !applied.Load() {
			t.Fatal("native connection bypassed Go credential setter")
		}
		stopRdpProcess(process)
		received = false
		for !received {
			select {
			case <-process.nativeEventsDone:
				received = true
			case <-tick.C:
				pump()
			case <-ctx.Done():
				t.Fatal("supervisor did not close native host")
			}
		}
		process.nativeHandoff.mu.Lock()
		retained := len(process.nativeHandoff.password) + len(process.nativeHandoff.gateway)
		process.nativeHandoff.mu.Unlock()
		if retained != 0 {
			t.Fatal("supervisor retained native credentials")
		}
		return
	}
	cmd := exec.CommandContext(ctx, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	events := make(chan []byte, 16)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			events <- append([]byte{}, scanner.Bytes()...)
		}
		close(events)
	}()
	payload := map[string]any{"op": "start", "requestId": "bridge-probe", "ownerWindow": strconv.FormatUint(uint64(hwnd), 10), "nativeCredentialBridge": true, "bounds": map[string]int{"x": -50000, "y": -50000, "width": 1, "height": 1}, "profile": map[string]any{"host": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port, "gatewayUsageMethod": 0}}
	if err := json.NewEncoder(input).Encode(payload); err != nil {
		t.Fatal(err)
	}
	var reference []byte
	for len(reference) == 0 {
		select {
		case raw, ok := <-events:
			if !ok {
				t.Fatal("native control exited before handoff")
			}
			var event struct {
				Type, Message string
				NativeControl []byte
			}
			if json.Unmarshal(raw, &event) != nil {
				t.Fatal("native event malformed")
			}
			if event.Type == "error" {
				t.Fatal("native preparation failed", event.Message)
			}
			if event.Type == "nativeControl" {
				reference = event.NativeControl
			}
		case <-tick.C:
			pump()
		case <-ctx.Done():
			t.Fatal("native control preparation timeout")
		}
	}
	local, e := localRdpDispatchReference(reference)
	if e != nil {
		t.Fatalf("native reference rejected: bytes=%d flags=%x error=%v", len(reference), reference[4:8], e)
	}
	if err := withNativeRdpDispatch(local, func(control unsafe.Pointer) error {
		if _, err := rdpDispatchID(control, "MissingWormholeProperty"); err != errRdpNativeCredentials {
			t.Fatal("unknown dispatch name", err)
		}
		if _, err := rdpDispatchID(control, "bad\x00name"); err != errRdpNativeCredentials {
			t.Fatal(err)
		}
		if _, err := rdpDispatchGet(control, "MissingWormholeProperty"); err != errRdpNativeCredentials {
			t.Fatal(err)
		}
		if _, err := rdpDispatchGet(control, "Connected"); err != errRdpNativeCredentials {
			t.Fatal("non-dispatch native property", err)
		}
		if err := rdpDispatchSetCredential(control, "MissingWormholeProperty", []byte("synthetic")); err != errRdpNativeCredentials {
			t.Fatal(err)
		}
		if err := rdpDispatchSetCredential(control, "Connected", []byte("synthetic")); err != errRdpNativeCredentials {
			t.Fatal("read-only native property", err)
		}
		if err := rdpDispatchSetCredential(control, "name", []byte{0xff}); err != errRdpNativeReference {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := applyNativeRdpCredentials(local, nil, nil, false, false); err != nil {
		t.Fatal(err)
	}
	if err := applyNativeRdpCredentials(local, nil, []byte("unicode-🔒"), true, true); err != nil {
		t.Fatal("empty/unicode native BSTR", err)
	}
	if e := applyNativeRdpCredentials(local, []byte("synthetic-native-password"), []byte("synthetic-gateway-password"), true, true); e != nil {
		t.Fatal("native COM setters", e)
	}
	if err := json.NewEncoder(input).Encode(map[string]any{"op": "connect", "requestId": "bridge-probe"}); err != nil {
		t.Fatal(err)
	}
	received := false
	for !received {
		select {
		case e := <-traffic:
			if e != nil {
				t.Fatal(e)
			}
			received = true
		case <-tick.C:
			pump()
		case <-ctx.Done():
			t.Fatal("native control never connected")
		}
	}

	_ = json.NewEncoder(input).Encode(map[string]any{"op": "shutdown"})
	_ = input.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	received = false
	for !received {
		select {
		case err := <-exited:
			if err != nil {
				t.Fatal("native control teardown", err)
			}
			received = true
		case <-tick.C:
			pump()
		case <-ctx.Done():
			t.Fatal("native control teardown timeout")
		}
	}
	cmd.Process = nil
}

func TestRdpNativeDispatchRejectsMalformedReferences(t *testing.T) {
	if unsafe.Sizeof(rdpOleVariant{}) != 24 {
		t.Fatal("unexpected Windows x64/arm64 VARIANT layout")
	}
	if err := applyNativeRdpCredentials([]byte("bad"), nil, nil, false, false); err != errRdpNativeReference {
		t.Fatal(err)
	}
	if !rdpComFailed(0x80004002) || rdpComFailed(0) {
		t.Fatal("COM HRESULT handling")
	}
	rdpComRelease(nil)
}

func TestNativeRdpCOMRejectsUnownedConnect(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_RDP_HOST")
	if path == "" {
		t.Skip("set WORMHOLE_TEST_RDP_HOST for native ActiveX bridge verification")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("native helper path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	if err := json.NewEncoder(input).Encode(map[string]any{"op": "connect", "requestId": "unowned"}); err != nil {
		t.Fatal(err)
	}
	// Keep stdin open: the stale handoff itself must deterministically exit.
	if err := cmd.Wait(); err != nil {
		t.Fatal("stale handoff did not exit cleanly", err)
	}
	var event rdpEvent
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event) != nil || event.Type != "error" || event.RequestID != "unowned" || len(event.NativeControl) != 0 {
		t.Fatal("unowned native control was accepted")
	}
}

func testNativeSealedRDPFixture(t *testing.T, path string, hwnd uintptr, pump func(), tick <-chan time.Time, ctx context.Context, listener net.Listener, traffic, closedTraffic <-chan error, routed, standalone, manual, requireContentProtection bool) {
	t.Helper()
	input, initialCommands := io.Pipe()
	var commands io.WriteCloser = initialCommands
	events, output := io.Pipe()
	defer func() { _ = commands.Close() }()
	defer events.Close()
	var applied atomic.Bool
	var borrowed []byte
	c := &rdpController{nativeHostPath: path, nativeCredentialApply: func(ref, p, g []byte, primary, gateway bool) error {
		if string(p) != "sealed-native-password" || !primary || gateway {
			t.Error("sealed native credentials changed")
		}
		borrowed = p
		err := applyNativeRdpCredentials(ref, p, g, primary, gateway)
		if err == nil {
			applied.Store(true)
		}
		return err
	}}
	done := make(chan error, 1)
	if standalone {
		executable := os.Getenv("WORMHOLE_TEST_RDP_BACKEND")
		var command *exec.Cmd
		if executable != "" {
			if !filepath.IsAbs(executable) {
				t.Fatal("native backend path must be absolute")
			}
			operation := "rdp-sealed"
			if manual {
				operation = "rdp-manual-sealed"
			}
			command = exec.Command(executable, "--operation", operation)
		} else {
			command = exec.Command(os.Args[0])
			mode := "1"
			if manual {
				mode = "manual"
			}
			command.Env = append(rdpChildEnvironment(os.Environ()), "WORMHOLE_RDP_SEALED_TEST_HELPER="+mode, "WORMHOLE_RDP_TEST_HELPER=")
		}
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = input.Close()
		_ = initialCommands.Close()
		var pipeErr error
		commands, pipeErr = command.StdinPipe()
		if pipeErr != nil {
			t.Fatal(pipeErr)
		}
		command.Stdout = output
		command.Stderr = io.Discard
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = commands.Close()
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		})
		go func() { err := command.Wait(); _ = output.Close(); done <- err }()
	} else {
		go func() { err := serveSealedRDPMode(input, output, c, manual); _ = output.Close(); done <- err }()
	}

	lines := make(chan []byte, 32)
	go func() {
		scanner := bufio.NewScanner(events)
		scanner.Buffer(make([]byte, 4096), 256*1024)
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			lines <- line
		}
		close(lines)
	}()
	var recipient struct {
		Type      string
		PublicKey []byte
	}
	received := false
	for !received {
		select {
		case line, ok := <-lines:
			if !ok || json.Unmarshal(line, &recipient) != nil || recipient.Type != "recipient" {
				t.Fatal("native recipient missing")
			}
			received = true
		case <-tick:
			pump()
		case <-ctx.Done():
			t.Fatal("recipient timeout")
		}
	}
	binding := vault.BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), Protocol: "rdp", Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Epoch: 1}
	var route *vault.TunnelBundleBinding
	endpoint := ""
	var socksDone <-chan error
	if routed {
		binding.Host = "rdp-must-use-proxy.example"
		binding.Port = 3389
		binding.TunnelConfigID = uuid.NewString()
		endpoint, socksDone = sharedRouteSOCKSFixture(t, listener.Addr().String(), binding.Host, int(binding.Port))
		route = &vault.TunnelBundleBinding{BundleBinding: binding, FileID: uuid.NewString(), Kind: 1, RowVersion: 1, ConfigurationVersion: 1}
	}
	payload := vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings(), Username: "synthetic", PasswordProvided: true, Password: []byte("sealed-native-password")}
	raw, err := vault.EncodeRDPBundle(payload)
	if manual {
		inner, e := vault.SealManualRDPCredentials(recipient.PublicKey, binding, route, endpoint, vault.RDPManualCredentials{Username: "manual-synthetic", Domain: "MANUAL", Password: []byte("sealed-native-password")})
		if e != nil {
			t.Fatal(e)
		}
		vault.Wipe(raw)
		raw, err = vault.EncodeRDPManualAuthorization(vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings()}, inner)
	}

	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	var bundle vault.SealedBundle
	if routed {
		bundle, err = vault.SealRoutedBundle(recipient.PublicKey, *route, endpoint, raw)
	} else {
		bundle, err = vault.SealBundle(recipient.PublicKey, binding, raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	opening := map[string]any{"binding": binding, "bundle": bundle, "ownerWindow": strconv.FormatUint(uint64(hwnd), 10), "bounds": rdpBounds{X: -50000, Y: -50000, Width: 1, Height: 1}}
	if requireContentProtection {
		opening["requireContentProtection"] = true
	}
	if routed {
		opening["binding"] = *route
		opening["endpoint"] = endpoint
	}
	if err = json.NewEncoder(commands).Encode(opening); err != nil {
		t.Fatal(err)
	}
	received = false
	for !received {
		select {
		case err := <-traffic:
			if err != nil {
				t.Fatal(err)
			}
			received = true
		case line, ok := <-lines:
			if !ok {
				t.Fatal("native process exited before connection")
			}
			if bytes.Contains(line, []byte("sealed-native-password")) || bytes.Contains(line, []byte("nativeControl")) {
				t.Fatal("native secret/capability leaked")
			}
		case <-tick:
			pump()
		case <-ctx.Done():
			t.Fatal("sealed RDP connection timeout")
		}
	}
	if !standalone && !applied.Load() {
		t.Fatal("sealed native connection skipped credential setter")
	}
	if err = json.NewEncoder(commands).Encode(map[string]any{"op": "app-lock", "sessionId": binding.SessionID, "requestId": uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	received = false
	for !received {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			received = true
		case <-lines:
		case <-tick:
			pump()
		case <-ctx.Done():
			t.Fatal("sealed app-lock did not join native process")
		}
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("sealed credentials retained after native handoff")
	}
	select {
	case err := <-closedTraffic:
		if err != nil && !errors.Is(err, windows.WSAECONNRESET) {
			t.Fatal("app-lock did not close native socket", err)
		}
	case <-ctx.Done():
		t.Fatal("native socket survived app-lock")
	}
	if routed {
		select {
		case err := <-socksDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("SOCKS route survived native session")
		}
	}
}

// A standalone native Go process uses the exact production service with private
// OS pipes. Optional WORMHOLE_TEST_RDP_BACKEND exercises the packaged CLI instead.
func init() {
	mode := os.Getenv("WORMHOLE_RDP_SEALED_TEST_HELPER")
	if mode != "1" && mode != "manual" {
		return
	}
	if securemem.DisableProcessDumps() != nil {
		os.Exit(2)
	}
	c := &rdpController{nativeHostPath: os.Getenv("WORMHOLE_TEST_RDP_HOST")}
	if serveSealedRDPMode(os.Stdin, os.Stdout, c, mode == "manual") != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
