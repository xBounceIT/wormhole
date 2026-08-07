package main

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeRdpTargetUsesExplicitPortBeforeHostPortSuffix(t *testing.T) {
	host, port, err := normalizeRdpTarget("rdp.example:3390", 0)
	if err != nil {
		t.Fatal(err)
	}
	if host != "rdp.example" || port != 3390 {
		t.Fatalf("unexpected target: %q:%d", host, port)
	}

	host, port, err = normalizeRdpTarget("2001:db8::10", 0)
	if err != nil {
		t.Fatal(err)
	}
	if host != "2001:db8::10" || port != rdpDefaultPort {
		t.Fatalf("unexpected IPv6 target: %q:%d", host, port)
	}

	host, port, err = normalizeRdpTarget("rdp.example:3390", 3389)
	if err != nil {
		t.Fatal(err)
	}
	if host != "rdp.example" || port != 3389 {
		t.Fatalf("explicit port was not preserved: %q:%d", host, port)
	}

	host, port, err = normalizeRdpTarget("[2001:db8::10]:3390", 0)
	if err != nil {
		t.Fatal(err)
	}
	if host != "2001:db8::10" || port != 3390 {
		t.Fatalf("unexpected bracketed IPv6 target: %q:%d", host, port)
	}

	for _, rawHost := range []string{"rdp.example:not-a-port", "[2001:db8::10]:bad", "rdp.example:"} {
		if _, _, err := normalizeRdpTarget(rawHost, 0); err == nil {
			t.Fatalf("malformed RDP target %q was accepted", rawHost)
		}
	}
}

func TestRdpCommandsWithoutAProcessAreIdempotentWhereTheSurfaceNeedsIt(t *testing.T) {
	for _, operation := range []string{"resize", "hide", "disconnect"} {
		if !isRdpNoopWithoutProcess(operation) {
			t.Fatalf("surface lifecycle operation %q should be idempotent", operation)
		}
	}
	for _, operation := range []string{"show", "focus"} {
		if isRdpNoopWithoutProcess(operation) {
			t.Fatalf("operation %q should still report a missing process", operation)
		}
	}
}

func TestRouteRdpThroughTunnelValidatesExplicitQuickConnectTunnel(t *testing.T) {
	controller := &rdpController{}
	command := &rdpCommand{Profile: rdpProfile{TunnelConfigID: "not-a-uuid"}}
	if err := controller.routeRdpThroughTunnel(command, "rdp.example", rdpDefaultPort); err == nil {
		t.Fatal("invalid quick-connect RDP tunnel was accepted")
	}
}

func TestRouteRdpThroughTunnelRejectsSavedTunnelOverride(t *testing.T) {
	controller := &rdpController{}
	command := &rdpCommand{Profile: rdpProfile{
		NodeID:         "saved-rdp",
		TunnelConfigID: "11111111-2222-3333-4444-555555555555",
	}}
	if err := controller.routeRdpThroughTunnel(command, "rdp.example", rdpDefaultPort); err == nil {
		t.Fatal("RDP command allowed a saved connection tunnel override")
	}
}

func TestRouteRdpThroughTunnelFailsClosedWhenEnabledWithoutConfig(t *testing.T) {
	enabled := true
	controller := &rdpController{}
	command := &rdpCommand{Profile: rdpProfile{TunnelEnabled: &enabled}}
	if err := controller.routeRdpThroughTunnel(command, "rdp.example", rdpDefaultPort); err == nil {
		t.Fatal("RDP tunnel request without a configuration was routed directly")
	}
}

func TestDisconnectCanMarkTheCurrentProcessTerminalBeforeExit(t *testing.T) {
	process := &rdpProcess{sessionID: "session-1", backend: "activex"}
	controller := &rdpController{processes: map[string]*rdpProcess{process.sessionID: process}}

	controller.markProcessTerminal(process)
	if !process.terminal {
		t.Fatal("current RDP process was not marked terminal")
	}

	replacement := &rdpProcess{sessionID: process.sessionID, backend: "freerdp"}
	controller.processes[process.sessionID] = replacement
	controller.markProcessTerminal(process)
	if replacement.terminal {
		t.Fatal("stale RDP process marked the replacement terminal")
	}
}

func TestRdpRequestMetadataSurvivesTypedCommandDecodeErrors(t *testing.T) {
	requestID, sessionID := rdpRequestMetadata([]byte(`{"requestId":"request-1","sessionId":"session-1","profile":{"password":42}}`))
	if requestID != "request-1" || sessionID != "session-1" {
		t.Fatalf("unexpected request metadata: %q %q", requestID, sessionID)
	}

	requestID, sessionID = rdpRequestMetadata([]byte("not-json"))
	if requestID != "" || sessionID != "" {
		t.Fatalf("malformed JSON returned metadata: %q %q", requestID, sessionID)
	}
}

func TestFreeRdpCandidatesIncludeTheMacSDLClients(t *testing.T) {
	candidates := freeRdpCandidatesForOS("darwin")
	if !contains(candidates, "sdl-freerdp") || !contains(candidates, "sdl-freerdp3") {
		t.Fatalf("macOS SDL FreeRDP clients were not discovered: %#v", candidates)
	}
}

func TestFreeRdpFullscreenPolicyDoesNotSuppressMacOSFullscreen(t *testing.T) {
	if !freeRdpUsesParentWindow("linux", "1234") {
		t.Fatal("Linux should use the Electron parent window when available")
	}
	if freeRdpUsesParentWindow("linux", "") {
		t.Fatal("Linux should not claim a missing parent window")
	}
	if freeRdpUsesParentWindow("darwin", "1234") {
		t.Fatal("macOS SDL FreeRDP must remain an external window")
	}
}

func TestBuildFreeRdpArgumentsMapsProfileAndSurfaceSettings(t *testing.T) {
	args, err := buildFreeRdpArguments(rdpCommand{
		SessionID:   "session-1",
		OwnerWindow: "1234",
		Bounds:      rdpBounds{Width: 1440, Height: 900},
		Profile: rdpProfile{
			Host:                 "rdp.example",
			Username:             "operator",
			Domain:               "CONTOSO",
			Password:             "secret-marker",
			ColorDepth:           32,
			RedirectClipboard:    true,
			DesktopBackground:    true,
			FontSmoothing:        true,
			VisualStyles:         false,
			RedirectDrives:       "all",
			ServerAuthentication: intPointer(2),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/v:rdp.example:3389",
		"/w:1440",
		"/h:900",
		"/bpp:32",
		"/u:operator",
		"/d:CONTOSO",
		"/p:secret-marker",
		"+dynamic-resolution",
		"+clipboard",
		"+wallpaper",
		"+fonts",
		"-aero",
		"-window-drag",
		"-menu-anims",
		"-themes",
		"/drives",
		"/parent-window:1234",
	}
	if runtime.GOOS == "linux" {
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("unexpected FreeRDP arguments:\nwant %#v\n got %#v", want, args)
		}
	} else if runtime.GOOS != "windows" && !containsAll(args, want[:len(want)-1]) {
		// macOS deliberately does not use the X11 parent-window option.
		t.Fatalf("missing common FreeRDP arguments: %#v", args)
	}
	if !contains(args, "/p:secret-marker") {
		t.Fatal("password was not passed to FreeRDP")
	}
}

func TestFreeRdpCertificatePolicyDefaultsToValidation(t *testing.T) {
	args, err := buildFreeRdpArguments(rdpCommand{
		Bounds:  rdpBounds{Width: 800, Height: 600},
		Profile: rdpProfile{Host: "rdp.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if contains(args, "/cert-ignore") {
		t.Fatal("omitted server authentication must not disable certificate validation")
	}

	args, err = buildFreeRdpArguments(rdpCommand{
		Bounds:  rdpBounds{Width: 800, Height: 600},
		Profile: rdpProfile{Host: "rdp.example", ServerAuthentication: intPointer(0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(args, "/cert-ignore") {
		t.Fatal("explicit no-authentication policy was not preserved")
	}
}

func TestFreeRdpSizePrefersMeasuredSurface(t *testing.T) {
	profile := rdpProfile{ScreenSize: "Full connection content"}
	if width, height := freeRdpSize(profile, rdpBounds{Width: 1600, Height: 1000}); width != 1600 || height != 1000 {
		t.Fatalf("measured surface was not preferred: %dx%d", width, height)
	}
	if width, height := freeRdpSize(rdpProfile{ScreenSize: "1024x768"}, rdpBounds{Width: 1600, Height: 1000}); width != 1024 || height != 768 {
		t.Fatalf("saved screen size was not used: %dx%d", width, height)
	}
}

func TestRdpArgumentBuilderDoesNotCreateShellSyntax(t *testing.T) {
	args, err := buildFreeRdpArguments(rdpCommand{
		Bounds: rdpBounds{Width: 800, Height: 600},
		Profile: rdpProfile{
			Host:     "rdp.example",
			Username: "user with spaces",
			Password: "$(not-a-command);&",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		if strings.Contains(arg, "\n") || strings.Contains(arg, "\r") {
			t.Fatalf("argument contains a line break: %q", arg)
		}
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func intPointer(value int) *int {
	return &value
}

func containsAll(values, wanted []string) bool {
	for _, value := range wanted {
		if !contains(values, value) {
			return false
		}
	}
	return true
}
