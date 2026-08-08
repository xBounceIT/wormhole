package main

import (
	"net"
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

func TestWindowsRdpCredentialFailureExcludesNonErrorLogonNotifications(t *testing.T) {
	for _, code := range []int{-7, -6, -5, -4, -3, -2, 3} {
		if isWindowsRdpCredentialFailure(code) {
			t.Fatalf("non-credential logon notification %d was classified as a credential failure", code)
		}
	}
}

func TestWindowsRdpCredentialFailureIncludesRetryableAuthenticationErrors(t *testing.T) {
	for _, code := range []int{-1, 0, 1, 2, -1073741714, -1073741715, -1073741276} {
		if !isWindowsRdpCredentialFailure(code) {
			t.Fatalf("authentication error %d did not allow a credential retry", code)
		}
	}
}

func TestNativeRdpEventClassificationIsAuthoritative(t *testing.T) {
	tests := []struct {
		name  string
		event rdpEvent
		want  bool
	}{
		{name: "continue logon", event: rdpEvent{Type: "logonError", Code: -2}, want: false},
		{name: "bad password", event: rdpEvent{Type: "logonError", Code: 0}, want: true},
		{name: "unrelated event", event: rdpEvent{Type: "connected", Code: 0}, want: false},
		{name: "untrusted marker", event: rdpEvent{Type: "connected", CredentialFailure: true}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifyNativeRdpEvent(&test.event)
			if test.event.CredentialFailure != test.want {
				t.Fatalf("CredentialFailure = %t, want %t", test.event.CredentialFailure, test.want)
			}
		})
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

func TestRouteRdpThroughTunnelAcceptsResolvedSavedTunnelHandoff(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	enabled := true
	controller := &rdpController{}
	command := &rdpCommand{Profile: rdpProfile{
		NodeID:         "saved-rdp",
		TunnelConfigID: "11111111-2222-3333-4444-555555555555",
		SocksEndpoint:  proxy.Addr().String(),
		TunnelEnabled:  &enabled,
	}}
	if err := controller.routeRdpThroughTunnel(command, "rdp.internal.example", rdpDefaultPort); err != nil {
		t.Fatalf("resolved saved RDP tunnel handoff was rejected: %v", err)
	}
	defer command.forwarder.close()
	if command.tunnel != nil {
		t.Fatal("resolved SOCKS handoff started a second VPN tunnel")
	}
	if command.forwarder == nil || command.Profile.Host != "127.0.0.1" || command.Profile.Port < 1 {
		t.Fatalf("resolved SOCKS handoff did not create a loopback forwarder: %#v", command.Profile)
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
		"/audio-mode:0",
		"+dynamic-resolution",
		"+clipboard",
		"+wallpaper",
		"+fonts",
		"-aero",
		"-window-drag",
		"-menu-anims",
		"-themes",
		"/drives",
		"/cache:bitmap:off",
		"/network:auto",
	}
	if runtime.GOOS == "linux" {
		if !contains(args, "/parent-window:1234") {
			t.Fatalf("Linux parent window was not mapped: %#v", args)
		}
	}
	if !containsAll(args, want) {
		t.Fatalf("missing common FreeRDP arguments: %#v", args)
	}
	if !contains(args, "/p:secret-marker") {
		t.Fatal("password was not passed to FreeRDP")
	}
}

func TestFreeRdpInvocationKeepsPasswordsOutOfProcessArguments(t *testing.T) {
	processArgs, input, err := buildFreeRdpInvocation(rdpCommand{
		Bounds: rdpBounds{Width: 1280, Height: 800},
		Profile: rdpProfile{
			Host: "rdp.example", Username: "operator", Password: "connection-secret",
			GatewayHostname: "gateway.example", GatewayUsageMethod: 1,
			GatewayUsername: "gateway-user", GatewayPassword: "gateway-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(processArgs, []string{"/args-from:stdin"}) {
		t.Fatalf("unexpected FreeRDP process arguments: %#v", processArgs)
	}
	for _, secret := range []string{"connection-secret", "gateway-secret"} {
		if strings.Contains(strings.Join(processArgs, " "), secret) {
			t.Fatalf("secret %q was exposed in process arguments", secret)
		}
		if !strings.Contains(input, secret) {
			t.Fatalf("secret %q was not supplied over stdin", secret)
		}
	}
}

func TestRdpProfileRejectsCredentialArgumentInjection(t *testing.T) {
	profile := rdpProfile{
		Host: "rdp.example", ScreenSize: "fitToWindow", ColorDepth: 32,
		KeyboardHookMode: 2, ConnectionSpeed: 7, ServerAuthentication: intPointer(2),
		Password: "safe\n/cert-ignore",
	}
	if err := validateRdpProfile(profile); err == nil {
		t.Fatal("accepted a newline-bearing RDP password")
	}
	profile.Password = "safe"
	profile.GatewayPassword = "safe\r/g:attacker"
	if err := validateRdpProfile(profile); err == nil {
		t.Fatal("accepted a newline-bearing RDP Gateway password")
	}
}

func TestFreeRdpArgumentsMapRedirectionAndPerformanceProfile(t *testing.T) {
	args, err := buildFreeRdpArguments(rdpCommand{
		Bounds: rdpBounds{Width: 1280, Height: 800},
		Profile: rdpProfile{
			Host: "rdp.example", AudioMode: 2, AudioCaptureMode: 1, RedirectClipboard: true,
			RedirectPrinters: true, RedirectSmartCards: true, RedirectPorts: true,
			RedirectDevices: true, RedirectDrives: "C,D", ConnectionSpeed: 3,
			DesktopBackground: true, FontSmoothing: true, DesktopComposition: true,
			WindowDrag: true, MenuAnimation: true, VisualStyles: true, BitmapCaching: false,
			AutoReconnect: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/audio-mode:2", "/microphone", "+auto-reconnect", "+clipboard", "/printer",
		"/smartcard", "/serial", "/usb:auto", "+wallpaper", "+fonts", "+aero",
		"+window-drag", "+menu-anims", "+themes", "/drive:C,C:\\", "/drive:D,D:\\",
		"/cache:bitmap:off", "/network:satellite",
	}
	if !containsAll(args, want) {
		t.Fatalf("RDP profile settings were not mapped to FreeRDP: %#v", args)
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

func TestRdpTargetRejectsArgumentChannelInjection(t *testing.T) {
	for _, host := range []string{"server\n/cert-ignore", "server\r/g:attacker", "bad host"} {
		if _, _, err := normalizeRdpTarget(host, 3389); err == nil {
			t.Fatalf("accepted malformed RDP host %q", host)
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
