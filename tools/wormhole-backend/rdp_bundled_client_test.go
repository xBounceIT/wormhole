package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt-in native integration test. Unlike the process fixtures, this exercises the
// parser in the actual bundled FreeRDP binary using the arguments the backend sends.
func TestBundledMacFreeRdpCommandLine(t *testing.T) {
	client := os.Getenv("WORMHOLE_RDP_SMOKE_CLIENT")
	if client == "" {
		t.Skip("set WORMHOLE_RDP_SMOKE_CLIENT to test the native macOS bundle")
	}
	run := func(args []string, input string) (string, bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, client, args...)
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("bundled client parser timed out")
		}
		var exitError *exec.ExitError
		if err != nil && !errors.As(err, &exitError) {
			t.Fatalf("could not run bundled client: %v", err)
		}
		// FreeRDP clients may return 128 when handling /version without connecting.
		success := err == nil || (exitError != nil && exitError.ExitCode() == 128)
		return string(output), success
	}
	ignoreCertificate := 0
	profiles := []rdpProfile{
		{Host: "127.0.0.1", Port: 3389},
		{
			Host: "127.0.0.1", Port: 3389, Username: "fixture user", Domain: "EXAMPLE",
			Password: "dummy:comma, Unicode à", GatewayHostname: "gateway.example.invalid",
			GatewayUsageMethod: 1, GatewayUsername: "gateway user", GatewayPassword: "dummy gateway password",
			ServerAuthentication: &ignoreCertificate, ColorDepth: 32, AudioMode: 2,
			AutoReconnect: true, RedirectClipboard: true, BitmapCaching: true, FullScreen: true,
		},
	}
	for _, profile := range profiles {
		args, input, err := buildFreeRdpInvocation(rdpCommand{Profile: profile})
		if err != nil {
			t.Fatal(err)
		}
		// /version is last so every preceding argument must be accepted first.
		output, success := run(args, input+"/version\n")
		if !success || !strings.Contains(output, "FreeRDP version 3.33.0") {
			t.Fatalf("bundled client rejected backend arguments: %s", output)
		}
	}
	// A negative control prevents a client that ignores stdin or skips invalid
	// preceding arguments on /version from making the integration test pass.
	if _, success := run([]string{"/args-from:stdin"}, "/wormhole-invalid-option\n/version\n"); success {
		t.Fatal("bundled client did not reject an invalid stdin argument")
	}
}
