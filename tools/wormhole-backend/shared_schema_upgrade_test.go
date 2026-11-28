package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestExportSharedSchemaUpgradeCLI(t *testing.T) {
	const id = "5581ede5-b096-44ea-869b-c165e4ca114f"
	const tag = "testscope"
	args := []string{"--operation", "export-shared-schema-upgrade"}
	request := func(version int) string {
		return fmt.Sprintf(`{"roleTag":"%s","workspaceId":"%s","installedVersion":%d}`, tag, id, version)
	}
	// Test the ordinary packaged entry point without a database path or credentials.
	for _, tc := range []struct {
		version int
		render  func(string, string) (string, error)
	}{{90, deploy.RowSecurityMigration}, {91, deploy.DeviceConnectionLimitMigration}} {
		want, err := tc.render(tag, id)
		if err != nil {
			t.Fatal(err)
		}
		var out, diag bytes.Buffer
		code := runBackendCLI(args, strings.NewReader(request(tc.version)), &out, &diag)
		if code != 0 || diag.Len() != 0 || out.String() != want ||
			!strings.Contains(want, "BEGIN;") || !strings.HasSuffix(strings.TrimSpace(want), "COMMIT;") ||
			strings.Contains(want, "{{") {
			t.Fatalf("invalid upgrade from %d: exit %d, diagnostics %q", tc.version, code, diag.String())
		}
	}
	for _, raw := range []string{"", "null", "{}", request(0), request(-1), request(deploy.SchemaVersion),
		request(deploy.SchemaVersion + 1), request(90) + "{}", strings.Repeat(" ", 1024) + request(90),
		strings.Replace(request(91), tag, "private-input", 1), strings.Replace(request(91), id, "private-input", 1),
		strings.Replace(request(91), `"installedVersion":91`, `"installedVersion":90,"installedVersion":91`, 1),
		strings.Replace(request(91), `"roleTag"`, `"password":"private-input","roleTag"`, 1)} {
		var out, diag bytes.Buffer
		if code := runBackendCLI(args, strings.NewReader(raw), &out, &diag); code != 1 || out.Len() != 0 ||
			diag.Len() == 0 || strings.Contains(diag.String(), "private-input") {
			t.Fatalf("unexpected invalid request response: %d %q", code, diag.String())
		}
	}
	if runBackendCLI(args, backendFailingReader{}, io.Discard, io.Discard) == 0 ||
		runBackendCLI(args, strings.NewReader(request(91)), backendFailingWriter{}, io.Discard) == 0 ||
		runBackendCLI(args, strings.NewReader(request(91)), shortUpgradeWriter{}, io.Discard) == 0 {
		t.Fatal("I/O failure reported success")
	}
}

type shortUpgradeWriter struct{}

func (shortUpgradeWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
