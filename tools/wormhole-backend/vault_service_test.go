package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultFoundationStatusDoesNotClaimProtection(t *testing.T) {
	h := &vaultFoundationHandler{}
	response, err := h.Handle(context.Background(), "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Stage                                         string
		ProtectionAvailable, SharedWorkspaceAvailable bool
	}
	if err := json.Unmarshal(response, &status); err != nil {
		t.Fatal(err)
	}
	if status.Stage != "foundation" || status.ProtectionAvailable || status.SharedWorkspaceAvailable {
		t.Fatal("unfinished vault advertised protection")
	}
	for _, op := range []string{"unlock", "credential-read", "unknown"} {
		if _, err := h.Handle(context.Background(), op, nil); err == nil {
			t.Fatal("unsupported operation allowed")
		}
	}
	if _, err := h.Handle(context.Background(), "status", json.RawMessage(`{}`)); err == nil {
		t.Fatal("payload accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Handle(ctx, "status", nil); err != context.Canceled {
		t.Fatal("cancel ignored")
	}
}

func TestVaultFoundationOwnershipAndNoDatabaseOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wormhole.db")
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	defer iw.Close()
	defer or.Close()
	done := make(chan error, 1)
	go func() { done <- serveVaultFoundation(path, ir, ow, time.Second) }()
	if _, err := io.WriteString(iw, `{"version":1,"id":1,"operation":"status"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(or).ReadString('\n')
	if err != nil || !strings.Contains(line, `"protectionAvailable":false`) {
		t.Fatalf("status: %s %v", line, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("vault touched database before unlock: %v", err)
	}
	second := serveVaultFoundation(path, io.NopCloser(strings.NewReader("")), vaultWriteCloser{io.Discard}, time.Second)
	if second == nil || second.Error() != "vault_owner_unavailable" {
		t.Fatalf("second owner: %v", second)
	}
	iw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := serveVaultFoundation(path, io.NopCloser(strings.NewReader("")), vaultWriteCloser{io.Discard}, time.Second); err != nil {
		t.Fatalf("lease not released: %v", err)
	}
	blocked := filepath.Join(dir, "file")
	if err := os.WriteFile(blocked, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serveVaultFoundation(filepath.Join(blocked, "db"), io.NopCloser(strings.NewReader("")), vaultWriteCloser{io.Discard}, time.Second); err == nil {
		t.Fatal("invalid storage accepted")
	}
}

func TestVaultCLIProcess(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_VAULT_CHILD") == "1" {
		os.Exit(runBackendCLI([]string{"--operation", "vault", "--database", os.Getenv("WORMHOLE_TEST_VAULT_DATABASE")}, os.Stdin, os.Stdout, os.Stderr))
	}
	for _, mode := range []string{"eof", "invalid", "lock"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dir := t.TempDir()
			path := filepath.Join(dir, "workspace.db")
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultCLIProcess$")
			cmd.Env = append(os.Environ(), "WORMHOLE_TEST_VAULT_CHILD=1", "WORMHOLE_TEST_VAULT_DATABASE="+path)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if mode == "invalid" {
				io.WriteString(in, "secret-path-and-password\n")
				in.Close()
				if err := cmd.Wait(); err == nil {
					t.Fatal("invalid frame accepted")
				}
				if strings.Contains(stderr.String(), "secret-path-and-password") || !strings.Contains(stderr.String(), "vault_service_stopped") {
					t.Fatalf("unsafe error: %s", stderr.String())
				}
			} else {
				json.NewEncoder(in).Encode(vaultwire.Request{Version: 1, ID: 1, Operation: "status"})
				var response vaultwire.Response
				if err := json.NewDecoder(out).Decode(&response); err != nil {
					t.Fatal(err)
				}
				if response.ID != 1 || response.Error != "" {
					t.Fatal(response)
				}
				if mode == "lock" {
					if err := json.NewEncoder(in).Encode(vaultwire.Request{Version: 1, ID: 2, Operation: "lock"}); err != nil {
						t.Fatal(err)
					}
				} else {
					in.Close()
				}
				if err := cmd.Wait(); err != nil {
					t.Fatalf("CLI exit: %v %s", err, stderr.String())
				}
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("CLI ran database migration before unlock")
			}
			if _, err := os.Stat(filepath.Join(dir, "logs")); !os.IsNotExist(err) {
				t.Fatal("CLI initialized legacy logs")
			}
		})
	}
}

func TestVaultCLIStreamAdapters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	var output, diagnostic strings.Builder
	if code := runVaultLaunchStream(path, strings.NewReader(""), &output, &diagnostic, vaultLaunchOptions{}); code != 0 {
		t.Fatal("EOF adapter failed")
	}
	if code := runVaultLaunchStream(path, strings.NewReader("bad\n"), &output, &diagnostic, vaultLaunchOptions{}); code != 1 {
		t.Fatal("invalid frame adapter accepted")
	}
	if strings.Contains(diagnostic.String(), "bad") {
		t.Fatal("error echoed payload")
	}
}
