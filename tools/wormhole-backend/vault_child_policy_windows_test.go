package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestVaultWindowsChildProcessPolicy(t *testing.T) {
	const modeName = "WORMHOLE_TEST_VAULT_CHILD_POLICY"
	const rootName = "WORMHOLE_TEST_VAULT_CHILD_POLICY_ROOT"
	const selector = "-test.run=^TestVaultWindowsChildProcessPolicy$"
	leaf := func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], selector)
		cmd.Env = append(os.Environ(), modeName+"=leaf")
		return cmd
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch mode := os.Getenv(modeName); mode {
	case "leaf":
		return
	case "vault", "vault-migration":
		root := os.Getenv(rootName)
		args := []string{"--operation", mode, "--database", filepath.Join(root, "workspace.db")}
		if mode == "vault-migration" {
			args = append(args, "--electron-user-data", filepath.Join(root, "app"), "--migration-session-data", filepath.Join(root, "isolated"))
		}
		var diagnostic strings.Builder
		if code := runBackendCLI(args, strings.NewReader(""), io.Discard, &diagnostic); code != 0 {
			t.Fatalf("vault launch returned %d: %s", code, diagnostic.String())
		}
		if err := leaf(ctx).Run(); !errors.Is(err, windows.ERROR_CHILD_PROCESS_BLOCKED) {
			t.Fatalf("kernel did not deny a child launch: %v", err)
		}
	default:
		if err := leaf(ctx).Run(); err != nil {
			t.Fatalf("unrestricted control could not launch the test program: %v", err)
		}
		for _, operation := range []string{"vault", "vault-migration"} {
			t.Run(operation, func(t *testing.T) {
				root := t.TempDir()
				for _, dir := range []string{"app", "isolated"} {
					if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.CommandContext(ctx, os.Args[0], selector)
				cmd.Env = append(os.Environ(), modeName+"="+operation, rootName+"="+root)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("test process failed: %v\n%s", err, out)
				}
			})
		}
	}
}
