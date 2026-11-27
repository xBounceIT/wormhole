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

	"golang.org/x/sys/unix"
)

func TestVaultDarwinChildProcessPolicy(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		if enforceVaultChildProcessPolicy() {
			t.Fatal("protected process admitted a root identity")
		}
		return
	}
	const modeName = "WORMHOLE_TEST_DARWIN_VAULT_CHILD_POLICY"
	const rootName = "WORMHOLE_TEST_DARWIN_VAULT_CHILD_POLICY_ROOT"
	const selector = "-test.run=^TestVaultDarwinChildProcessPolicy$"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	leaf := func() error {
		cmd := exec.CommandContext(ctx, os.Args[0], selector)
		cmd.Env = append(os.Environ(), modeName+"=leaf")
		return cmd.Run()
	}
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
		limit := unix.Rlimit{Cur: 1, Max: 1}
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &limit); !errors.Is(err, unix.EPERM) {
			t.Fatal("vault was allowed to relax the hard process limit", err)
		}
		if err := leaf(); !errors.Is(err, unix.EAGAIN) {
			t.Fatal("kernel did not deny the child launch", err)
		}
	default:
		if err := leaf(); err != nil {
			t.Fatal("unrestricted control could not launch the test program", err)
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
