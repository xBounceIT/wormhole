//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVaultLinuxChildProcessPolicy(t *testing.T) {
	const modeName = "WORMHOLE_TEST_LINUX_VAULT_CHILD_POLICY"
	const rootName = "WORMHOLE_TEST_LINUX_VAULT_CHILD_POLICY_ROOT"
	const selector = "-test.run=^TestVaultLinuxChildProcessPolicy$"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		workerStarted := make(chan struct{})
		workerTry := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			close(workerStarted)
			select {
			case <-workerTry:
				result <- leaf()
			case <-ctx.Done():
			}
		}()
		<-workerStarted
		root := os.Getenv(rootName)
		args := []string{"--operation", mode, "--database", filepath.Join(root, "workspace.db")}
		if mode == "vault-migration" {
			args = append(args, "--electron-user-data", filepath.Join(root, "app"), "--migration-session-data", filepath.Join(root, "isolated"))
		}
		var diagnostic strings.Builder
		if code := runBackendCLI(args, strings.NewReader(""), io.Discard, &diagnostic); code != 0 {
			t.Fatalf("vault launch returned %d: %s", code, diagnostic.String())
		}
		close(workerTry)
		if err := leaf(); !errors.Is(err, unix.EPERM) {
			t.Fatalf("kernel did not deny a child launch: %v", err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, unix.EPERM) {
				t.Fatalf("pre-existing Go thread could launch a child: %v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		// Hold each worker on its own OS thread so the scheduler has to
		// create new threads under the installed process filter.
		ready := make(chan error, 12)
		release := make(chan struct{})
		defer close(release)
		for range cap(ready) {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ready <- leaf()
				<-release
			}()
		}
		for range cap(ready) {
			select {
			case err := <-ready:
				if !errors.Is(err, unix.EPERM) {
					t.Fatalf("new Go thread could launch a child: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("kernel blocked new threads", ctx.Err())
			}
		}
	default:
		if err := leaf(); err != nil {
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
