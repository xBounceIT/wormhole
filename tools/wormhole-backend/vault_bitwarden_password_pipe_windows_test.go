package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

func TestVaultBitwardenCLIUnlockWindowsPasswordStream(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node runtime required to verify the CLI password reader")
	}
	// Exercise the same Node streams used by the Bitwarden CLI password reader.
	const script = `const fs = require('node:fs');
const lines = require('node:readline').createInterface(fs.createReadStream(process.argv[1], {encoding:'utf8'}));
lines.once('line', value => process.exit(value === '  synthetic rénewal 🔒  ' ? 0 : 1));`
	frame := []byte("  synthetic rénewal 🔒  \n")
	for _, mode := range []string{"read", "wrong-process", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			pipe, err := openVaultBitwardenPasswordPipe(frame)
			if err != nil {
				t.Fatal(err)
			}
			defer pipe.close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "cancelled" {
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
				if err := pipe.deliver(ctx, os.Getpid(), frame); !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
					t.Fatal("unconnected password pipe was not cancelled", err)
				}
				return
			}
			cmd := exec.CommandContext(ctx, node, "-e", script, pipe.path)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-process" {
				err := pipe.deliver(ctx, os.Getpid(), frame)
				cancel()
				_ = cmd.Wait()
				if !errors.Is(err, vault.ErrAuthentication) {
					t.Fatal("password stream accepted an unrecognized process", err)
				}
				return
			}
			if err := pipe.deliver(ctx, cmd.Process.Pid, frame); err != nil {
				cancel()
				_ = cmd.Wait()
				t.Fatal("password was not delivered", err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal("Node could not read the password stream", err)
			}
		})
	}
}
