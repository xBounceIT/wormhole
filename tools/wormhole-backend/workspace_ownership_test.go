package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultWorkspaceOwnershipModesAndPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "one.db")
	first, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	second, err := acquireWorkspaceOwnership(filepath.Join(filepath.Dir(path), "two.db"), false)
	if err != nil {
		t.Fatal("legacy siblings must coexist", err)
	}
	defer second()
	if release, err := acquireWorkspaceOwnership(path, true); release != nil || err != errWorkspaceInUse {
		t.Fatal("exclusive admitted readers", err)
	}
	first()
	if release, err := acquireWorkspaceOwnership(path, true); release != nil || err != errWorkspaceInUse {
		t.Fatal("remaining reader ignored", err)
	}
	second()
	exclusive, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive()
	first() // A stale release must not unlock a new owner with a recycled OS handle.
	for _, mode := range []bool{false, true} {
		if release, err := acquireWorkspaceOwnership(path, mode); release != nil || err != errWorkspaceInUse {
			t.Fatal("exclusive owner bypassed", mode, err)
		}
	}
	other, err := acquireWorkspaceOwnership(filepath.Join(t.TempDir(), "db"), true)
	if err != nil {
		t.Fatal("unrelated directory blocked", err)
	}
	other()
	exclusive()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guard created database", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(filepath.Join(filepath.Dir(blocked), ".workspace-owner.lock"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", t.TempDir(), filepath.Join(file, "db"), blocked} {
		if release, err := acquireWorkspaceOwnership(invalid, true); release != nil || err != errWorkspaceInUse {
			t.Fatal("invalid path admitted", invalid, err)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(path), alias); err != nil {
		t.Log("symlink unavailable:", err)
		return
	}
	owner, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer owner()
	if release, err := acquireWorkspaceOwnership(filepath.Join(alias, "two.db"), false); release != nil || err != errWorkspaceInUse {
		t.Fatal("parent alias bypassed guard", err)
	}
	link := filepath.Join(t.TempDir(), "db-link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireWorkspaceOwnership(link, false); release != nil || err != errWorkspaceInUse {
		t.Fatal("database symlink admitted", err)
	}
}

func TestVaultWorkspaceOwnershipUnlockLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	doc, key := pendingVault(t, path)
	defer vault.Wipe(key)
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
	legacy, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy()
	if _, err := h.Handle(context.Background(), "describe", nil); err != nil {
		t.Fatal("metadata blocked", err)
	}
	if _, err := h.Handle(context.Background(), "unlock", input); err != errWorkspaceInUse {
		t.Fatal("unlock ignored legacy owner", err)
	}
	legacy()
	if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID})); err == nil {
		t.Fatal("invalid factor accepted")
	}
	probe, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal("failed unlock leaked ownership", err)
	}
	probe()
	if _, err := h.Handle(context.Background(), "unlock", input); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireWorkspaceOwnership(path, false); release != nil || err != errWorkspaceInUse {
		t.Fatal("unlocked handler lost guard", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal("close leaked ownership", err)
	}
	defer next()
	h.Close()
	if release, err := acquireWorkspaceOwnership(path, false); release != nil || err != errWorkspaceInUse {
		t.Fatal("repeated close released next owner", err)
	}
}

func TestVaultWorkspaceOwnershipMigrationAndCLI(t *testing.T) {
	_, path, doc, key, plan, _ := migrationStageFixture(t)
	defer vault.Wipe(key)
	legacy, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy()
	if _, err := stageLegacyVaultDomains(context.Background(), path, "", doc, key, plan); err != errWorkspaceInUse {
		t.Fatal("migration ignored legacy reader", err)
	}
	if _, err := os.Stat(path + ".migrating-" + doc.FileID + ".slots"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blocked migration created stage", err)
	}
	legacy()
	exclusive, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive()
	untouched := filepath.Join(filepath.Dir(path), "untouched.db")
	var stderr bytes.Buffer
	if code := runBackendCLI([]string{"--database", untouched, "--operation", "startup"}, strings.NewReader(""), io.Discard, &stderr); code != 1 || stderr.String() != "workspace_owner_unavailable\n" {
		t.Fatal("CLI guard", code, stderr.String())
	}
	if _, err := os.Stat(untouched); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blocked CLI initialized database", err)
	}
	exclusive()
	if _, err := stageLegacyVaultDomains(context.Background(), path, "", doc, key, plan); err != nil {
		t.Fatal("migration failed after reader exit", err)
	}
	probe, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal("migration leaked guard", err)
	}
	probe()
}

// Signal only once the CLI reaches request decoding while its lifetime lease is held.
type ownershipSignalReader struct {
	input io.Reader
	ready io.Writer
	sent  bool
}

func (r *ownershipSignalReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		_, _ = r.ready.Write([]byte("ready\n"))
	}
	return r.input.Read(p)
}

func TestVaultWorkspaceOwnershipCLIProcess(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_OWNERSHIP_CHILD") == "1" {
		input := &ownershipSignalReader{input: os.Stdin, ready: os.Stdout}
		var lease func()
		defer func() {
			if lease != nil {
				lease()
			}
		}()
		os.Exit(runBackendCLIWithOwnership([]string{"--database", os.Getenv("WORMHOLE_TEST_OWNERSHIP_DB"), "--operation", "workspace-update-node"}, input, io.Discard, io.Discard, &lease))
	}
	path := filepath.Join(t.TempDir(), "db")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultWorkspaceOwnershipCLIProcess$")
	cmd.Env = append(os.Environ(), "WORMHOLE_TEST_OWNERSHIP_CHILD=1", "WORMHOLE_TEST_OWNERSHIP_DB="+path)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	signal := make([]byte, 6)
	if _, err := io.ReadFull(output, signal); err != nil || string(signal) != "ready\n" {
		t.Fatal("child never reached input", string(signal), err)
	}
	if release, err := acquireWorkspaceOwnership(path, true); release != nil || err != errWorkspaceInUse {
		t.Fatal("CLI process lost lifetime guard", err)
	}
	peer, err := acquireWorkspaceOwnership(path, false)
	if err != nil {
		t.Fatal("concurrent legacy owner rejected", err)
	}
	peer()
	input.Close()
	if err := cmd.Wait(); err == nil {
		t.Fatal("EOF should reject malformed request")
	}
	after, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal("exiting CLI leaked guard", err)
	}
	after()
}

func TestVaultWorkspaceOwnershipSurvivesCommandReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	var lease func()
	defer func() {
		if lease != nil {
			lease()
		}
	}()
	code := runBackendCLIWithOwnership([]string{"--database", path, "--operation", "workspace-update-node"}, strings.NewReader(""), io.Discard, io.Discard, &lease)
	if code != 1 || lease == nil {
		t.Fatal("command did not retain ownership", code)
	}
	if release, err := acquireWorkspaceOwnership(path, true); release != nil || err != errWorkspaceInUse {
		t.Fatal("lease released before process termination", err)
	}
	lease()
	probe, err := acquireWorkspaceOwnership(path, true)
	if err != nil {
		t.Fatal(err)
	}
	probe()
}
