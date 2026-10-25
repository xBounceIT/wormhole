package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func init() {
	if os.Getenv("WORMHOLE_SSH_TRUST_RACE_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(2)
	}
	var input struct {
		Database string             `json:"database"`
		Request  tunnelWriteRequest `json:"request"`
	}
	if json.Unmarshal(scanner.Bytes(), &input) != nil {
		os.Exit(2)
	}
	wanted := filepath.Dir(legacyTunnelSecretPath(input.Database, input.Request.ID))
	previous := privateFileDirectorySync
	paused := false
	privateFileDirectorySync = func(directory string) error {
		if directory != wanted || paused {
			return previous(directory)
		}
		paused = true
		fmt.Fprintln(os.Stdout, "WRITTEN")
		if !scanner.Scan() {
			os.Exit(2)
		}
		return os.ErrPermission // Roll back the GUI save after another process approves trust.
	}
	if _, err := updateTunnel(input.Database, input.Request); err == nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "ROLLED_BACK")
	os.Exit(0)
}

func TestSSHJumpTrustSurvivesAnotherProcessRollingBackItsSave(t *testing.T) {
	if runtime.GOOS != "windows" {
		// Non-Windows tests use a process-local protected-store fake. Native lock contention
		// and cancellation tests below run on all platforms; DPAPI permits this process test.
		t.Skip("cross-process protected-store fixture requires Windows DPAPI")
	}
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	raw, _ := json.Marshal(map[string]any{"Mode": "manual", "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
	details, err := updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 7, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := jumpSnapshot(t, path, details.ID)
	target, err := resolveSSHJumpTarget(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0])
	command.Env = append(os.Environ(), "WORMHOLE_SSH_TRUST_RACE_HELPER=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	if err := json.NewEncoder(stdin).Encode(map[string]any{"database": path, "request": tunnelWriteRequest{ID: details.ID, Name: "Parallel editor", Kind: 7, Settings: details.Settings}}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || reader.Text() != "WRITTEN" {
		t.Fatal("parallel editor did not reach its protected-file write")
	}
	approved := make(chan error, 1)
	go func() { approved <- persistSSHJumpPin(ctx, snapshot, target, pin) }()
	var approvalErr error
	completed := false
	select {
	case approvalErr = <-approved:
		completed = true
	case <-time.After(2 * time.Second):
		// A correctly serialized trust write waits for the other process's rollback.
	}
	if _, err := fmt.Fprintln(stdin, "resume"); err != nil {
		t.Fatal(err)
	}
	if !reader.Scan() || reader.Text() != "ROLLED_BACK" {
		t.Fatal("parallel editor did not roll back")
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("parallel editor failed: %v", err)
	}
	if !completed {
		approvalErr = <-approved
	}
	if approvalErr != nil {
		t.Fatal(approvalErr)
	}
	saved, err := readTunnel(path, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(saved.Settings)
	if !bytes.Contains(saved.Settings, []byte(pin)) {
		t.Fatal("another process's failed save rolled back a newly approved SSH host key")
	}
}

func TestSSHJumpTrustCannotFollowAConcurrentInheritedHostChange(t *testing.T) {
	host, port, pin := jumpTestServer(t)
	path, details := jumpFixture(t, host, port)
	jumpExec(t, path, "UPDATE Nodes SET Host=NULL WHERE Id=?;", jumpNodeID)
	jumpExec(t, path, "UPDATE Nodes SET Host=? WHERE Id=?;", host, jumpFolderID)
	snapshot := jumpSnapshot(t, path, details.ID)
	target, err := resolveSSHJumpTarget(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec("UPDATE Nodes SET Host='changed-bastion.test',UpdatedAt='changed' WHERE Id=?;", jumpFolderID); err != nil {
		t.Fatal(err)
	}
	resolved, resume := make(chan struct{}), make(chan struct{})
	var signalled, resumed sync.Once
	defer resumed.Do(func() { close(resume) })
	previous := sshCredentialPrivateKeyLock
	sshCredentialPrivateKeyLock = func(path string) (func(), error) {
		release, err := previous(path)
		if err != nil {
			return nil, err
		}
		return func() {
			release()
			signalled.Do(func() { close(resolved) })
			<-resume
		}, nil
	}
	t.Cleanup(func() { sshCredentialPrivateKeyLock = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- persistSSHJumpPin(ctx, snapshot, target, pin) }()
	select {
	case <-resolved:
	case <-ctx.Done():
		t.Fatal("trust writer did not resolve its original connection")
	}
	// Publish a folder edit after the trust writer has resolved the old host, but before
	// its SQLite fingerprint update can acquire the writer reservation.
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	resumed.Do(func() { close(resume) })
	if err := <-done; err == nil {
		t.Fatal("fingerprint approved for the old host was stored after the inherited host changed")
	}
	saved, err := readTunnel(path, tunnelReadRequest{ID: details.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(saved.Settings)
	if saved.JumpHostKeySha256 != "" {
		t.Fatal("the new inherited host acquired the old host's fingerprint")
	}
}

func TestSSHJumpNodeTrustFailsClosedOnMissingContextAndDatabaseErrors(t *testing.T) {
	for _, scenario := range []string{"missing-context", "cancelled", "unavailable", "deleted", "already-pinned", "reserve-fails", "write-fails"} {
		t.Run(scenario, func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			snapshot := jumpSnapshot(t, path, details.ID)
			target, err := resolveSSHJumpTarget(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			attemptPath, expected := path, ""
			switch scenario {
			case "missing-context":
				target.nodeTrustContext = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "unavailable":
				attemptPath = t.TempDir()
			case "deleted":
				jumpExec(t, path, "DELETE FROM Nodes WHERE Id=?;", jumpNodeID)
			case "already-pinned":
				_, _, expected = jumpTestServer(t)
				jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", expected, jumpNodeID)
				target, err = resolveSSHJumpTarget(snapshot)
				if err != nil {
					t.Fatal(err)
				}
			case "reserve-fails":
				jumpExec(t, path, "CREATE TRIGGER deny_reserve BEFORE UPDATE OF UpdatedAt ON Nodes BEGIN SELECT RAISE(ABORT, 'test reservation failure'); END;")
			case "write-fails":
				jumpExec(t, path, "CREATE TRIGGER deny_pin BEFORE UPDATE OF SshKnownHostFingerprint ON Nodes BEGIN SELECT RAISE(ABORT, 'test write failure'); END;")
			}
			if err := persistSSHJumpNodePin(ctx, attemptPath, target, pin); err == nil {
				t.Fatal("invalid or failed trust transaction succeeded")
			}
			saved, err := readTunnel(path, tunnelReadRequest{ID: details.ID})
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(saved.Settings)
			if saved.JumpHostKeySha256 != expected {
				t.Fatal("failed trust transaction modified the pinned key")
			}
		})
	}
}
