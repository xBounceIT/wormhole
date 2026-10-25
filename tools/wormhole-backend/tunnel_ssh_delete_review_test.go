package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func jumpDeleteReviewCases() []struct {
	name, table, id string
	remove          func(string) error
} {
	return []struct {
		name, table, id string
		remove          func(string) error
	}{
		{"credential", "CredentialProfiles", jumpCredentialID, func(path string) error {
			return deleteCredential(path, credentialDeleteRequest{ID: jumpCredentialID})
		}},
		{"folder", "Nodes", jumpFolderID, func(path string) error {
			_, err := deleteWorkspaceNode(path, workspaceNodeRequest{NodeID: jumpFolderID})
			return err
		}},
	}
}

func TestSSHJumpDeletionWaitsForTunnelWriter(t *testing.T) {
	for _, scenario := range jumpDeleteReviewCases() {
		for _, lock := range []string{"in-process", "native"} {
			t.Run(scenario.name+"/"+lock, func(t *testing.T) {
				path, details := jumpFixture(t, "bastion.test", 22)
				var release func()
				if lock == "in-process" {
					tunnelMutationMu.Lock()
					release = tunnelMutationMu.Unlock
				} else {
					var err error
					release, err = acquireTunnelConfigurationLock(context.Background(), path)
					if err != nil {
						t.Fatal(err)
					}
				}
				var once sync.Once
				unlock := func() { once.Do(release) }
				defer unlock()
				started, done := make(chan struct{}), make(chan error, 1)
				finished := false
				t.Cleanup(func() {
					unlock()
					if !finished {
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("deletion did not finish after releasing the tunnel writer")
						}
					}
				})
				go func() {
					close(started)
					done <- scenario.remove(path)
				}()
				<-started
				select {
				case err := <-done:
					finished = true
					t.Fatalf("deletion checked references while a tunnel writer held its lock: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				// Complete the other writer's removal before releasing its lock. The pending
				// deletion must inspect the committed references, not reject the older route.
				jumpExec(t, path, "DELETE FROM TunnelConfigs WHERE Id=?;", details.ID)
				unlock()
				select {
				case err := <-done:
					finished = true
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("deletion stayed blocked after the tunnel writer committed")
				}
				database, err := openDatabase(path, true)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				var count int
				if err := database.QueryRow("SELECT COUNT(*) FROM "+scenario.table+" WHERE Id=?;", scenario.id).Scan(&count); err != nil || count != 0 {
					t.Fatalf("unreferenced entry was not deleted: count=%d, err=%v", count, err)
				}
			})
		}
	}
}

func TestSSHJumpDeletionFailsClosedWhenConfigurationLockIsUnavailable(t *testing.T) {
	for _, scenario := range jumpDeleteReviewCases() {
		t.Run(scenario.name, func(t *testing.T) {
			path, details := jumpFixture(t, "bastion.test", 22)
			if err := deleteTunnel(path, tunnelDeleteRequest{ID: details.ID}); err != nil {
				t.Fatal(err)
			}
			lockPath := tunnelConfigurationLockPath(path)
			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(lockPath, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := scenario.remove(path); err == nil {
				t.Fatal("deletion proceeded without its configuration lock")
			}
			database, err := openDatabase(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			var count int
			if err := database.QueryRow("SELECT COUNT(*) FROM "+scenario.table+" WHERE Id=?;", scenario.id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("failed lock acquisition modified the entry: count=%d, err=%v", count, err)
			}
		})
	}
}

func jumpCacheIdentityFixture() string {
	snapshot := tunnelConfigSnapshot{id: "jump", kind: 8}
	target := sshTarget{host: "bastion.test", port: 22, username: "ops", password: "fixed test password"}
	return sshJumpSnapshotIdentity(snapshot, &target, "", true)
}

func TestSSHJumpCacheIdentityProcessFixture(t *testing.T) {
	if os.Getenv("WORMHOLE_SSH_CACHE_IDENTITY_FIXTURE") != "1" {
		return
	}
	identity := jumpCacheIdentityFixture()
	if identity != jumpCacheIdentityFixture() {
		t.Fatal("unchanged credentials cannot reuse a stable process-local identity")
	}
	fmt.Fprintln(os.Stdout, "CACHE_IDENTITY "+identity)
}

func TestSSHJumpCacheIdentityIsProcessLocal(t *testing.T) {
	identity := jumpCacheIdentityFixture()
	if identity != jumpCacheIdentityFixture() {
		t.Fatal("unchanged credentials cannot share a tunnel in the same process")
	}
	seen := map[string]bool{identity: true}
	for index := 0; index < 2; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHJumpCacheIdentityProcessFixture$")
		command.Env = append(os.Environ(), "WORMHOLE_SSH_CACHE_IDENTITY_FIXTURE=1")
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("identity fixture failed: %v", err)
		}
		found := ""
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "CACHE_IDENTITY ") {
				if found != "" {
					t.Fatal("duplicate cache identity fixture result")
				}
				found = strings.TrimSpace(strings.TrimPrefix(line, "CACHE_IDENTITY "))
			}
		}
		if len(found) != 64 {
			t.Fatal("identity fixture did not emit a complete result")
		}
		if seen[found] {
			t.Fatal("credential-derived cache identities can be reused across processes")
		}
		seen[found] = true
	}
}
