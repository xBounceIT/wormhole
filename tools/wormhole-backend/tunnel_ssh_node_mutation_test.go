package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const jumpMoveFolderID = "44444444-4444-4444-8444-444444444444"

func jumpNodeMutationCases() []struct {
	name   string
	mutate func(string) error
} {
	return []struct {
		name   string
		mutate func(string) error
	}{
		{"credential-settings", func(path string) error {
			return updateWorkspaceNodeCredentialSettings(path, workspaceNodeCredentialSettingsRequest{NodeID: jumpNodeID, Mode: 2, CredentialID: jumpCredentialID})
		}},
		{"inherited-credential-settings", func(path string) error {
			return updateWorkspaceNodeCredentialSettings(path, workspaceNodeCredentialSettingsRequest{NodeID: jumpFolderID, Mode: 1})
		}},
		{"update-connection", func(path string) error {
			return updateWorkspaceNode(path, workspaceNodeWriteRequest{ID: jumpNodeID, Name: "Rebound", Kind: "connection", Protocol: "ssh", Host: "bastion.test", Port: 22, CredentialMode: 2, CredentialID: jumpCredentialID})
		}},
		{"update-folder", func(path string) error {
			return updateWorkspaceNode(path, workspaceNodeWriteRequest{ID: jumpFolderID, Name: "Rebound folder", Kind: "folder", CredentialMode: 1})
		}},
		{"inline-credential", func(path string) error {
			return updateWorkspaceNodeInlineCredential(path, workspaceNodeInlineCredentialRequest{NodeID: jumpNodeID, Protocol: "ssh", Username: "inline", Password: "replacement"})
		}},
		{"move-inheritance", func(path string) error {
			return moveWorkspaceNodes(path, workspaceMoveNodesRequest{NodeIDs: []string{jumpNodeID}, TargetID: jumpMoveFolderID, Placement: "inside"})
		}},
		{"create-connection", func(path string) error {
			_, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "New binding", Kind: "connection", Protocol: "ssh", Host: "bastion.test", CredentialMode: 2, CredentialID: jumpCredentialID})
			return err
		}},
		{"duplicate-connection", func(path string) error {
			_, err := duplicateWorkspaceNode(path, workspaceNodeRequest{NodeID: jumpNodeID})
			return err
		}},
	}
}

func jumpNodeMutationFixture(t *testing.T) string {
	t.Helper()
	path, _ := jumpFixture(t, "bastion.test", 22)
	jumpExec(t, path, `INSERT INTO Nodes (Id,Name,Kind,SortOrder,CredentialMode,CreatedAt,UpdatedAt) VALUES (?,'Destination',0,1,1,'now','now');`, jumpMoveFolderID)
	return path
}

func TestSSHJumpNodeMutationsWaitForGuardedDeletion(t *testing.T) {
	for _, scenario := range jumpNodeMutationCases() {
		for _, lock := range []string{"in-process", "native"} {
			t.Run(scenario.name+"/"+lock, func(t *testing.T) {
				path := jumpNodeMutationFixture(t)
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
				done := make(chan error, 1)
				finished := false
				t.Cleanup(func() {
					unlock()
					if !finished {
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("node mutation did not finish after guarded deletion released its lock")
						}
					}
				})
				go func() { done <- scenario.mutate(path) }()
				select {
				case err := <-done:
					finished = true
					t.Fatalf("node mutation bypassed guarded deletion: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				unlock()
				select {
				case err := <-done:
					finished = true
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("node mutation remained blocked after guarded deletion")
				}
			})
		}
	}
}

func TestSSHJumpNodeMutationsFailClosedWithoutConfigurationLock(t *testing.T) {
	for _, scenario := range jumpNodeMutationCases() {
		t.Run(scenario.name, func(t *testing.T) {
			path := jumpNodeMutationFixture(t)
			before := jumpNodeRows(t, path)
			lockPath := tunnelConfigurationLockPath(path)
			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(lockPath, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := scenario.mutate(path); err == nil {
				t.Fatal("node mutation proceeded without its configuration lock")
			}
			if after := jumpNodeRows(t, path); after != before {
				t.Fatal("failed lock acquisition modified workspace nodes")
			}
		})
	}
}

func TestSSHJumpNodeBindingValidatesAfterDeletionCommits(t *testing.T) {
	const deletedID = "55555555-5555-4555-8555-555555555555"
	for _, entry := range []string{"credential-settings", "inherited-credential-settings", "update-connection", "update-folder", "create-connection"} {
		t.Run(entry, func(t *testing.T) {
			path := jumpNodeMutationFixture(t)
			jumpExec(t, path, `INSERT INTO CredentialProfiles (Id,Name,Kind,Protocol,Username,CreatedAt) VALUES (?,'Unused',0,0,'ops','now');`, deletedID)
			before := jumpNodeRows(t, path)
			release, err := acquireTunnelConfigurationLock(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			unlock := func() { once.Do(release) }
			done := make(chan error, 1)
			finished := false
			t.Cleanup(func() {
				unlock()
				if !finished {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("binding did not finish after deletion committed")
					}
				}
			})
			go func() {
				if entry == "credential-settings" || entry == "inherited-credential-settings" {
					nodeID := jumpNodeID
					if entry == "inherited-credential-settings" {
						nodeID = jumpFolderID
					}
					done <- updateWorkspaceNodeCredentialSettings(path, workspaceNodeCredentialSettingsRequest{NodeID: nodeID, Mode: 2, CredentialID: deletedID})
					return
				}
				request := workspaceNodeWriteRequest{ID: jumpNodeID, Name: "Rebound", ParentID: jumpFolderID, Kind: "connection", Protocol: "ssh", Host: "bastion.test", CredentialMode: 2, CredentialID: deletedID}
				if entry == "create-connection" {
					_, err := createWorkspaceNode(path, request)
					done <- err
				} else {
					if entry == "update-folder" {
						request.ID, request.ParentID, request.Kind = jumpFolderID, "", "folder"
					}
					done <- updateWorkspaceNode(path, request)
				}
			}()
			select {
			case err := <-done:
				finished = true
				t.Fatalf("binding bypassed guarded deletion: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			// Model deletion's commit after its reference check. The pending binder must
			// validate this new state, never attach an identifier read before the lock.
			jumpExec(t, path, "DELETE FROM CredentialProfiles WHERE Id=?", deletedID)
			unlock()
			select {
			case err := <-done:
				finished = true
				if err == nil || !strings.Contains(err.Error(), "selected credential was not found") {
					t.Fatalf("binding did not reject the credential removed by deletion: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("binding remained blocked after deletion committed")
			}
			if jumpNodeRows(t, path) != before {
				t.Fatal("failed binding changed a node or attached a deleted credential")
			}
		})
	}
}

func jumpNodeRows(t *testing.T, path string) string {
	t.Helper()
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT Id,COALESCE(ParentId,''),Name,COALESCE(CredentialMode,0),COALESCE(CredentialId,''),COALESCE(Username,''),COALESCE(UseInlinePassword,0) FROM Nodes ORDER BY Id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var nodes [][]any
	for rows.Next() {
		var id, parent, name, credential, user string
		var mode, inline int
		if err := rows.Scan(&id, &parent, &name, &mode, &credential, &user, &inline); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, []any{id, parent, name, mode, credential, user, inline})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(nodes)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
