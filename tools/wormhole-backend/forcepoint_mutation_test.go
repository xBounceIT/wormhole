package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type forcepointMutationFixture struct {
	Mode     string
	Database string
	ID       string
	Kind     int64
	Original json.RawMessage
	Next     json.RawMessage
}

// Run a real second backend process: a package-level mutex cannot protect this boundary.
func TestForcepointMutationProcessHelper(t *testing.T) {
	if os.Getenv("WORMHOLE_FORCEPOINT_MUTATION_HELPER") != "1" {
		return
	}
	var fixture forcepointMutationFixture
	if err := json.NewDecoder(os.Stdin).Decode(&fixture); err != nil {
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	_ = encoder.Encode(map[string]bool{"started": true})
	var err error
	snapshot := tunnelConfigSnapshot{databasePath: fixture.Database, id: fixture.ID}
	switch fixture.Mode {
	case "pin":
		err = persistForcepointPinIfUnchanged(snapshot, fixture.Original, fixture.Next)
	case "update":
		_, err = updateTunnel(fixture.Database, tunnelWriteRequest{ID: fixture.ID, Name: "Forcepoint", Kind: fixture.Kind, Settings: fixture.Next})
	case "delete":
		err = deleteTunnel(fixture.Database, tunnelDeleteRequest{ID: fixture.ID})
	case "other-provider-trust":
		persistStormshieldTrustIfUnchanged(snapshot, fixture.Original, fixture.Next)
	default:
		os.Exit(3)
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	_ = encoder.Encode(map[string]string{"error": message})
	os.Exit(0)
}

func TestForcepointTrustAndProfileMutationsSerializeAcrossProcesses(t *testing.T) {
	for _, mode := range []string{"pin", "update", "delete", "other-provider-trust"} {
		t.Run(mode, func(t *testing.T) {
			settings := forcepointSettingsForTest()
			kind := int64(7)
			if mode == "other-provider-trust" {
				kind = 4
				settings["Server"] = "vpn.example.test"
			}
			raw, _ := json.Marshal(settings)
			path := filepath.Join(t.TempDir(), "wormhole.db")
			created, err := createTunnel(path, tunnelWriteRequest{Name: "Forcepoint", Kind: kind, Settings: raw})
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(created.Settings)
			switch mode {
			case "pin":
				settings["ServerCertSha256Pin"] = strings.Repeat("ab", 32)
			case "update":
				settings["Password"] = "new-password"
			case "other-provider-trust":
				settings["TrustServerCertificate"] = true
			}
			next, _ := json.Marshal(settings)
			defer clearBytes(next)
			release, err := acquireExclusiveFileLock(filepath.Join(filepath.Dir(path), ".tunnels.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if release != nil {
					release()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestForcepointMutationProcessHelper$")
			command.Env = append(os.Environ(), "WORMHOLE_FORCEPOINT_MUTATION_HELPER=1")
			payload, _ := json.Marshal(forcepointMutationFixture{Mode: mode, Database: path, ID: created.ID, Kind: kind, Original: created.Settings, Next: next})
			defer clearBytes(payload)
			command.Stdin = bytes.NewReader(payload)
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
			decoder := json.NewDecoder(output)
			var started map[string]bool
			if err := decoder.Decode(&started); err != nil || !started["started"] {
				t.Fatal("second backend did not reach the mutation", err)
			}
			type result struct {
				response map[string]string
				err      error
			}
			completed := make(chan result, 1)
			go func() {
				var response map[string]string
				err := decoder.Decode(&response)
				completed <- result{response: response, err: err}
			}()
			select {
			case <-completed:
				t.Fatal("a second backend mutated the tunnel while another process held its storage lock")
			case <-time.After(200 * time.Millisecond):
			}
			if mode == "pin" {
				// Commit newer credentials while the competing consent is waiting.
				delete(settings, "ServerCertSha256Pin")
				settings["Password"] = "new-password"
				updated, _ := json.Marshal(settings)
				defer clearBytes(updated)
				if err := protectFile(legacyTunnelSecretPath(path, created.ID), updated); err != nil {
					t.Fatal(err)
				}
			}
			release()
			release = nil
			var finished result
			select {
			case finished = <-completed:
			case <-ctx.Done():
				t.Fatal("second backend did not resume after the lock was released")
			}
			if finished.err != nil {
				t.Fatal("second backend lost its result", finished.err)
			}
			if mode == "pin" {
				if !strings.Contains(finished.response["error"], "tunnel changed") {
					t.Fatal("stale certificate consent did not reject the newer settings")
				}
			} else if finished.response["error"] != "" {
				t.Fatal(finished.response["error"])
			}
			saved, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
			if mode == "delete" {
				if err == nil {
					t.Fatal("profile deletion did not complete")
				}
				if _, err := os.Stat(legacyTunnelSecretPath(path, created.ID)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("deleted profile retained its protected credentials", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(saved.Settings)
			var values map[string]json.RawMessage
			_ = json.Unmarshal(saved.Settings, &values)
			defer clearTunnelSettingsMap(values)
			if mode == "other-provider-trust" {
				if !tunnelSettingBool(values, "TrustServerCertificate") {
					t.Fatal("the existing provider trust flow did not resume")
				}
			} else if tunnelSettingString(values, "Password") != "new-password" || tunnelSettingString(values, "ServerCertSha256Pin") != "" {
				t.Fatal("concurrent consent replaced newer credentials or certificate trust")
			}
		})
	}
}

func TestForcepointMutationLockFailureLeavesSettingsUntouched(t *testing.T) {
	settings := forcepointSettingsForTest()
	raw, _ := json.Marshal(settings)
	path := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(path, tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(created.Settings)
	lockPath := filepath.Join(filepath.Dir(path), ".tunnels.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	settings["Password"] = "must-not-save"
	next, _ := json.Marshal(settings)
	defer clearBytes(next)
	snapshot := tunnelConfigSnapshot{databasePath: path, id: created.ID}
	if err := persistForcepointPinIfUnchanged(snapshot, created.Settings, next); err == nil || err.Error() != "could not lock VPN tunnel storage" {
		t.Fatal("certificate persistence ignored a storage lock failure", err)
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: created.Name, Kind: 7, Settings: next}); err == nil {
		t.Fatal("profile update ignored a storage lock failure")
	}
	if err := deleteTunnel(path, tunnelDeleteRequest{ID: created.ID}); err == nil {
		t.Fatal("profile deletion ignored a storage lock failure")
	}
	persistStormshieldTrustIfUnchanged(snapshot, created.Settings, next)
	saved, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
	if err != nil || !bytes.Equal(saved.Settings, created.Settings) {
		t.Fatal("lock failure changed protected settings or metadata", err)
	}
	defer clearBytes(saved.Settings)
	blockedDirectory := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blockedDirectory, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireTunnelMutationLock(filepath.Join(blockedDirectory, "wormhole.db")); err == nil || err.Error() != "could not prepare VPN tunnel storage" {
		t.Fatal("unavailable storage did not return a sanitized preparation error", err)
	}
}
