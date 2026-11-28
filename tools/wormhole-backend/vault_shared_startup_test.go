package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func TestVaultSharedStartupProjection(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{true: "pending-password", false: "ordinary"}[pending], func(t *testing.T) {
			h, f, _, probe := vaultSharedFixture(t)
			device, err := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
			if err != nil {
				t.Fatal(err)
			}
			slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(device)
			if err != nil {
				t.Fatal(err)
			}
			expectedID := slots.Slots[len(slots.Slots)-1].ID
			if pending {
				// Pre-unlock projection deliberately cannot authenticate this inner
				// journal. It may show only slot hints, never grant recovery authority.
				candidateID := uuid.NewString()
				candidate := bytes.ReplaceAll(device, []byte(expectedID), []byte(candidateID))
				expectedID = candidateID
				wrapper := struct {
					FormatVersion uint16          `json:"formatVersion"`
					Device        json.RawMessage `json:"device"`
					Transition    json.RawMessage `json:"transition"`
				}{3, candidate, json.RawMessage(`{"private":"journal-sentinel"}`)}
				raw, err := json.Marshal(wrapper)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sharedTrustTransitionPath(f.o.TrustPath), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(sharedWorkspaceDirectory(h.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := h.Handle(context.Background(), "startup", nil)
			if err != nil {
				t.Fatal(err)
			}
			var result vaultStartupMetadata
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if result.Shared == nil || result.Shared.LastLoginName != "alice" || result.Shared.ServerDisplayName != "Workspace" || result.NewWorkspace || result.Slots == nil || !result.Slots.Encrypted {
				t.Fatal("projection", string(raw))
			}
			if result.Slots.Slots[len(result.Slots.Slots)-1].ID != expectedID {
				t.Fatal("pending projection silently used active device")
			}
			var exact map[string]json.RawMessage
			if json.Unmarshal(raw, &exact) != nil || len(exact) != 4 {
				t.Fatal("unexpected startup fields")
			}
			if h.owner != nil || h.shared != nil || *probe != nil {
				t.Fatal("startup opened account/network")
			}
			for _, forbidden := range []string{"journal-sentinel", "binding", "trust", "ciphertext", "keyCheck", "wrapped", "salt", "localhost", "database", "workspaceId", "account", "kdf-low"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Fatal("private/native field leaked", forbidden)
				}
			}
			description, err := h.Handle(context.Background(), "describe", nil)
			if err != nil {
				t.Fatal(err)
			}
			var described struct {
				Slots any `json:"slots"`
			}
			if json.Unmarshal(description, &described) != nil || described.Slots == nil || bytes.Contains(description, []byte("alice")) {
				t.Fatal("describe leaked shared hints")
			}
			after, err := os.ReadDir(sharedWorkspaceDirectory(h.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("startup wrote files")
			}
			actual, err := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
			if err != nil || !bytes.Equal(actual, device) {
				t.Fatal("startup changed device", err)
			}
		})
	}
}

func TestVaultSharedStartupFailureIsNotLocalFallback(t *testing.T) {
	for _, mode := range []string{"missing-anchor", "bad-protection", "missing-device", "bad-device", "enrollment", "bad-journal", "journal-directory", "local-db", "local-slots", "locked", "canceled", "identity", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			h, f, _, probe := vaultSharedFixture(t)
			ctx := context.Background()
			switch mode {
			case "missing-anchor":
				if err := os.Remove(sharedStartupAnchorPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "bad-protection":
				h.sharedProtection.unprotect = func(string, []byte) ([]byte, error) { return nil, os.ErrPermission }
			case "missing-device":
				if err := os.Remove(sharedDeviceEnrollmentPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "bad-device":
				if err := os.WriteFile(sharedDeviceEnrollmentPath(f.o.TrustPath), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "enrollment":
				if err := os.WriteFile(sharedPendingEnrollmentPath(f.o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-journal":
				if err := os.WriteFile(sharedTrustTransitionPath(f.o.TrustPath), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "journal-directory":
				if err := os.Mkdir(sharedTrustTransitionPath(f.o.TrustPath), 0700); err != nil {
					t.Fatal(err)
				}
			case "local-db":
				if err := os.WriteFile(h.databasePath, []byte("private"), 0600); err != nil {
					t.Fatal(err)
				}
			case "local-slots":
				if err := os.WriteFile(vaultSlotPath(h.databasePath), []byte("private"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				release, err := tryAcquireExclusiveFileLock(f.o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "identity", "sequence":
				a, err := readSharedStartupAnchor(f.o.TrustPath, h.startupProtection())
				if err != nil {
					t.Fatal(err)
				}
				if mode == "identity" {
					a.FileID = a.VaultID
				} else {
					a.MinimumSequence++
				}
				raw, err := json.Marshal(a)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = h.startupProtection().protect("", raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sharedStartupAnchorPath(f.o.TrustPath), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, operation := range []string{"startup", "describe"} {
				raw, err := h.Handle(ctx, operation, nil)
				if err == nil || len(raw) != 0 || h.owner != nil || h.shared != nil || *probe != nil {
					t.Fatal("failed shared profile fell back", operation, err)
				}
			}
		})
	}
	h := &vaultFoundationHandler{databasePath: "relative"}
	if _, _, err := h.describeSharedStartup(context.Background()); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if _, _, err := h.describeSharedStartup(nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	h.databasePath = filepath.Join(t.TempDir(), "removed.db")
	h.shared = &vaultSharedSession{}
	for _, operation := range []string{"startup", "describe"} {
		if raw, err := h.Handle(context.Background(), operation, nil); err != errSharedTrustStorage || len(raw) != 0 {
			t.Fatal("active shared profile disappeared into local startup", err)
		}
	}
}
