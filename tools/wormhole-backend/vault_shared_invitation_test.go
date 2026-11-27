package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func TestSharedInvitationInspectionAndNativeFileContainOnlyPublicHints(t *testing.T) {
	h, _, _, source, input, _ := initialJoinFixture(t)
	token := input["invitation"].(string)
	file := filepath.Join(t.TempDir(), "workspace.whinv")
	if err := os.WriteFile(file, []byte(" "+token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"shared-invitation-inspect", "shared-invitation-file"} {
		payload := map[string]any{"invitation": " " + token + "\n"}
		if operation == "shared-invitation-file" {
			payload = map[string]any{"path": file}
		}
		raw, err := h.Handle(context.Background(), operation, vaultInput(t, payload))
		var result map[string]string
		if err != nil || json.Unmarshal(raw, &result) != nil || len(result) != 4 || result["invitation"] != token || result["loginName"] != "alice" || result["workspaceId"] == "" || result["tls"] == "" {
			t.Fatal("invalid public invitation hints", err)
		}
		if source.calls != 0 || source.opens != 0 || h.shared != nil || h.owner != nil {
			t.Fatal("inspection created an owner or contacted PostgreSQL")
		}
		if !h.ExitOnCancel(operation) {
			t.Fatal("file inspection cannot retire a blocked owner")
		}
	}
	if _, err := os.Lstat(h.databasePath); !os.IsNotExist(err) {
		t.Fatal("inspection created local SQLite", err)
	}
}

func TestSharedInvitationInspectionFailsClosedWithoutReturningSelectedFileContents(t *testing.T) {
	h, _, _, source, input, _ := initialJoinFixture(t)
	token := input["invitation"].(string)
	i, err := sharedpg.DecodeInvitation(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"malformed", "unknown", "duplicate", "null", "old-version", "controls", "large-token", "large-payload", "relative-file", "unclean-file", "missing-file", "directory", "private-file", "oversized-file", "local-workspace", "shared-workspace", "cancelled", "nil-context", "closed"} {
		t.Run(mode, func(t *testing.T) {
			operation := "shared-invitation-inspect"
			payload := vaultInput(t, map[string]any{"invitation": token})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "malformed":
				payload = []byte(`{"invitation":"WHINV2-invalid"}`)
			case "unknown":
				payload = vaultInput(t, map[string]any{"invitation": token, "role": "administrator"})
			case "duplicate":
				payload = append([]byte(`{"invitation":"other",`), payload[1:]...)
			case "null":
				payload = []byte(`{"invitation":null}`)
			case "old-version", "controls":
				inv := i
				if mode == "old-version" {
					inv.FormatVersion, inv.Enrollment = 1, nil
				} else {
					enrollment := *i.Enrollment
					inv.Enrollment = &enrollment
					inv.LoginName = "alice\n"
					inv.Enrollment.Context.LoginName = inv.LoginName
				}
				text, e := sharedpg.EncodeInvitation(inv, time.Now())
				if e != nil {
					t.Fatal(e)
				}
				payload = vaultInput(t, map[string]any{"invitation": text})
			case "large-token":
				payload = vaultInput(t, map[string]any{"invitation": strings.Repeat("x", maxSharedInvitationInput+1)})
			case "large-payload":
				payload = make([]byte, 8*maxSharedInvitationInput+1)
			case "relative-file", "unclean-file", "missing-file", "directory", "private-file", "oversized-file":
				operation = "shared-invitation-file"
				path := filepath.Join(t.TempDir(), "invitation.whinv")
				switch mode {
				case "relative-file":
					path = "relative.whinv"
				case "unclean-file":
					path = filepath.Dir(path) + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(path)
				case "directory":
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
				case "private-file":
					if e := os.WriteFile(path, []byte("private selected-file sentinel"), 0600); e != nil {
						t.Fatal(e)
					}
				case "oversized-file":
					if e := os.WriteFile(path, make([]byte, maxSharedInvitationInput+1), 0600); e != nil {
						t.Fatal(e)
					}
				}
				payload = vaultInput(t, map[string]any{"path": path})
			case "local-workspace":
				if e := os.WriteFile(h.databasePath, []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
				defer os.Remove(h.databasePath)
			case "shared-workspace":
				path := sharedWorkspaceDirectory(h.databasePath)
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
				defer os.Remove(path)
			case "cancelled":
				cancel()
			case "nil-context":
				ctx = nil
			case "closed":
				h.closed = true
				defer func() { h.closed = false }()
			}
			raw, err := h.inspectSharedInvitation(ctx, operation == "shared-invitation-file", payload)
			if err == nil || len(raw) != 0 || source.opens != 0 || source.calls != 0 {
				t.Fatal("invalid invitation exposed contents or opened a connection", mode, err)
			}
		})
	}
}
