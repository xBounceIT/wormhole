package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func sharedSetupTestHandler(t *testing.T) (*vaultFoundationHandler, map[string]any) {
	t.Helper()
	protection := startupTestProtection()
	return &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db"), sharedProtection: &protection}, map[string]any{
		"hosting": "managed", "host": "127.0.0.1", "port": 5432, "database": "wormhole", "caPem": sharedControllerCA(t),
	}
}

func setupTestCall(t *testing.T, h *vaultFoundationHandler, action string, input map[string]any) sharedSetupReply {
	t.Helper()
	var payload []byte
	if input != nil {
		payload = vaultInput(t, input)
	}
	raw, err := h.Handle(context.Background(), "shared-setup-"+action, payload)
	var reply sharedSetupReply
	if err != nil || json.Unmarshal(raw, &reply) != nil {
		t.Fatal("setup action", action, err)
	}
	return reply
}

func TestSharedSetupPlanSurvivesRestartAndPinsExport(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	if out := setupTestCall(t, h, "plan", nil); out.Plan != nil {
		t.Fatal("unexpected initial plan")
	}
	first := setupTestCall(t, h, "prepare", request).Plan
	if first == nil || first.State != setupPrepared || len(first.RoleTag) != 16 || first.Hosting != "managed" {
		t.Fatal("invalid generated plan", first)
	}
	next := &vaultFoundationHandler{databasePath: h.databasePath, sharedProtection: h.sharedProtection}
	if restored := setupTestCall(t, next, "plan", nil).Plan; restored == nil || *restored != *first {
		t.Fatal("plan identity changed after restart")
	}
	if _, err := next.Handle(context.Background(), "shared-setup-prepare", vaultInput(t, request)); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("existing plan was replaced", err)
	}
	identity := map[string]any{"workspaceId": first.WorkspaceID}
	destination := filepath.Join(filepath.Dir(h.databasePath), "setup.sql")
	export := setupTestCall(t, next, "export", map[string]any{"workspaceId": first.WorkspaceID, "path": destination})
	script, err := os.ReadFile(destination)
	if err != nil || export.Failure != "" || export.Plan.State != setupExported || !strings.Contains(string(script), first.WorkspaceID) || !strings.Contains(string(script), "wh_"+first.RoleTag+"_owner") {
		t.Fatal("export was not bound to plan")
	}
	second := filepath.Join(filepath.Dir(h.databasePath), "repeat.sql")
	again := setupTestCall(t, h, "export", map[string]any{"workspaceId": first.WorkspaceID, "path": second})
	repeat, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(repeat, script) || *again.Plan != *export.Plan {
		t.Fatal("export could not resume exact identity")
	}
	if err := os.WriteFile(second, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if failed := setupTestCall(t, h, "export", map[string]any{"workspaceId": first.WorkspaceID, "path": second}); failed.Failure != "export-failed" {
		t.Fatal("existing path was accepted")
	}
	if raw, err := os.ReadFile(second); err != nil || string(raw) != "existing" {
		t.Fatal("existing file was replaced", err)
	}
	if _, err := next.Handle(context.Background(), "shared-setup-discard", vaultInput(t, identity)); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("exported plan was discarded", err)
	}
	if blocked := setupTestCall(t, next, "run", identity); blocked.Failure != "check-required" {
		t.Fatal("exported plan allowed SQL dispatch", blocked)
	}
}

func TestSharedSetupExportHBA(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	request["hosting"] = "self-hosted"
	plan := setupTestCall(t, h, "prepare", request).Plan
	path := filepath.Join(t.TempDir(), "workspace.conf")
	args := map[string]any{"workspaceId": plan.WorkspaceID, "path": path, "networks": []string{"127.1.2.3/8"}}
	if got := setupTestCall(t, h, "export-hba", args); got.Failure != "invalid-networks" {
		t.Fatal("invalid client networks", got)
	}
	args["networks"] = []string{"127.0.0.1"}
	if got := setupTestCall(t, h, "export-hba", args); got.Failure != "" || *got.Plan != *plan {
		t.Fatal("export changed deployment state", got)
	}
	rules, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(rules), " /^wh_"+plan.RoleTag+"_ 127.0.0.1/32 scram-sha-256") {
		t.Fatal("workspace rules missing", err)
	}
	args["networks"] = []string{"::1"}
	if got := setupTestCall(t, h, "export-hba", args); got.Failure != "export-failed" {
		t.Fatal("existing destination accepted", got)
	}
	if unchanged, err := os.ReadFile(path); err != nil || !bytes.Equal(rules, unchanged) {
		t.Fatal("existing HBA file changed")
	}
	args["path"] = filepath.Join(t.TempDir(), "script.sql")
	if _, err := h.Handle(context.Background(), "shared-setup-export-hba", vaultInput(t, args)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("invalid HBA destination", err)
	}
	managed, request := sharedSetupTestHandler(t)
	args["path"] = path
	args["workspaceId"] = setupTestCall(t, managed, "prepare", request).Plan.WorkspaceID
	if _, err := managed.Handle(context.Background(), "shared-setup-export-hba", vaultInput(t, args)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("managed deployment accepted HBA export", err)
	}
}

func TestSharedSetupOnlyDiscardsPreparedPlans(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	request["hosting"] = "self-hosted"
	first := setupTestCall(t, h, "prepare", request).Plan
	if out := setupTestCall(t, h, "discard", map[string]any{"workspaceId": first.WorkspaceID}); out.Plan != nil {
		t.Fatal("discard left a plan")
	}
	second := setupTestCall(t, h, "prepare", request).Plan
	if second.WorkspaceID == first.WorkspaceID || second.RoleTag == first.RoleTag {
		t.Fatal("new plan reused discarded identity")
	}
	if _, err := h.Handle(context.Background(), "shared-setup-export", vaultInput(t, map[string]any{"workspaceId": first.WorkspaceID})); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("stale document accepted", err)
	}
}

func TestSharedSetupUncertainDispatchRetainsPlan(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	first := setupTestCall(t, h, "prepare", request).Plan
	path := sharedSetupPlanPath(h.databasePath)
	plan, err := readSharedSetupPlan(path, h.startupProtection())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	settings := sharedpg.Settings{DeviceRole: "fixture"}
	if _, err := runSharedSetup(ctx, path, &plan, settings, []byte("test-dba-password"), h.startupProtection()); err == nil {
		t.Fatal("canceled attempt reported success")
	}
	next := &vaultFoundationHandler{databasePath: h.databasePath, sharedProtection: h.sharedProtection}
	stored := setupTestCall(t, next, "plan", nil).Plan
	if stored.WorkspaceID != first.WorkspaceID || stored.State != setupSubmitted {
		t.Fatal("lost dispatch did not retain plan", stored)
	}
	if reply := setupTestCall(t, next, "run", map[string]any{"workspaceId": first.WorkspaceID}); reply.Failure != "check-required" {
		t.Fatal("restarted process repeated DDL")
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte("test-dba-password")) {
		t.Fatal("password appeared in plan file", err)
	}
}

func TestSharedSetupWriteRefusalKeepsThePreparedReceipt(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	draft := setupTestCall(t, h, "prepare", request).Plan
	protection := h.startupProtection()
	path := sharedSetupPlanPath(h.databasePath)
	plan, err := readSharedSetupPlan(path, protection)
	if err != nil {
		t.Fatal(err)
	}
	protection.protect = nil
	credentials := vaultInput(t, map[string]any{"workspaceId": draft.WorkspaceID, "role": "dba", "password": []byte("synthetic")})
	raw, err := executeSharedSetup(context.Background(), path, plan, "shared-setup-run", credentials, protection)
	var reply sharedSetupReply
	if err != nil || json.Unmarshal(raw, &reply) != nil || reply.Failure != "unavailable" || reply.Plan == nil || *reply.Plan != *draft {
		t.Fatal("storage refusal reported a submitted deployment", err)
	}
	stored := setupTestCall(t, h, "plan", nil).Plan
	if stored == nil || *stored != *draft {
		t.Fatal("failed intent write changed the prepared plan")
	}
}

func TestSharedSetupRejectsInvalidOrReplacedInput(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	for _, payload := range []string{`{}`, `{"hosting":"managed","hosting":"self-hosted"}`, `{"hosting":"managed","host":"localhost","port":5432,"database":"test","caPem":""}`} {
		if raw, err := h.Handle(context.Background(), "shared-setup-prepare", []byte(payload)); err == nil || raw != nil {
			t.Fatal("invalid target accepted")
		}
	}
	for _, payload := range []string{`{}`, `{"workspaceId":"x","role":"dba","password":[1,2]}`, `{"workspaceId":"x","role":"dba","password":"!"}`, `{"workspaceId":"x","role":"dba","password":"AA=="}`} {
		if _, password, err := setupCredentials([]byte(payload), "x"); password != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid password accepted")
		}
	}
	plan := setupTestCall(t, h, "prepare", request).Plan
	role, password, err := setupCredentials(vaultInput(t, map[string]any{"workspaceId": plan.WorkspaceID, "role": "dba", "password": []byte("synthetic")}), plan.WorkspaceID)
	if err != nil || role != "dba" || string(password) != "synthetic" {
		t.Fatal("valid credentials refused", err)
	}
	clear(password)
	path := sharedSetupPlanPath(h.databasePath)
	other := filepath.Join(filepath.Dir(path), "other.db.shared-setup")
	raw, err := os.ReadFile(path)
	if err != nil || os.WriteFile(other, raw, 0600) != nil {
		t.Fatal("could not preserve synthetic setup fixture", err)
	}
	if _, err := readSharedSetupPlan(other, h.startupProtection()); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("path substitution accepted", err)
	}
	protection := h.startupProtection()
	plaintext, err := protection.unprotect(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	nonCanonical, err := protection.protect(path, append(plaintext, '\n'))
	if err != nil || os.WriteFile(path, nonCanonical, 0600) != nil {
		t.Fatal("could not prepare authenticated but noncanonical setup fixture", err)
	}
	if _, err := readSharedSetupPlan(path, protection); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("noncanonical setup data was accepted", err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(context.Background(), "shared-setup-prepare", vaultInput(t, request)); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("corrupt plan was overwritten", err)
	}
}
