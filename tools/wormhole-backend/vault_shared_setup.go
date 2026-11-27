package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedSetupReply struct {
	Plan          *sharedSetupSummary                `json:"plan"`
	AdminPending  bool                               `json:"adminPending,omitempty"`
	Administrator *sharedpg.WorkspaceBootstrapStatus `json:"administrator,omitempty"`
	Recovery      *sharedAdminRecoveryDisplay        `json:"recovery,omitempty"`
	Preflight     *sharedpg.DeploymentPreflight      `json:"preflight,omitempty"`
	Deployment    *sharedpg.SchemaDeployment         `json:"deployment,omitempty"`
	Checks        *sharedpg.DeploymentChecks         `json:"checks,omitempty"`
	TLS           *sharedSetupTLSOutput              `json:"tls,omitempty"`
	ServerKit     *sharedSetupServerKitReceipt       `json:"serverKit,omitempty"`
	Import        *sharedSetupImportPreview          `json:"importPreview,omitempty"`
	Failure       string                             `json:"failure,omitempty"`
}

func (h *vaultFoundationHandler) sharedSetup(ctx context.Context, op string, payload []byte) (json.RawMessage, error) {
	limit := maxSharedSetupPlan
	if op == "shared-setup-import-review" {
		limit = vaultwire.MaxFrameBytes - 65536
	}
	if h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.migrationQuiesced ||
		!filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath || len(payload) > limit {
		return nil, vaultwire.ErrProtocol
	}
	if h.owner == nil {
		if err := requireNewVaultWorkspace(h.databasePath); err != nil {
			return nil, err
		}
	}
	path := sharedSetupPlanPath(h.databasePath)
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return nil, errSharedTrustConflict
	}
	defer release()
	protection := h.startupProtection()
	plan, err := readSharedSetupPlan(path, protection)
	missing := errors.Is(err, errSharedTrustMissing)
	if err != nil && !missing {
		return nil, err
	}
	if op == "shared-setup-plan" {
		if len(payload) != 0 {
			return nil, vaultwire.ErrProtocol
		}
		if missing {
			return json.Marshal(sharedSetupReply{})
		}
		pending, err := sharedAdminCheckpointExists(path)
		if err != nil {
			return nil, err
		}
		return json.Marshal(sharedSetupReply{Plan: &plan.Summary, AdminPending: pending, TLS: plan.tlsOutput(), ServerKit: plan.kitReceipt()})
	}
	if op == "shared-setup-prepare" {
		if !missing {
			return nil, errSharedTrustConflict
		}
		return prepareSharedSetup(path, payload, protection)
	}
	if op == "shared-setup-prepare-tls" || op == "shared-setup-prepare-generated-tls" {
		if !missing {
			return nil, errSharedTrustConflict
		}
		return prepareSharedSetupTLS(ctx, path, payload, protection, op == "shared-setup-prepare-generated-tls")
	}
	if missing {
		return nil, errSharedTrustMissing
	}
	if op == "shared-setup-export-hba" {
		return exportSharedSetupHBA(plan.Summary, payload)
	}
	if op == "shared-setup-save-server-kit" || op == "shared-setup-delete-server-key" {
		return changeSharedServerKit(ctx, path, plan, op, payload, protection)
	}
	if op == "shared-setup-export" || op == "shared-setup-discard" {
		return editSharedSetup(path, plan, op, payload, protection)
	}
	if op == "shared-setup-import-review" {
		return h.reviseSharedSetupImport(ctx, plan, payload)
	}
	if strings.HasPrefix(op, "shared-setup-admin-") {
		return h.sharedSetupAdministrator(ctx, path, plan, op, payload)
	}
	return executeSharedSetup(ctx, path, plan, op, payload, protection)
}

func prepareSharedSetup(path string, payload []byte, protection sharedStartupProtection) (json.RawMessage, error) {
	var summary sharedSetupSummary
	var ca []byte
	if decodeVaultObject(payload, map[string]any{
		"hosting": &summary.Hosting, "host": &summary.Host, "port": &summary.Port,
		"database": &summary.Database, "caPem": &ca,
	}, "hosting", "host", "port", "database", "caPem") != nil {
		return nil, vaultwire.ErrProtocol
	}
	plan, err := createSharedSetupPlan(path, summary, ca)
	if err != nil {
		return nil, err
	}
	if err := writeSharedSetupPlan(path, plan, protection); err != nil {
		return nil, err
	}
	return json.Marshal(sharedSetupReply{Plan: &plan.Summary})
}

func editSharedSetup(path string, plan sharedSetupPlan, op string, payload []byte, protection sharedStartupProtection) (json.RawMessage, error) {
	var id, destination string
	fields := map[string]any{"workspaceId": &id}
	required := []string{"workspaceId"}
	if op == "shared-setup-export" {
		fields["path"] = &destination
		required = append(required, "path")
	}
	if decodeVaultObject(payload, fields, required...) != nil || id != plan.Summary.WorkspaceID {
		return nil, vaultwire.ErrProtocol
	}
	if op == "shared-setup-discard" {
		if pending, err := sharedAdminCheckpointExists(path); err != nil || pending || plan.Summary.State != setupPrepared {
			return nil, errSharedTrustConflict
		}
		if err := discardUnpublishedServerKit(plan); err != nil {
			return nil, err
		}
		if err := discardSharedSetupPlan(path); err != nil {
			return nil, err
		}
		return json.Marshal(sharedSetupReply{})
	}
	if plan.Summary.State == setupSubmitted {
		return nil, errSharedTrustConflict
	}
	if !validSetupExportPath(destination, ".sql") {
		return nil, vaultwire.ErrProtocol
	}
	script, err := deploy.SchemaScript(plan.Summary.RoleTag, id)
	if err != nil {
		return nil, err
	}
	plan.Summary.State = setupExported
	if err := writeSharedSetupPlan(path, plan, protection); err != nil {
		return nil, err
	}
	if err := publishSharedSetupFile(destination, []byte(script)); err != nil {
		return json.Marshal(sharedSetupReply{Plan: &plan.Summary, Failure: "export-failed"})
	}
	return json.Marshal(sharedSetupReply{Plan: &plan.Summary})
}

func validSetupExportPath(path, extension string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 &&
		strings.EqualFold(filepath.Ext(path), extension) && !strings.ContainsRune(path, 0)
}

func exportSharedSetupHBA(plan sharedSetupSummary, payload []byte) (json.RawMessage, error) {
	var id, path string
	var networks []string
	if plan.Hosting != "self-hosted" || len(payload) > 16*1024 || decodeVaultObject(payload, map[string]any{
		"workspaceId": &id, "path": &path, "networks": &networks,
	}, "workspaceId", "path", "networks") != nil || id != plan.WorkspaceID || !validSetupExportPath(path, ".conf") {
		return nil, vaultwire.ErrProtocol
	}
	reply := sharedSetupReply{Plan: &plan}
	rules, err := sharedpg.DeploymentHBARules(plan.Database, plan.RoleTag, id, networks)
	if err != nil {
		reply.Failure = "invalid-networks"
	} else if err := publishSharedSetupFile(path, []byte(rules)); err != nil {
		reply.Failure = "export-failed"
	}
	return json.Marshal(reply)
}

// The main-owned file picker supplies an explicit destination. Publish a
// complete artifact without replacing any existing file at that destination.
func publishSharedSetupFile(destination string, data []byte) error {
	directory := filepath.Dir(destination)
	file, err := os.CreateTemp(directory, ".wormhole-setup-*")
	if err != nil {
		return err
	}
	stage := file.Name()
	defer os.Remove(stage)
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := publishVaultFile(stage, destination); err != nil {
		return err
	}
	return privateFileDirectorySync(directory)
}

func setupCredentials(payload []byte, expectedID string) (role string, password []byte, err error) {
	var id string
	var raw json.RawMessage
	defer func() { vault.Wipe(raw) }()
	if len(payload) > 4096 || decodeVaultObject(payload, map[string]any{"workspaceId": &id, "role": &role, "password": &raw}, "workspaceId", "role", "password") != nil ||
		id != expectedID || len(raw) == 0 || raw[0] != '"' {
		return "", nil, vaultwire.ErrProtocol
	}
	if json.Unmarshal(raw, &password) != nil || len(password) == 0 || len(password) > 1024 || !utf8.Valid(password) || bytes.IndexByte(password, 0) >= 0 {
		vault.Wipe(password)
		return "", nil, vaultwire.ErrProtocol
	}
	return role, password, nil
}

func executeSharedSetup(ctx context.Context, path string, plan sharedSetupPlan, op string, payload []byte, protection sharedStartupProtection) (json.RawMessage, error) {
	s := &plan.Summary
	if op == "shared-setup-run" && s.State != setupPrepared {
		return json.Marshal(sharedSetupReply{Plan: s, Failure: "check-required"})
	}
	role, password, err := setupCredentials(payload, s.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(password)
	settings := sharedpg.Settings{Endpoints: []sharedpg.Endpoint{{Host: s.Host, Port: s.Port}}, Database: s.Database, DeviceRole: role, TLS: sharedpg.TLSVerified, CAPEM: plan.CAPEM, Profile: vault.Standard}
	if plan.ServerKit != nil {
		if plan.ServerKit.State == serverKitPending {
			return nil, errSharedTrustConflict
		}
		settings, err = sharedpg.PinDeploymentServerCertificate(settings, plan.TLS.ServerPEM)
		if err != nil {
			return nil, err
		}
	}
	reply := sharedSetupReply{Plan: s}
	switch op {
	case "shared-setup-preflight":
		var report sharedpg.DeploymentPreflight
		report, err = sharedpg.CheckDeploymentPrerequisites(ctx, settings, password)
		if err == nil {
			reply.Preflight = &report
		}
	case "shared-setup-check", "shared-setup-run":
		var report sharedpg.SchemaDeployment
		if op == "shared-setup-check" {
			var inspection sharedpg.DeploymentInspection
			inspection, err = sharedpg.CheckSchemaDeployment(ctx, settings, password, s.RoleTag, s.WorkspaceID)
			if err == nil {
				report = inspection.SchemaDeployment
				reply.Checks = &inspection.Checks
			}
			if err == nil && report.RequiresTLS && plan.ServerKit != nil && plan.ServerKit.State == serverKitSaved {
				next := *plan.ServerKit
				next.State = serverKitVerified
				plan.ServerKit = &next
				if err := writeSharedSetupPlan(path, plan, protection); err != nil {
					return nil, err
				}
				reply.ServerKit = plan.kitReceipt()
			}
		} else {
			report, err = runSharedSetup(ctx, path, &plan, settings, password, protection)
		}
		if err == nil {
			reply.Deployment = &report
		}
	default:
		return nil, vaultwire.ErrProtocol
	}
	if err != nil {
		reply.Failure = setupFailure(err)
	}
	return json.Marshal(reply)
}

func runSharedSetup(ctx context.Context, path string, plan *sharedSetupPlan, settings sharedpg.Settings, password []byte, protection sharedStartupProtection) (sharedpg.SchemaDeployment, error) {
	// Persist intent before SQL. Reconciliation is read-only, even if a native
	// process exits after the transaction commits but before it can send a reply.
	submitted := *plan
	submitted.Summary.State = setupSubmitted
	if err := writeSharedSetupPlan(path, submitted, protection); err != nil {
		if errors.Is(err, errSharedTrustCommitUncertain) {
			*plan = submitted
		}
		return sharedpg.SchemaDeployment{}, err
	}
	*plan = submitted
	report, err := sharedpg.DeploySchema(ctx, settings, password, plan.Summary.RoleTag, plan.Summary.WorkspaceID)
	if errors.Is(err, sharedpg.ErrDeploymentRejected) || errors.Is(err, sharedpg.ErrAuthentication) ||
		errors.Is(err, sharedpg.ErrConfiguration) || errors.Is(err, sharedpg.ErrConnectionLimit) || errors.Is(err, sharedpg.ErrConnection) {
		// These outcomes prove SQL did not commit. A failed release leaves the
		// original check-first instruction in place.
		retry := *plan
		retry.Summary.State = setupPrepared
		if writeErr := writeSharedSetupPlan(path, retry, protection); writeErr != nil {
			return sharedpg.SchemaDeployment{}, writeErr
		}
		*plan = retry
	}
	return report, err
}

func setupFailure(err error) string {
	var probe *sharedpg.DeploymentConnectionError
	switch {
	case errors.As(err, &probe):
		return string(probe.Stage)
	case errors.Is(err, sharedpg.ErrAuthentication):
		return "scram"
	case errors.Is(err, sharedpg.ErrDeploymentRejected):
		return "rejected"
	case errors.Is(err, sharedpg.ErrDeploymentMismatch):
		return "mismatch"
	case errors.Is(err, sharedpg.ErrDeploymentUncertain), errors.Is(err, errSharedTrustCommitUncertain):
		return "check-required"
	case errors.Is(err, sharedpg.ErrConfiguration):
		return "configuration"
	default:
		return "unavailable"
	}
}
