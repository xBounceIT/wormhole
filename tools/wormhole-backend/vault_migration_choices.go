package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) migrationChoices(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	var id, version, fingerprint string
	var choices []json.RawMessage
	targets := map[string]any{"nodeId": &id, "rowVersion": &version}
	required := []string{"nodeId", "rowVersion"}
	if operation == "migration-decide" {
		targets["fingerprint"] = &fingerprint
		targets["choices"] = &choices
		required = append(required, "fingerprint", "choices")
	}
	if decodeVaultObject(raw, targets, required...) != nil || !vaultCredentialID(id) {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, false)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	if operation == "migration-report" {
		report, err := h.owner.ReadResolverMigrationReport(ctx, id, revision)
		if err != nil {
			return nil, err
		}
		profile, err := h.owner.ReadSecurityProfile(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			localvault.ResolverMigrationReport
			CanDecide bool `json:"canDecide"`
		}{report, profile.Effective == vault.Default || profile.Effective == vault.Standard})
	}
	digest, err := hex.DecodeString(fingerprint)
	if operation != "migration-decide" || revision == math.MaxInt64 || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != fingerprint || len(choices) < 1 || len(choices) > 3 {
		return nil, vaultwire.ErrProtocol
	}
	decisions := make([]resolver.MigrationDecision, 0, len(choices))
	seen := map[string]bool{}
	for _, rawChoice := range choices {
		var path, choice string
		if decodeVaultObject(rawChoice, map[string]any{"protocolPath": &path, "choice": &choice}, "protocolPath", "choice") != nil || seen[path] || (choice != "keep" && choice != "new") {
			return nil, vaultwire.ErrProtocol
		}
		switch path {
		case "ssh", "sftp", "rdp", "rdp-gateway", "vnc", "reveal":
		default:
			return nil, vaultwire.ErrProtocol
		}
		seen[path] = true
		decisions = append(decisions, resolver.MigrationDecision{NodeID: id, ProtocolPath: path, Choice: choice})
	}
	n, err := h.owner.DecideResolverMigration(ctx, id, revision, fingerprint, decisions)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{id, strconv.FormatUint(n.RowVersion, 10), true})
}
