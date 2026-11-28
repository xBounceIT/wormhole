package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedSetupTLSOutput struct {
	CAPEM     string `json:"caPem"`
	ServerPEM string `json:"serverPem"`
}

func (p sharedSetupPlan) tlsOutput() *sharedSetupTLSOutput {
	if p.TLS == nil {
		return nil
	}
	return &sharedSetupTLSOutput{CAPEM: string(p.CAPEM), ServerPEM: p.TLS.ServerPEM}
}

func sharedSetupTLSScope(plan sharedSetupPlan) (sharedpg.WorkspaceBootstrapScope, error) {
	// The factor envelope authenticates its own public PKI record. The native
	// scope separately binds that record to the path and deployment coordinates.
	plan.TLS = nil
	plan.CAPEM = nil
	return sharedAdminCheckpointScope(plan)
}

func prepareSharedSetupTLS(ctx context.Context, path string, payload []byte, protection sharedStartupProtection, generate bool) (json.RawMessage, error) {
	var summary sharedSetupSummary
	summary.Hosting = "self-hosted"
	var csr string
	var hosts []string
	var accountJSON, askJSON, passphraseJSON json.RawMessage
	defer func() {
		vault.Wipe(accountJSON)
		vault.Wipe(askJSON)
		vault.Wipe(passphraseJSON)
	}()
	fields := map[string]any{
		"host": &summary.Host, "port": &summary.Port, "database": &summary.Database,
		"approvedHosts": &hosts, "accountPassword": &accountJSON, "ask": &askJSON,
	}
	required := []string{"host", "port", "database", "approvedHosts", "accountPassword"}
	if generate {
		fields["keyPassphrase"] = &passphraseJSON
		required = append(required, "keyPassphrase")
	} else {
		fields["csr"] = &csr
		required = append(required, "csr")
	}
	if len(payload) > 96*1024 || decodeVaultObject(payload, fields, required...) != nil ||
		(!generate && (len(csr) == 0 || len(csr) > sharedpg.MaxServerCSRBytes)) || len(hosts) > 64 {
		return nil, vaultwire.ErrProtocol
	}
	var account, ask, passphrase []byte
	defer func() {
		vault.Wipe(account)
		vault.Wipe(ask)
		vault.Wipe(passphrase)
	}()
	if len(accountJSON) == 0 || accountJSON[0] != '"' || json.Unmarshal(accountJSON, &account) != nil || len(account) == 0 || len(account) > 1024 ||
		(len(askJSON) != 0 && (askJSON[0] != '"' || json.Unmarshal(askJSON, &ask) != nil || len(ask) != 32)) {
		return nil, vaultwire.ErrProtocol
	}
	if generate && (len(passphraseJSON) == 0 || passphraseJSON[0] != '"' || json.Unmarshal(passphraseJSON, &passphrase) != nil ||
		len(passphrase) == 0 || len(passphrase) > 1024) {
		return nil, vaultwire.ErrProtocol
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(floor); err != nil {
		return nil, err
	}
	plan := newSharedSetupPlan(path, summary)
	scope, err := sharedSetupTLSScope(plan)
	if err != nil {
		return nil, err
	}
	if generate {
		folder, folderErr := resolveServerKitFolder(plan.Summary.WorkspaceID, true)
		if folderErr != nil {
			return nil, folderErr
		}
		var key []byte
		plan.TLS, key, err = sharedpg.GenerateWorkspaceServerTLS(ctx, scope, summary.Host, hosts, account, ask, passphrase, time.Now())
		if err == nil {
			plan.ServerKit = &sharedSetupServerKit{sharedSetupServerKitReceipt{folder, serverKitPending}, sha256.Sum256(key), key}
		}
	} else {
		plan.TLS, err = sharedpg.PrepareWorkspaceTLS(ctx, scope, summary.Host, hosts, []byte(csr), account, ask, time.Now())
	}
	if !generate && errors.Is(err, sharedpg.ErrServerCertificate) {
		return json.Marshal(sharedSetupReply{Failure: "csr"})
	}
	if err != nil {
		return nil, err
	}
	plan.CAPEM = plan.TLS.CAPEM()
	if !plan.valid(path) {
		return nil, sharedpg.ErrConfiguration
	}
	if err := writeSharedSetupPlan(path, plan, protection); err != nil {
		return nil, err
	}
	return json.Marshal(sharedSetupReply{Plan: &plan.Summary, TLS: plan.tlsOutput(), ServerKit: plan.kitReceipt()})
}

// Call only after an authenticated administrator checkpoint has taken custody.
// If pruning was interrupted, reopening the checkpoint retries this retirement.
func retireWorkspaceTLSDraft(path string, plan sharedSetupPlan, protection sharedStartupProtection) error {
	if plan.TLS == nil || plan.TLS.Protection == nil {
		return nil
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return errSharedTrustStorage
	}
	draft := *plan.TLS
	draft.Protection = nil
	plan.TLS = &draft
	return writeSharedSetupPlan(path, plan, protection)
}
