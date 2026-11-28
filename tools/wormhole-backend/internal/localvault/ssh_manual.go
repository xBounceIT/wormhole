package localvault

import (
	"bytes"
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type SSHManualPlan struct {
	Host     SSHHostPlan `json:"host"`
	Mode     string      `json:"mode"`
	AutoSudo bool        `json:"autoSudo"`
	SFTPOnly bool        `json:"sftpOnly"`
}

func projectSSHManualPlan(host SSHHostPlan, r Resolution, mode string, sftpOnly bool) (SSHManualPlan, error) {
	if (mode != "account" && mode != "passphrase") || !vault.ValidSSHFingerprint(host.Fingerprint) {
		return SSHManualPlan{}, vault.ErrPolicy
	}
	if mode == "passphrase" && (r.Credential == nil || r.Credential.Provider != "local" || r.Credential.Kind != "sshKey") {
		return SSHManualPlan{}, vault.ErrPolicy
	}
	return SSHManualPlan{Host: host, Mode: mode, AutoSudo: !sftpOnly && r.Plan.Protocol == 0 && r.Plan.SSHAutoSudo, SFTPOnly: sftpOnly}, nil
}

func (o *Owner) PlanManualSSHConnection(ctx context.Context, q TunnelPlanRequest, route *vault.TunnelBundleBinding, mode string, sftpOnly bool) (SSHManualPlan, error) {
	if ctx == nil || (mode == "account" && q.CredentialOverride != "") {
		return SSHManualPlan{}, vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	host, r, err := o.planSSHHost(ctx, q, route)
	if err != nil {
		return SSHManualPlan{}, err
	}
	return projectSSHManualPlan(host, r, mode, sftpOnly)
}

// SealManualSSHConnection authorizes a document envelope for the exact verified
// host snapshot. Account mode borrows no stored account; passphrase mode borrows
// only the selected key/certificate, explicitly excluding its saved passphrase.
func (o *Owner) SealManualSSHConnection(ctx context.Context, q SSHBundleRequest, expected SSHManualPlan, route *vault.TunnelBundleBinding, endpoint string, inner vault.SealedBundle) (SSHConnectionBundle, error) {
	mode := expected.Mode
	request := TunnelBundleRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch, q.PublicKey}
	if ctx == nil || request.Validate() != nil || (mode != "account" && mode != "passphrase") {
		return SSHConnectionBundle{}, vault.ErrFormat
	}
	if mode == "account" && q.CredentialOverride != "" || route == nil && endpoint != "" || route != nil && !vault.ValidRouteEndpoint(endpoint) {
		return SSHConnectionBundle{}, vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	host, r, err := o.planSSHHost(ctx, request.Plan(), route)
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	current, err := projectSSHManualPlan(host, r, mode, q.SFTPOnly)
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	if current != expected {
		return SSHConnectionBundle{}, vault.ErrPolicy
	}
	base := vault.SSHBundlePayload{Fingerprint: host.Fingerprint, AutoSudo: current.AutoSudo, SFTPOnly: current.SFTPOnly}
	defer func() {
		vault.Wipe(base.PrivateKey)
		vault.Wipe(base.Certificate)
	}()
	if mode == "passphrase" {
		c := r.Credential
		base.Username = r.Plan.Username
		for _, field := range c.Fields {
			if !field.Present || (field.Field != "privateKey" && field.Field != "certificate") {
				continue
			}
			var dst *[]byte
			if field.Field == "privateKey" {
				dst = &base.PrivateKey
			} else {
				dst = &base.Certificate
			}
			if err := o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: field.Field}, field.Version, true, func(value []byte) error { *dst = bytes.Clone(value); return nil }); err != nil {
				return SSHConnectionBundle{}, err
			}
		}
	}
	raw, err := vault.EncodeSSHManualAuthorization(vault.SSHManualAuthorization{Mode: mode, FileID: host.FileID, Revision: host.Revision, Base: base, Manual: inner})
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	if err = ctx.Err(); err != nil {
		return SSHConnectionBundle{}, err
	}
	var sealed vault.SealedBundle
	if route == nil {
		sealed, err = vault.SealBundle(q.PublicKey, host.Binding, raw)
	} else {
		sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
	}
	if err != nil {
		return SSHConnectionBundle{}, err
	}
	if err = ctx.Err(); err != nil {
		vault.Wipe(sealed.Enc)
		vault.Wipe(sealed.Ciphertext)
		return SSHConnectionBundle{}, err
	}
	return SSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: host.Binding, Bundle: sealed}, nil
}
