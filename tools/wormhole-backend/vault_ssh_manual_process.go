package main

import "github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"

// The native recipient alone combines the authorized key/options with one
// isolated account or passphrase. Empty passphrase explicitly replaces stored
// state; no password/passphrase is present in the outer authorization frame.
func openSealedSSHManualPayload(private []byte, opening sealedSSHOpening, mode string, plaintext []byte) (vault.SSHBundlePayload, []byte, error) {
	a, err := vault.DecodeSSHManualAuthorization(plaintext)
	if err != nil {
		return vault.SSHBundlePayload{}, nil, err
	}
	if a.Mode != mode || a.Base.SFTPOnly != opening.sftpOnly {
		return vault.SSHBundlePayload{}, nil, vault.ErrPolicy
	}
	c := vault.SSHManualContext{Binding: opening.binding, Route: opening.route, Endpoint: opening.endpoint, Mode: mode, FileID: a.FileID, Revision: a.Revision, Fingerprint: a.Base.Fingerprint, AutoSudo: a.Base.AutoSudo, SFTPOnly: a.Base.SFTPOnly}
	raw, err := vault.OpenManualSSHCredentials(private, c, a.Manual)
	if err != nil {
		return vault.SSHBundlePayload{}, nil, err
	}
	p, err := vault.DecodeSSHManualCredentials(c, raw)
	if err != nil {
		vault.Wipe(raw)
		return vault.SSHBundlePayload{}, nil, err
	}
	if mode == "account" {
		p.AutoSudo, p.SFTPOnly = a.Base.AutoSudo, a.Base.SFTPOnly
	} else {
		a.Base.Passphrase = p.Passphrase
		p = a.Base
	}
	return p, raw, nil
}
