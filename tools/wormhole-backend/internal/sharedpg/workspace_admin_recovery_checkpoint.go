package sharedpg

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxWorkspaceAdminRecoveryCheckpointBytes = 2 * 1024 * 1024

// Checkpoint returns the encrypted issuance for durable storage before Publish.
// The recovery code, kit and signed TLS bundle are needed again to reopen it.
func (r *PreparedWorkspaceRecovery) Checkpoint() []byte {
	if r == nil || len(r.code) != vault.InviteCodeBytes {
		return nil
	}
	return bytes.Clone(r.checkpoint)
}

func adminRecoveryCheckpointKey(target WorkspaceRecoveryTarget, tls *VerifiedTLSBundle, encryption vault.KeyRef, code []byte) ([]byte, vault.Binding, error) {
	serialized, err := json.Marshal(target)
	if err != nil {
		return nil, vault.Binding{}, err
	}
	targetHash := sha256.Sum256(serialized)
	digest := tls.Pin().Digest
	raw, err := vault.ParseRecoveryKey(code)
	if err != nil {
		return nil, vault.Binding{}, err
	}
	defer vault.Wipe(raw)
	key, err := hkdf.Key(sha256.New, raw, digest, "wormhole/v1/admin-recovery-checkpoint", 32)
	return key, vault.Binding{WorkspaceID: target.WorkspaceID.String(), Table: "SharedAdminRecovery", OwnerID: hex.EncodeToString(targetHash[:]),
		Field: hex.EncodeToString(digest), KeyID: encryption.ID.String(), KeyVersion: encryption.Version}, err
}

func sealAdminRecoveryCheckpoint(target WorkspaceRecoveryTarget, tls *VerifiedTLSBundle, encryption vault.KeyRef, code, wire, inviteCode []byte) ([]byte, error) {
	key, binding, err := adminRecoveryCheckpointKey(target, tls, encryption, code)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	plain := make([]byte, len(inviteCode)+len(wire))
	defer vault.Wipe(plain)
	copy(plain, inviteCode)
	copy(plain[len(inviteCode):], wire)
	envelope, err := vault.Seal(key, binding, plain)
	if err != nil {
		return nil, err
	}
	sealed, err := json.Marshal(envelope)
	if err == nil && len(sealed) > MaxWorkspaceAdminRecoveryCheckpointBytes {
		return nil, vault.ErrFormat
	}
	return sealed, err
}

// OpenWorkspaceRecoveryCheckpoint restores the same issuance without trusting
// coordinates or keys from disk. It performs no network activity. Publish
// must confirm the server receipt again before the invitation can be borrowed.
func OpenWorkspaceRecoveryCheckpoint(target WorkspaceRecoveryTarget, kit, recoveryCode, trustBundle, sealed []byte) (*PreparedWorkspaceRecovery, error) {
	tag, err := target.roleTag()
	if err != nil {
		return nil, err
	}
	var envelope vault.Envelope
	if len(sealed) == 0 || len(sealed) > MaxWorkspaceAdminRecoveryCheckpointBytes || json.Unmarshal(sealed, &envelope) != nil {
		return nil, vault.ErrFormat
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, sealed) {
		return nil, vault.ErrFormat
	}
	record, keys, tls, err := openWorkspaceRecoveryTrust(target.WorkspaceID, kit, recoveryCode, trustBundle)
	if err != nil {
		return nil, err
	}
	keys.Wipe()
	key, binding, err := adminRecoveryCheckpointKey(target, tls, record.Encryption, recoveryCode)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(plain)
	var wire workspaceAdminRecoveryWire
	if len(plain) <= vault.InviteCodeBytes || len(plain) > vault.InviteCodeBytes+maxAdminRecoveryWire ||
		json.Unmarshal(plain[vault.InviteCodeBytes:], &wire) != nil || (wire.Version != 1 && wire.Version != 2) ||
		wire.WorkspaceID != target.WorkspaceID || wire.Invite.WorkspaceID != target.WorkspaceID {
		return nil, vault.ErrFormat
	}
	canonical, err = json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, plain[vault.InviteCodeBytes:]) {
		return nil, vault.ErrFormat
	}
	settings := target.settings(tls)
	invitation := adminRecoveryInvitation(settings, tag, record, wire.Invite, wire.ExpiresAt)
	var bootstrap vault.Envelope
	if json.Unmarshal(wire.Bootstrap, &bootstrap) != nil {
		return nil, vault.ErrFormat
	}
	code := plain[:vault.InviteCodeBytes]
	opened, err := invitation.OpenBootstrap(code, wire.Invite, bootstrap, time.Now())
	if err != nil {
		return nil, err
	}
	opened.Wipe()
	return &PreparedWorkspaceRecovery{version: wire.Version, invitation: invitation, settings: settings, wire: canonical, code: bytes.Clone(code), checkpoint: bytes.Clone(sealed)}, nil
}
