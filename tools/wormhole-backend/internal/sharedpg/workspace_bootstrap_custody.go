package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxWorkspaceRecoveryKitBytes = 64 * 1024
const maxBootstrapRecoveryBytes = 1024

type WorkspaceBootstrapStatus struct {
	EnrollmentID string `json:"enrollmentId"`
	LoginName    string `json:"loginName"`
	Stage        string `json:"stage"`
}

func (c *WorkspaceBootstrapCheckpoint) Status() WorkspaceBootstrapStatus {
	if !c.active() {
		return WorkspaceBootstrapStatus{}
	}
	i := c.data.Invitation
	stages := [...]string{"", "prepared", "recovery-exported", "recovery-confirmed", "published"}
	return WorkspaceBootstrapStatus{i.Enrollment.Context.InviteID.String(), i.LoginName, stages[c.phase]}
}

type workspaceRecoveryKit struct {
	Version    uint16               `json:"version"`
	Workspace  uuid.UUID            `json:"workspaceId"`
	Encryption vault.KeyRef         `json:"organisationEncryption"`
	Signing    vault.KeyRef         `json:"organisationSigning"`
	Public     vault.UserPublicKeys `json:"organisation"`
	Capsule    vault.Envelope       `json:"capsule"`
	CA         *workspaceRecoveryCA `json:"ca,omitempty"`
}

type workspaceRecoveryCA struct {
	Certificate []byte             `json:"certificateDer"`
	Key         workspaceCAKeyCopy `json:"key"`
}

// The v2 capsule adds a CA key copy encrypted to the organisation. PostgreSQL
// stores the immutable capsule in the same bootstrap transaction as the trust
// bundle, which holds the issuer certificate. Older capsules remain readable.
type workspaceBootstrapRecoveryV2 struct {
	Version int                `json:"version"`
	Capsule vault.Envelope     `json:"capsule"`
	CA      workspaceCAKeyCopy `json:"ca"`
}

func encodeWorkspaceBootstrapRecovery(capsule vault.Envelope, ca *workspaceCAKeyCopy) ([]byte, error) {
	if ca == nil {
		return json.Marshal(capsule)
	}
	return json.Marshal(workspaceBootstrapRecoveryV2{2, capsule, *ca})
}

func decodeWorkspaceBootstrapRecovery(wire workspaceBootstrapWire, roots [][]byte) (vault.Envelope, *workspaceRecoveryCA, error) {
	capsule, key, err := decodeBootstrapRecoveryCapsule(wire)
	if err != nil || key == nil {
		return capsule, nil, err
	}
	if len(roots) != 1 {
		return vault.Envelope{}, nil, vault.ErrFormat
	}
	return capsule, &workspaceRecoveryCA{Certificate: roots[0], Key: *key}, nil
}

func decodeBootstrapRecoveryCapsule(wire workspaceBootstrapWire) (vault.Envelope, *workspaceCAKeyCopy, error) {
	var record workspaceBootstrapRecoveryV2
	if len(wire.Recovery) == 0 || len(wire.Recovery) > maxBootstrapRecoveryBytes || json.Unmarshal(wire.Recovery, &record) != nil {
		return vault.Envelope{}, nil, vault.ErrFormat
	}
	var wrapped *workspaceCAKeyCopy
	if record.Version == 0 {
		if json.Unmarshal(wire.Recovery, &record.Capsule) != nil {
			return vault.Envelope{}, nil, vault.ErrFormat
		}
	} else {
		org := vault.OrganisationRecoveryBinding{WorkspaceID: wire.WorkspaceID, Encryption: wire.OrganisationEncryption, Signing: wire.OrganisationSigning}
		if record.Version != 2 || record.CA.Key.Version != 1 || vault.VerifyKeyCopy(record.CA.binding(org), record.CA.Copy, wire.Organisation.Signing) != nil {
			return vault.Envelope{}, nil, vault.ErrFormat
		}
		wrapped = &record.CA
	}
	canonical, err := encodeWorkspaceBootstrapRecovery(record.Capsule, wrapped)
	if err != nil || !bytes.Equal(canonical, wire.Recovery) || len(record.Capsule.Ciphertext) != 80 {
		return vault.Envelope{}, nil, vault.ErrFormat
	}
	return record.Capsule, wrapped, nil
}

func (c *WorkspaceBootstrapCheckpoint) recoveryGroups() [2]int {
	id := c.data.Invitation.Enrollment.Context.InviteID
	first, second := int(id[0])%11+1, int(id[1])%10+1
	if second >= first {
		second++
	}
	return [2]int{first, second}
}

// PrepareRecovery lends an encrypted offline kit and seals the display key to
// the content-protected window's own recipient. The caller persists the kit
// before reporting export. The printed key never passes through main IPC.
func (c *WorkspaceBootstrapCheckpoint) PrepareRecovery(publicKey []byte) ([]byte, [2]int, vault.SealedBundle, error) {
	if !c.active() || c.phase >= bootstrapRecoveryConfirmed || len(c.recoveryKey) != 32 {
		return nil, [2]int{}, vault.SealedBundle{}, vault.ErrPolicy
	}
	code, err := vault.FormatRecoveryKey(c.recoveryKey)
	if err != nil {
		return nil, [2]int{}, vault.SealedBundle{}, err
	}
	defer vault.Wipe(code)
	i := c.data.Invitation
	bundle, err := vault.SealRecoveryDisplay(publicKey, i.WorkspaceID.String(), i.Enrollment.Context.InviteID.String(), code)
	if err != nil {
		return nil, [2]int{}, vault.SealedBundle{}, err
	}
	tls, err := i.AuthenticatedTLSBundle(c.wire.Organisation.Signing, c.wire.OrganisationSigning)
	if err != nil {
		return nil, [2]int{}, vault.SealedBundle{}, err
	}
	capsule, ca, err := decodeWorkspaceBootstrapRecovery(c.wire, tls.bundle.CAs)
	if err != nil {
		return nil, [2]int{}, vault.SealedBundle{}, err
	}
	record := workspaceRecoveryKit{Version: 1, Workspace: i.WorkspaceID, Encryption: c.wire.OrganisationEncryption,
		Signing: c.wire.OrganisationSigning, Public: c.wire.Organisation, Capsule: capsule, CA: ca}
	if ca != nil {
		record.Version = 2
	}
	kit, err := encodeWorkspaceRecoveryKit(record)
	return kit, c.recoveryGroups(), bundle, err
}

func encodeWorkspaceRecoveryKit(record workspaceRecoveryKit) ([]byte, error) {
	kit, err := json.Marshal(record)
	if err == nil && len(kit) > MaxWorkspaceRecoveryKitBytes {
		return nil, vault.ErrFormat
	}
	return kit, err
}

func decodeWorkspaceRecoveryKit(workspace uuid.UUID, kit []byte) (workspaceRecoveryKit, error) {
	var record workspaceRecoveryKit
	if workspace == uuid.Nil || len(kit) == 0 || len(kit) > MaxWorkspaceRecoveryKitBytes || json.Unmarshal(kit, &record) != nil || record.Workspace != workspace ||
		(record.Version != 1 || record.CA != nil) && (record.Version != 2 || record.CA == nil) {
		return workspaceRecoveryKit{}, vault.ErrFormat
	}
	canonical, err := encodeWorkspaceRecoveryKit(record)
	if err != nil || !bytes.Equal(kit, canonical) {
		return workspaceRecoveryKit{}, vault.ErrFormat
	}
	return record, nil
}

// OpenWorkspaceRecoveryKit opens both organisation keys after offline custody.
// The caller must authenticate the kit and expected workspace independently
// before authorizing a server recovery transaction. Always wipe the result.
func OpenWorkspaceRecoveryKit(workspace uuid.UUID, kit, recoveryCode []byte) (*vault.UserKeys, error) {
	record, err := decodeWorkspaceRecoveryKit(workspace, kit)
	if err != nil {
		return nil, err
	}
	return record.open(recoveryCode)
}

func (record workspaceRecoveryKit) open(recoveryCode []byte) (*vault.UserKeys, error) {
	key, err := vault.ParseRecoveryKey(recoveryCode)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	org := vault.OrganisationRecoveryBinding{WorkspaceID: record.Workspace, Encryption: record.Encryption, Signing: record.Signing}
	keys, err := vault.OpenOrganisationRecovery(key, org, record.Capsule, record.Public)
	if err != nil {
		return nil, err
	}
	if record.CA != nil && !record.CA.matches(keys.EncryptionPrivate, org, record.Public.Signing) {
		keys.Wipe()
		return nil, vault.ErrAuthentication
	}
	return keys, nil
}

func (ca workspaceRecoveryCA) matches(encryptionPrivate []byte, org vault.OrganisationRecoveryBinding, signer []byte) bool {
	cert, err := x509.ParseCertificate(ca.Certificate)
	if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return false
	}
	raw, err := vault.OpenKeyCopy(encryptionPrivate, ca.Key.binding(org), ca.Key.Copy, signer)
	if err != nil {
		return false
	}
	defer vault.Wipe(raw)
	private, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return false
	}
	defer wipeWorkspaceCAKey(private)
	return private.PublicKey.Equal(cert.PublicKey)
}

func (c *WorkspaceBootstrapCheckpoint) MarkRecoveryExported() error {
	if !c.active() || c.phase >= bootstrapRecoveryConfirmed {
		return vault.ErrPolicy
	}
	c.phase = bootstrapRecoveryExported
	return nil
}

func (c *WorkspaceBootstrapCheckpoint) ConfirmRecoveryCustody(groups []byte) error {
	if !c.active() || c.phase != bootstrapRecoveryExported {
		return vault.ErrPolicy
	}
	if len(groups) != 10 {
		return vault.ErrFormat
	}
	formatted, err := vault.FormatRecoveryKey(c.recoveryKey)
	if err != nil {
		return err
	}
	defer vault.Wipe(formatted)
	indices := c.recoveryGroups()
	first, second := 7+(indices[0]-1)*6, 7+(indices[1]-1)*6
	if subtle.ConstantTimeCompare(groups[:5], formatted[first:first+5])&subtle.ConstantTimeCompare(groups[5:], formatted[second:second+5]) != 1 {
		return vault.ErrAuthentication
	}
	c.phase = bootstrapRecoveryConfirmed
	vault.Wipe(c.recoveryKey)
	c.recoveryKey = nil
	return nil
}

// Publish requires a locally acknowledged recovery handoff. Callers reopen the
// durable checkpoint for this operation, preserving its issuance on failure.
func (c *WorkspaceBootstrapCheckpoint) Publish(ctx context.Context, role string, dbaPassword []byte) error {
	if !c.active() || c.phase < bootstrapRecoveryConfirmed {
		return vault.ErrPolicy
	}
	if _, err := publishWorkspaceBootstrapWire(ctx, c.data.Invitation, c.wire.Organisation.Signing, c.wire.OrganisationSigning, c.wire.Bootstrap, c.data.Wire, role, dbaPassword, c.code); err != nil {
		return err
	}
	c.phase = bootstrapPublished
	return nil
}

// BorrowJoin never serializes the invitation code. The existing admission
// coordinator consumes it inside Go and owns its own device staging protocol.
func (c *WorkspaceBootstrapCheckpoint) BorrowJoin(use func(Invitation, []byte) error) error {
	if !c.active() || c.phase != bootstrapPublished || use == nil {
		return vault.ErrPolicy
	}
	return use(c.data.Invitation, c.code)
}
