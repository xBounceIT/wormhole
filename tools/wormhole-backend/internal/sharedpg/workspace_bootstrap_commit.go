package sharedpg

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const workspaceBootstrapSQL = `SELECT wormhole_api_v1.bootstrap_workspace($1::jsonb,$2::text)`

type workspaceBootstrapCopyWire struct {
	Key        uuid.UUID `json:"key"`
	Holder     uuid.UUID `json:"holder"`
	Enc        []byte    `json:"enc"`
	Ciphertext []byte    `json:"ciphertext"`
	Signature  []byte    `json:"signature"`
}

type workspaceBootstrapWire struct {
	Version                uint16                       `json:"version"`
	WorkspaceID            uuid.UUID                    `json:"workspaceId"`
	RoleTag                string                       `json:"roleTag"`
	Database               string                       `json:"database"`
	ExpiresAt              int64                        `json:"expiresAt"`
	Invite                 vault.InviteContext          `json:"invite"`
	OrganisationEncryption vault.KeyRef                 `json:"organisationEncryption"`
	OrganisationSigning    vault.KeyRef                 `json:"organisationSigning"`
	Organisation           vault.UserPublicKeys         `json:"organisation"`
	Encryption             vault.UserKeyCertificate     `json:"encryption"`
	Signing                vault.UserKeyCertificate     `json:"signing"`
	Boundary               vault.BoundaryManifest       `json:"boundary"`
	BoundaryBody           []byte                       `json:"boundaryBody"`
	Copies                 []workspaceBootstrapCopyWire `json:"copies"`
	SignedState            []byte                       `json:"signedState"`
	SignedProfile          []byte                       `json:"signedProfile"`
	TLSBundle              []byte                       `json:"tlsBundle"`
	Bootstrap              []byte                       `json:"bootstrap"`
	Manifest               []byte                       `json:"manifest"`
	Recovery               []byte                       `json:"recovery"`
}

func (p *workspaceBootstrap) wire() ([]byte, error) {
	cert := p.certification
	state, err := vault.EncodeUserKeyState(cert.State)
	if err != nil {
		return nil, err
	}
	manifest, err := vault.EncodeInviteManifest(p.manifest)
	if err != nil {
		return nil, err
	}
	boundary, err := vault.EncodeBoundaryManifest(p.boundary)
	if err != nil {
		return nil, err
	}
	recovery, err := encodeWorkspaceBootstrapRecovery(p.recoveryKeys, p.caKey)
	if err != nil {
		return nil, err
	}
	i := p.invitation
	value := workspaceBootstrapWire{
		Version: 1, WorkspaceID: i.WorkspaceID, RoleTag: i.Enrollment.RoleTag, Database: i.Database, ExpiresAt: i.ExpiresAt, Invite: i.Enrollment.Context,
		OrganisationEncryption: p.recovery.Encryption, OrganisationSigning: p.recovery.Signing, Organisation: p.organisation,
		Encryption: cert.Encryption, Signing: cert.Signing, Boundary: p.boundary, BoundaryBody: boundary,
		SignedState: state, SignedProfile: cert.SignedProfile, TLSBundle: i.TLSIdentity.Bundle, Bootstrap: p.envelope, Manifest: manifest, Recovery: recovery,
	}
	for _, item := range p.copies {
		value.Copies = append(value.Copies, workspaceBootstrapCopyWire{item.binding.Key.ID, item.binding.Holder.ID, item.copy.Envelope.Enc, item.copy.Envelope.Ciphertext, item.copy.Signature})
	}
	return json.Marshal(value)
}

// publishWorkspaceBootstrapWire borrows the temporary DBA password and enrollment
// code. Only a SCRAM verifier, public values and ciphertext reach PostgreSQL.
// Publish only after durable setup and offline recovery acknowledgement. On
// uncertainty repeat the exact same prepared records, never create a new admin.
func publishWorkspaceBootstrapWire(ctx context.Context, i Invitation, organisation ed25519.PublicKey, signer vault.KeyRef, bootstrap, wire []byte, role string, password, code []byte) (string, error) {
	if ctx == nil || !identifier(role) {
		return "", ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now := time.Now()
	if err := i.Validate(now); err != nil {
		return "", err
	}
	var envelope vault.Envelope
	if json.Unmarshal(bootstrap, &envelope) != nil {
		return "", ErrConfiguration
	}
	opened, err := i.OpenBootstrap(code, i.Enrollment.Context, envelope, now)
	if err != nil {
		return "", err
	}
	opened.Wipe()
	_, verifier, err := i.EnrollmentVerifier(code, now)
	if err != nil {
		return "", err
	}
	defer vault.Wipe(verifier)
	tls, err := i.AuthenticatedTLSBundle(organisation, signer)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	conn, err := Connect(ctx, Settings{Endpoints: i.Endpoints, Database: i.Database, DeviceRole: role, TLS: TLSVerified, TLSBundle: tls, Profile: vault.Standard}, password)
	if err != nil {
		return "", err
	}
	defer closeDeploymentConnection(conn)
	receipt, err := readDeploymentResponse(ctx, conn, workspaceBootstrapSQL, [][]byte{wire, verifier}, len("provisioning"))
	if err != nil {
		return "", err
	}
	state := string(receipt)
	if state != "provisioning" && state != "ready" {
		return "", ErrDeploymentUncertain
	}
	return state, nil
}
