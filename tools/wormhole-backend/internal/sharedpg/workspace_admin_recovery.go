package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const recoveryMaterialSQL = `SELECT wormhole_api_v1.workspace_admin_recovery_material()`
const recoverWorkspaceAdminSQL = `SELECT wormhole_api_v1.recover_workspace_admin($1::jsonb,$2::text)::text`
const recoveryBoundarySupportSQL = `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.workspace_admin_recovery_boundaries()') IS NOT NULL)::text`
const recoveryBoundariesSQL = `SELECT wormhole_api_v1.workspace_admin_recovery_boundaries()`
const recoverWorkspaceBoundariesSQL = `SELECT wormhole_api_v1.recover_workspace_boundaries($1::jsonb,$2::text)::text`
const maxAdminRecoveryMaterial = 8 * 1024 * 1024
const maxAdminRecoveryWire = 1024 * 1024
const maxAdminRecoveryBoundaries = (vault.MaxInviteKeyCopies - 2) / 2

// WorkspaceRecoveryTarget is the location approved by the operator, together
// with the workspace identity they intend to recover. The deployer login is
// distinct from an ordinary device or the login used for schema installation.
type WorkspaceRecoveryTarget struct {
	WorkspaceID  uuid.UUID
	Endpoint     Endpoint
	Database     string
	DeployerRole string
}

type workspaceAdminRecoveryCopy struct {
	vault.KeyRef
	Kind       string `json:"kind,omitempty"`
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature"`
}

type workspaceAdminRecoveryMaterial struct {
	WorkspaceID            uuid.UUID            `json:"workspaceId"`
	RoleTag                string               `json:"roleTag"`
	Database               string               `json:"database"`
	TLSDigest              string               `json:"tlsDigest"`
	Policy                 []byte               `json:"policy"`
	Capsule                []byte               `json:"capsule"`
	OrganisationEncryption vault.KeyRef         `json:"organisationEncryption"`
	OrganisationSigning    vault.KeyRef         `json:"organisationSigning"`
	Organisation           vault.UserPublicKeys `json:"organisation"`
	workspaceAdminRecoveryBoundary
	Boundaries []workspaceAdminRecoveryBoundary `json:"boundaries,omitempty"`
}

type workspaceAdminRecoveryBoundary struct {
	BoundaryID      uuid.UUID                    `json:"boundaryId"`
	BoundaryVersion uint64                       `json:"boundaryVersion"`
	Boundary        []byte                       `json:"boundary"`
	Copies          []workspaceAdminRecoveryCopy `json:"copies"`
}

type workspaceAdminRecoveryWire struct {
	Version        uint16                       `json:"version"`
	WorkspaceID    uuid.UUID                    `json:"workspaceId"`
	MaterialDigest string                       `json:"materialDigest"`
	Invite         vault.InviteContext          `json:"invite"`
	ExpiresAt      int64                        `json:"expiresAt"`
	Encryption     vault.UserKeyCertificate     `json:"encryption"`
	Signing        vault.UserKeyCertificate     `json:"signing"`
	SignedState    []byte                       `json:"signedState"`
	Bootstrap      []byte                       `json:"bootstrap"`
	Manifest       []byte                       `json:"manifest"`
	Copies         []workspaceAdminRecoveryCopy `json:"copies"`
}

// PreparedWorkspaceRecovery owns one exact issuance. Call Close on every exit.
// No DBA password or opened organisation key is retained in the draft.
type PreparedWorkspaceRecovery struct {
	version    uint16
	invitation Invitation
	settings   Settings
	wire       []byte
	code       []byte
	checkpoint []byte
	published  bool
}

func (r *PreparedWorkspaceRecovery) Close() {
	if r != nil {
		vault.Wipe(r.code)
		r.code = nil
		r.published = false
	}
}

func (r *PreparedWorkspaceRecovery) LoginName() string { return r.invitation.LoginName }

func (t WorkspaceRecoveryTarget) roleTag() (string, error) {
	role, ok := strings.CutPrefix(t.DeployerRole, "wh_")
	tag, tagged := strings.CutSuffix(role, "_deployer")
	if !ok || !tagged || deploy.ValidateIdentity(tag, t.WorkspaceID.String()) != nil ||
		!identifier(t.Database) || t.Endpoint.Port == 0 {
		return "", ErrConfiguration
	}
	return tag, nil
}

func (t WorkspaceRecoveryTarget) settings(tls *VerifiedTLSBundle) Settings {
	return Settings{Endpoints: []Endpoint{t.Endpoint}, Database: t.Database, DeviceRole: t.DeployerRole,
		TLS: TLSVerified, TLSBundle: tls, Profile: vault.Standard}
}

// PrepareWorkspaceRecovery authenticates the signed TLS bundle using the
// organisation key recovered locally before opening any network connection.
// It compares the ready server's identity, policy and graph against those keys
// and prepares the new user's ordinary certified enrollment without mutation.
func PrepareWorkspaceRecovery(ctx context.Context, target WorkspaceRecoveryTarget, kit, recoveryCode, trustBundle, dbaPassword []byte, login string) (*PreparedWorkspaceRecovery, error) {
	if ctx == nil || len(dbaPassword) == 0 || len(dbaPassword) > 1024 {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tag, err := target.roleTag()
	if err != nil {
		return nil, err
	}
	if _, err := vault.SharedSalt(target.WorkspaceID.String(), login); err != nil {
		return nil, ErrConfiguration
	}
	record, keys, tls, err := openWorkspaceRecoveryTrust(target.WorkspaceID, kit, recoveryCode, trustBundle)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe()
	settings := target.settings(tls)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	conn, err := Connect(ctx, settings, dbaPassword)
	if err != nil {
		return nil, err
	}
	defer closeDeploymentConnection(conn)
	capability, err := readDeploymentResponse(ctx, conn, recoveryBoundarySupportSQL, nil, 5)
	if err != nil {
		return nil, err
	}
	query := recoveryMaterialSQL
	var version uint16 = 1
	switch string(capability) {
	case "true":
		query, version = recoveryBoundariesSQL, 2
	case "false":
	default:
		return nil, ErrAdmissionResponse
	}
	raw, err := readDeploymentResponse(ctx, conn, query, nil, maxAdminRecoveryMaterial)
	if err != nil {
		return nil, err
	}
	draft, err := prepareWorkspaceRecoveryDraft(settings, tag, login, record, keys, raw, time.Now())
	if err != nil {
		return nil, err
	}
	if draft.version != version {
		draft.Close()
		return nil, ErrAdmissionResponse
	}
	draft.checkpoint, err = sealAdminRecoveryCheckpoint(target, tls, record.Encryption, recoveryCode, draft.wire, draft.code)
	if err != nil {
		draft.Close()
		return nil, err
	}
	return draft, nil
}

func openWorkspaceRecoveryTrust(workspace uuid.UUID, kit, code, trustBundle []byte) (workspaceRecoveryKit, *vault.UserKeys, *VerifiedTLSBundle, error) {
	record, err := decodeWorkspaceRecoveryKit(workspace, kit)
	if err != nil {
		return workspaceRecoveryKit{}, nil, nil, err
	}
	keys, err := record.open(code)
	if err != nil {
		return workspaceRecoveryKit{}, nil, nil, err
	}
	bundle, err := DecodeTLSTrustBundle(trustBundle)
	if err == nil {
		var verified *VerifiedTLSBundle
		verified, err = VerifyTLSTrustBundle(bundle, TLSTrustPin{
			WorkspaceID: workspace, Signer: record.Signing, Organisation: record.Public.Signing, MinimumSequence: 1,
		})
		if err == nil {
			return record, keys, verified, nil
		}
	}
	keys.Wipe()
	return workspaceRecoveryKit{}, nil, nil, err
}

func prepareWorkspaceRecoveryDraft(settings Settings, tag, login string, kit workspaceRecoveryKit, keys *vault.UserKeys, raw []byte, now time.Time) (*PreparedWorkspaceRecovery, error) {
	var material workspaceAdminRecoveryMaterial
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > maxAdminRecoveryMaterial || decoder.Decode(&material) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, ErrAdmissionResponse
	}
	pin := settings.TLSBundle.Pin()
	if material.WorkspaceID != kit.Workspace || material.RoleTag != tag || material.Database != settings.Database ||
		material.TLSDigest != hex.EncodeToString(pin.Digest) ||
		material.OrganisationEncryption != kit.Encryption || material.OrganisationSigning != kit.Signing ||
		!bytes.Equal(material.Organisation.Encryption, kit.Public.Encryption) || !bytes.Equal(material.Organisation.Signing, kit.Public.Signing) {
		return nil, vault.ErrAuthentication
	}
	capsule, _, err := decodeBootstrapRecoveryCapsule(workspaceBootstrapWire{
		Recovery: material.Capsule, WorkspaceID: kit.Workspace, OrganisationEncryption: kit.Encryption,
		OrganisationSigning: kit.Signing, Organisation: kit.Public,
	})
	if err != nil || !reflect.DeepEqual(capsule, kit.Capsule) {
		return nil, vault.ErrAuthentication
	}
	policy, err := vault.DecodeSignedPolicy(material.Policy)
	if err != nil || vault.VerifyPolicy(policy, kit.Workspace.String(), kit.Signing.ID.String(), kit.Signing.Version, kit.Public.Signing, 1) != nil {
		return nil, vault.ErrAuthentication
	}
	if (policy.Policy.Profile != vault.Default && policy.Policy.Profile != vault.Standard) || !policy.Policy.OrgEscrow ||
		policy.Policy.MinAPI > 1 || policy.Policy.MaxAPI < 1 {
		return nil, vault.ErrPolicy
	}
	boundaries, version, err := recoveryBoundarySelection(material)
	if err != nil {
		return nil, err
	}
	bootstrap, err := vault.NewInviteBootstrap(kit.Public.Signing)
	if err != nil {
		return nil, err
	}
	defer bootstrap.Wipe()
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		return nil, err
	}
	i := vault.InviteContext{WorkspaceID: kit.Workspace, UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: login}
	invitation := verifiedEnrollmentInvitation(i, tag, settings.Database, settings.Endpoints,
		kit.Public.Signing, settings.TLSBundle.Encode(), now.Add(30*time.Minute).Unix())
	signer := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(signer)
	certification, err := certifyInvitationBootstrap(i, kit.Signing, public, signer)
	if err != nil {
		return nil, err
	}
	state, err := vault.EncodeUserKeyState(certification.State)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	wire := workspaceAdminRecoveryWire{Version: version, WorkspaceID: i.WorkspaceID, MaterialDigest: hex.EncodeToString(digest[:]), Invite: i,
		ExpiresAt: invitation.ExpiresAt, Encryption: certification.Encryption, Signing: certification.Signing, SignedState: state}
	manifest := vault.InviteManifest{FormatVersion: 1, Context: i, Revision: 1, ExpiresAt: invitation.ExpiresAt, Bootstrap: public,
		Issuers: []vault.InviteIssuer{{Key: kit.Signing, Public: kit.Public.Signing}}}
	for _, item := range []struct {
		ref vault.KeyRef
		key []byte
	}{{kit.Encryption, keys.EncryptionPrivate}, {kit.Signing, keys.SigningSeed}} {
		if err := appendAdminRecoveryCopy(&wire, &manifest, item.ref, item.key, public.Encryption, keys.SigningSeed, kit.Signing); err != nil {
			return nil, err
		}
	}
	for _, material := range boundaries {
		if err := appendAdminRecoveryBoundary(&wire, &manifest, kit, keys, material, public.Encryption); err != nil {
			return nil, err
		}
	}
	signed, err := vault.SignInviteManifest(manifest, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	wire.Manifest, err = vault.EncodeInviteManifest(signed)
	if err != nil {
		return nil, err
	}
	code := make([]byte, vault.InviteCodeBytes)
	rand.Read(code)
	draft := &PreparedWorkspaceRecovery{version: version, invitation: invitation, settings: settings, code: code}
	wrapped, err := invitation.SealBootstrap(code, bootstrap, now)
	if err == nil {
		wire.Bootstrap, err = EncodeInvitationBootstrapEnvelope(invitation, wrapped, now)
	}
	if err == nil {
		draft.wire, err = json.Marshal(wire)
		if len(draft.wire) > maxAdminRecoveryWire {
			err = vault.ErrFormat
		}
	}
	if err != nil {
		draft.Close()
		return nil, err
	}
	return draft, nil
}

func recoveryBoundarySelection(material workspaceAdminRecoveryMaterial) ([]workspaceAdminRecoveryBoundary, uint16, error) {
	if material.Boundaries == nil {
		return []workspaceAdminRecoveryBoundary{material.workspaceAdminRecoveryBoundary}, 1, nil
	}
	if material.BoundaryID != uuid.Nil || material.BoundaryVersion != 0 || material.Boundary != nil || material.Copies != nil ||
		len(material.Boundaries) == 0 || len(material.Boundaries) > maxAdminRecoveryBoundaries {
		return nil, 0, ErrAdmissionResponse
	}
	var previous uuid.UUID
	for _, boundary := range material.Boundaries {
		if bytes.Compare(previous[:], boundary.BoundaryID[:]) >= 0 {
			return nil, 0, ErrAdmissionResponse
		}
		previous = boundary.BoundaryID
	}
	return material.Boundaries, 2, nil
}

func appendAdminRecoveryBoundary(wire *workspaceAdminRecoveryWire, manifest *vault.InviteManifest, kit workspaceRecoveryKit,
	keys *vault.UserKeys, material workspaceAdminRecoveryBoundary, recipient []byte) error {
	boundary, err := vault.DecodeBoundaryManifest(material.Boundary)
	trust := vault.BoundaryTrust{WorkspaceID: kit.Workspace, BoundaryID: material.BoundaryID, Signer: kit.Signing,
		Organisation: kit.Public.Signing, MinimumRevision: material.BoundaryVersion}
	if err != nil || material.BoundaryVersion != boundary.Revision || vault.VerifyBoundaryManifest(boundary, trust) != nil ||
		!boundary.Active || !boundary.OrgEscrow || boundary.OwnerUserID != uuid.Nil || boundary.PreviousView != nil || boundary.PreviousSecret != nil ||
		len(material.Copies) != 2 || material.Copies[0].Kind != "boundary-secret" || material.Copies[0].KeyRef != boundary.Secret.Key ||
		material.Copies[1].Kind != "boundary-view" || material.Copies[1].KeyRef != boundary.View.Key {
		return vault.ErrAuthentication
	}
	for index, item := range material.Copies {
		binding := vault.KeyCopyBinding{WorkspaceID: kit.Workspace, Key: item.KeyRef, Holder: kit.Encryption, Issuer: kit.Signing}
		copy := vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: vault.FormatVersion,
			SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: item.Enc, Ciphertext: item.Ciphertext}, Signature: item.Signature}
		purpose := [2]vault.BoundaryPurpose{vault.BoundarySecret, vault.BoundaryView}[index]
		key, err := vault.OpenBoundaryKeyCopy(keys.EncryptionPrivate, binding, copy, vault.KeyCopyTrust{Issuer: kit.Signing, Public: kit.Public.Signing}, boundary, trust, purpose)
		if err != nil {
			return err
		}
		err = appendAdminRecoveryCopy(wire, manifest, item.KeyRef, key, recipient, keys.SigningSeed, kit.Signing)
		vault.Wipe(key)
		if err != nil {
			return err
		}
	}
	return nil
}

func appendAdminRecoveryCopy(wire *workspaceAdminRecoveryWire, manifest *vault.InviteManifest, key vault.KeyRef, raw, public, seed []byte, signer vault.KeyRef) error {
	binding := vault.KeyCopyBinding{WorkspaceID: wire.WorkspaceID, Key: key, Holder: wire.Encryption.Key, Issuer: signer}
	copy, err := vault.SealKeyCopy(raw, binding, public, seed)
	if err != nil {
		return err
	}
	manifest.Copies = append(manifest.Copies, binding)
	wire.Copies = append(wire.Copies, workspaceAdminRecoveryCopy{
		KeyRef: key, Enc: copy.Envelope.Enc, Ciphertext: copy.Envelope.Ciphertext, Signature: copy.Signature,
	})
	return nil
}

// After durably saving Checkpoint, call Publish with the temporary DBA password.
// A retry resubmits the same signed records and a verifier for the same code.
func (r *PreparedWorkspaceRecovery) Publish(ctx context.Context, dbaPassword []byte) error {
	if r == nil || len(r.code) != vault.InviteCodeBytes || len(r.checkpoint) == 0 || ctx == nil || len(dbaPassword) == 0 || len(dbaPassword) > 1024 {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, verifier, err := r.invitation.EnrollmentVerifier(r.code, time.Now())
	if err != nil {
		return err
	}
	defer vault.Wipe(verifier)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	conn, err := Connect(ctx, r.settings, dbaPassword)
	if err != nil {
		return err
	}
	defer closeDeploymentConnection(conn)
	query := recoverWorkspaceAdminSQL
	if r.version == 2 {
		query = recoverWorkspaceBoundariesSQL
	}
	receipt, err := readDeploymentResponse(ctx, conn, query, [][]byte{r.wire, verifier}, 36)
	if err != nil {
		return err
	}
	if string(receipt) != r.invitation.Enrollment.Context.InviteID.String() {
		return ErrDeploymentUncertain
	}
	r.published = true
	return nil
}

// BorrowJoin supplies the normal invitation to the native admission owner only
// after publication. The callback must not retain the invitation or its code.
// Never serialize the enrollment code for a renderer.
func (r *PreparedWorkspaceRecovery) BorrowJoin(use func(Invitation, []byte) error) error {
	if r == nil || !r.published || use == nil {
		return vault.ErrPolicy
	}
	return use(r.invitation, r.code)
}
