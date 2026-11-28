package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type MemberInvitationHandover struct {
	WorkspaceID uuid.UUID          `json:"workspaceId"`
	RequestID   uuid.UUID          `json:"requestId"`
	InviteID    uuid.UUID          `json:"inviteId"`
	Token       string             `json:"token"`
	Bundle      vault.SealedBundle `json:"bundle"`
}

type MemberInvitationRequest struct {
	Login, Name string
	RequestID   uuid.UUID
	Recipient   []byte
	// PrepareCopy seals the code for native clipboard use. The caller makes
	// that copy available only when the returned handover is successful.
	PrepareCopy func(invite uuid.UUID, expiresAt int64, code []byte) error
}

// IssueMemberInvitation hands the public document and a separately encrypted
// code to the requesting window only after PostgreSQL confirms publication.
// The caller must verify the current custodian's factors before invoking it.
func (s *Session) IssueMemberInvitation(ctx context.Context, trust TrustState, settings Settings,
	keys *vault.UserKeys, request MemberInvitationRequest) (result MemberInvitationHandover, err error) {
	if request.RequestID == uuid.Nil || len(request.Recipient) != 32 {
		return result, ErrConfiguration
	}
	plan, err := s.prepareNewMember(ctx, trust, settings, keys, request.Login, request.Name)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := plan.close(); closeErr != nil {
			result = MemberInvitationHandover{}
			err = errors.Join(err, closeErr)
		}
	}()
	token, err := EncodeInvitation(plan.invitation, time.Now())
	if err != nil {
		return result, err
	}
	var display vault.SealedBundle
	identity := plan.invitation.Enrollment.Context
	err = plan.code.With(func(code []byte) error {
		var err error
		display, err = vault.SealInviteDisplay(request.Recipient, request.RequestID, identity, token, code)
		if err != nil {
			return errors.Join(ErrMemberInvitationRecipient, err)
		}
		if request.PrepareCopy != nil {
			return request.PrepareCopy(identity.InviteID, plan.invitation.ExpiresAt, code)
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	if err := s.publishNewMember(ctx, trust, plan); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return MemberInvitationHandover{WorkspaceID: identity.WorkspaceID, RequestID: request.RequestID, InviteID: identity.InviteID, Token: token, Bundle: display}, nil
}

var ErrMemberInvitationRecipient = errors.New("invalid member invitation display recipient")

func (s *Session) MemberInvitationSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure(
		'wormhole_api_v1.publish_member_invitation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,jsonb,text)') IS NOT NULL)::text`)
}

// A new member starts without administrator keys or workspace-wide grants.
// The current organisation signs the bootstrap under its existing policy.
type memberInvitationPublication struct {
	Context    vault.InviteContext      `json:"context"`
	Name       string                   `json:"name"`
	ExpiresAt  int64                    `json:"expiresAt"`
	Encryption vault.UserKeyCertificate `json:"encryption"`
	Signing    vault.UserKeyCertificate `json:"signing"`
	State      []byte                   `json:"signedState"`
	Manifest   []byte                   `json:"manifest"`
	Envelope   []byte                   `json:"bootstrap"`
}

type preparedMemberInvitation struct {
	invitation   Invitation
	issuer       uuid.UUID
	tlsDigest    []byte
	policyDigest []byte
	publication  []byte
	verifier     []byte
	code         *securemem.Buffer
}

const memberInvitationSignerSQL = `SELECT role_tag,database_name,key_id::text,key_version::text,
encode(enc,'hex'),encode(ciphertext,'hex'),encode(proof,'hex') FROM wormhole_api_v1.member_invitation_signer(` + serverCAArguments + `,$10::text)`
const publishMemberInvitationSQL = `SELECT wormhole_api_v1.publish_member_invitation(` + serverCAArguments + `,$10::jsonb,$11::text)`

// The protected administrator flow supplies a freshly authenticated account.
// Only the organisation signing copy is opened. Account or boundary private
// keys are never placed in an ordinary member's invitation.
func (s *Session) prepareNewMember(ctx context.Context, trust TrustState, settings Settings,
	keys *vault.UserKeys, login, name string) (*preparedMemberInvitation, error) {
	if ctx == nil || keys == nil || settings.TLS != TLSVerified || settings.TLSBundle == nil ||
		!adminGroupText(login, 256) || (name != "" && !adminGroupText(name, 4096)) {
		return nil, ErrConfiguration
	}
	if _, err := vault.SharedSalt(trust.WorkspaceID.String(), login); err != nil {
		return nil, err
	}
	anchor, err := accountResetIssuer(trust, settings.TLSBundle, keys)
	if err != nil {
		return nil, err
	}
	var plan *preparedMemberInvitation
	err = s.queryServerCA(ctx, trust, memberInvitationSignerSQL, [][]byte{[]byte(login)}, 2048, 1, 7, func(rows [][][]byte) error {
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 || len(rows[0]) != 7 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		tag := string(row[0])
		if string(row[1]) != settings.Database || settings.DeviceRole != "wh_"+tag+"_d_"+trust.DeviceID.String() {
			return ErrAdmissionResponse
		}
		ref, sealed, err := parseServerCAOrgCopy(row[2:])
		if err != nil || ref != anchor.Signer {
			return ErrAdmissionResponse
		}
		seed, err := openServerCAOrgCopy(trust, ref, sealed, keys.EncryptionPrivate, keys.SigningSeed)
		if err != nil {
			return err
		}
		defer vault.Wipe(seed)
		plan, err = prepareMemberInvitation(trust, settings.TLSBundle, tag, settings.Database, settings.Endpoints, login, name, seed, time.Now())
		return err
	})
	if err != nil {
		if plan != nil {
			plan.close()
		}
		return nil, err
	}
	if plan == nil {
		return nil, ErrAccountRevision
	}
	return plan, nil
}

func (s *Session) publishNewMember(ctx context.Context, trust TrustState, plan *preparedMemberInvitation) error {
	if ctx == nil || plan == nil || plan.code == nil || plan.issuer != trust.UserID || plan.invitation.WorkspaceID != trust.WorkspaceID ||
		trust.Account == nil || trust.Enrollment == nil || !bytes.Equal(plan.tlsDigest, trust.TLSDigest) ||
		!bytes.Equal(plan.policyDigest, trust.PolicyDigest) || plan.invitation.ExpiresAt <= time.Now().Unix() {
		return ErrConfiguration
	}
	ready, err := s.serverCapability(ctx, accountResetPublicationReadySQL)
	if err != nil {
		return err
	}
	if !ready {
		return ErrAccountResetLogging
	}
	return s.queryServerCA(ctx, trust, publishMemberInvitationSQL, [][]byte{plan.publication, plan.verifier}, 64, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != "published" {
			return ErrAdmissionResponse
		}
		return nil
	})
}

func (p *preparedMemberInvitation) close() error {
	vault.Wipe(p.verifier)
	p.verifier = nil
	if p.code == nil {
		return nil
	}
	if err := p.code.Close(); err != nil {
		return err
	}
	p.code = nil
	return nil
}

func prepareMemberInvitation(trust TrustState, tls *VerifiedTLSBundle, roleTag, database string, endpoints []Endpoint,
	login, name string, seed []byte, now time.Time) (*preparedMemberInvitation, error) {
	if !adminGroupText(login, 256) || (name != "" && !adminGroupText(name, 4096)) || len(seed) != ed25519.SeedSize || now.IsZero() {
		return nil, ErrConfiguration
	}
	anchor, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return nil, err
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(signer)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), anchor.Organisation) {
		return nil, vault.ErrAuthentication
	}
	identity := vault.InviteContext{WorkspaceID: trust.WorkspaceID, UserID: uuid.New(), InviteID: uuid.New(),
		KeyID: uuid.New(), KeyVersion: 1, LoginName: login}
	invitation := verifiedEnrollmentInvitation(identity, roleTag, database, endpoints, anchor.Organisation, tls.Encode(), now.Add(72*time.Hour).Unix())
	if err := invitation.Validate(now); err != nil {
		return nil, err
	}
	bootstrap, err := vault.NewInviteBootstrap(anchor.Organisation)
	if err != nil {
		return nil, err
	}
	defer bootstrap.Wipe()
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		return nil, err
	}
	certification, err := certifyInvitationBootstrap(identity, anchor.Signer, public, signer)
	if err != nil {
		return nil, err
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: identity, Revision: 1,
		ExpiresAt: invitation.ExpiresAt, Bootstrap: public, Issuers: []vault.InviteIssuer{}, Copies: []vault.KeyCopyBinding{}}, seed)
	if err != nil {
		return nil, err
	}
	wire := memberInvitationPublication{Context: identity, Name: name, ExpiresAt: invitation.ExpiresAt,
		Encryption: certification.Encryption, Signing: certification.Signing}
	if wire.State, err = vault.EncodeUserKeyState(certification.State); err != nil {
		return nil, err
	}
	if wire.Manifest, err = vault.EncodeInviteManifest(manifest); err != nil {
		return nil, err
	}
	code, err := securemem.New(vault.InviteCodeBytes, false)
	if err != nil {
		return nil, err
	}
	result := &preparedMemberInvitation{invitation: invitation, issuer: trust.UserID, code: code,
		tlsDigest: bytes.Clone(trust.TLSDigest), policyDigest: bytes.Clone(trust.PolicyDigest)}
	err = code.With(func(secret []byte) error {
		rand.Read(secret)
		envelope, err := invitation.SealBootstrap(secret, bootstrap, now)
		if err != nil {
			return err
		}
		if wire.Envelope, err = EncodeInvitationBootstrapEnvelope(invitation, envelope, now); err != nil {
			return err
		}
		_, result.verifier, err = invitation.EnrollmentVerifier(secret, now)
		return err
	})
	if err == nil {
		result.publication, err = json.Marshal(wire)
	}
	if err != nil {
		return nil, errors.Join(err, result.close())
	}
	return result, nil
}
