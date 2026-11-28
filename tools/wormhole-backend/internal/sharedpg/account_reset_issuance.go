package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountResetMaterialSQL = `SELECT wormhole_api_v1.account_reset_material(` + serverCAArguments + `,$10::text)::text`
const publishAccountResetSQL = `SELECT wormhole_api_v1.publish_account_reset(` + serverCAArguments +
	`,$10::uuid,$11::jsonb,$12::bigint,pg_catalog.decode($13,'hex'),pg_catalog.decode($14,'hex'),pg_catalog.decode($15,'hex'),$16::text)`
const accountResetMaterialLimit = 2*vault.MaxUserEnrollmentCertificateBytes + 8192
const accountResetPublicationReadySQL = `SELECT wormhole_api_v1.account_reset_publication_ready()::text`

var ErrAccountResetLogging = errors.New("account reset credential logging is enabled")

type accountResetMaterial struct {
	RoleTag         string                       `json:"roleTag"`
	Database        string                       `json:"database"`
	Subject         accountResetSubject          `json:"subject"`
	SignedState     []byte                       `json:"signedState"`
	Enrollment      []byte                       `json:"enrollment"`
	Copies          []workspaceAdminRecoveryCopy `json:"copies"`
	Recipient       vault.KeyRef                 `json:"recipient"`
	RecipientPublic []byte                       `json:"recipientPublic"`
	RecipientProof  []byte                       `json:"recipientProof"`
}

// PreparedAccountReset owns one issuance. Calls must be serialized by its
// native owner. Close it on every exit. PostgreSQL receives ciphertext and a
// SCRAM verifier. The plaintext account keys are wiped before preparation returns.
type PreparedAccountReset struct {
	offer      accountResetOffer
	issuer     uuid.UUID
	document   []byte
	capsule    []byte
	verifier   []byte
	commitHash [32]byte
	factors    *securemem.Buffer
	published  bool
	delivered  bool
}

func (p *PreparedAccountReset) MatchesTarget(user uuid.UUID) bool {
	return p != nil && user != uuid.Nil && p.offer.Subject.UserID == user
}

func (p *PreparedAccountReset) MatchesReenrollment(user uuid.UUID, login string, suspension uint64) bool {
	return p.MatchesTarget(user) && p.offer.Version == 2 && p.offer.Subject.LoginName == login && p.offer.Subject.Suspension == suspension
}

func (p *PreparedAccountReset) Close() error {
	if p == nil {
		return nil
	}
	vault.Wipe(p.verifier)
	p.verifier = nil
	if p.factors == nil {
		return nil
	}
	if err := p.factors.Close(); err != nil {
		return err
	}
	p.factors = nil
	return nil
}

// PrepareAccountReset must be called by a freshly authenticated custodian.
// It targets the immutable login and keeps both certified keys. Preparation is
// read-only apart from the audit entry for the release of ciphertext.
func (s *Session) PrepareAccountReset(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	endpoints []Endpoint, actor *vault.UserKeys, targetLogin string) (*PreparedAccountReset, error) {
	if ctx == nil || actor == nil {
		return nil, ErrConfiguration
	}
	if _, err := vault.SharedSalt(trust.WorkspaceID.String(), targetLogin); err != nil {
		return nil, err
	}
	anchor, err := accountResetIssuer(trust, tls, actor)
	if err != nil {
		return nil, err
	}
	material, err := s.readAccountResetMaterial(ctx, trust, accountResetMaterialSQL, [][]byte{[]byte(targetLogin)}, 4)
	if err != nil {
		return nil, err
	}
	if material.Subject.LoginName != targetLogin {
		return nil, vault.ErrAuthentication
	}
	targetPublic, err := material.verifyTarget(trust, anchor)
	if err != nil {
		return nil, err
	}
	org, err := material.openOrganisation(trust, anchor, actor)
	if err != nil {
		return nil, err
	}
	defer org.Wipe()
	target, err := openEscrowKeyPair(material.Copies, material.Subject.Encryption, material.Subject.Signing, func(row workspaceAdminRecoveryCopy) ([]byte, error) {
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: row.KeyRef,
			Holder: material.Recipient, Issuer: material.Subject.Signing}
		return vault.OpenKeyCopy(org.EncryptionPrivate, binding, accountRecoverySignedCopy(row), targetPublic.Signing)
	})
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	if err := verifyEscrowKeyPair(target, targetPublic); err != nil {
		return nil, err
	}
	now := time.Now()
	offer := accountResetOffer{Version: 1, WorkspaceID: trust.WorkspaceID, ID: uuid.New(), Subject: material.Subject,
		UserPublic: targetPublic, RoleTag: material.RoleTag, Database: material.Database, Endpoints: append([]Endpoint(nil), endpoints...),
		Organisation: anchor.Organisation, Signer: anchor.Signer, TLSBundle: tls.Encode(), SignedPolicy: bytes.Clone(trust.SignedProfile),
		ExpiresAt: now.Add(accountResetLifetime).Unix()}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepareResetOffer(offer, trust.UserID, org.SigningSeed, target, now)
}

func accountResetIssuer(trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys) (vault.UserKeyTrust, error) {
	anchor, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return anchor, err
	}
	policy, err := trust.Policy()
	if err != nil || !policy.OrgEscrow {
		return anchor, ErrAccountRecovery
	}
	public, err := actor.Public()
	if err != nil {
		return anchor, err
	}
	digest := enrollmentPublicDigest(public)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return anchor, vault.ErrAuthentication
	}
	return anchor, nil
}

func (s *Session) readAccountResetMaterial(ctx context.Context, trust TrustState, statement string, arguments [][]byte, copyCount int) (accountResetMaterial, error) {
	var material accountResetMaterial
	err := s.queryServerCA(ctx, trust, statement, arguments, accountResetMaterialLimit, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 || json.Unmarshal(rows[0][0], &material) != nil ||
			len(material.Copies) != copyCount || len(material.Enrollment) > vault.MaxUserEnrollmentCertificateBytes || len(material.SignedState) > 4096 {
			return ErrAdmissionResponse
		}
		return nil
	})
	return material, err
}

func (m accountResetMaterial) openOrganisation(trust TrustState, anchor vault.UserKeyTrust, actor *vault.UserKeys) (*vault.UserKeys, error) {
	recipient := vault.OrganisationRecoveryRecipient{WorkspaceID: trust.WorkspaceID,
		Encryption: m.Recipient, Signer: anchor.Signer, PublicKey: m.RecipientPublic}
	if err := vault.VerifyOrganisationRecoveryRecipient(recipient, m.RecipientProof, trust.WorkspaceID, anchor.Signer, anchor.Organisation); err != nil {
		return nil, err
	}
	org, err := openEscrowKeyPair(m.Copies, m.Recipient, anchor.Signer, func(row workspaceAdminRecoveryCopy) ([]byte, error) {
		return openServerCAOrgCopy(trust, row.KeyRef, accountRecoverySignedCopy(row), actor.EncryptionPrivate, actor.SigningSeed)
	})
	if err != nil {
		return nil, err
	}
	if err := verifyEscrowKeyPair(org, vault.UserPublicKeys{Encryption: m.RecipientPublic, Signing: anchor.Organisation}); err != nil {
		org.Wipe()
		return nil, err
	}
	return org, nil
}

func (m accountResetMaterial) verifyTarget(trust TrustState, issuer vault.UserKeyTrust) (vault.UserPublicKeys, error) {
	stateDigest := sha256.Sum256(m.SignedState)
	certDigest := sha256.Sum256(m.Enrollment)
	if !bytes.Equal(stateDigest[:], m.Subject.StateDigest) || !bytes.Equal(certDigest[:], m.Subject.CertificateDigest) {
		return vault.UserPublicKeys{}, vault.ErrAuthentication
	}
	state, err := vault.DecodeUserKeyState(m.SignedState)
	if err != nil {
		return vault.UserPublicKeys{}, err
	}
	if m.Subject.Suspension != 0 && state.Sequence != m.Subject.AccountSequence {
		return vault.UserPublicKeys{}, vault.ErrAuthentication
	}
	cert, err := vault.DecodeUserEnrollmentCertificate(m.Enrollment)
	if err != nil {
		return vault.UserPublicKeys{}, err
	}
	floor := trust.catalogAuthorFloor(m.Subject.UserID)
	target := vault.UserKeyTrust{WorkspaceID: trust.WorkspaceID, UserID: m.Subject.UserID, Signer: issuer.Signer,
		Organisation: issuer.Organisation, MinimumSequence: floor.Revision}
	author := trust.catalogAuthorMaterial(UnverifiedNodeAuthor{
		Key: m.Subject.Signing, State: &state, EnrollmentCertificate: &cert,
	})
	if err := vault.VerifyUserEnrollmentCertificate(cert, state, target, max(author.minimum, 1)); err != nil {
		return vault.UserPublicKeys{}, err
	}
	if floor.Revision == state.Sequence && !bytes.Equal(floor.Digest, stateDigest[:]) {
		return vault.UserPublicKeys{}, ErrAccountEquivocation
	}
	if trust.UserID == m.Subject.UserID && m.Subject.WrapRevision < trust.WrappingRevision {
		return vault.UserPublicKeys{}, vault.ErrRollback
	}
	if cert.Manifest.Context.LoginName != m.Subject.LoginName ||
		m.Subject.Encryption != (vault.KeyRef{ID: cert.Rekey.EncryptionKeyID, Version: cert.Rekey.KeyVersion}) ||
		m.Subject.Signing != (vault.KeyRef{ID: cert.Rekey.SigningKeyID, Version: cert.Rekey.KeyVersion}) {
		return vault.UserPublicKeys{}, vault.ErrAuthentication
	}
	return cert.Rekey.Public, nil
}

func openEscrowKeyPair(rows []workspaceAdminRecoveryCopy, encryption, signing vault.KeyRef,
	open func(workspaceAdminRecoveryCopy) ([]byte, error)) (*vault.UserKeys, error) {
	var keys vault.UserKeys
	for _, row := range rows {
		var target *[]byte
		switch row.KeyRef {
		case encryption:
			target = &keys.EncryptionPrivate
		case signing:
			target = &keys.SigningSeed
		default:
			continue
		}
		if *target != nil {
			keys.Wipe()
			return nil, ErrAdmissionResponse
		}
		var err error
		*target, err = open(row)
		if err != nil {
			keys.Wipe()
			return nil, err
		}
	}
	if len(keys.EncryptionPrivate) != 32 || len(keys.SigningSeed) != ed25519.SeedSize {
		keys.Wipe()
		return nil, ErrAdmissionResponse
	}
	return &keys, nil
}

func verifyEscrowKeyPair(keys *vault.UserKeys, expected vault.UserPublicKeys) error {
	public, err := keys.Public()
	if err != nil || !bytes.Equal(public.Encryption, expected.Encryption) || !bytes.Equal(public.Signing, expected.Signing) {
		return vault.ErrAuthentication
	}
	return nil
}

func prepareResetOffer(offer accountResetOffer, issuer uuid.UUID, seed []byte, keys *vault.UserKeys, now time.Time) (*PreparedAccountReset, error) {
	if len(seed) != ed25519.SeedSize || issuer == uuid.Nil {
		return nil, ErrConfiguration
	}
	body, err := offer.signingBytes()
	if err != nil {
		return nil, err
	}
	signing := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(signing)
	offer.Signature = ed25519.Sign(signing, body)
	if _, _, err := offer.transport(now); err != nil {
		return nil, err
	}
	document, err := json.Marshal(offer)
	if err != nil || len(document) > MaxAccountResetOfferBytes {
		return nil, ErrAccountRecovery
	}
	p := &PreparedAccountReset{offer: offer, issuer: issuer, document: document}
	p.factors, err = securemem.New(vault.InviteCodeBytes+32, false)
	if err != nil {
		return nil, err
	}
	err = p.factors.With(func(secret []byte) error {
		rand.Read(secret)
		code, ask := secret[:vault.InviteCodeBytes], secret[vault.InviteCodeBytes:]
		digest := sha256.Sum256(document)
		master, err := accountResetKey(code, ask, digest, "wormhole/v1/account-reset-capsule")
		if err != nil {
			return err
		}
		defer vault.Wipe(master)
		capsule, err := vault.SealUserKeys(master, offer.capsuleBinding(), keys)
		if err != nil {
			return err
		}
		p.capsule, err = json.Marshal(capsule)
		if err != nil {
			return err
		}
		commit, err := accountResetKey(code, ask, digest, "wormhole/v1/account-reset-commit")
		if err != nil {
			return err
		}
		p.commitHash = sha256.Sum256(commit)
		vault.Wipe(commit)
		login, err := vault.DeriveInviteLogin(code, offer.codeContext())
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		p.verifier, err = NewSCRAMVerifier(login)
		return err
	})
	if err != nil {
		if cleanupErr := p.Close(); cleanupErr != nil {
			return p, errors.Join(err, cleanupErr)
		}
		return nil, err
	}
	return p, nil
}

// PublishAccountReset reconciles retries of the same offer. PostgreSQL rechecks
// current custodianship, policy and exact target revisions before issuing a role.
func (s *Session) PublishAccountReset(ctx context.Context, trust TrustState, p *PreparedAccountReset) error {
	return s.publishAccountReset(ctx, trust, p, nil)
}

func (s *Session) publishAccountReset(ctx context.Context, trust TrustState, p *PreparedAccountReset, stage func() error) error {
	if ctx == nil || p == nil || p.factors == nil || len(p.verifier) == 0 {
		return ErrConfiguration
	}
	o := p.offer
	policy := sha256.Sum256(o.SignedPolicy)
	tls := sha256.Sum256(o.TLSBundle)
	if trust.Account == nil || trust.Enrollment == nil || trust.WorkspaceID != o.WorkspaceID || trust.UserID != p.issuer ||
		!bytes.Equal(trust.PolicyDigest, policy[:]) || !bytes.Equal(trust.TLSDigest, tls[:]) || o.ExpiresAt <= time.Now().Unix() {
		return vault.ErrAuthentication
	}
	rows, err := s.Query(ctx, accountResetPublicationReadySQL, nil)
	if err != nil {
		return err
	}
	if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != "true" {
		return ErrAccountResetLogging
	}
	subject, err := json.Marshal(o.Subject)
	if err != nil {
		return err
	}
	offerHash := sha256.Sum256(p.document)
	args := [][]byte{[]byte(o.ID.String()), subject, strconv.AppendInt(nil, o.ExpiresAt, 10),
		hex.AppendEncode(nil, offerHash[:]), hex.AppendEncode(nil, p.commitHash[:]), hex.AppendEncode(nil, p.capsule), p.verifier}
	statement := publishAccountResetSQL
	if o.Version == 2 {
		bootstrap, err := json.Marshal(o.Replacement)
		if err != nil || len(bootstrap) > maxAccountReenrollmentBootstrap {
			return ErrAccountRecovery
		}
		statement = publishAccountReenrollmentSQL
		args = append(args, hex.AppendEncode(nil, bootstrap))
	}
	if stage != nil {
		if err := stage(); err != nil {
			return err
		}
	}
	err = s.queryServerCA(ctx, trust, statement, args, 64, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != o.role() {
			return ErrAdmissionResponse
		}
		return nil
	})
	if err == nil {
		p.published = true
	}
	return err
}

// BorrowHandover releases a confirmed offer to a protected native presenter
// once. The callback must neither retain the borrowed slices nor call Close.
func (p *PreparedAccountReset) BorrowHandover(use func(document, code, ask []byte) error) error {
	if p == nil || p.factors == nil || !p.published || p.delivered || use == nil || p.offer.ExpiresAt <= time.Now().Unix() {
		return ErrAccountRecovery
	}
	err := p.factors.With(func(secret []byte) error {
		return use(bytes.Clone(p.document), secret[:vault.InviteCodeBytes], secret[vault.InviteCodeBytes:])
	})
	if err == nil {
		p.delivered = true
	}
	return err
}
