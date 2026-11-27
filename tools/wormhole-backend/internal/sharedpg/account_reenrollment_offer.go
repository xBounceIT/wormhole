package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountReenrollmentMaterialSQL = `SELECT wormhole_api_v1.account_reenrollment_material(` + serverCAArguments + `,$10::uuid,$11::bigint)::text`
const publishAccountReenrollmentSQL = `SELECT wormhole_api_v1.publish_account_reenrollment(` + serverCAArguments +
	`,$10::uuid,$11::jsonb,$12::bigint,pg_catalog.decode($13,'hex'),pg_catalog.decode($14,'hex'),pg_catalog.decode($15,'hex'),$16::text,pg_catalog.decode($17,'hex'))`
const fetchAccountReenrollmentSQL = `SELECT pg_catalog.encode(wormhole_api_v1.account_reenrollment_capsule($1::uuid,pg_catalog.decode($2,'hex')),'hex')`
const accountReenrollmentSupportedSQL = `SELECT
	(pg_catalog.to_regprocedure('wormhole_api_v1.redeem_account_reenrollment(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea,bytea)') IS NOT NULL)::text`
const maxAccountReenrollmentBootstrap = 32768

type accountReplacementEnrollment struct {
	Manifest   vault.InviteManifest     `json:"manifest"`
	Encryption vault.UserKeyCertificate `json:"encryption"`
	Signing    vault.UserKeyCertificate `json:"signing"`
	State      vault.UserKeyState       `json:"state"`
}

func (o accountResetOffer) verifyReplacement(now time.Time) error {
	r := o.Replacement
	if r == nil || o.Subject.Suspension == 0 || o.Subject.Suspension > math.MaxInt64 ||
		o.Subject.AccountSequence == 0 || o.Subject.AccountSequence >= math.MaxInt64 ||
		r.State.Sequence != o.Subject.AccountSequence+1 || !r.State.Active ||
		len(r.Manifest.Copies) != 0 || len(r.Manifest.Issuers) != 0 ||
		r.Manifest.Revision != 1 || r.State.Encryption.Version != 1 || r.State.Signing.Version != 1 ||
		r.State.MinimumSigningCertificate != 1 || r.State.MinimumEncryptionCertificate != 1 {
		return ErrAccountRecovery
	}
	for _, key := range []uuid.UUID{r.State.Encryption.ID, r.State.Signing.ID} {
		if key == o.Subject.Encryption.ID || key == o.Subject.Signing.ID {
			return vault.ErrAuthentication
		}
	}
	if !bytes.Equal(r.Manifest.Bootstrap.Encryption, o.UserPublic.Encryption) || !bytes.Equal(r.Manifest.Bootstrap.Signing, o.UserPublic.Signing) ||
		!bytes.Equal(r.Encryption.PublicKey, o.UserPublic.Encryption) || !bytes.Equal(r.Signing.PublicKey, o.UserPublic.Signing) {
		return vault.ErrAuthentication
	}
	if err := vault.VerifyInviteManifest(r.Manifest, o.codeContext(), o.Organisation, 1, o.ExpiresAt, now); err != nil {
		return err
	}
	pin := vault.UserKeyTrust{WorkspaceID: o.WorkspaceID, UserID: o.Subject.UserID, Signer: o.Signer, Organisation: o.Organisation, MinimumSequence: o.Subject.AccountSequence + 1}
	if err := vault.VerifyUserKeyState(r.State, pin); err != nil {
		return err
	}
	if err := vault.VerifyUserKeyCertificate(r.Encryption, pin.WorkspaceID, pin.UserID, r.State.Encryption, "user-enc", pin.Signer,
		pin.Organisation, r.State.MinimumEncryptionCertificate); err != nil {
		return err
	}
	return vault.VerifyUserKeyCertificate(r.Signing, pin.WorkspaceID, pin.UserID, r.State.Signing, "user-sign", pin.Signer,
		pin.Organisation, r.State.MinimumSigningCertificate)
}

// AccountReenrollmentSupported checks that the server can register the new
// enrollment. Older servers could issue offers without a redemption endpoint.
func (s *Session) AccountReenrollmentSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, accountReenrollmentSupportedSQL)
}

// PrepareAccountReenrollment creates a bootstrap for the exact suspended
// account. The custodian receives no previous account private key and the
// delivered factors reveal only temporary bootstrap keys to the recipient.
func (s *Session) PrepareAccountReenrollment(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	endpoints []Endpoint, actor *vault.UserKeys, account uuid.UUID, suspension uint64) (*PreparedAccountReset, error) {
	if ctx == nil || actor == nil || account == uuid.Nil || account == trust.UserID || suspension == 0 || suspension > math.MaxInt64 {
		return nil, ErrConfiguration
	}
	anchor, err := accountResetIssuer(trust, tls, actor)
	if err != nil {
		return nil, err
	}
	if supported, err := s.AccountReenrollmentSupported(ctx); err != nil || !supported {
		return nil, errors.Join(ErrAccountRecovery, err)
	}
	material, err := s.readAccountResetMaterial(ctx, trust, accountReenrollmentMaterialSQL,
		[][]byte{[]byte(account.String()), strconv.AppendUint(nil, suspension, 10)}, 2)
	if err != nil {
		return nil, err
	}
	if material.Subject.UserID != account || material.Subject.Suspension != suspension ||
		material.Subject.AccountSequence == 0 || material.Subject.AccountSequence >= math.MaxInt64 {
		return nil, vault.ErrAuthentication
	}
	if _, err := material.verifyTarget(trust, anchor); err != nil {
		return nil, err
	}
	organisation, err := material.openOrganisation(trust, anchor, actor)
	if err != nil {
		return nil, err
	}
	defer organisation.Wipe()
	now := time.Now()
	offer := accountResetOffer{Version: 2, WorkspaceID: trust.WorkspaceID, ID: uuid.New(), Subject: material.Subject,
		RoleTag: material.RoleTag, Database: material.Database, Endpoints: append([]Endpoint(nil), endpoints...),
		Organisation: anchor.Organisation, Signer: anchor.Signer, TLSBundle: tls.Encode(), SignedPolicy: bytes.Clone(trust.SignedProfile),
		ExpiresAt: now.Add(accountResetLifetime).Unix()}
	return createAccountReenrollmentOffer(ctx, offer, trust.UserID, organisation.SigningSeed, now)
}

func createAccountReenrollmentOffer(ctx context.Context, offer accountResetOffer, issuer uuid.UUID, seed []byte, now time.Time) (*PreparedAccountReset, error) {
	if ctx == nil || offer.Version != 2 || issuer == uuid.Nil || len(seed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bootstrap, err := vault.NewInviteBootstrap(offer.Organisation)
	if err != nil {
		return nil, err
	}
	defer bootstrap.Wipe()
	keys := &vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}
	offer.UserPublic, err = keys.Public()
	if err != nil {
		return nil, err
	}
	invite := offer.codeContext()
	invite.KeyID, invite.KeyVersion = uuid.New(), 1
	org := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(org)
	cert, err := certifyInvitationBootstrap(invite, offer.Signer, offer.UserPublic, org)
	if err != nil {
		return nil, err
	}
	cert.State.Sequence = offer.Subject.AccountSequence + 1
	state, err := vault.SignUserKeyState(cert.State, org)
	if err != nil {
		return nil, err
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: invite, Revision: 1,
		ExpiresAt: offer.ExpiresAt, Bootstrap: offer.UserPublic}, seed)
	if err != nil {
		return nil, err
	}
	offer.Replacement = &accountReplacementEnrollment{Manifest: manifest, Encryption: cert.Encryption, Signing: cert.Signing, State: state}
	return prepareResetOffer(offer, issuer, seed, keys, now)
}

// AccountReenrollment owns the new private keys generated by the recipient.
// The caller must wipe Keys. Opening the handover does not publish the
// enrollment, restore roots, or change account access.
type AccountReenrollment struct {
	Keys        *vault.UserKeys
	Certificate vault.UserEnrollmentCertificate
	State       vault.UserKeyState
}

func OpenAccountReenrollment(ctx context.Context, document, code, ask []byte) (*AccountReenrollment, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	offer, err := parseAccountOffer(document)
	if err != nil {
		return nil, err
	}
	if offer.Version != 2 {
		return nil, ErrAccountRecovery
	}
	settings, _, err := offer.transport(time.Now())
	if err != nil {
		return nil, err
	}
	keys, err := openAccountReset(ctx, offer, settings, sha256.Sum256(document), code, ask)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe()
	return prepareAccountReenrollmentKeys(ctx, offer, keys, time.Now())
}

func prepareAccountReenrollmentKeys(ctx context.Context, offer accountResetOffer, keys *vault.UserKeys, now time.Time) (*AccountReenrollment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := offer.Replacement
	bootstrap := &vault.InviteBootstrap{EncryptionPrivate: keys.EncryptionPrivate, SigningSeed: keys.SigningSeed, OrganisationPublic: offer.Organisation}
	fresh, proof, err := vault.PrepareInviteRekey(offer.codeContext(), bootstrap)
	if err != nil {
		return nil, err
	}
	certificate := vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: r.Manifest, BootstrapEncryption: r.Encryption, BootstrapSigning: r.Signing, Rekey: proof}
	pin := vault.UserKeyTrust{WorkspaceID: offer.WorkspaceID, UserID: offer.Subject.UserID, Signer: offer.Signer, Organisation: offer.Organisation, MinimumSequence: r.State.Sequence}
	certificate, err = vault.PrepareUserEnrollmentCertificate(certificate, offer.codeContext(), r.State, pin, 1, now)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		fresh.Wipe()
		return nil, err
	}
	return &AccountReenrollment{Keys: fresh, Certificate: certificate, State: r.State}, nil
}
