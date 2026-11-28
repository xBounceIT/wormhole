package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const invitationCertificationSQL = `SELECT pg_catalog.encode(signed_state,'hex'),state_sequence::text,pg_catalog.encode(signed_profile,'hex'),
enc_suite::text,pg_catalog.encode(enc_public,'hex'),enc_signer_id::text,enc_signer_version::text,enc_cert_revision::text,pg_catalog.encode(enc_signature,'hex'),
sign_suite::text,pg_catalog.encode(sign_public,'hex'),sign_signer_id::text,sign_signer_version::text,sign_cert_revision::text,pg_catalog.encode(sign_signature,'hex')
FROM wormhole_api_v1.enrollment_certification($1::uuid,$2::bigint,pg_catalog.decode($3,'hex'))`

type UnverifiedInvitationCertification struct {
	State         vault.UserKeyState       `json:"-"`
	Encryption    vault.UserKeyCertificate `json:"-"`
	Signing       vault.UserKeyCertificate `json:"-"`
	SignedProfile []byte                   `json:"-"`
}

func (s *Session) InvitationCertification(ctx context.Context, i Invitation, manifest vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if _, err := i.EnrollmentRole(time.Now()); err != nil {
		return nil, err
	}
	if manifest.Context != i.Enrollment.Context || manifest.ExpiresAt != i.ExpiresAt {
		return nil, ErrInvitation
	}
	raw, err := vault.EncodeInviteManifest(manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	rows, err := s.Query(ctx, invitationCertificationSQL, [][]byte{[]byte(i.Enrollment.Context.InviteID.String()), []byte(strconv.FormatUint(manifest.Revision, 10)), hex.AppendEncode(nil, digest[:])})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	result, err := parseInvitationCertification(rows, i)
	if err != nil {
		s.cancel()
	}
	return result, err
}

func parseInvitationCertification(rows [][][]byte, i Invitation) (*UnverifiedInvitationCertification, error) {
	if i.Enrollment == nil || len(rows) != 1 || len(rows[0]) != 15 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	state, err := parseAccountKeyState([][][]byte{row[:2]}, AdmissionRequest{WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID})
	if err != nil {
		return nil, err
	}
	if state.Encryption != (vault.KeyRef{ID: i.Enrollment.Context.KeyID, Version: i.Enrollment.Context.KeyVersion}) {
		return nil, ErrAdmissionResponse
	}
	if len(row[2]) == 0 || len(row[2]) > 2*vault.MaxSignedPolicyBytes {
		return nil, ErrAdmissionResponse
	}
	profile, err := hex.DecodeString(string(row[2]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	if _, err := vault.DecodeSignedPolicy(profile); err != nil {
		return nil, ErrAdmissionResponse
	}
	certificates, err := parseUserKeyCertificates(row[3:], vault.UserKeyBinding{WorkspaceID: i.WorkspaceID, UserID: state.UserID, Encryption: state.Encryption, Signing: state.Signing})
	if err != nil || certificates[0].Signer != state.Signer {
		return nil, ErrAdmissionResponse
	}
	return &UnverifiedInvitationCertification{State: *state, Encryption: *certificates[0], Signing: *certificates[1], SignedProfile: profile}, nil
}

// Verify uses the organisation key authenticated by the invitation/code flow.
// It establishes no device authorization. Floors are supplied by the caller;
// first enrollment uses explicit floors of at least one. Reverify before commit.
func (u *UnverifiedInvitationCertification) Verify(i Invitation, organisation ed25519.PublicKey, manifest vault.InviteManifest, minimumState, minimumPolicy, minimumManifest uint64, now time.Time) (vault.Policy, vault.UserKeyTrust, error) {
	fail := func(err error) (vault.Policy, vault.UserKeyTrust, error) {
		return vault.Policy{}, vault.UserKeyTrust{}, err
	}
	if u == nil || minimumState == 0 || minimumPolicy == 0 {
		return fail(ErrConfiguration)
	}
	if _, err := i.EnrollmentRole(now); err != nil {
		return fail(err)
	}
	fingerprint := sha256.Sum256(organisation)
	if len(organisation) != ed25519.PublicKeySize || !bytes.Equal(fingerprint[:], i.OrganisationFingerprint) {
		return fail(vault.ErrAuthentication)
	}
	if err := vault.VerifyInviteManifest(manifest, i.Enrollment.Context, organisation, minimumManifest, i.ExpiresAt, now); err != nil {
		return fail(err)
	}
	trust := vault.UserKeyTrust{WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID, Signer: u.State.Signer, Organisation: bytes.Clone(organisation), MinimumSequence: minimumState, MinimumWrappingRevision: 1}
	if err := vault.VerifyUserKeyState(u.State, trust); err != nil {
		return fail(err)
	}
	if !u.State.Active {
		return fail(vault.ErrPolicy)
	}
	if u.State.Encryption != (vault.KeyRef{ID: i.Enrollment.Context.KeyID, Version: i.Enrollment.Context.KeyVersion}) {
		return fail(vault.ErrAuthentication)
	}
	if err := vault.VerifyUserKeyCertificate(u.Encryption, trust.WorkspaceID, trust.UserID, u.State.Encryption, "user-enc", trust.Signer, organisation, u.State.MinimumEncryptionCertificate); err != nil {
		return fail(err)
	}
	if err := vault.VerifyUserKeyCertificate(u.Signing, trust.WorkspaceID, trust.UserID, u.State.Signing, "user-sign", trust.Signer, organisation, u.State.MinimumSigningCertificate); err != nil {
		return fail(err)
	}
	if !bytes.Equal(manifest.Bootstrap.Encryption, u.Encryption.PublicKey) || !bytes.Equal(manifest.Bootstrap.Signing, u.Signing.PublicKey) {
		return fail(vault.ErrAuthentication)
	}
	signed, err := vault.DecodeSignedPolicy(u.SignedProfile)
	if err != nil {
		return fail(err)
	}
	if err := vault.VerifyPolicy(signed, i.WorkspaceID.String(), trust.Signer.ID.String(), trust.Signer.Version, organisation, minimumPolicy); err != nil {
		return fail(err)
	}
	if signed.Policy.MinAPI > 1 || signed.Policy.MaxAPI < 1 {
		return fail(ErrAPIVersion)
	}
	if _, err := i.AuthenticatedTLSBundle(organisation, trust.Signer); err != nil {
		return fail(err)
	}
	return signed.Policy, trust, nil
}
