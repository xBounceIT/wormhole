package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func certificationProfile(t *testing.T, workspace uuid.UUID, signer vault.KeyRef) []byte {
	t.Helper()
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	signed, err := vault.SignPolicy(vault.Policy{FormatVersion: 1, WorkspaceID: workspace.String(), Sequence: 1, Profile: vault.Standard, KDF: vault.KDFV1, ASKRequired: true, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, signer.ID.String(), signer.Version, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func certificationFixture(t *testing.T) (Invitation, vault.InviteManifest, [][][]byte, ed25519.PrivateKey, time.Time) {
	t.Helper()
	accountRows, trust, _ := accountEnrollmentRows(t)
	account, err := parseAccountEnrollmentMaterial(accountRows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := account.EnrollmentCertificate
	i, _ := enrollmentInvitationFixture(t)
	i.WorkspaceID = trust.WorkspaceID
	i.Enrollment.Context = c.Manifest.Context
	i.LoginName = c.Manifest.Context.LoginName
	i.ExpiresAt = c.Manifest.ExpiresAt
	fingerprint := sha256.Sum256(trust.Organisation)
	i.OrganisationFingerprint = bytes.Clone(fingerprint[:])
	row := [][]byte{accountRows[0][12], accountRows[0][13], hex.AppendEncode(nil, certificationProfile(t, trust.WorkspaceID, trust.Signer))}
	for _, cert := range []vault.UserKeyCertificate{c.BootstrapEncryption, c.BootstrapSigning} {
		row = append(row, []byte(strconv.FormatUint(uint64(cert.Suite), 10)), hex.AppendEncode(nil, cert.PublicKey), []byte(cert.Signer.ID.String()), []byte(strconv.FormatUint(uint64(cert.Signer.Version), 10)), []byte(strconv.FormatUint(cert.Revision, 10)), hex.AppendEncode(nil, cert.Signature))
	}
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	t.Cleanup(func() { vault.Wipe(org) })
	return i, c.Manifest, [][][]byte{row}, org, time.Unix(i.ExpiresAt-1, 0)
}

func TestInvitationCertificationParsing(t *testing.T) {
	i, manifest, rows, org, now := certificationFixture(t)
	parsed, err := parseInvitationCertification(rows, i)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][][][]byte{nil, {{}}, {rows[0], rows[0]}} {
		if _, err := parseInvitationCertification(bad, i); err != ErrAdmissionResponse {
			t.Fatal(err)
		}
	}
	for n := range rows[0] {
		bad := [][][]byte{append([][]byte(nil), rows[0]...)}
		bad[0][n] = []byte("bad")
		if _, err := parseInvitationCertification(bad, i); err != ErrAdmissionResponse {
			t.Fatal("column", n, err)
		}
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'0'}, 2*vault.MaxSignedPolicyBytes+1), []byte("00")} {
		bad := [][][]byte{append([][]byte(nil), rows[0]...)}
		bad[0][2] = raw
		if _, err := parseInvitationCertification(bad, i); err != ErrAdmissionResponse {
			t.Fatal(err)
		}
	}
	other := i
	other.Enrollment = nil
	if _, err := parseInvitationCertification(rows, other); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	changed := *i.Enrollment
	changed.Context.KeyID = uuid.New()
	other = i
	other.Enrollment = &changed
	if _, err := parseInvitationCertification(rows, other); err != ErrAdmissionResponse {
		t.Fatal("anchor mismatch", err)
	}
	wipeQueryRows(rows)
	policy, trust, err := parsed.Verify(i, org.Public().(ed25519.PublicKey), manifest, 1, 1, 1, now)
	if err != nil || policy.Profile != vault.Standard || trust.Signer != parsed.State.Signer {
		t.Fatal("valid certification", err)
	}
	trust.Organisation[0] ^= 1
	if _, _, err := parsed.Verify(i, org.Public().(ed25519.PublicKey), manifest, 1, 1, 1, now); err != nil {
		t.Fatal("result alias", err)
	}
	if _, err := parseUserKeyCertificates(nil, vault.UserKeyBinding{}); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.InvitationCertification(nil, i, manifest); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.InvitationCertification(context.Background(), Invitation{}, manifest); err != ErrInvitation {
		t.Fatal(err)
	}
	wrong := manifest
	wrong.Context.InviteID = uuid.New()
	if _, err := s.InvitationCertification(context.Background(), i, wrong); err != ErrInvitation {
		t.Fatal(err)
	}
	wrong = manifest
	wrong.Revision = 0
	if _, err := s.InvitationCertification(context.Background(), i, wrong); err == nil {
		t.Fatal("malformed manifest")
	}
	if _, err := s.InvitationCertification(context.Background(), i, manifest); err != ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestInvitationCertificationVerification(t *testing.T) {
	for _, mode := range []string{"nil", "state-floor-zero", "policy-floor-zero", "invite", "fingerprint", "manifest", "state", "state-rollback", "revoked", "anchor", "enc-cert", "sign-cert", "public-pair", "profile-encoding", "profile-signature", "profile-rollback", "api"} {
		t.Run(mode, func(t *testing.T) {
			i, manifest, rows, org, now := certificationFixture(t)
			value, err := parseInvitationCertification(rows, i)
			if err != nil {
				t.Fatal(err)
			}
			minState, minPolicy := uint64(1), uint64(1)
			switch mode {
			case "nil":
				value = nil
			case "state-floor-zero":
				minState = 0
			case "policy-floor-zero":
				minPolicy = 0
			case "invite":
				i.ExpiresAt = now.Unix()
			case "fingerprint":
				i.OrganisationFingerprint[0] ^= 1
			case "manifest":
				manifest.Signature[0] ^= 1
			case "state":
				value.State.Signature[0] ^= 1
			case "state-rollback":
				minState = 2
			case "revoked":
				value.State.Active = false
				value.State, err = vault.SignUserKeyState(value.State, org)
			case "anchor":
				value.State.Encryption.ID = uuid.New()
				value.State, err = vault.SignUserKeyState(value.State, org)
			case "enc-cert":
				value.Encryption.Signature[0] ^= 1
			case "sign-cert":
				value.Signing.Signature[0] ^= 1
			case "public-pair":
				value.Signing.PublicKey = bytes.Repeat([]byte{37}, 32)
				value.Signing, err = vault.SignUserKeyCertificate(value.Signing, org)
			case "profile-encoding":
				value.SignedProfile = nil
			case "profile-signature":
				signed, e := vault.DecodeSignedPolicy(value.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				signed.Signature[0] ^= 1
				value.SignedProfile, err = vault.EncodeSignedPolicy(signed)
			case "profile-rollback":
				minPolicy = 2
			case "api":
				signed, e := vault.DecodeSignedPolicy(value.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				signed.Policy.MinAPI = 2
				signed.Policy.MaxAPI = 2
				signed, err = vault.SignPolicy(signed.Policy, value.State.Signer.ID.String(), 1, org)
				if err == nil {
					value.SignedProfile, err = vault.EncodeSignedPolicy(signed)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			policy, trust, err := value.Verify(i, org.Public().(ed25519.PublicKey), manifest, minState, minPolicy, 1, now)
			if err == nil || policy.FormatVersion != 0 || len(trust.Organisation) != 0 {
				t.Fatal("invalid certification trusted", err)
			}
		})
	}
}
