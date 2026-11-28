package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

type enrollmentCertificateFixture struct {
	certificate  UserEnrollmentCertificate
	state        UserKeyState
	trust        UserKeyTrust
	bootstrap    *InviteBootstrap
	plan         *InviteRewrapPlan
	organisation ed25519.PrivateKey
	master       []byte
	binding      UserKeyBinding
	envelope     Envelope
}

func newEnrollmentCertificateFixture(t *testing.T) enrollmentCertificateFixture {
	t.Helper()
	b, m, copies, seed := manifestFixture(t)
	t.Cleanup(b.Wipe)
	organisation := ed25519.NewKeyFromSeed(seed)
	t.Cleanup(func() { Wipe(organisation) })
	plan, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, b, m, copies, 2, m.ExpiresAt, time.Unix(m.ExpiresAt-1, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plan.Wipe)
	root := KeyRef{ID: uuid.New(), Version: 1}
	enc := KeyRef{ID: m.Context.KeyID, Version: m.Context.KeyVersion}
	sign := KeyRef{ID: uuid.New(), Version: 1}
	state, err := SignUserKeyState(UserKeyState{FormatVersion: 1, WorkspaceID: m.Context.WorkspaceID, UserID: m.Context.UserID, Sequence: 3, Active: true, Encryption: enc, Signing: sign, MinimumEncryptionCertificate: 2, MinimumSigningCertificate: 4, Signer: root}, organisation)
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := SignUserKeyCertificate(UserKeyCertificate{FormatVersion: 1, WorkspaceID: state.WorkspaceID, UserID: state.UserID, Key: enc, Kind: "user-enc", Suite: SuiteX25519HKDFSHA256AES256GCM, PublicKey: m.Bootstrap.Encryption, Revision: 2, Signer: root}, organisation)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := SignUserKeyCertificate(UserKeyCertificate{FormatVersion: 1, WorkspaceID: state.WorkspaceID, UserID: state.UserID, Key: sign, Kind: "user-sign", Suite: 1, PublicKey: m.Bootstrap.Signing, Revision: 4, Signer: root}, organisation)
	if err != nil {
		t.Fatal(err)
	}
	c := UserEnrollmentCertificate{FormatVersion: 1, Manifest: m, BootstrapEncryption: encryption, BootstrapSigning: signing, Rekey: plan.Proof}
	trust := UserKeyTrust{WorkspaceID: state.WorkspaceID, UserID: state.UserID, Signer: root, Organisation: bytes.Clone(b.OrganisationPublic), MinimumSequence: 3, MinimumWrappingRevision: 1}
	master := bytes.Repeat([]byte{63}, 32)
	t.Cleanup(func() { Wipe(master) })
	binding := UserKeyBinding{WorkspaceID: state.WorkspaceID, UserID: state.UserID, Encryption: KeyRef{ID: plan.Proof.EncryptionKeyID, Version: 1}, Signing: KeyRef{ID: plan.Proof.SigningKeyID, Version: 1}, Revision: 1}
	envelope, err := SealUserKeys(master, binding, plan.Keys)
	if err != nil {
		t.Fatal(err)
	}
	return enrollmentCertificateFixture{c, state, trust, b, plan, organisation, master, binding, envelope}
}

func TestHistoricalEnrollmentCertifiesStoredCopiesWithoutRestoringMembership(t *testing.T) {
	f := newEnrollmentCertificateFixture(t)
	disabled := f.state
	disabled.Active = false
	disabled.Sequence++
	disabled, err := SignUserKeyState(disabled, f.organisation)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUserEnrollmentCertificate(f.certificate, disabled, f.trust, f.certificate.Manifest.Revision); err != ErrPolicy {
		t.Fatal("a historical certificate restored live enrollment", err)
	}
	if err := VerifyHistoricalUserEnrollmentCertificate(f.certificate, f.trust); err != nil {
		t.Fatal("a genuinely certified signer could not authorize rewrap of existing ciphertext", err)
	}
	unrelated := f.trust
	unrelated.UserID = uuid.New()
	if err := VerifyHistoricalUserEnrollmentCertificate(f.certificate, unrelated); err != ErrAuthentication {
		t.Fatal("historical certification crossed subject scope", err)
	}
	tampered := f.certificate
	tampered.Rekey.Signature = bytes.Clone(tampered.Rekey.Signature)
	tampered.Rekey.Signature[0] ^= 1
	if err := VerifyHistoricalUserEnrollmentCertificate(tampered, f.trust); err != ErrAuthentication {
		t.Fatal("historical certification accepted an invalid rekey", err)
	}
}

func TestUserEnrollmentCertificateRoundTripAndUnlock(t *testing.T) {
	f := newEnrollmentCertificateFixture(t)
	c := f.certificate
	now := time.Unix(c.Manifest.ExpiresAt-1, 0)
	prepared, err := PrepareUserEnrollmentCertificate(c, c.Manifest.Context, f.state, f.trust, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeUserEnrollmentCertificate(prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUserEnrollmentCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.Rekey.Signature[0] ^= 1 // Preparation owns an independent public snapshot.
	if err := VerifyUserEnrollmentCertificate(decoded, f.state, f.trust, 2); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnrolledUserKeys(f.master, f.binding, f.envelope, decoded, f.state, f.trust, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	if !bytes.Equal(opened.EncryptionPrivate, f.plan.Keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, f.plan.Keys.SigningSeed) {
		t.Fatal("wrong final private keys")
	}
	if _, err := PrepareUserEnrollmentCertificate(decoded, decoded.Manifest.Context, f.state, f.trust, 2, time.Unix(decoded.Manifest.ExpiresAt, 0)); err != ErrAuthentication {
		t.Fatal("expired live enrollment")
	}
	// Historical account certification remains valid after the invite expires.
	if err := VerifyUserEnrollmentCertificate(decoded, f.state, f.trust, 2); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), []byte("!"), append(bytes.Clone(raw), ' '), bytes.Repeat([]byte{' '}, MaxUserEnrollmentCertificateBytes+1), append([]byte(`{"unknown":1,`), raw[1:]...)} {
		if _, err := DecodeUserEnrollmentCertificate(bad); err != ErrFormat {
			t.Fatal("ambiguous certificate accepted", err)
		}
	}
}

func TestUserEnrollmentCertificateAuthentication(t *testing.T) {
	for _, mode := range []string{"state-signature", "revoked", "state-rollback", "enc-cert", "sign-cert", "manifest", "manifest-rollback", "rekey", "wrong-anchor", "wrong-user", "public-pair", "old-signing-id", "org-id", "capsule", "binding", "wrap-rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newEnrollmentCertificateFixture(t)
			c := f.certificate
			state, trust := f.state, f.trust
			minimum := uint64(2)
			want := ErrAuthentication
			switch mode {
			case "state-signature":
				state.Signature[0] ^= 1
			case "revoked":
				state.Active = false
				state, _ = SignUserKeyState(state, f.organisation)
				want = ErrPolicy
			case "state-rollback":
				trust.MinimumSequence++
				want = ErrRollback
			case "enc-cert":
				c.BootstrapEncryption.Signature[0] ^= 1
			case "sign-cert":
				c.BootstrapSigning.Signature[0] ^= 1
			case "manifest":
				c.Manifest.Signature[0] ^= 1
			case "manifest-rollback":
				minimum++
				want = ErrRollback
			case "rekey":
				c.Rekey.Signature[0] ^= 1
			case "wrong-anchor":
				state.Encryption = KeyRef{ID: uuid.New(), Version: 1}
				state, _ = SignUserKeyState(state, f.organisation)
			case "wrong-user":
				trust.UserID = uuid.New()
			case "public-pair":
				c.BootstrapSigning.PublicKey = bytes.Repeat([]byte{17}, 32)
				c.BootstrapSigning, _ = SignUserKeyCertificate(c.BootstrapSigning, f.organisation)
			case "old-signing-id", "org-id":
				c.Rekey.SigningKeyID = state.Signing.ID
				if mode == "org-id" {
					c.Rekey.SigningKeyID = trust.Signer.ID
				}
				raw, err := c.Rekey.signingBytes(c.Manifest.Context)
				if err != nil {
					t.Fatal(err)
				}
				key := ed25519.NewKeyFromSeed(f.bootstrap.SigningSeed)
				c.Rekey.Signature = ed25519.Sign(key, raw)
				Wipe(key)
			case "capsule":
				f.envelope.Ciphertext[0] ^= 1
			case "binding":
				f.binding.Encryption.ID = uuid.New()
			case "wrap-rollback":
				trust.MinimumWrappingRevision = 2
				want = ErrRollback
			}
			keys, err := OpenEnrolledUserKeys(f.master, f.binding, f.envelope, c, state, trust, minimum)
			if keys != nil || err != want {
				t.Fatal("invalid enrollment accepted", err, want)
			}
		})
	}
}

func TestUserEnrollmentCertificateShape(t *testing.T) {
	f := newEnrollmentCertificateFixture(t)
	for _, mutate := range []func(*UserEnrollmentCertificate){func(c *UserEnrollmentCertificate) { c.FormatVersion = 0 }, func(c *UserEnrollmentCertificate) { c.Manifest.Revision = 0 }, func(c *UserEnrollmentCertificate) { c.BootstrapEncryption.Kind = "bad" }, func(c *UserEnrollmentCertificate) { c.BootstrapSigning.Signature = nil }, func(c *UserEnrollmentCertificate) { c.Rekey.KeyVersion = 0 }, func(c *UserEnrollmentCertificate) { c.Rekey.Signature = nil }} {
		c := f.certificate
		mutate(&c)
		if _, err := EncodeUserEnrollmentCertificate(c); err == nil {
			t.Fatal("invalid certificate shape")
		}
		if err := VerifyUserEnrollmentCertificate(c, f.state, f.trust, 2); err == nil {
			t.Fatal("invalid shape verified")
		}
		raw, _ := json.Marshal(c)
		if _, err := DecodeUserEnrollmentCertificate(raw); err == nil {
			t.Fatal("invalid shape decoded")
		}
	}
	other := f.certificate.Manifest.Context
	other.InviteID = uuid.New()
	if _, err := PrepareUserEnrollmentCertificate(f.certificate, other, f.state, f.trust, 2, time.Unix(f.certificate.Manifest.ExpiresAt-1, 0)); err != ErrAuthentication {
		t.Fatal("different issuance prepared", err)
	}
	f.state.Signature[0] ^= 1
	if _, err := PrepareUserEnrollmentCertificate(f.certificate, f.certificate.Manifest.Context, f.state, f.trust, 2, time.Unix(f.certificate.Manifest.ExpiresAt-1, 0)); err != ErrAuthentication {
		t.Fatal("unverified state prepared", err)
	}
}
