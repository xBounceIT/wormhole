package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedEnrolledFixture(t *testing.T) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	t.Helper()
	c, p, o, root, master, account, org := sharedUnlockFixture(t)
	bootstrap := &vault.InviteBootstrap{EncryptionPrivate: bytes.Repeat([]byte{33}, 32), SigningSeed: bytes.Repeat([]byte{34}, 32), OrganisationPublic: bytes.Clone(org.Public().(ed25519.PublicKey))}
	defer bootstrap.Wipe()
	inviteContext := vault.InviteContext{WorkspaceID: o.Binding.WorkspaceID, UserID: o.Binding.UserID, InviteID: uuid.New(), KeyID: account.State.Encryption.ID, KeyVersion: account.State.Encryption.Version, LoginName: "alice"}
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: inviteContext, Revision: 1, ExpiresAt: time.Now().Add(time.Hour).Unix(), Bootstrap: public, Copies: []vault.KeyCopyBinding{}, Issuers: []vault.InviteIssuer{}}, org.Seed())
	if err != nil {
		t.Fatal(err)
	}
	keys, proof, err := vault.PrepareInviteRekey(inviteContext, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	certificate := &vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest, BootstrapEncryption: *account.EncryptionCertificate, BootstrapSigning: *account.SigningCertificate, Rekey: proof}
	account.Binding.Encryption = vault.KeyRef{ID: proof.EncryptionKeyID, Version: 1}
	account.Binding.Signing = vault.KeyRef{ID: proof.SigningKeyID, Version: 1}
	account.Envelope, err = vault.SealUserKeys(master, account.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	account.EnrollmentCertificate = certificate
	account.EncryptionCertificate, account.SigningCertificate = nil, nil
	current, err := readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision)
	if err != nil {
		t.Fatal(err)
	}
	current, err = c.persistAccountState(current, *account.State, account.Binding.Revision)
	if err != nil {
		t.Fatal(err)
	}
	next, err := current.AdvanceEnrollment(*certificate, account.Binding.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.persistAccountTrust(current, next); err != nil {
		t.Fatal(err)
	}
	p.enrollmentMaterial = p.accountMaterial
	p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
		t.Error("enrolled account used direct endpoint")
		return nil, sharedpg.ErrConfiguration
	}
	return c, p, o, root, master, account, org
}

func TestSharedEnrolledUnlockPersistsCertificatesButNotUnopenedWrapping(t *testing.T) {
	for _, mode := range []string{"delegation", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, master, account, org := sharedEnrolledFixture(t)
			before, err := readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := vault.EncodeUserEnrollmentCertificate(*account.EnrollmentCertificate)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := vault.DecodeUserEnrollmentCertificate(raw)
			if err != nil {
				t.Fatal(err)
			}
			certificate.BootstrapSigning.Revision++
			certificate.BootstrapSigning, err = vault.SignUserKeyCertificate(certificate.BootstrapSigning, org)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "delegation" {
				certificate.Rekey.Signature[0] ^= 1
			} else {
				account.Envelope.Ciphertext[0] ^= 1
				account.Binding.Revision++
			}
			account.EnrollmentCertificate = &certificate
			if err := c.Unlock(context.Background(), master, vault.KDFV1, false); !errors.Is(err, vault.ErrAuthentication) {
				t.Fatal("invalid account admitted", err)
			}
			stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, before.Revision)
			if err != nil {
				t.Fatal(err)
			}
			key := "key/" + account.State.Signing.ID.String() + "/" + strconv.FormatUint(uint64(account.State.Signing.Version), 10)
			if stored.Catalog[key].Revision != certificate.BootstrapSigning.Revision || stored.WrappingRevision != before.WrappingRevision || c.Unlocked() || c.privateKeys != nil {
				t.Fatal("partial facts lost, unverified wrap accepted, or private keys retained")
			}
			reset := stored
			reset.FormatVersion = 6
			reset.Enrollment = nil
			if _, err := readSharedAccountMaterial(context.Background(), p, reset); !errors.Is(err, sharedpg.ErrAccountRevision) {
				t.Fatal("format6 reset fell back to bootstrap", err)
			}
		})
	}
}

func TestSharedEnrolledUnlockAndPasswordChange(t *testing.T) {
	c, p, o, root, master, account, org := sharedEnrolledFixture(t)
	account.EnrollmentCertificate.Manifest.Revision++
	var err error
	account.EnrollmentCertificate.Manifest, err = vault.SignInviteManifest(account.EnrollmentCertificate.Manifest, org.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision)
	if err != nil || !c.Unlocked() || stored.Enrollment.ManifestRevision != 2 {
		t.Fatal("unlock did not persist selection", err)
	}
	newRoot := bytes.Repeat([]byte{94}, 32)
	p.changePassword = func(_ context.Context, plan *sharedpg.PreparedPasswordChange, _ string) (*sharedpg.PasswordChangeReceipt, error) {
		pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
		if err != nil || plan == nil || pending.Previous.Enrollment == nil || pending.Next.Enrollment == nil {
			t.Fatal("unprotected enrolled password change", err)
		}
		return &sharedpg.PasswordChangeReceipt{WrappingRevision: account.Binding.Revision + 1, AuthEpoch: 2}, nil
	}
	if _, err := c.ChangePassword(context.Background(), master, bytes.Repeat([]byte{93}, 32), newRoot, vault.KDFV1, false, "ui"); err != nil {
		t.Fatal(err)
	}
	promoted, err := readSharedTrustFile(o.TrustPath, newRoot, o.Binding, stored.Revision+1)
	if err != nil || promoted.Enrollment.ManifestRevision != 2 {
		t.Fatal("password promotion lost pin", err)
	}
}

func TestSharedEnrolledUnlockRejections(t *testing.T) {
	for _, mode := range []string{"read", "missing", "mixed", "forged", "binding", "reset", "pin", "write"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, master, account, org := sharedEnrolledFixture(t)
			switch mode {
			case "read":
				p.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, sharedpg.ErrQuery }
			case "missing":
				account.EnrollmentCertificate = nil
			case "mixed":
				account.EncryptionCertificate = &account.EnrollmentCertificate.BootstrapEncryption
			case "forged":
				account.EnrollmentCertificate.Rekey.Signature[0] ^= 1
			case "binding":
				account.Binding.Encryption.ID = uuid.New()
			case "reset":
				state := *account.State
				state.Sequence++
				state.Encryption.ID = uuid.New()
				var err error
				state, err = vault.SignUserKeyState(state, org)
				if err != nil {
					t.Fatal(err)
				}
				account.State = &state
			case "pin":
				current, err := readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := openSharedAccountKeys(master, account, sharedpg.TrustState{}, 1); err == nil {
					t.Fatal("untrusted open")
				}
				current.Enrollment.PublicDigest[0] ^= 1
				keys, _, err := openSharedAccountKeys(master, account, current, 1)
				if keys != nil || err != sharedpg.ErrAccountEquivocation {
					t.Fatal("pin substitution", err)
				}
				return
			case "write":
				account.EnrollmentCertificate.Manifest.Revision++
				account.EnrollmentCertificate.Manifest, _ = vault.SignInviteManifest(account.EnrollmentCertificate.Manifest, org.Seed())
				original := privateFileDirectorySync
				t.Cleanup(func() { privateFileDirectorySync = original })
				p.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
					privateFileDirectorySync = func(string) error { return errors.New("test sync failure") }
					return account, nil
				}
			}
			if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err == nil || c.Unlocked() || c.privateKeys != nil {
				t.Fatal("invalid enrollment unlocked", err)
			}
		})
	}
}

func TestSharedEnrolledPasswordRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "commit"}[committed], func(t *testing.T) {
			old, previous, o, oldRoot, master, account, org := sharedEnrolledFixture(t)
			if err := old.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
				t.Fatal(err)
			}
			if err := old.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			state, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			newRoot := bytes.Repeat([]byte{99}, 32)
			if _, err := stageSharedTrustRootTransition(o.TrustPath, oldRoot, newRoot, o.Binding, state.Revision); err != nil {
				t.Fatal(err)
			}
			actual := *account
			if committed {
				nextMaster := bytes.Repeat([]byte{97}, 32)
				actual.Binding, actual.Envelope, err = vault.RewrapUserKeys(master, nextMaster, account.Binding, account.Envelope, account.EnrollmentCertificate.Rekey.Public)
				if err != nil {
					t.Fatal(err)
				}
				master = nextMaster
			}
			actual.EnrollmentCertificate.Manifest.Revision++
			actual.EnrollmentCertificate.Manifest, err = vault.SignInviteManifest(actual.EnrollmentCertificate.Manifest, org.Seed())
			if err != nil {
				t.Fatal(err)
			}
			lifetime, cancel := context.WithCancel(context.Background())
			p := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response}
			p.loginMaterial, err = vault.DeriveKey(master, nil, vault.PurposeLogin)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(p.loginMaterial)
			p.accountState = func(context.Context) (*vault.UserKeyState, error) { return actual.State, nil }
			p.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return &actual, nil }
			c := newSharedAdmissionControllerWithSession(p)
			defer c.Close(context.Background())
			credential := sharedRecoveryOldPassword
			targetRoot := oldRoot
			if committed {
				credential = sharedRecoveryNewPassword
				targetRoot = newRoot
			}
			result, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, credential)
			if err != nil || result == nil || result.Changed != committed {
				t.Fatal("enrolled recovery", err)
			}
			stored, err := readSharedTrustFile(o.TrustPath, targetRoot, o.Binding, result.TrustRevision)
			if err != nil || stored.Enrollment.ManifestRevision != 2 || stored.WrappingRevision != actual.Binding.Revision {
				t.Fatal("recovery lost floor", err)
			}
		})
	}
}
