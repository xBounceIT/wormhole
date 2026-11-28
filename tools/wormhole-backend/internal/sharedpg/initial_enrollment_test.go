package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func initialCertification(t *testing.T, i Invitation, b *UnverifiedInvitationBootstrap) *UnverifiedInvitationCertification {
	t.Helper()
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	signer := vault.KeyRef{ID: uuid.New(), Version: 1}
	enc := vault.KeyRef{ID: i.Enrollment.Context.KeyID, Version: 1}
	sign := vault.KeyRef{ID: uuid.New(), Version: 1}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: 1, WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID, Sequence: 1, Active: true, Encryption: enc, Signing: sign, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: signer}, org)
	if err != nil {
		t.Fatal(err)
	}
	certs := make([]vault.UserKeyCertificate, 2)
	for n, key := range []vault.KeyRef{enc, sign} {
		kind, suite, public := "user-enc", uint16(2), b.Manifest.Bootstrap.Encryption
		if n == 1 {
			kind, suite, public = "user-sign", 1, b.Manifest.Bootstrap.Signing
		}
		certs[n], err = vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: i.WorkspaceID, UserID: state.UserID, Key: key, Kind: kind, Suite: suite, PublicKey: public, Revision: 1, Signer: signer}, org)
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := vault.SignPolicy(vault.Policy{FormatVersion: 1, WorkspaceID: i.WorkspaceID.String(), Sequence: 1, Profile: vault.Default, KDF: vault.KDFLow, LowKDFApproved: true, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, signer.ID.String(), 1, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSignedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return &UnverifiedInvitationCertification{State: state, Encryption: certs[0], Signing: certs[1], SignedProfile: raw}
}

func TestPrepareInitialEnrollment(t *testing.T) {
	for _, mode := range []string{"success", "standard-floor", "ask", "tls-signed", "tls-wrong-signer", "nil-context", "canceled", "bad-code-length", "wrong-code", "empty-password", "bad-ask", "required-ask", "bad-name", "expired", "fetch", "certify", "certificate", "unsupported", "unknown-floor", "copies", "bad-plan", "cancel-after-copies"} {
		t.Run(mode, func(t *testing.T) {
			i, now := enrollmentInvitationFixture(t)
			code, password := bytes.Repeat([]byte{52}, 16), []byte("password")
			b, keyCopies := invitationCopyFixture(t, i, code, 1, now)
			cert := initialCertification(t, i, b)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var ask []byte
			floor, name := vault.Default, "native device"
			switch mode {
			case "standard-floor":
				floor = vault.Standard
			case "ask":
				ask = bytes.Repeat([]byte{8}, 32)
			case "tls-signed", "tls-wrong-signer":
				ca, _ := serverIssuer(t, nil)
				org := ed25519.NewKeyFromSeed(make([]byte, 32))
				defer vault.Wipe(org)
				signer := cert.State.Signer
				if mode == "tls-wrong-signer" {
					signer.ID = uuid.New()
				}
				setInvitationTLS(t, &i, signer, org, ca)
				secret, err := vault.OpenInviteBootstrap(code, i.Enrollment.Context, b.Envelope, i.OrganisationFingerprint)
				if err != nil {
					t.Fatal(err)
				}
				b.Envelope, err = i.SealBootstrap(code, secret, now)
				secret.Wipe()
				if err != nil {
					t.Fatal(err)
				}
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "bad-code-length":
				code = nil
			case "wrong-code":
				code = bytes.Repeat([]byte{99}, 16)
			case "empty-password":
				password = nil
			case "bad-ask":
				ask = []byte{1}
			case "required-ask":
				signed, err := vault.DecodeSignedPolicy(cert.SignedProfile)
				if err != nil {
					t.Fatal(err)
				}
				signed.Policy.ASKRequired = true
				org := ed25519.NewKeyFromSeed(make([]byte, 32))
				defer vault.Wipe(org)
				signed, err = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
				if err != nil {
					t.Fatal(err)
				}
				cert.SignedProfile, err = vault.EncodeSignedPolicy(signed)
				if err != nil {
					t.Fatal(err)
				}
			case "bad-name":
				name = "bad\x00name"
			case "expired":
				i.ExpiresAt = time.Now().Unix() - 1
			case "certificate":
				cert.Encryption.Signature[0] ^= 1
			case "unsupported":
				floor = vault.Hardened
			case "unknown-floor":
				floor = "unknown"
			}
			fetched, certified, copied := 0, 0, 0
			var opened *vault.InviteBootstrap
			var plan *vault.InviteRewrapPlan
			result, err := prepareInitialEnrollment(ctx, i, code, password, ask, name, vault.Default, floor,
				func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) {
					fetched++
					if mode == "fetch" {
						return nil, ErrAuthentication
					}
					return b, nil
				},
				func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
					certified++
					if mode == "certify" {
						return nil, ErrAuthentication
					}
					return cert, nil
				},
				func(ctx context.Context, i Invitation, got *UnverifiedInvitationBootstrap, secret *vault.InviteBootstrap, revision uint64) (*vault.InviteRewrapPlan, error) {
					copied++
					opened = secret
					if got != b || revision != 1 {
						t.Fatal("bootstrap snapshot changed")
					}
					if mode == "copies" {
						return nil, ErrInvitation
					}
					var e error
					plan, e = vault.PrepareCertifiedInviteRewrap(ctx, i.Enrollment.Context, secret, b.Manifest, keyCopies, 1, i.ExpiresAt, time.Now())
					if mode == "bad-plan" && plan != nil {
						plan.SourceManifestRevision++
					}
					if mode == "cancel-after-copies" {
						cancel()
					}
					return plan, e
				})
			if opened != nil && (opened.EncryptionPrivate != nil || opened.SigningSeed != nil) {
				t.Fatal("bootstrap secret retained")
			}
			if plan != nil && plan.Keys != nil {
				t.Fatal("rewrap keys retained")
			}
			success := mode == "success" || mode == "standard-floor" || mode == "ask" || mode == "tls-signed"
			if !success {
				if err == nil || result != nil {
					t.Fatal("failure published material", err)
				}
				if (mode == "nil-context" || mode == "canceled" || mode == "bad-code-length" || mode == "empty-password" || mode == "bad-ask" || mode == "bad-name" || mode == "expired") && fetched != 0 {
					t.Fatal("invalid input reached network")
				}
				if (mode == "fetch" || mode == "wrong-code") && certified != 0 {
					t.Fatal("unauthenticated bootstrap advanced")
				}
				if (mode == "certificate" || mode == "unsupported" || mode == "unknown-floor" || mode == "required-ask" || mode == "certify" || mode == "tls-wrong-signer") && copied != 0 {
					t.Fatal("invalid policy/certification advanced")
				}
				return
			}
			if err != nil || result == nil || fetched != 1 || certified != 1 || copied != 1 {
				t.Fatal("prepare", err)
			}
			defer result.Close()
			if err := result.Borrow(func(master *AccountMaster, root *DeviceTrustRoot, commit *PreparedInvitationCommit) error {
				b := root.Binding()
				pending, e := commit.PendingEnrollment(b)
				if e != nil {
					return e
				}
				if pending.KDF == vault.KDFLow && mode == "standard-floor" {
					t.Error("local KDF floor ignored")
				}
				if pending.ASKRequired != (mode == "ask") {
					t.Error("ASK lost")
				}
				return root.Use(func(key []byte) error {
					if len(key) != 32 {
						t.Error("missing root")
					}
					return commit.ValidateAccountMaster(master)
				})
			}); err != nil {
				t.Fatal(err)
			}
			raw, e := json.Marshal(result)
			if e != nil || string(raw) != "{}" {
				t.Fatal("serialized preparation")
			}
			verifyInitialDeviceStorage(t, result, password, ask, floor)
			if err := result.Close(); err != nil {
				t.Fatal(err)
			}
			if err := result.Borrow(func(*AccountMaster, *DeviceTrustRoot, *PreparedInvitationCommit) error {
				t.Fatal("closed preparation borrowed")
				return nil
			}); err == nil {
				t.Fatal("closed preparation")
			}
		})
	}
}

func TestInitialEnrollmentCleanupRetry(t *testing.T) {
	m := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	r := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	s := &masterMemoryProbe{data: make([]byte, 32), failClose: true}
	p := &PreparedInitialEnrollment{master: &AccountMaster{memory: m}, root: &DeviceTrustRoot{memory: r}, storage: s, deviceFile: []byte("ciphertext"), commit: &PreparedInvitationCommit{params: [][]byte{[]byte("verifier")}}}
	if err := p.Borrow(nil); err == nil {
		t.Fatal("nil callback")
	}
	if err := p.Close(); !errors.Is(err, ErrAccountMasterCleanup) || !errors.Is(err, ErrDeviceTrustRootCleanup) || !errors.Is(err, ErrDeviceStorageCleanup) {
		t.Fatal(err)
	}
	if p.master == nil || p.root == nil || p.storage == nil || p.deviceFile != nil || p.commit != nil || !m.retired || !r.retired || !s.retired {
		t.Fatal("cleanup ownership lost")
	}
	m.failClose = false
	r.failClose = false
	s.failClose = false
	if err := p.Close(); err != nil || p.master != nil || p.root != nil || p.storage != nil {
		t.Fatal(err)
	}
	var absent *PreparedInitialEnrollment
	if absent.Close() != nil || absent.Borrow(nil) == nil {
		t.Fatal("nil owner")
	}
}
