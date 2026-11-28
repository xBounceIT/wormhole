package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type continuationFixture struct {
	i                  Invitation
	code, root, sealed []byte
	b                  TrustBinding
	master             *AccountMaster
	prepared           *PreparedInvitationCommit
	bootstrap          *UnverifiedInvitationBootstrap
	certification      *UnverifiedInvitationCertification
	o                  InvitationContinuationOptions
}

func newContinuationFixture(t *testing.T, copies int) *continuationFixture {
	t.Helper()
	i, now := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{31}, 16)
	bootstrap, keyCopies := invitationCopyFixture(t, i, code, copies, now)
	cert := initialCertification(t, i, bootstrap)
	opened, err := bootstrap.Authenticate(i, code, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	plan, err := vault.PrepareCertifiedInviteRewrap(context.Background(), i.Enrollment.Context, opened, bootstrap.Manifest, keyCopies, 1, i.ExpiresAt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Wipe()
	master := &AccountMaster{memory: &masterMemoryProbe{data: bytes.Repeat([]byte{88}, 32)}, preset: vault.KDFV1, askUsed: true, workspaceID: i.WorkspaceID, loginName: i.LoginName}
	t.Cleanup(func() {
		if err := master.Close(); err != nil {
			t.Error(err)
		}
	})
	b := TrustBinding{WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID, DeviceID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1}
	p, err := PrepareInvitationCommit(i, cert, opened.OrganisationPublic, bootstrap.Manifest, plan, master, b.DeviceID, "recoverable device", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Wipe)
	pending, err := p.PendingEnrollment(b)
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{77}, 32)
	sealed, err := p.SealContinuation(root, b, i)
	if err != nil {
		t.Fatal(err)
	}
	r := admissionRequest()
	r.WorkspaceID, r.UserID, r.DeviceID = b.WorkspaceID, b.UserID, b.DeviceID
	return &continuationFixture{i: i, code: code, root: root, sealed: sealed, b: b, master: master, prepared: p, bootstrap: bootstrap, certification: cert, o: InvitationContinuationOptions{Request: r, Observed: pending, OSFloor: vault.Default, UserFloor: vault.Default, AcknowledgeTLSOff: true}}
}

func (f *continuationFixture) open(t *testing.T) *InvitationContinuation {
	t.Helper()
	c, err := OpenInvitationContinuation(f.root, f.b, f.master, f.sealed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Wipe)
	return c
}

func TestInvitationContinuationRoundTripDoesNotPersistLoginMaterial(t *testing.T) {
	f := newContinuationFixture(t, 2)
	c := f.open(t)
	raw, err := json.Marshal(c.record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, f.prepared.params[5]) || bytes.Contains(raw, f.code) || bytes.Contains(raw, f.root) || bytes.Contains(raw, bytes.Repeat([]byte{88}, 32)) {
		t.Fatal("continuation retained login material")
	}
	encoded, _ := json.Marshal(c)
	if string(encoded) != "{}" {
		t.Fatal("native continuation serialized")
	}
	metadata, err := c.Invitation()
	if err != nil || !reflect.DeepEqual(metadata, f.i) {
		t.Fatal("invitation changed", err)
	}
	metadata.OrganisationFingerprint[0] ^= 1
	again, err := c.Invitation()
	if err != nil || !bytes.Equal(again.OrganisationFingerprint, f.i.OrganisationFingerprint) {
		t.Fatal("public copy aliases continuation")
	}
	parameters, err := c.parameters(nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := range parameters {
		if n != 5 && !bytes.Equal(parameters[n], f.prepared.params[n]) {
			t.Fatal("prepared payload changed", n)
		}
	}
	if parameters[5] != nil {
		t.Fatal("saved verifier")
	}
	nonce, cipher := c.record.Nonce, c.record.Ciphertext
	c.Wipe()
	c.Wipe()
	if !bytes.Equal(nonce, make([]byte, len(nonce))) || !bytes.Equal(cipher, make([]byte, len(cipher))) {
		t.Fatal("retired record retained borrowed payload")
	}
	if _, err := c.Invitation(); err == nil {
		t.Fatal("retired continuation revived")
	}
	var absent *InvitationContinuation
	absent.Wipe()
}

func TestInvitationContinuationRevalidatesBeforeProducingMutation(t *testing.T) {
	f := newContinuationFixture(t, 1)
	c := f.open(t)
	opened, fetched, certified, observations := 0, 0, 0, 0
	p, err := resumeInvitationContinuation(context.Background(), c, f.code, f.o, func(next PendingEnrollment) error {
		observations++
		if err := f.o.Observed.ValidateObservationAdvance(f.b, next); err != nil {
			return err
		}
		f.o.Observed = next
		return nil
	}, func(_ context.Context, settings Settings, login []byte, changes ChangePolicy) error {
		opened++
		if len(login) == 0 || !changes.TransactionPooler {
			return ErrConfiguration
		}
		_, err := Config(settings)
		return err
	}, func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) {
		fetched++
		return f.bootstrap, nil
	}, func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
		certified++
		return f.certification, nil
	})
	if err != nil || p == nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	if opened != 1 || fetched != 1 || certified != 1 || observations != 2 {
		t.Fatal("fresh proof or persistence skipped", opened, fetched, certified, observations)
	}
	if bytes.Equal(p.params[5], f.prepared.params[5]) || !bytes.HasPrefix(p.params[5], []byte("SCRAM-SHA-256$")) {
		t.Fatal("verifier was not regenerated")
	}
	for n := range p.params {
		if n != 5 && !bytes.Equal(p.params[n], f.prepared.params[n]) {
			t.Fatal("resumed different mutation", n)
		}
	}
	if err := p.ValidateAccountMaster(f.master); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Invitation(); err == nil {
		t.Fatal("continuation reusable after revalidation")
	}
}

func TestInvitationContinuationFailsClosedAtEveryProofBoundary(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "short-code", "wrong-code", "request", "binding", "other-capsule", "local-revocation", "floor", "open", "fetch", "nil-bootstrap", "manifest", "new-manifest", "certify", "nil-certification", "profile", "state", "certificate", "new-certificate", "persist-profile", "persist-state", "remote-revocation", "remote-policy", "cancel-observer", "closed-master"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationFixture(t, 0)
			c := f.open(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var runCtx context.Context = ctx
			org := ed25519.NewKeyFromSeed(make([]byte, 32))
			defer vault.Wipe(org)
			switch mode {
			case "nil-context":
				runCtx = nil
			case "canceled":
				cancel()
			case "short-code":
				f.code = nil
			case "wrong-code":
				f.code = bytes.Repeat([]byte{99}, 16)
			case "request":
				f.o.Request.AppVersion = ""
			case "binding":
				f.o.Request.DeviceID = uuid.New()
			case "other-capsule":
				f.o.Observed.CapsuleDigest = bytes.Repeat([]byte{3}, 32)
			case "local-revocation":
				state := f.certification.State
				state.Sequence++
				state.Active = false
				state, err := vault.SignUserKeyState(state, org)
				if err != nil {
					t.Fatal(err)
				}
				f.o.Observed, err = f.o.Observed.ObserveAccount(f.b, state, 1)
				if err != nil {
					t.Fatal(err)
				}
			case "floor":
				f.o.OSFloor = vault.Hardened
			case "profile":
				f.certification.SignedProfile[0] ^= 1
			case "state":
				f.certification.State.Signature[0] ^= 1
			case "certificate":
				f.certification.Encryption.Signature[0] ^= 1
			case "new-certificate":
				f.certification.Encryption.Revision++
				var err error
				f.certification.Encryption, err = vault.SignUserKeyCertificate(f.certification.Encryption, org)
				if err != nil {
					t.Fatal(err)
				}
			case "remote-revocation":
				f.certification.State.Sequence++
				f.certification.State.Active = false
				var err error
				f.certification.State, err = vault.SignUserKeyState(f.certification.State, org)
				if err != nil {
					t.Fatal(err)
				}
			case "remote-policy":
				p, err := vault.DecodeSignedPolicy(f.certification.SignedProfile)
				if err != nil {
					t.Fatal(err)
				}
				p.Policy.Sequence++
				p.Policy.Profile, p.Policy.KDF, p.Policy.LowKDFApproved = vault.Hardened, vault.KDFV2, false
				p, err = vault.SignPolicy(p.Policy, p.SignerKeyID, p.SignerKeyVersion, org)
				if err != nil {
					t.Fatal(err)
				}
				f.certification.SignedProfile, err = vault.EncodeSignedPolicy(p)
				if err != nil {
					t.Fatal(err)
				}
			case "closed-master":
				if err := f.master.Close(); err != nil {
					t.Fatal(err)
				}
			}
			opened, observed := 0, 0
			p, err := resumeInvitationContinuation(runCtx, c, f.code, f.o, func(next PendingEnrollment) error {
				observed++
				if mode == "persist-profile" && observed == 1 || mode == "persist-state" && observed == 2 {
					return errors.New("storage unavailable")
				}
				if err := f.o.Observed.ValidateObservationAdvance(f.b, next); err != nil {
					return err
				}
				f.o.Observed = next
				if mode == "cancel-observer" {
					cancel()
				}
				return nil
			}, func(context.Context, Settings, []byte, ChangePolicy) error {
				opened++
				if mode == "open" {
					return ErrConnection
				}
				return nil
			}, func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) {
				if mode == "fetch" {
					return nil, ErrConnection
				}
				if mode == "nil-bootstrap" {
					return nil, nil
				}
				if mode == "manifest" {
					f.bootstrap.Manifest.Revision++
				}
				if mode == "new-manifest" {
					f.bootstrap.Manifest.Revision++
					var err error
					f.bootstrap.Manifest, err = vault.SignInviteManifest(f.bootstrap.Manifest, org[:32])
					if err != nil {
						t.Fatal(err)
					}
				}
				return f.bootstrap, nil
			}, func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
				if mode == "certify" {
					return nil, ErrInvitation
				}
				if mode == "nil-certification" {
					return nil, nil
				}
				return f.certification, nil
			})
			if p != nil {
				p.Wipe()
				t.Fatal("failed continuation produced mutation", mode)
			}
			if err == nil {
				t.Fatal("invalid continuation accepted", mode)
			}
			if _, err := c.Invitation(); err == nil {
				t.Fatal("failed continuation remained live")
			}
			if mode == "remote-revocation" && (observed != 2 || f.o.Observed.ObservedTrust().Account.Active) {
				t.Fatal("remote revocation lost before denial")
			}
			if mode == "remote-policy" && f.o.Observed.ObservedTrust().PolicySequence != 2 {
				t.Fatal("stronger policy lost before denial")
			}
			if (mode == "local-revocation" || mode == "floor" || mode == "other-capsule" || mode == "binding" || mode == "request" || mode == "closed-master") && opened != 0 {
				t.Fatal("invalid local state reached network")
			}
		})
	}
}

func TestInvitationContinuationPreservesSignedPolicyAPIWindow(t *testing.T) {
	for _, minimum := range []uint32{1, 2} {
		t.Run(string(rune('0'+minimum)), func(t *testing.T) {
			f := newContinuationFixture(t, 0)
			signed, err := vault.DecodeSignedPolicy(f.certification.SignedProfile)
			if err != nil {
				t.Fatal(err)
			}
			signed.Policy.Sequence++
			signed.Policy.MinAPI, signed.Policy.MaxAPI = minimum, 3
			org := ed25519.NewKeyFromSeed(make([]byte, 32))
			defer vault.Wipe(org)
			signed, err = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
			if err != nil {
				t.Fatal(err)
			}
			f.certification.SignedProfile, err = vault.EncodeSignedPolicy(signed)
			if err != nil {
				t.Fatal(err)
			}
			p, err := resumeInvitationContinuation(context.Background(), f.open(t), f.code, f.o, func(next PendingEnrollment) error {
				if err := f.o.Observed.ValidateObservationAdvance(f.b, next); err != nil {
					return err
				}
				f.o.Observed = next
				return nil
			}, func(context.Context, Settings, []byte, ChangePolicy) error { return nil }, func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) { return f.bootstrap, nil }, func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
				return f.certification, nil
			})
			if p != nil {
				defer p.Wipe()
			}
			if minimum == 1 && (err != nil || p == nil) {
				t.Fatal("compatible wider policy rejected", err)
			}
			if minimum == 2 && (err == nil || p != nil) {
				t.Fatal("unsupported policy enabled continuation")
			}
			if f.o.Observed.ObservedTrust().PolicySequence != 2 {
				t.Fatal("authenticated API policy floor was discarded")
			}
		})
	}
}

func sealContinuationRecordForTest(t *testing.T, f *continuationFixture, r invitationContinuationRecord) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.DeriveKey(f.root, f.b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(key)
	binding, err := invitationContinuationBinding(f.b)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := vault.Seal(key, binding, raw)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestInvitationContinuationAuthenticatesRecordsAndIndependentMaster(t *testing.T) {
	for _, mode := range []string{"format", "invitation", "name", "nonce", "capsule", "wrong-master", "master-workspace", "master-preset", "observed", "role", "copies", "copy-count", "copy-id", "copy-hex", "copy-signature", "binding", "root", "empty", "oversize", "json", "noncanonical", "unknown-field", "other-purpose"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationFixture(t, 1)
			c := f.open(t)
			r := c.record
			switch mode {
			case "format":
				r.FormatVersion = 2
			case "invitation":
				r.Invitation = "invalid"
			case "name":
				r.Name = ""
			case "nonce":
				r.Nonce = make([]byte, 11)
			case "capsule":
				r.Ciphertext = bytes.Clone(r.Ciphertext)
				r.Ciphertext[0] ^= 1
				r.Pending.CapsuleDigest = enrollmentCapsuleDigest(vault.Envelope{Nonce: r.Nonce, Ciphertext: r.Ciphertext})
			case "wrong-master":
				f.master.memory.(*masterMemoryProbe).data[0] ^= 1
			case "master-workspace":
				f.master.workspaceID = uuid.New()
			case "master-preset":
				f.master.preset = vault.KDFV2
			case "observed":
				trust := r.Pending.Trust
				r.Pending.Observed = &trust
			case "role":
				r.Pending.RoleTag = "othertag"
			case "copies":
				r.Copies = nil
			case "copy-count":
				r.Copies = append(r.Copies, r.Copies[0])
			case "copy-id":
				r.Copies[0].KeyID = uuid.NewString()
			case "copy-hex":
				r.Copies[0].Enc = "zz"
			case "copy-signature":
				r.Copies[0].Signature = strings.Repeat("00", 64)
			}
			sealed := sealContinuationRecordForTest(t, f, r)
			switch mode {
			case "binding":
				f.b.KeyID = uuid.New()
			case "root":
				f.root = nil
			case "empty":
				sealed = nil
			case "oversize":
				sealed = make([]byte, 2*MaxInvitationContinuationBytes+1)
			case "json":
				sealed = []byte("{")
			case "noncanonical":
				sealed = append(sealed, ' ')
			case "unknown-field":
				sealed = append([]byte(`{"unexpected":true,`), sealed[1:]...)
			case "other-purpose":
				var err error
				sealed, err = SealPendingEnrollment(f.root, f.b, f.o.Observed)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := OpenInvitationContinuation(f.root, f.b, f.master, sealed)
			if got != nil {
				got.Wipe()
				t.Fatal("invalid record created a continuation", mode)
			}
			if err == nil {
				t.Fatal("invalid record accepted", mode)
			}
		})
	}
}

func TestInvitationContinuationSealingRejectsAlteredPreparation(t *testing.T) {
	for _, mode := range []string{"nil", "invitation", "token", "binding", "expired", "pending", "observed", "nonce", "ciphertext", "capsule", "copies", "parameter", "root"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationFixture(t, 0)
			p := f.prepared
			switch mode {
			case "nil":
				p = nil
			case "invitation":
				f.i.Enrollment = nil
			case "token":
				f.i.Endpoints = nil
			case "binding":
				f.b.UserID = uuid.New()
			case "expired":
				p.expires = 0
			case "pending":
				p.pending = []byte("invalid")
			case "observed":
				r := f.o.Observed
				trust := r.Trust
				r.Observed = &trust
				var err error
				p.pending, err = json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
			case "nonce":
				p.params[8] = []byte("invalid")
			case "ciphertext":
				p.params[9] = []byte("invalid")
			case "capsule":
				p.params[9] = []byte(strings.Repeat("00", 81))
			case "copies":
				p.params[11] = []byte("invalid")
			case "parameter":
				p.params[0] = []byte(uuid.NewString())
			case "root":
				f.root = nil
			}
			if raw, err := p.SealContinuation(f.root, f.b, f.i); err == nil || len(raw) != 0 {
				t.Fatal("altered preparation sealed", mode, err)
			}
		})
	}
}

func TestInvitationContinuationPolicyAndOwnerBoundaries(t *testing.T) {
	f := newContinuationFixture(t, 0)
	var absent *Session
	if p, err := absent.ResumeInvitationContinuation(context.Background(), f.open(t), f.code, f.o, func(PendingEnrollment) error { return nil }); p != nil || err == nil {
		t.Fatal("nil session accepted")
	}
	session := NewSession()
	defer session.Close(context.Background())
	if p, err := session.ResumeInvitationContinuation(context.Background(), nil, nil, f.o, nil); p != nil || err == nil {
		t.Fatal("missing native owner accepted")
	}
	invalid := f.o.Observed
	invalid.FormatVersion = 0
	if _, err := invalid.ObservePolicy(f.b, f.certification.SignedProfile); err == nil {
		t.Fatal("invalid observation accepted")
	}
	if _, err := (TrustState{}).AdvancePolicy(f.certification.SignedProfile); err == nil {
		t.Fatal("missing pin accepted")
	}
	badPolicy := f.o.Observed
	badPolicy.Trust.SignedProfile = []byte("invalid signed policy")
	if _, err := continuationPolicy(f.master, badPolicy, vault.Default, vault.Default); err == nil {
		t.Fatal("invalid policy accepted")
	}
	f.master.preset = vault.KDFLow
	if _, err := continuationPolicy(f.master, f.o.Observed, vault.Default, vault.Default); err == nil {
		t.Fatal("changed master derivation accepted")
	}
	f.master.preset = vault.KDFV1
	c := f.open(t)
	c.record.Pending.Certificate.FormatVersion = 0
	if _, err := c.parameters(nil); err == nil {
		t.Fatal("invalid certificate encoded")
	}
	c.record.Pending = f.o.Observed
	c.record.Copies = []invitationCopyWire{{Ciphertext: strings.Repeat("0", 1024*1024)}}
	if _, err := c.parameters(nil); err == nil {
		t.Fatal("oversized copies encoded")
	}
}

func TestInvitationContinuationRequiresObservedTLSBundleBeforeLogin(t *testing.T) {
	f := newContinuationFixture(t, 0)
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	bundle := trustedTLSFixture(t, f.o.Observed.ObservedTrust(), org, 1)
	var err error
	f.o.Observed, err = f.o.Observed.ObserveTLS(f.b, bundle)
	if err != nil {
		t.Fatal(err)
	}
	opens := 0
	p, err := resumeInvitationContinuation(context.Background(), f.open(t), f.code, f.o, func(PendingEnrollment) error { return nil },
		func(context.Context, Settings, []byte, ChangePolicy) error {
			opens++
			return nil
		},
		func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) { return f.bootstrap, nil },
		func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
			return f.certification, nil
		})
	if p != nil {
		p.Wipe()
	}
	if err == nil || p != nil || opens != 0 {
		t.Fatal("observed TLS floor was bypassed before SCRAM", err, opens)
	}
}

func TestInvitationContinuationUsesExactCurrentTLSRootsAndBounds(t *testing.T) {
	for _, mode := range []string{"current", "missing", "stale", "foreign", "host", "off", "unobserved"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationFixture(t, 0)
			f.i.Endpoints = []Endpoint{{Host: "db.example.test", Port: 5432}}
			if mode == "host" {
				f.i.Endpoints[0].Host = "db.example.com"
			}
			if mode == "off" {
				f.i.TLS, f.i.CAPEM = TLSOff, nil
			}
			var err error
			f.sealed, err = f.prepared.SealContinuation(f.root, f.b, f.i)
			if err != nil {
				t.Fatal(err)
			}
			org := ed25519.NewKeyFromSeed(make([]byte, 32))
			defer vault.Wipe(org)
			base := f.o.Observed
			bundle := trustedTLSFixture(t, base.ObservedTrust(), org, 1)
			f.o.Observed, err = base.ObserveTLS(f.b, bundle)
			if err != nil {
				t.Fatal(err)
			}
			f.o.TLSBundle = bundle
			switch mode {
			case "missing":
				f.o.TLSBundle = nil
			case "stale":
				latest := trustedTLSFixture(t, base.ObservedTrust(), org, 2)
				f.o.Observed, err = base.ObserveTLS(f.b, latest)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign":
				other := base.ObservedTrust()
				other.WorkspaceID = uuid.New()
				f.o.TLSBundle = trustedTLSFixture(t, other, org, 1)
			case "unobserved":
				f.o.Observed = base
			}
			opens := 0
			var borrowed []byte
			p, err := resumeInvitationContinuation(context.Background(), f.open(t), f.code, f.o, func(next PendingEnrollment) error { f.o.Observed = next; return nil },
				func(_ context.Context, settings Settings, login []byte, changes ChangePolicy) error {
					opens++
					borrowed = login
					if settings.TLSBundle != bundle || len(settings.CAPEM) != 0 || !changes.TransactionPooler {
						return ErrConfiguration
					}
					config, err := Config(settings)
					if err != nil {
						return err
					}
					if config.ChannelBinding != "require" {
						return ErrConfiguration
					}
					return nil
				}, func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error) { return f.bootstrap, nil },
				func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error) {
					return f.certification, nil
				})
			if p != nil {
				defer p.Wipe()
			}
			if mode == "current" {
				if err != nil || p == nil || opens != 1 {
					t.Fatal("current signed TLS bundle was not usable", err, opens)
				}
				if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
					t.Fatal("temporary login proof retained")
				}
			} else if err == nil || p != nil || opens != 0 {
				t.Fatal("invalid TLS floor reached connection", mode, err, opens)
			}
		})
	}
}
