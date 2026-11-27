package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func enrollmentTrustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, vault.UserEnrollmentCertificate, ed25519.PrivateKey, *UnverifiedAdmission, AdmissionRequest) {
	t.Helper()
	rows, trust, _ := accountEnrollmentRows(t)
	m, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	root, binding, _, admission, request, _ := trustFixture(t)
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	t.Cleanup(func() { vault.Wipe(org) })
	policy, err := vault.DecodeSignedPolicy(admission.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = vault.SignPolicy(policy.Policy, trust.Signer.ID.String(), 1, org)
	if err != nil {
		t.Fatal(err)
	}
	admission.SignedProfile, err = vault.EncodeSignedPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewTrustState(admission, request, PolicyTrust{WorkspaceID: request.WorkspaceID, SignerKeyID: trust.Signer.ID.String(), SignerKeyVersion: 1, PublicKey: trust.Organisation, MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err = s.AdvanceAccount(*m.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	return root, binding, s, *m.EnrollmentCertificate, org, admission, request
}

func TestTrustEnrollmentPersistenceAndOtherUpdates(t *testing.T) {
	root, b, base, c, org, admission, request := enrollmentTrustFixture(t)
	s, err := base.AdvanceEnrollment(c, 1)
	if err != nil || s.FormatVersion != 5 || s.Revision != base.Revision+1 || base.Enrollment != nil {
		t.Fatal("upgrade", err)
	}
	if err := base.ValidateAdvance(s); err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, s)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTrustState(root, b, raw, s.Revision)
	if err != nil || !reflect.DeepEqual(opened, s) {
		t.Fatal("protected pin", err)
	}
	same, err := s.AdvanceEnrollment(c, 1)
	if err != nil || !reflect.DeepEqual(same, s) {
		t.Fatal("idempotence", err)
	}
	same.Enrollment.PublicDigest[0] ^= 1
	if bytes.Equal(same.Enrollment.PublicDigest, s.Enrollment.PublicDigest) {
		t.Fatal("pin alias")
	}
	profile, err := s.Advance(admission, request)
	if err != nil || !reflect.DeepEqual(profile.Enrollment, s.Enrollment) {
		t.Fatal("profile lost pin", err)
	}
	profile.Enrollment.PublicDigest[0] ^= 1
	if bytes.Equal(profile.Enrollment.PublicDigest, s.Enrollment.PublicDigest) {
		t.Fatal("profile alias")
	}
	wrapped, err := s.AdvanceAccount(*s.Account, 2)
	if err != nil || wrapped.FormatVersion != 5 || !reflect.DeepEqual(wrapped.Enrollment, s.Enrollment) || s.ValidateAdvance(wrapped) != nil {
		t.Fatal("password change lost pin", err)
	}
	tls := trustedTLSFixture(t, s, org, 1)
	withTLS, err := s.AdvanceTLS(tls)
	if err != nil || withTLS.FormatVersion != 5 || !reflect.DeepEqual(withTLS.Enrollment, s.Enrollment) || s.ValidateAdvance(withTLS) != nil {
		t.Fatal("TLS lost pin", err)
	}
	if _, err := withTLS.VerifyTLS(tls.raw); err != nil {
		t.Fatal(err)
	}
	fromTLS, err := base.AdvanceTLS(tls)
	if err != nil {
		t.Fatal(err)
	}
	fromTLS, err = fromTLS.AdvanceEnrollment(c, 1)
	if err != nil || fromTLS.TLSSequence != 1 {
		t.Fatal("enrollment lost TLS", err)
	}
	newRoot := bytes.Repeat([]byte{92}, 32)
	transition, journal, err := PrepareTrustRootTransition(root, newRoot, b, raw, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	transition, err = OpenTrustRootTransition(newRoot, b, journal)
	if err != nil {
		t.Fatal(err)
	}
	for _, committed := range []bool{false, true} {
		var result TrustState
		if committed {
			result, err = transition.PromotionState(b)
		} else {
			result, err = transition.AbortState(b)
		}
		if err != nil || !reflect.DeepEqual(result.Enrollment, s.Enrollment) {
			t.Fatal("journal lost enrollment", err)
		}
	}
	observed := transition.ObservedTrust()
	observed.Enrollment.PublicDigest[0] ^= 1
	if bytes.Equal(observed.Enrollment.PublicDigest, transition.Previous.Enrollment.PublicDigest) {
		t.Fatal("journal alias")
	}
	reset := *s.Account
	reset.Sequence++
	reset.Encryption.ID, reset.Signing.ID = uuid.New(), uuid.New()
	reset, err = vault.SignUserKeyState(reset, org)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := s.AdvanceAccount(reset, 1)
	if err != nil || retired.Enrollment != nil || retired.FormatVersion != 5 || !retired.valid() || s.ValidateAdvance(retired) != nil {
		t.Fatal("reset", err)
	}
	if _, err := retired.AdvanceEnrollment(c, 1); err != vault.ErrAuthentication {
		t.Fatal("old anchor replay", err)
	}
}

func TestTrustEnrollmentRejectsRollbackAndReplacement(t *testing.T) {
	_, _, base, c, org, _, _ := enrollmentTrustFixture(t)
	s, err := base.AdvanceEnrollment(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*EnrollmentPin){
		func(p *EnrollmentPin) { p.Encryption.ID = uuid.New() },
		func(p *EnrollmentPin) { p.Signing.ID = uuid.New() },
		func(p *EnrollmentPin) { p.PublicDigest[0] ^= 1 },
	} {
		other := s
		other.Enrollment = cloneEnrollmentPin(s.Enrollment)
		mutate(other.Enrollment)
		if _, err := other.AdvanceEnrollment(c, 2); err != ErrAccountEquivocation {
			t.Fatal("replacement", err)
		}
		other.Revision++
		if err := s.ValidateAdvance(other); err != ErrTrustRollback {
			t.Fatal("writer replacement", err)
		}
	}
	for _, wrapping := range []uint64{0, math.MaxInt64 + 1} {
		if _, err := s.AdvanceEnrollment(c, wrapping); err != ErrTrustState {
			t.Fatal(err)
		}
	}
	if _, err := s.AdvanceEnrollment(c, 1); err != ErrTrustRollback {
		t.Fatal(err)
	}
	if _, err := (TrustState{}).AdvanceEnrollment(c, 1); err != ErrTrustState {
		t.Fatal(err)
	}
	full := s
	full.Revision = math.MaxUint64
	if _, err := full.AdvanceEnrollment(c, 3); err != ErrTrustState {
		t.Fatal(err)
	}
	dropped := s
	dropped.Enrollment = nil
	dropped.Revision++
	if err := s.ValidateAdvance(dropped); err != ErrTrustRollback {
		t.Fatal("pin dropped", err)
	}
	higher := c
	higher.Manifest.Revision++
	higher.Manifest, err = vault.SignInviteManifest(higher.Manifest, org.Seed())
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.AdvanceEnrollment(higher, 2)
	if err != nil || s.ValidateAdvance(next) != nil {
		t.Fatal("manifest floor advance", err)
	}
	if _, err := next.AdvanceEnrollment(c, 2); err != vault.ErrRollback {
		t.Fatal("manifest rollback", err)
	}
	back := next
	back.Enrollment = cloneEnrollmentPin(next.Enrollment)
	back.Enrollment.ManifestRevision--
	back.Revision++
	if next.ValidateAdvance(back) != ErrTrustRollback {
		t.Fatal("writer floor rollback")
	}
	revoked := *s.Account
	revoked.Active = false
	revoked.Sequence++
	revoked, err = vault.SignUserKeyState(revoked, org)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := s.AdvanceAccount(revoked, 2)
	if err != nil || !reflect.DeepEqual(denied.Enrollment, s.Enrollment) {
		t.Fatal(err)
	}
	if _, err := denied.AdvanceEnrollment(c, 2); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}

func TestTrustEnrollmentShape(t *testing.T) {
	_, _, base, c, _, _, _ := enrollmentTrustFixture(t)
	s, err := base.AdvanceEnrollment(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TrustState){
		func(s *TrustState) { s.FormatVersion = 3 },
		func(s *TrustState) { s.Account = nil },
		func(s *TrustState) { s.Enrollment.ManifestRevision = 0 },
		func(s *TrustState) { s.Enrollment.PublicDigest = nil },
		func(s *TrustState) { s.Enrollment.Signing = s.Enrollment.Encryption },
		func(s *TrustState) { s.Enrollment.Encryption.ID = uuid.Nil },
		func(s *TrustState) { s.Enrollment.Signing.Version = 2 },
		func(s *TrustState) { s.Enrollment.Encryption.ID = s.Account.Encryption.ID },
		func(s *TrustState) { s.TLSDigest = make([]byte, 32) },
	} {
		bad := s
		bad.Enrollment = cloneEnrollmentPin(s.Enrollment)
		mutate(&bad)
		if bad.valid() {
			t.Fatal("invalid pin shape")
		}
	}
}

func TestTrustEnrollmentJournalObservation(t *testing.T) {
	root, b, base, certificate, org, _, _ := enrollmentTrustFixture(t)
	current, err := base.AdvanceEnrollment(certificate, 1)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := bytes.Repeat([]byte{88}, 32)
	prepare := func(s TrustState) TrustRootTransition {
		t.Helper()
		raw, err := SealTrustState(root, b, s)
		if err != nil {
			t.Fatal(err)
		}
		pending, _, err := PrepareTrustRootTransition(root, newRoot, b, raw, s.Revision)
		if err != nil {
			t.Fatal(err)
		}
		return pending
	}
	pending := prepare(current)
	same, err := pending.ObserveEnrollment(b, certificate, 1)
	if err != nil || !reflect.DeepEqual(same, pending) {
		t.Fatal("unchanged observation", err)
	}
	if _, err := (TrustRootTransition{}).ObserveEnrollment(b, certificate, 1); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := prepare(base).ObserveEnrollment(b, certificate, 1); err != ErrTrustState {
		t.Fatal("journal established first pin", err)
	}
	bad := certificate
	bad.Rekey.Signature = bytes.Clone(certificate.Rekey.Signature)
	bad.Rekey.Signature[0] ^= 1
	if _, err := pending.ObserveEnrollment(b, bad, 1); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	certificate.Manifest.Revision++
	certificate.Manifest, err = vault.SignInviteManifest(certificate.Manifest, org.Seed())
	if err != nil {
		t.Fatal(err)
	}
	next, err := pending.ObserveEnrollment(b, certificate, 2)
	if err != nil || next.Observed == nil || next.Observed.Enrollment.ManifestRevision != 2 || next.Observed.WrappingRevision != 2 {
		t.Fatal("observation", err)
	}
	if err := pending.ValidateObservationAdvance(b, next); err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustRootTransition(newRoot, b, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTrustRootTransition(newRoot, b, raw); err != nil {
		t.Fatal(err)
	}
}
