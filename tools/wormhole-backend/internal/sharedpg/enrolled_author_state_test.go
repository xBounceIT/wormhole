package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func captureEnrolledBootstrap(t *testing.T, dst **vault.InviteBootstrap) func(*vault.InviteBootstrap) {
	t.Helper()
	return func(b *vault.InviteBootstrap) {
		*dst = &vault.InviteBootstrap{EncryptionPrivate: bytes.Clone(b.EncryptionPrivate), SigningSeed: bytes.Clone(b.SigningSeed), OrganisationPublic: bytes.Clone(b.OrganisationPublic)}
		t.Cleanup((*dst).Wipe)
	}
}

func signEnrolledNode(t *testing.T, f connectionFixture, a UnverifiedNodeAuthor, seed []byte, revision uint64) UnverifiedTreeNode {
	t.Helper()
	node := f.records.Chain[0].Node
	key := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(key)
	var err error
	node.Seal, err = sharedcatalog.SignNode(f.s.WorkspaceID, node.Boundary, node.Metadata, revision, a.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func TestEnrolledAuthorFloorsRenewalAndSourceRollback(t *testing.T) {
	f, _, _ := enrolledReleaseFixture(t, false)
	a := f.records.Chain[0].Author
	before, err := f.s.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{91}, 32)
	binding := TrustBinding{WorkspaceID: before.WorkspaceID, UserID: before.UserID, DeviceID: before.DeviceID, KeyID: uuid.New(), KeyVersion: 1}
	raw, err := SealTrustState(root, binding, before)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, binding, raw, before.Revision)
	if err != nil || !reflect.DeepEqual(before, restored) {
		t.Fatal("format6 roundtrip", err)
	}
	// Renew the bootstrap certificate and current signed state independently.
	// Its cost/revision is not the final delegation's manifest floor.
	c := *a.EnrollmentCertificate
	c.BootstrapSigning.Revision++
	c.BootstrapSigning, err = vault.SignUserKeyCertificate(c.BootstrapSigning, f.org)
	if err != nil {
		t.Fatal(err)
	}
	state := *a.State
	state.Sequence++
	state.MinimumSigningCertificate = c.BootstrapSigning.Revision
	state, err = vault.SignUserKeyState(state, f.org)
	if err != nil {
		t.Fatal(err)
	}
	a.State, a.EnrollmentCertificate = &state, &c
	next, err := restored.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil || restored.ValidateAdvance(next) != nil {
		t.Fatal("bootstrap renewal reset final floor", err)
	}
	if !reflect.DeepEqual(next.Catalog[catalogKeyName("key", a.Key)], restored.Catalog[catalogKeyName("key", a.Key)]) {
		t.Fatal("bootstrap certificate leaked into final proof digest")
	}
	old := c
	c.Manifest.Revision++
	seed := f.org.Seed()
	defer vault.Wipe(seed)
	c.Manifest, err = vault.SignInviteManifest(c.Manifest, seed)
	if err != nil {
		t.Fatal(err)
	}
	a.EnrollmentCertificate = &c
	advanced, err := next.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil || next.ValidateAdvance(advanced) != nil {
		t.Fatal("manifest renewal", err)
	}
	if _, err := advanced.AdvanceEnrollment(old, advanced.WrappingRevision); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("source enrollment ignored catalog floor", err)
	}
	owned, err := advanced.AdvanceEnrollment(c, advanced.WrappingRevision)
	if err != nil || owned.FormatVersion != 6 || owned.Enrollment.ManifestRevision != 6 {
		t.Fatal("enrollment downgraded format6", err)
	}
	downgrade := owned
	downgrade.FormatVersion = 5
	if _, err := downgrade.Policy(); err == nil {
		t.Fatal("old format accepted enrollment namespace")
	}
	for _, bad := range []string{"enrollment/bad/1/bad/1", "enrollment/" + a.State.Signing.ID.String() + "/0/" + a.State.Encryption.ID.String() + "/1", catalogKeyName("enrollment", a.State.Signing), catalogEnrollmentName(*a.State) + "/extra"} {
		if validCatalogFloors(map[string]CatalogFloor{bad: {Revision: 1, Digest: make([]byte, 32)}}) {
			t.Fatal("invalid enrollment namespace", bad)
		}
	}
}

func TestEnrolledAuthorPinsRejectForksWithoutReservingNewKeys(t *testing.T) {
	var bootstrap *vault.InviteBootstrap
	f, _, _ := enrolledReleaseFixture(t, false, captureEnrolledBootstrap(t, &bootstrap))
	a := f.records.Chain[0].Author
	// Another member's public author can be observed before local private keys
	// open. A policy-only trust state must stay valid after format6 advancement.
	foreign := cloneTrustState(f.s)
	foreign.Enrollment = nil
	foreign.Account = nil
	foreign.WrappingRevision = 0
	foreign.FormatVersion = 2
	foreign.UserID = uuid.New()
	before, err := foreign.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil || !before.valid() || before.Account != nil {
		t.Fatal("public enrolled observation", err)
	}
	fork := *a.EnrollmentCertificate
	keys, proof, err := vault.PrepareInviteRekey(fork.Manifest.Context, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	fork.Rekey = proof
	fork.Manifest.Revision++
	seed := f.org.Seed()
	defer vault.Wipe(seed)
	fork.Manifest, err = vault.SignInviteManifest(fork.Manifest, seed)
	if err != nil {
		t.Fatal(err)
	}
	newAuthor := UnverifiedNodeAuthor{Key: vault.KeyRef{ID: proof.SigningKeyID, Version: 1}, State: a.State, EnrollmentCertificate: &fork}
	node := signEnrolledNode(t, f, newAuthor, keys.SigningSeed, 2)
	next, err := before.AdvanceCatalog(node, newAuthor)
	if !errors.Is(err, ErrCatalogEquivocation) || !reflect.DeepEqual(next, before) || next.Catalog[catalogKeyName("key", newAuthor.Key)].Revision != 0 {
		t.Fatal("fork reserved new key/record floors", err)
	}
	// The independently pinned local account refuses a fork even before any
	// catalog observation has established a general member-selection pin.
	next, err = f.s.AdvanceCatalog(node, newAuthor)
	if !errors.Is(err, ErrAccountEquivocation) || !reflect.DeepEqual(next, f.s) {
		t.Fatal("local enrollment pin replaced", err)
	}
	// An observed public selection also constrains first local enrollment.
	// The capsule may open, but that cannot erase a previously observed pair.
	account := cloneTrustState(f.s)
	account.Enrollment = nil
	account, err = account.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil {
		t.Fatal(err)
	}
	next, err = account.AdvanceEnrollment(fork, account.WrappingRevision)
	if !errors.Is(err, ErrCatalogEquivocation) || !reflect.DeepEqual(next, account) {
		t.Fatal("first local enrollment replaced catalog selection", err)
	}
}

func TestEnrolledAuthorRejectsBootstrapDowngrade(t *testing.T) {
	var bootstrap *vault.InviteBootstrap
	f, _, _ := enrolledReleaseFixture(t, false, captureEnrolledBootstrap(t, &bootstrap))
	a := f.records.Chain[0].Author
	direct := UnverifiedNodeAuthor{Key: a.State.Signing, State: a.State, Certificate: &a.EnrollmentCertificate.BootstrapSigning}
	node := signEnrolledNode(t, f, direct, bootstrap.SigningSeed, 2)
	foreign := cloneTrustState(f.s)
	foreign.Enrollment, foreign.Account, foreign.WrappingRevision = nil, nil, 0
	foreign.FormatVersion = 2
	foreign.UserID = uuid.New()
	foreign, err := foreign.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []TrustState{f.s, foreign} {
		next, err := state.AdvanceCatalog(node, direct)
		if !errors.Is(err, vault.ErrAuthentication) || !reflect.DeepEqual(next, state) {
			t.Fatal("enrolled author reverted to bootstrap key", err)
		}
	}
	// Refusing the bootstrap signature must still retain a newer authentic
	// account observation, so later reads cannot replay its previous state.
	state := *a.State
	state.Sequence++
	state, err = vault.SignUserKeyState(state, f.org)
	if err != nil {
		t.Fatal(err)
	}
	direct.State = &state
	next, err := foreign.AdvanceCatalog(node, direct)
	if !errors.Is(err, vault.ErrAuthentication) || next.Catalog["author/"+state.UserID.String()].Revision != state.Sequence || foreign.ValidateAdvance(next) != nil || next.Catalog["node/"+node.Metadata.ID].Revision != foreign.Catalog["node/"+node.Metadata.ID].Revision {
		t.Fatal("bootstrap refusal lost account observation or accepted node", err)
	}
}

func TestEnrolledAuthorEncryptionOnlySignedResetUsesNewAnchor(t *testing.T) {
	var bootstrap *vault.InviteBootstrap
	f, _, _ := enrolledReleaseFixture(t, false, captureEnrolledBootstrap(t, &bootstrap))
	a := f.records.Chain[0].Author
	before, err := f.s.AdvanceCatalog(f.records.Chain[0].Node, a)
	if err != nil {
		t.Fatal(err)
	}
	state := *a.State
	state.Sequence++
	state.Encryption = vault.KeyRef{ID: uuid.New(), Version: 1}
	state, err = vault.SignUserKeyState(state, f.org)
	if err != nil {
		t.Fatal(err)
	}
	c := *a.EnrollmentCertificate
	vault.Wipe(bootstrap.EncryptionPrivate)
	bootstrap.EncryptionPrivate = bytes.Repeat([]byte{29}, 32)
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	c.BootstrapEncryption.Key, c.BootstrapEncryption.PublicKey = state.Encryption, public.Encryption
	c.BootstrapEncryption, err = vault.SignUserKeyCertificate(c.BootstrapEncryption, f.org)
	if err != nil {
		t.Fatal(err)
	}
	c.Manifest.Context.KeyID, c.Manifest.Context.KeyVersion, c.Manifest.Context.InviteID = state.Encryption.ID, state.Encryption.Version, uuid.New()
	c.Manifest.Bootstrap, c.Manifest.Revision = public, 1
	seed := f.org.Seed()
	defer vault.Wipe(seed)
	c.Manifest, err = vault.SignInviteManifest(c.Manifest, seed)
	if err != nil {
		t.Fatal(err)
	}
	keys, proof, err := vault.PrepareInviteRekey(c.Manifest.Context, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	c.Rekey = proof
	a = UnverifiedNodeAuthor{Key: vault.KeyRef{ID: proof.SigningKeyID, Version: 1}, State: &state, EnrollmentCertificate: &c}
	node := signEnrolledNode(t, f, a, keys.SigningSeed, 2)
	observed, err := before.AdvanceCatalog(node, a)
	if err != nil || observed.Enrollment != nil || observed.Catalog[catalogEnrollmentName(state)].Revision != 1 || observed.Catalog[catalogEnrollmentName(*f.s.Account)].Revision != 5 || before.ValidateAdvance(observed) != nil {
		t.Fatal("encryption-only reset mixed bootstrap anchors", err)
	}
	owned, err := observed.AdvanceEnrollment(c, observed.WrappingRevision)
	if err != nil || owned.FormatVersion != 6 || owned.Enrollment.ManifestRevision != 1 {
		t.Fatal("signed reset inherited old manifest floor", err)
	}
}

func TestEnrolledBootstrapFloorsSurviveInvalidDelegation(t *testing.T) {
	f, _, _ := enrolledReleaseFixture(t, false)
	a := f.records.Chain[0].Author
	raw, err := vault.EncodeUserEnrollmentCertificate(*a.EnrollmentCertificate)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := vault.DecodeUserEnrollmentCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	bad.BootstrapSigning.Revision++
	bad.BootstrapSigning, err = vault.SignUserKeyCertificate(bad.BootstrapSigning, f.org)
	if err != nil {
		t.Fatal(err)
	}
	bad.Rekey.Signature[0] ^= 1
	a.EnrollmentCertificate = &bad
	next, err := f.s.AdvanceCatalog(f.records.Chain[0].Node, a)
	key := catalogKeyName("key", f.s.Account.Signing)
	if !errors.Is(err, vault.ErrAuthentication) || next.Catalog[key].Revision != bad.BootstrapSigning.Revision || f.s.ValidateAdvance(next) != nil || next.Catalog["node/"+f.node().String()].Revision != 0 {
		t.Fatal("authenticated bootstrap floor lost on bad delegation", err)
	}
	partial, err := f.s.AdvanceEnrollment(bad, f.s.WrappingRevision)
	if !errors.Is(err, vault.ErrAuthentication) || partial.Catalog[key].Revision != bad.BootstrapSigning.Revision || f.s.ValidateAdvance(partial) != nil {
		t.Fatal("account enrollment dropped certificate observation", err)
	}
	old := f.records.Chain[0].Author
	if _, err := next.AdvanceCatalog(f.records.Chain[0].Node, old); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("old bootstrap certificate reused", err)
	}
	if _, err := next.AdvanceEnrollment(*old.EnrollmentCertificate, next.WrappingRevision); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("unlock ignored bootstrap certificate floor", err)
	}
	root := bytes.Repeat([]byte{11}, 32)
	binding := TrustBinding{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, DeviceID: f.s.DeviceID, KeyID: uuid.New(), KeyVersion: 1}
	before, err := SealTrustState(root, binding, f.s)
	if err != nil {
		t.Fatal(err)
	}
	pending, _, err := PrepareTrustRootTransition(root, bytes.Repeat([]byte{12}, 32), binding, before, f.s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := pending.ObserveEnrollment(binding, bad, pending.ObservedTrust().WrappingRevision)
	if !errors.Is(err, vault.ErrAuthentication) || observed.ObservedTrust().Catalog[key].Revision != bad.BootstrapSigning.Revision || pending.ValidateObservationAdvance(binding, observed) != nil {
		t.Fatal("password recovery lost public observation", err)
	}
}
