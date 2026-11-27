package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func credentialTrustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, UnverifiedCredential, UnverifiedNodeAuthor, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	root, b, s, node, author, org, key := catalogTrustFixture(t)
	c := UnverifiedCredential{Record: sharedcatalog.CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: node.Metadata.ID, Name: "Account", Protocol: "ssh", Kind: "password", Provider: "local"}, Fields: []vaultstore.CredentialField{{Field: "password", Version: 1, Present: true}}}, Boundary: node.Boundary}
	var err error
	c.Seal, err = sharedcatalog.SignCredential(b.WorkspaceID, c.Boundary, c.Record, 1, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	return root, b, s, c, author, org, key
}

func TestCredentialTrustPersistenceForksAndTombstones(t *testing.T) {
	root, b, s, c, author, _, key := credentialTrustFixture(t)
	next, err := s.AdvanceCredential(c, author)
	if err != nil || len(next.Catalog) != 3 || s.Catalog != nil || next.Revision != s.Revision+1 {
		t.Fatal("initial credential trust", err)
	}
	if s.ValidateAdvance(next) != nil {
		t.Fatal("invalid advance")
	}
	roundtrip := func(v TrustState) TrustState {
		t.Helper()
		raw, e := SealTrustState(root, b, v)
		if e != nil {
			t.Fatal(e)
		}
		restored, e := OpenTrustState(root, b, raw, v.Revision)
		if e != nil || !reflect.DeepEqual(restored, v) {
			t.Fatal("credential floors roundtrip", e)
		}
		return restored
	}
	next = roundtrip(next)
	same, err := next.AdvanceCredential(c, author)
	if err != nil || !reflect.DeepEqual(same, next) {
		t.Fatal("idempotence", err)
	}
	for _, floor := range same.Catalog {
		floor.Digest[0] ^= 1
		break
	}
	if reflect.DeepEqual(same.Catalog, next.Catalog) {
		t.Fatal("fixture failed")
	}
	if _, err = next.AdvanceCredential(c, author); err != nil {
		t.Fatal("aliasing", err)
	}
	fork := c
	fork.Record.Metadata.Username = "other"
	fork.Seal, err = sharedcatalog.SignCredential(b.WorkspaceID, fork.Boundary, fork.Record, 1, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.AdvanceCredential(fork, author); err != ErrCatalogEquivocation {
		t.Fatal("credential fork", err)
	}
	fork.Seal, err = sharedcatalog.SignCredential(b.WorkspaceID, fork.Boundary, fork.Record, 2, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := next.AdvanceCredential(fork, author)
	if err != nil {
		t.Fatal(err)
	}
	updated = roundtrip(updated)
	if _, err = updated.AdvanceCredential(c, author); err != vault.ErrRollback {
		t.Fatal("credential rollback", err)
	}
	tomb := fork
	tomb.Record.Deleted = true
	tomb.Record.Fields = []vaultstore.CredentialField{{Field: "password", Version: 2, Present: false}}
	tomb.Seal, err = sharedcatalog.SignCredential(b.WorkspaceID, tomb.Boundary, tomb.Record, 3, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := updated.AdvanceCredential(tomb, author)
	if err != vaultstore.ErrMissing || deleted.Revision != updated.Revision+1 || deleted.Catalog["credential/"+c.Record.Metadata.ID].Revision != 3 {
		t.Fatal("tombstone discarded", err)
	}
	if updated.ValidateAdvance(deleted) != nil {
		t.Fatal("invalid tombstone advance")
	}
	deleted = roundtrip(deleted)
	if _, err = deleted.AdvanceCredential(fork, author); err != vault.ErrRollback {
		t.Fatal("deleted profile replay", err)
	}
	// A node with the same UUID occupies a different revision namespace.
	node := UnverifiedTreeNode{Metadata: vaultstore.NodeMetadata{ID: c.Record.Metadata.ID, Name: "Node", Kind: 1}, Boundary: c.Boundary}
	node.Seal, err = sharedcatalog.SignNode(b.WorkspaceID, node.Boundary, node.Metadata, 1, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := deleted.AdvanceCatalog(node, author)
	if err != nil || len(mixed.Catalog) != 4 || mixed.Catalog["node/"+node.Metadata.ID].Revision != 1 {
		t.Fatal("record namespace collision", err)
	}
	mixed = roundtrip(mixed)
	cleared := cloneTrustState(mixed)
	delete(cleared.Catalog, "credential/"+c.Record.Metadata.ID)
	cleared.Revision++
	if mixed.ValidateAdvance(cleared) != ErrTrustRollback {
		t.Fatal("credential floor erased")
	}
	// Password transitions require an authenticated account anchor.
	mixed, err = mixed.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, mixed)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := bytes.Repeat([]byte{88}, 32)
	_, encoded, err := PrepareTrustRootTransition(root, newRoot, b, raw, mixed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTrustRootTransition(newRoot, b, encoded)
	if err != nil || !reflect.DeepEqual(opened.Next.Catalog, mixed.Catalog) {
		t.Fatal("password transition lost credential floor", err)
	}
}

func TestCredentialTrustRevocationAndPartialObservations(t *testing.T) {
	root, b, s, c, author, org, _ := credentialTrustFixture(t)
	bad := c
	bad.Seal.Signature = nil
	partial, err := s.AdvanceCredential(bad, author)
	if err != vault.ErrAuthentication || len(partial.Catalog) != 2 || partial.Revision != s.Revision+1 {
		t.Fatal("lost authenticated observations", err)
	}
	if _, ok := partial.Catalog["credential/"+c.Record.Metadata.ID]; ok {
		t.Fatal("unauthenticated floor")
	}
	// A newly valid certificate with changed contents at an already observed
	// revision must be rejected even when the credential signature then fails.
	alternativeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	defer vault.Wipe(alternativeKey)
	alternativeCert := *author.Certificate
	alternativeCert.PublicKey = alternativeKey.Public().(ed25519.PublicKey)
	alternativeCert, err = vault.SignUserKeyCertificate(alternativeCert, org)
	if err != nil {
		t.Fatal(err)
	}
	certForkAuthor := author
	certForkAuthor.Certificate = &alternativeCert
	if _, err = partial.AdvanceCredential(c, certForkAuthor); err != ErrCatalogEquivocation {
		t.Fatal("certificate fork discarded after record failure", err)
	}
	current, err := s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err = current.AdvanceCredential(c, author)
	if err != nil {
		t.Fatal(err)
	}
	revoked := *author.State
	revoked.Sequence++
	revoked.Active = false
	revoked, err = vault.SignUserKeyState(revoked, org)
	if err != nil {
		t.Fatal(err)
	}
	deniedAuthor := author
	deniedAuthor.State = &revoked
	deniedAuthor.Certificate = nil
	denied, err := current.AdvanceCredential(c, deniedAuthor)
	if err != vault.ErrPolicy || denied.Revision != current.Revision+1 || denied.Account.Active || denied.Account.Sequence != revoked.Sequence {
		t.Fatal("revocation missed login anchor", err)
	}
	if current.ValidateAdvance(denied) != nil {
		t.Fatal("invalid own-account advance")
	}
	raw, err := SealTrustState(root, b, denied)
	if err != nil {
		t.Fatal(err)
	}
	denied, err = OpenTrustState(root, b, raw, denied.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = denied.AdvanceCredential(c, author); err != vault.ErrRollback {
		t.Fatal("revocation replay", err)
	}
	if _, err = denied.AdvanceAccount(*author.State, 1); err != vault.ErrRollback {
		t.Fatal("login ignores credential author revocation", err)
	}
	// The login anchor remains authoritative before any catalog-author entry exists.
	accountOnly, err := s.AdvanceAccount(revoked, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accountOnly.AdvanceCredential(c, author); err != vault.ErrRollback {
		t.Fatal("account floor ignored", err)
	}
	// A valid author state at the same sequence but different content is a fork.
	alternate := *author.State
	alternate.MinimumSigningCertificate++
	alternate, err = vault.SignUserKeyState(alternate, org)
	if err != nil {
		t.Fatal(err)
	}
	forkAuthor := author
	forkAuthor.State = &alternate
	_, err = partial.AdvanceCredential(c, forkAuthor)
	if err != ErrCatalogEquivocation {
		t.Fatal("author fork", err)
	}
}

func TestCredentialTrustBoundsAndMalformed(t *testing.T) {
	_, _, s, c, author, _, _ := credentialTrustFixture(t)
	if _, err := (TrustState{}).AdvanceCredential(c, author); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := s.AdvanceCredential(c, UnverifiedNodeAuthor{}); err != ErrTrustState {
		t.Fatal(err)
	}
	bad := c
	bad.Record.Metadata.ID = "bad"
	if _, err := s.AdvanceCredential(bad, author); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	bad.Record.Metadata.ID = uuid.Nil.String()
	if _, err := s.AdvanceCredential(bad, author); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	for _, name := range []string{"credential/bad", "credential/" + uuid.NewString() + "/1"} {
		if validCatalogFloors(map[string]CatalogFloor{name: {1, make([]byte, 32)}}) {
			t.Fatal("invalid credential namespace")
		}
	}
	full := cloneTrustState(s)
	full.Catalog = make(map[string]CatalogFloor)
	for i := 0; i < MaxCatalogFloors; i++ {
		full.Catalog["credential/"+uuid.NewString()] = CatalogFloor{1, make([]byte, 32)}
	}
	if _, err := full.AdvanceCredential(c, author); err != ErrTrustState {
		t.Fatal("floor capacity", err)
	}
	overflow := s
	overflow.Revision = math.MaxUint64
	if _, err := overflow.AdvanceCredential(c, author); err != ErrTrustState {
		t.Fatal("revision overflow", err)
	}
	boundary := s
	boundary.Revision = math.MaxUint64 - 1
	next, err := boundary.AdvanceCredential(c, author)
	if err != nil || next.Revision != math.MaxUint64 {
		t.Fatal("last representable revision", err)
	}
	if _, err = next.AdvanceCredential(c, author); err != nil {
		t.Fatal("idempotence at maximum", err)
	}
}

func TestCredentialRevocationBeforeAccountAnchor(t *testing.T) {
	_, _, s, c, author, org, _ := credentialTrustFixture(t)
	if s.Account != nil {
		t.Fatal("expected policy-only trust")
	}
	revoked := *author.State
	revoked.Sequence++
	revoked.Active = false
	revoked, err := vault.SignUserKeyState(revoked, org)
	if err != nil {
		t.Fatal(err)
	}
	deniedAuthor := author
	deniedAuthor.State = &revoked
	deniedAuthor.Certificate = nil
	denied, err := s.AdvanceCredential(c, deniedAuthor)
	if err != vault.ErrPolicy || denied.Catalog["author/"+s.UserID.String()].Revision != revoked.Sequence {
		t.Fatal("missing revocation", err)
	}
	if _, err = denied.AdvanceAccount(*author.State, 1); err != vault.ErrRollback {
		t.Fatal("policy-only catalog revocation ignored at first account anchor", err)
	}
	// Authenticated account state cannot disagree with an equal-sequence floor.
	alternate := revoked
	alternate.Active = true
	alternate, err = vault.SignUserKeyState(alternate, org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = denied.AdvanceAccount(alternate, 1); err != ErrAccountEquivocation {
		t.Fatal("first anchor fork", err)
	}
	inconsistent, err := s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	inconsistent.Catalog = cloneCatalogFloors(denied.Catalog)
	if inconsistent.valid() {
		t.Fatal("inconsistent account/catalog accepted")
	}
	current, err := denied.AdvanceAccount(revoked, 1)
	if err != nil || current.Account.Active || !current.valid() {
		t.Fatal("authentic revoked anchor rejected", err)
	}
	if denied.ValidateAdvance(current) != nil {
		t.Fatal("revoked anchor cannot persist")
	}
}

func TestCredentialRevocationAtCatalogCapacity(t *testing.T) {
	root, b, s, c, author, org, _ := credentialTrustFixture(t)
	var err error
	s, err = s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.Catalog = make(map[string]CatalogFloor)
	for i := 0; i < MaxCatalogFloors; i++ {
		s.Catalog["credential/"+uuid.NewString()] = CatalogFloor{1, make([]byte, 32)}
	}
	revoked := *author.State
	revoked.Sequence++
	revoked.Active = false
	revoked, err = vault.SignUserKeyState(revoked, org)
	if err != nil {
		t.Fatal(err)
	}
	deniedAuthor := author
	deniedAuthor.State = &revoked
	deniedAuthor.Certificate = nil
	next, err := s.AdvanceCredential(c, deniedAuthor)
	if err != ErrTrustState || next.Account == nil || next.Account.Active || next.Revision != s.Revision+1 || len(next.Catalog) != MaxCatalogFloors {
		t.Fatal("capacity discarded authenticated own revocation", err)
	}
	if s.ValidateAdvance(next) != nil {
		t.Fatal("capacity revocation cannot persist")
	}
	raw, err := SealTrustState(root, b, next)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, b, raw, next.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.AdvanceAccount(*author.State, 1); err != vault.ErrRollback {
		t.Fatal("capacity revocation replay", err)
	}
}
