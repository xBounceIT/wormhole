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

func catalogTrustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, UnverifiedTreeNode, UnverifiedNodeAuthor, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	root, b, s, state, org, _, _ := accountTrustFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	t.Cleanup(func() { vault.Wipe(key) })
	cert, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: b.WorkspaceID, UserID: b.UserID, Key: state.Signing, Kind: "user-sign", Suite: 1, PublicKey: key.Public().(ed25519.PublicKey), Revision: 3, Signer: state.Signer}, org)
	if err != nil {
		t.Fatal(err)
	}
	node := UnverifiedTreeNode{Metadata: vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Node", Kind: 1}, Boundary: uuid.New()}
	node.Seal, err = sharedcatalog.SignNode(b.WorkspaceID, node.Boundary, node.Metadata, 1, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	return root, b, s, node, UnverifiedNodeAuthor{Key: state.Signing, State: &state, Certificate: &cert}, org, key
}

func TestCatalogTrustPersistenceAndRevocation(t *testing.T) {
	root, b, s, node, author, org, key := catalogTrustFixture(t)
	next, err := s.AdvanceCatalog(node, author)
	if err != nil || len(next.Catalog) != 3 || s.Catalog != nil || next.Revision != s.Revision+1 {
		t.Fatal(next, err)
	}
	if err := s.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, next)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, b, raw, next.Revision)
	if err != nil || !reflect.DeepEqual(restored, next) {
		t.Fatal("roundtrip", err)
	}
	same, err := restored.AdvanceCatalog(node, author)
	if err != nil || !reflect.DeepEqual(same, restored) {
		t.Fatal("idempotent", err)
	}
	for _, v := range same.Catalog {
		v.Digest[0] ^= 1
		break
	}
	if reflect.DeepEqual(same.Catalog, restored.Catalog) {
		t.Fatal("fixture did not mutate")
	}
	if _, err := restored.AdvanceCatalog(node, author); err != nil {
		t.Fatal("clone aliases", err)
	}
	changed := node
	changed.Metadata.Name = "Changed"
	changed.Seal, _ = sharedcatalog.SignNode(b.WorkspaceID, changed.Boundary, changed.Metadata, 1, author.Key, key)
	if _, err := restored.AdvanceCatalog(changed, author); err != ErrCatalogEquivocation {
		t.Fatal("node equivocation", err)
	}
	changed.Seal, _ = sharedcatalog.SignNode(b.WorkspaceID, changed.Boundary, changed.Metadata, 2, author.Key, key)
	advanced, err := restored.AdvanceCatalog(changed, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advanced.AdvanceCatalog(node, author); err != vault.ErrRollback {
		t.Fatal("node rollback", err)
	}
	revoked := *author.State
	revoked.Sequence++
	revoked.Active = false
	revoked, _ = vault.SignUserKeyState(revoked, org)
	revokedAuthor := author
	revokedAuthor.State = &revoked
	revokedAuthor.Certificate = nil
	denied, err := advanced.AdvanceCatalog(node, revokedAuthor)
	if err != vault.ErrPolicy || denied.Revision != advanced.Revision+1 {
		t.Fatal("revocation discarded", err)
	}
	if err := advanced.ValidateAdvance(denied); err != nil {
		t.Fatal(err)
	}
	raw, err = SealTrustState(root, b, denied)
	if err != nil {
		t.Fatal(err)
	}
	denied, err = OpenTrustState(root, b, raw, denied.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.AdvanceCatalog(node, author); err != vault.ErrRollback {
		t.Fatal("revocation replay after restart", err)
	}
	cleared := cloneTrustState(denied)
	cleared.Revision++
	cleared.Catalog = nil
	if denied.ValidateAdvance(cleared) != ErrTrustRollback {
		t.Fatal("floors erased")
	}
	// The protected login account is also an author-state floor even before a
	// catalog entry exists for that author.
	accountState, err := s.AdvanceAccount(revoked, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accountState.AdvanceCatalog(node, author); err != vault.ErrRollback {
		t.Fatal("login-account floor ignored", err)
	}
	activeAccount, err := s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	selfRevoked, err := activeAccount.AdvanceCatalog(node, revokedAuthor)
	if err != vault.ErrPolicy || selfRevoked.Account.Active || selfRevoked.Account.Sequence != revoked.Sequence {
		t.Fatal("catalog revocation missed login anchor", err)
	}
	if err := activeAccount.ValidateAdvance(selfRevoked); err != nil {
		t.Fatal(err)
	}
	if _, err := selfRevoked.AdvanceAccount(*author.State, 1); err != vault.ErrRollback {
		t.Fatal("login ignored catalog revocation", err)
	}
}

func TestCatalogTrustBoundsAndTransitions(t *testing.T) {
	root, b, s, node, author, _, _ := catalogTrustFixture(t)
	if _, err := (TrustState{}).AdvanceCatalog(node, author); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := s.AdvanceCatalog(node, UnverifiedNodeAuthor{}); err != ErrTrustState {
		t.Fatal(err)
	}
	bad := node
	bad.Metadata.ID = "bad"
	if _, err := s.AdvanceCatalog(bad, author); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	bad = node
	bad.Seal.Signature = nil
	partial, err := s.AdvanceCatalog(bad, author)
	if err != vault.ErrAuthentication || len(partial.Catalog) != 2 {
		t.Fatal("authenticated observations lost", err)
	}
	for _, key := range []string{"bad", "node/bad", "node/" + uuid.NewString() + "/1", "key/" + uuid.NewString(), "key/" + uuid.NewString() + "/0", "other/" + uuid.NewString()} {
		if validCatalogFloors(map[string]CatalogFloor{key: {1, make([]byte, 32)}}) {
			t.Fatal("invalid key", key)
		}
	}
	for _, floor := range []CatalogFloor{{0, make([]byte, 32)}, {1 << 63, make([]byte, 32)}, {1, nil}} {
		if validCatalogFloors(map[string]CatalogFloor{"node/" + uuid.NewString(): floor}) {
			t.Fatal("invalid floor")
		}
	}
	full := cloneTrustState(s)
	full.Catalog = make(map[string]CatalogFloor)
	for i := 0; i < MaxCatalogFloors; i++ {
		full.Catalog["key/"+uuid.NewString()+"/2147483647"] = CatalogFloor{math.MaxInt64, make([]byte, 32)}
	}
	raw, err := SealTrustState(root, b, full)
	if err != nil {
		t.Fatal("maximum catalog cannot persist", err)
	}
	if _, err := OpenTrustState(root, b, raw, full.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := full.AdvanceCatalog(node, author); err != ErrTrustState {
		t.Fatal("catalog bound", err)
	}
	overflow := s
	overflow.Revision = math.MaxUint64
	if _, err := overflow.AdvanceCatalog(node, author); err != ErrTrustState {
		t.Fatal("counter overflow", err)
	}
	current, err := s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err = current.AdvanceCatalog(node, author)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = SealTrustState(root, b, current)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := bytes.Repeat([]byte{88}, 32)
	transition, encoded, err := PrepareTrustRootTransition(root, newRoot, b, raw, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTrustRootTransition(newRoot, b, encoded)
	if err != nil || !reflect.DeepEqual(opened.Next.Catalog, current.Catalog) {
		t.Fatal("password transition lost floors", err)
	}
	for _, floor := range transition.Next.Catalog {
		floor.Digest[0] ^= 1
		break
	}
	if _, err := SealTrustState(root, b, current); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(transition.Next.Catalog, current.Catalog) {
		t.Fatal("transition aliases source")
	}
}
