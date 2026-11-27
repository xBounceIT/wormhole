package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type catalogProbe struct {
	*sharedAdmissionProbe
	page    func(context.Context, sharedpg.TreeCursor, int) (*sharedpg.UnverifiedTreePage, error)
	author  func(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error)
	changes func(context.Context, uint64, uint64) (*sharedpg.CatalogChanges, error)
}

func (p *catalogProbe) ChangesSince(ctx context.Context, epoch, since uint64) (*sharedpg.CatalogChanges, error) {
	return p.changes(ctx, epoch, since)
}

func TestSharedCatalogPageConcurrentClose(t *testing.T) {
	c, p, _, _, _, _ := catalogControllerFixture(t)
	entered := make(chan struct{})
	p.author = func(ctx context.Context, _ uuid.UUID, _ uint64, _ uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	finished := make(chan error, 1)
	go func() {
		page, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 2)
		if page != nil {
			finished <- errors.New("closed controller returned metadata")
			return
		}
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("catalog retained gate after close")
	}
	if c.Unlocked() || c.privateKeys != nil || c.root != nil {
		t.Fatal("closed catalog retained secrets")
	}
}

func (p *catalogProbe) TreePage(ctx context.Context, c sharedpg.TreeCursor, n int) (*sharedpg.UnverifiedTreePage, error) {
	return p.page(ctx, c, n)
}
func (p *catalogProbe) NodeAuthor(ctx context.Context, id uuid.UUID, e, s uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
	return p.author(ctx, id, e, s)
}

func catalogControllerFixture(t *testing.T, profiles ...vault.Profile) (*sharedAdmissionController, *catalogProbe, sharedAdmissionOptions, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	t.Helper()
	profile := vault.Standard
	if len(profiles) != 0 {
		profile = profiles[0]
	}
	c, p, o, root, master, account, org := sharedUnlockFixtureWithPolicy(t, profile, vault.KDFV1, false)
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(key)
	page := &sharedpg.UnverifiedTreePage{Epoch: 1, ChangeSeq: 9}
	for i := 0; i < 2; i++ {
		node := sharedpg.UnverifiedTreeNode{Metadata: vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Node", Kind: 1}, Permissions: permissions.View, Boundary: uuid.New()}
		var err error
		node.Seal, err = sharedcatalog.SignNode(o.Binding.WorkspaceID, node.Boundary, node.Metadata, 1, account.State.Signing, key)
		if err != nil {
			t.Fatal(err)
		}
		page.Nodes = append(page.Nodes, node)
	}
	probe := &catalogProbe{sharedAdmissionProbe: p}
	probe.page = func(context.Context, sharedpg.TreeCursor, int) (*sharedpg.UnverifiedTreePage, error) {
		return page, nil
	}
	probe.author = func(_ context.Context, _ uuid.UUID, epoch, seq uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
		if epoch != 1 || seq != 9 {
			t.Error("snapshot binding lost")
		}
		return &sharedpg.UnverifiedNodeAuthor{Key: account.State.Signing, State: account.State, Certificate: account.SigningCertificate}, nil
	}
	c.session = probe
	c.catalogAnchor = func(_ context.Context, path string, key []byte, binding sharedpg.TrustBinding, want sharedpg.TrustState) error {
		got, err := readSharedTrustFile(path, key, binding, want.Revision)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			return errSharedTrustConflict
		}
		return nil
	}
	return c, probe, o, root, account, org
}

func TestSharedCatalogPagePublication(t *testing.T) {
	c, _, o, root, _, _ := catalogControllerFixture(t)
	initial := c.trustRevision
	page, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 2)
	if err != nil || len(page.Nodes) != 2 || page.ChangeSeq != 9 || !c.Unlocked() {
		t.Fatal(page, err)
	}
	stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
	if err != nil || stored.Revision != initial+1 || len(stored.Catalog) != 3 {
		t.Fatal("page not atomically persisted", err)
	}
	if _, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 2); err != nil || c.trustRevision != initial+1 {
		t.Fatal("repeat page", err)
	}
	if _, err := c.CatalogPage(nil, sharedpg.TreeCursor{}, 2); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	for _, cursor := range []sharedpg.TreeCursor{{Epoch: 1}, {After: uuid.New()}, {After: uuid.New(), Epoch: 1 << 63}, {After: uuid.New(), Epoch: 1, ChangeSeq: 1 << 63}} {
		if _, err := c.CatalogPage(context.Background(), cursor, 2); err != sharedpg.ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 33); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CatalogPage(cancelled, sharedpg.TreeCursor{}, 2); err != context.Canceled {
		t.Fatal(err)
	}
	c.unlocked.Store(false)
	if _, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 2); err != sharedpg.ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestSharedCatalogPageFailures(t *testing.T) {
	for _, scenario := range []string{"account-error", "nil-account", "revoked-account", "rotated-account", "late-rotation", "tree-error", "nil-page", "nil-author", "author-error", "tamper", "partial-revocation", "storage-fail", "anchor-fail", "anchor-uncertain", "default-anchor", "cancel", "no-view", "cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			c, p, o, root, account, org := catalogControllerFixture(t)
			initial := c.trustRevision
			want := error(vault.ErrAuthentication)
			synthetic := errors.New("fixture failure")
			switch scenario {
			case "storage-fail":
				original := privateFileDirectorySync
				t.Cleanup(func() { privateFileDirectorySync = original })
				privateFileDirectorySync = func(string) error { return synthetic }
				want = errSharedTrustCommitUncertain
			case "late-rotation":
				state := *account.State
				state.Sequence++
				state.Signing.ID = uuid.New()
				state, _ = vault.SignUserKeyState(state, org)
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{56}, 32))
				defer vault.Wipe(key)
				cert := *account.SigningCertificate
				cert.Key = state.Signing
				cert.PublicKey = key.Public().(ed25519.PublicKey)
				cert, _ = vault.SignUserKeyCertificate(cert, org)
				page, _ := p.page(context.Background(), sharedpg.TreeCursor{}, 2)
				for i := range page.Nodes {
					n := &page.Nodes[i]
					n.Seal, _ = sharedcatalog.SignNode(o.Binding.WorkspaceID, n.Boundary, n.Metadata, 2, state.Signing, key)
				}
				p.author = func(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
					return &sharedpg.UnverifiedNodeAuthor{Key: state.Signing, State: &state, Certificate: &cert}, nil
				}
			case "account-error":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, synthetic }
				want = synthetic
			case "nil-account":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, nil }
				want = sharedpg.ErrAdmissionResponse
			case "revoked-account", "rotated-account":
				state := *account.State
				state.Sequence++
				if scenario == "revoked-account" {
					state.Active = false
					want = vault.ErrPolicy
				} else {
					state.Signing.ID = uuid.New()
				}
				state, _ = vault.SignUserKeyState(state, org)
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return &state, nil }
			case "tree-error":
				p.page = func(context.Context, sharedpg.TreeCursor, int) (*sharedpg.UnverifiedTreePage, error) {
					return nil, sharedpg.ErrTreeSnapshotChanged
				}
				want = sharedpg.ErrTreeSnapshotChanged
			case "nil-page":
				p.page = func(context.Context, sharedpg.TreeCursor, int) (*sharedpg.UnverifiedTreePage, error) { return nil, nil }
				want = sharedpg.ErrAdmissionResponse
			case "nil-author":
				p.author = func(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
					return nil, nil
				}
				want = sharedpg.ErrAdmissionResponse
			case "author-error":
				p.author = func(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
					return nil, synthetic
				}
				want = synthetic
			case "tamper", "no-view", "cleanup":
				page, _ := p.page(context.Background(), sharedpg.TreeCursor{}, 2)
				page.Nodes[0].Metadata.Name = "forged"
				if scenario == "no-view" {
					page.Nodes[0].Permissions = 0
					want = sharedpg.ErrAdmissionResponse
				}
				if scenario == "cleanup" {
					p.closeFailure.Store(true)
					t.Cleanup(func() { p.closeFailure.Store(false); _ = c.Close(context.Background()) })
					want = errSharedAdmissionCleanup
				}
			case "partial-revocation":
				calls := 0
				old := p.author
				p.author = func(ctx context.Context, id uuid.UUID, e, s uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
					calls++
					value, err := old(ctx, id, e, s)
					if calls == 2 {
						state := *value.State
						state.Sequence++
						state.Active = false
						state, _ = vault.SignUserKeyState(state, org)
						value.State = &state
						value.Certificate = nil
					}
					return value, err
				}
				want = vault.ErrPolicy
			case "anchor-fail":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return synthetic
				}
				want = synthetic
			case "anchor-uncertain":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return errSharedTrustCommitUncertain
				}
				want = errSharedTrustCommitUncertain
			case "default-anchor":
				c.catalogAnchor = nil
				want = errSharedTrustMissing
			case "cancel":
				p.author = func(ctx context.Context, _ uuid.UUID, _ uint64, _ uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
					c.cancel()
					<-ctx.Done()
					return nil, ctx.Err()
				}
				want = context.Canceled
			}
			page, err := c.CatalogPage(context.Background(), sharedpg.TreeCursor{}, 2)
			if page != nil || err != want || c.Unlocked() {
				t.Fatalf("page=%v err=%v want=%v unlocked=%v", page, err, want, c.Unlocked())
			}
			if scenario == "partial-revocation" || scenario == "revoked-account" {
				stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
				if err != nil || stored.Account.Active {
					t.Fatal("revocation lost", err)
				}
			}
		})
	}
}
