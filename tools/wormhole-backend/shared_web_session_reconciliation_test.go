package main

import (
	"context"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedCatalogErasesWebArchivesOnlyInVerifiedViewRanges(t *testing.T) {
	ctx := context.Background()
	c, p, options, _, _, _ := catalogControllerFixture(t)
	catalog, err := p.page(ctx, sharedpg.TreeCursor{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(catalog.Nodes, func(i, j int) bool { return catalog.Nodes[i].Metadata.ID < catalog.Nodes[j].Metadata.ID })
	first := uuid.MustParse(catalog.Nodes[0].Metadata.ID)
	last := uuid.MustParse(catalog.Nodes[1].Metadata.ID)
	revokedFirst := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	revokedLast := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	cache := vaultCredentialFixture(t).owner
	file := uuid.New()
	c.vpnSSO = &sharedVPNSSOStorage{owner: cache, fileID: file.String()}
	keep := func(id uuid.UUID, account uuid.UUID) localvault.WebSessionBinding {
		return localvault.WebSessionBinding{
			WorkspaceID: options.Binding.WorkspaceID.String(), FileID: file.String(), AccountID: account.String(),
			NodeID: id.String(), Host: "visible.example", Protocol: "https", Port: 443,
		}
	}
	subject := options.Binding.UserID
	other := uuid.New()
	for _, b := range []localvault.WebSessionBinding{
		keep(first, subject), keep(last, subject), keep(revokedFirst, subject), keep(revokedLast, subject),
		keep(revokedFirst, other),
	} {
		if _, err := cache.SaveWebSessionState(ctx, b, 0, []byte("synthetic shared web archive")); err != nil {
			t.Fatal(err)
		}
	}
	cursor := sharedpg.TreeCursor{After: first, Epoch: catalog.Epoch, ChangeSeq: catalog.ChangeSeq}
	p.page = func(_ context.Context, cursorIn sharedpg.TreeCursor, _ int) (*sharedpg.UnverifiedTreePage, error) {
		result := *catalog
		if cursorIn.After == uuid.Nil {
			result.Nodes = catalog.Nodes[:1]
			result.Next = &cursor
		} else {
			result.Nodes = catalog.Nodes[1:]
		}
		return &result, nil
	}
	expect := func(b localvault.WebSessionBinding, retained bool) {
		t.Helper()
		err := cache.WithWebSessionState(ctx, b, func(rev uint64, payload []byte) error {
			if (len(payload) > 0) != retained || (retained && rev != 1) || (!retained && rev != 2) {
				t.Fatalf("unexpected web archive presence for %s: revision %d, retained %t", b.NodeID, rev, len(payload) > 0)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CatalogPage(ctx, sharedpg.TreeCursor{}, 1); err != nil {
		t.Fatal(err)
	}
	expect(keep(first, subject), true) // View is sufficient to retain the archive.
	expect(keep(last, subject), true)
	expect(keep(revokedFirst, subject), false)
	expect(keep(revokedLast, subject), true) // Outside the first authenticated page.
	expect(keep(revokedFirst, other), true)

	if _, err := c.CatalogPage(ctx, cursor, 1); err != nil {
		t.Fatal(err)
	}
	expect(keep(last, subject), true)
	expect(keep(revokedLast, subject), false)
	expect(keep(revokedFirst, other), true)
}

func TestSharedWebArchiveReconciliationRejectsUncertainRange(t *testing.T) {
	c, _, _, _, _, _ := catalogControllerFixture(t)
	c.vpnSSO = &sharedVPNSSOStorage{owner: vaultCredentialFixture(t).owner, fileID: "invalid"}
	ctx := context.Background()
	page := &sharedCatalogPage{Epoch: 1, ChangeSeq: 7}
	if err := c.reconcileVisibleWebArchives(ctx, sharedpg.TreeCursor{}, page); err != vault.ErrAuthentication {
		t.Fatalf("cache identity was not authenticated: %v", err)
	}
	c.vpnSSO.fileID = uuid.NewString()
	page.Next = &sharedpg.TreeCursor{After: uuid.New(), Epoch: 1, ChangeSeq: 7}
	if err := c.reconcileVisibleWebArchives(ctx, sharedpg.TreeCursor{}, page); err != sharedpg.ErrAdmissionResponse {
		t.Fatalf("empty nonterminal page erased archives: %v", err)
	}
	page.Next = nil
	crossedSnapshot := sharedpg.TreeCursor{After: uuid.New(), Epoch: 1, ChangeSeq: 6}
	if err := c.reconcileVisibleWebArchives(ctx, crossedSnapshot, page); err != sharedpg.ErrAdmissionResponse {
		t.Fatalf("crossed snapshots authorized erasure: %v", err)
	}
}
