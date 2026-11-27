package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const sharedCatalogFirst = `{"after":"","epoch":"0","changeSeq":"0","limit":2}`

func TestVaultSharedCatalog(t *testing.T) {
	c, p, o, _, account, _ := catalogControllerFixture(t)
	page, _ := p.page(context.Background(), sharedpg.TreeCursor{}, 2)
	page.Nodes[0].Permissions |= permissions.Use
	id := uuid.NewString()
	page.Nodes[0].Metadata.CredentialID = &id
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(key)
	page.Nodes[0].Seal, _ = sharedcatalog.SignNode(o.Binding.WorkspaceID, page.Nodes[0].Boundary, page.Nodes[0].Metadata, 1, account.State.Signing, key)
	page.Next = &sharedpg.TreeCursor{After: uuid.MustParse(page.Nodes[1].Metadata.ID), Epoch: 1, ChangeSeq: 9}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	t.Cleanup(func() { _ = h.Close() })
	raw, err := h.Handle(context.Background(), "shared-catalog", []byte(sharedCatalogFirst))
	if err != nil {
		t.Fatal(err)
	}
	var result vaultSharedCatalogPage
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Nodes) != 2 || result.Epoch != "1" || result.ChangeSeq != "9" || result.Next == nil {
		t.Fatal("projection", err)
	}
	if !result.Nodes[0].CanUse || result.Nodes[1].CanUse {
		t.Fatal("Use hint confused View with Use")
	}
	for _, forbidden := range []string{id, "credentialId", "boundary", "signature", "privateKey", "permissions", "rowVersion"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("non-display field leaked", forbidden)
		}
	}
	if _, err := h.Handle(context.Background(), "catalog", nil); err != vaultwire.ErrProtocol {
		t.Fatal("local catalog fallback", err)
	}
	if _, err := h.Handle(context.Background(), "shared-catalog", []byte(`{}`)); err != vaultwire.ErrProtocol || !c.Unlocked() {
		t.Fatal("bad request mutated owner", err)
	}
	p.author = func(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error) {
		return nil, sharedpg.ErrTreeSnapshotChanged
	}
	if raw, err := h.Handle(context.Background(), "shared-catalog", []byte(sharedCatalogFirst)); err == nil || raw != nil || !h.closed {
		t.Fatal("failed catalog kept service", err)
	}
	if _, err := (&vaultFoundationHandler{}).sharedCatalog(context.Background(), []byte(sharedCatalogFirst)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestSharedCatalogRequest(t *testing.T) {
	for _, raw := range []string{"", `null`, `{}`, strings.Repeat(" ", 1025), `{"after":"","epoch":"0","changeSeq":"0","limit":2,"password":"x"}`, `{"after":"","epoch":"0","changeSeq":"0","limit":2,"limit":1}`, `{"after":"","epoch":0,"changeSeq":"0","limit":2}`} {
		if _, _, err := decodeSharedCatalogRequest([]byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid request", raw, err)
		}
	}
	for _, replace := range [][2]string{{`"limit":2`, `"limit":0`}, {`"limit":2`, `"limit":33`}, {`"epoch":"0"`, `"epoch":"01"`}, {`"epoch":"0"`, `"epoch":"1"`}, {`"changeSeq":"0"`, `"changeSeq":"-1"`}, {`"changeSeq":"0"`, `"changeSeq":"9223372036854775808"`}, {`"after":""`, `"after":"bad"`}, {`"after":""`, `"after":"00000000-0000-0000-0000-000000000000"`}, {`"changeSeq":"0"`, `"changeSeq":"1"`}} {
		if _, _, err := decodeSharedCatalogRequest([]byte(strings.Replace(sharedCatalogFirst, replace[0], replace[1], 1))); err != vaultwire.ErrProtocol {
			t.Fatal("invalid cursor", replace, err)
		}
	}
	id := uuid.NewString()
	valid := `{"after":"` + id + `","epoch":"1","changeSeq":"9223372036854775807","limit":32}`
	if cursor, limit, err := decodeSharedCatalogRequest([]byte(valid)); err != nil || limit != 32 || cursor.After.String() != id {
		t.Fatal(cursor, limit, err)
	}
	if _, _, err := decodeSharedCatalogRequest([]byte(strings.Replace(valid, `"epoch":"1"`, `"epoch":"0"`, 1))); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}
func TestVaultSharedCatalogUseHintDoesNotConnectFolders(t *testing.T) {
	c, p, o, _, account, _ := catalogControllerFixture(t)
	page, _ := p.page(context.Background(), sharedpg.TreeCursor{}, 2)
	page.Nodes[0].Metadata.Kind = 0
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(key)
	for i := range page.Nodes {
		page.Nodes[i].Permissions |= permissions.Use
		var err error
		page.Nodes[i].Seal, err = sharedcatalog.SignNode(o.Binding.WorkspaceID, page.Nodes[i].Boundary, page.Nodes[i].Metadata, 1, account.State.Signing, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	t.Cleanup(func() { _ = h.Close() })
	raw, err := h.Handle(context.Background(), "shared-catalog", []byte(sharedCatalogFirst))
	var result vaultSharedCatalogPage
	if err != nil || json.Unmarshal(raw, &result) != nil || len(result.Nodes) != 2 || result.Nodes[0].CanUse || !result.Nodes[1].CanUse {
		t.Fatal("folder Use became connection authority", err)
	}
}

func TestVaultSharedCatalogNoteHintIsViewableWithoutUse(t *testing.T) {
	c, p, options, _, account, _ := catalogControllerFixture(t)
	probe := &noteViewProbe{credentialReleaseProbe: &credentialReleaseProbe{catalogProbe: p}}
	c.session = probe
	page, _ := p.page(context.Background(), sharedpg.TreeCursor{}, 2)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(key)
	digest := strings.Repeat("a", 64)
	for i := range page.Nodes {
		node := &page.Nodes[i]
		node.Metadata.Imported = &vaultstore.NodeImportReference{Digest: digest, NoteVersion: 1}
		var err error
		node.Seal, err = sharedcatalog.SignNode(options.Binding.WorkspaceID, node.Boundary, node.Metadata, 7, account.State.Signing, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	t.Cleanup(func() { _ = h.Close() })
	for _, supported := range []bool{false, true} {
		probe.supported = supported
		probe.capabilityChecks = 0
		raw, err := h.Handle(context.Background(), "shared-catalog", []byte(sharedCatalogFirst))
		var result vaultSharedCatalogPage
		if err != nil || json.Unmarshal(raw, &result) != nil || len(result.Nodes) != 2 || probe.capabilityChecks != 1 || bytes.Contains(raw, []byte(digest)) {
			t.Fatal("catalog exposed the signed attachment or missed its capability", err)
		}
		want := ""
		if supported {
			want = "7"
		}
		for _, node := range result.Nodes {
			if node.CanUse || node.NotesRevision != want {
				t.Fatal("note display was coupled to Use or ignored server support")
			}
		}
	}
}
