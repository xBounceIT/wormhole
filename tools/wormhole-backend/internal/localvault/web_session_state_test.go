package localvault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestWebSessionArchiveIndexPaginatesAuthenticatedAccountRecords(t *testing.T) {
	ctx := context.Background()
	o, path, opts, _ := owner(t)
	account := WebSessionArchiveOwner{
		WorkspaceID: uuid.MustParse(opts.Identity.WorkspaceID),
		FileID:      uuid.MustParse(opts.Identity.FileID), AccountID: uuid.New(),
	}
	binding := func(owner WebSessionArchiveOwner, id uuid.UUID) WebSessionBinding {
		b := owner.binding(id)
		b.Protocol, b.Host, b.Port = "https", "index.example", 443
		return b
	}
	target, legacyNode := uuid.New(), uuid.New()
	other := account
	other.AccountID = uuid.New()
	b := binding(account, target)
	for _, record := range []WebSessionBinding{b, binding(other, target)} {
		if _, err := o.SaveWebSessionState(ctx, record, 0, []byte("indexed archive fixture")); err != nil {
			t.Fatal(err)
		}
	}
	legacy := binding(account, legacyNode)
	scope, _ := legacy.scope()
	digest, _ := legacy.digest()
	raw := append([]byte(webSessionArchiveMagic), digest[:]...)
	raw = append(raw, "legacy archive fixture"...)
	if _, err := o.PutLocalState(ctx, vaultstore.LocalStateWebSession, scope, raw, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutLocalState(ctx, "mcp-token", account.WorkspaceID.String(), []byte("unrelated fixture"), 0); err != nil {
		t.Fatal(err)
	}
	var observed []WebSessionArchiveRecord
	pages := 0
	for cursor := ""; ; {
		records, next, err := o.ListWebSessionArchives(ctx, account, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		observed = append(observed, records...)
		pages++
		if next == "" {
			break
		}
		if pages > 4 || next <= cursor {
			t.Fatalf("archive scan failed to advance: %q -> %q", cursor, next)
		}
		cursor = next
	}
	if pages != 5 || !reflect.DeepEqual(observed, []WebSessionArchiveRecord{{Node: target, Revision: 1}}) {
		t.Fatalf("unexpected authenticated inventory: %+v in %d pages", observed, pages)
	}
	if err := o.WithWebSessionState(ctx, legacy, func(rev uint64, value []byte) error {
		if rev != 1 || string(value) != "legacy archive fixture" {
			t.Fatal("legacy checkpoint became unreadable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SaveWebSessionState(ctx, b, 1, []byte("new revision fixture")); err != nil {
		t.Fatal(err)
	}
	if err := o.RevokeWebSessionArchive(ctx, account, observed[0]); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("stale permission observation erased a later revision: %v", err)
	}
	if err := o.RevokeWebSessionArchive(ctx, account, WebSessionArchiveRecord{Node: target, Revision: 2}); err != nil {
		t.Fatal(err)
	}
	if records, _, err := o.ListWebSessionArchives(ctx, account, "", 32); err != nil || len(records) != 0 {
		t.Fatalf("revoked checkpoint remained indexed: %+v %v", records, err)
	}
	if records, _, err := o.ListWebSessionArchives(ctx, other, "", 32); err != nil || len(records) != 1 {
		t.Fatalf("revocation affected another account: %+v %v", records, err)
	}
	if _, _, err := o.ListWebSessionArchives(ctx, WebSessionArchiveOwner{}, "", 32); err != vault.ErrFormat {
		t.Fatalf("invalid owner reached the archive index: %v", err)
	}
	if _, _, err := o.ListWebSessionArchives(ctx, account, "arbitrary", 32); err != vaultstore.ErrFormat {
		t.Fatalf("invalid cursor reached the archive index: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil || bytes.Contains(disk, target[:]) || bytes.Contains(disk, []byte(target.String())) {
		t.Fatalf("archive scope became plaintext: %v", err)
	}
}

func TestWebSessionArchiveIndexRejectsAuthenticatedScopeSubstitution(t *testing.T) {
	o, _, opts, _ := owner(t)
	ctx := context.Background()
	account := WebSessionArchiveOwner{
		WorkspaceID: uuid.MustParse(opts.Identity.WorkspaceID),
		FileID:      uuid.MustParse(opts.Identity.FileID), AccountID: uuid.New(),
	}
	b := account.binding(uuid.New())
	b.Protocol, b.Host, b.Port = "https", "index.example", 443
	scope, _ := b.scope()
	digest, _ := b.digest()
	prefix := append([]byte(indexedWebSessionMagic), digest[:]...)
	wrongNode := uuid.New()
	for _, id := range []uuid.UUID{account.WorkspaceID, account.FileID, account.AccountID, wrongNode} {
		prefix = append(prefix, id[:]...)
	}
	for i, contents := range [][]byte{prefix[:indexedWebSessionHeaderBytes-1], append(prefix, 1)} {
		if _, err := o.PutLocalState(ctx, vaultstore.LocalStateWebSession, scope, contents, uint64(i)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.ListWebSessionArchives(ctx, account, "", 32); err != vault.ErrAuthentication {
			t.Fatalf("inventoried a scope not bound to the sealed record: %v", err)
		}
		if err := o.WithWebSessionState(ctx, b, func(uint64, []byte) error {
			t.Fatal("archive was released under mismatched coordinates")
			return nil
		}); err != vault.ErrAuthentication {
			t.Fatalf("read accepted a substituted archive: %v", err)
		}
	}
}

func TestWebSessionStateIsDeviceScopedEncryptedAndRevisionBound(t *testing.T) {
	ctx := context.Background()
	o, path, opts, root := owner(t)
	b := WebSessionBinding{WorkspaceID: opts.Identity.WorkspaceID, FileID: opts.Identity.FileID,
		AccountID: uuid.NewString(), NodeID: uuid.NewString(), Protocol: "https", Host: "test.example",
		Port: 443, TunnelID: uuid.NewString(), TunnelKind: 9, TunnelRevision: 2, ConfigurationVersion: 1}
	fixture := []byte("synthetic web archive only the owner may read")
	borrow := func(owner *Owner, binding WebSessionBinding, revision uint64, expected []byte) {
		t.Helper()
		var released []byte
		err := owner.WithWebSessionState(ctx, binding, func(rev uint64, stored []byte) error {
			if rev != revision || !bytes.Equal(stored, expected) {
				t.Fatalf("unexpected archive revision %d", rev)
			}
			released = stored
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(released, make([]byte, len(released))) {
			t.Fatal("borrowed native archive survived callback")
		}
	}
	borrow(o, b, 0, nil)
	if rev, err := o.SaveWebSessionState(ctx, b, 0, fixture); err != nil || rev != 1 {
		t.Fatalf("archive save: %d %v", rev, err)
	}
	if _, err := o.SaveWebSessionState(ctx, b, 0, fixture); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("older browser overwrote the archive: %v", err)
	}
	for label, mutate := range map[string]func(*WebSessionBinding){
		"workspace": func(x *WebSessionBinding) { x.WorkspaceID = uuid.NewString() },
		"device":    func(x *WebSessionBinding) { x.FileID = uuid.NewString() },
		"account":   func(x *WebSessionBinding) { x.AccountID = uuid.NewString() },
		"node":      func(x *WebSessionBinding) { x.NodeID = uuid.NewString() },
	} {
		t.Run(label, func(t *testing.T) {
			x := b
			mutate(&x)
			borrow(o, x, 0, nil)
		})
	}
	for _, x := range []WebSessionBinding{
		func() WebSessionBinding { x := b; x.Host = "another.example"; return x }(),
		func() WebSessionBinding { x := b; x.ConfigurationVersion++; return x }(),
		func() WebSessionBinding { x := b; x.IgnoreCertificateErrors = true; return x }(),
	} {
		borrow(o, x, 1, nil)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, fixture) {
		t.Fatalf("archive visible in the database: %v", err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	borrow(reopened, b, 1, fixture)
	changed := b
	changed.Host = "new.example"
	if _, err := reopened.ForgetWebSessionState(ctx, changed, 0); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("stale erase succeeded: %v", err)
	}
	if rev, err := reopened.ForgetWebSessionState(ctx, changed, 1); err != nil || rev != 2 {
		t.Fatalf("old route erase: %d %v", rev, err)
	}
	borrow(reopened, b, 2, nil)
}

func TestWebSessionStateRejectsInvalidBindingsAndCorruptRecords(t *testing.T) {
	o, _, opts, _ := owner(t)
	ctx := context.Background()
	b := WebSessionBinding{WorkspaceID: opts.Identity.WorkspaceID, FileID: opts.Identity.FileID,
		AccountID: uuid.NewString(), NodeID: uuid.NewString(), Protocol: "https", Host: "test.example", Port: 443}
	valid, err := b.Fingerprint()
	if err != nil || valid == [32]byte{} {
		t.Fatal(err)
	}
	bad := b
	bad.TunnelRevision = 1
	if _, err := o.SaveWebSessionState(ctx, bad, 0, []byte("fixture")); err != vault.ErrFormat {
		t.Fatalf("direct state accepted route data: %v", err)
	}
	bad = b
	bad.Protocol, bad.IgnoreCertificateErrors = "http", true
	if _, err := bad.Fingerprint(); err != vault.ErrFormat {
		t.Fatal("HTTP archive accepted certificate policy")
	}
	bad.AccountID = "invalid"
	if _, err := bad.Fingerprint(); err != vault.ErrFormat {
		t.Fatal("archive accepted invalid account")
	}
	if _, err := o.SaveWebSessionState(ctx, b, 0, make([]byte, vault.MaxWebSessionArchiveBytes+1)); err != vault.ErrFormat {
		t.Fatal("archive accepted invalid size")
	}
	scope, err := b.scope()
	if err != nil {
		t.Fatal(err)
	}
	use := func(uint64, []byte) error { t.Fatal("invalid archive released"); return nil }
	for _, invalid := range []WebSessionBinding{bad, {}} {
		if err := o.WithWebSessionState(ctx, invalid, use); err != vault.ErrFormat {
			t.Fatalf("invalid read coordinates: %v", err)
		}
		if _, err := o.SaveWebSessionState(ctx, invalid, 0, []byte{1}); err != vault.ErrFormat {
			t.Fatalf("invalid write coordinates: %v", err)
		}
		if _, err := o.ForgetWebSessionState(ctx, invalid, 0); err != vault.ErrFormat {
			t.Fatalf("invalid erase coordinates: %v", err)
		}
	}
	bad = b
	bad.TunnelID, bad.TunnelRevision, bad.ConfigurationVersion = uuid.NewString(), 1, 2
	if err := o.WithWebSessionState(ctx, bad, use); err != vault.ErrFormat {
		t.Fatalf("invalid route revision: %v", err)
	}
	for row, raw := range [][]byte{[]byte("short"), make([]byte, webSessionHeaderBytes+1)} {
		if _, err := o.PutLocalState(ctx, vaultstore.LocalStateWebSession, scope, raw, uint64(row)); err != nil {
			t.Fatal(err)
		}
		if err := o.WithWebSessionState(ctx, b, use); err != vault.ErrAuthentication {
			t.Fatalf("invalid store state was accepted: %v", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.WithWebSessionState(canceled, b, use); err != context.Canceled {
		t.Fatalf("cancelled archive request: %v", err)
	}
}
