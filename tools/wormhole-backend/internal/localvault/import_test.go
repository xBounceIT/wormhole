package localvault

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestImportNodeTunnelPreservesTimesAndReferences(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	opts.Create = false
	times := ImportTimes{"2020-01-02T03:04:05Z", "2023-02-03T04:05:06.1234567Z"}
	credential, err := o.ImportCredential(ctx, draft(), times.CreatedAt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := o.ImportTunnel(ctx, tunnelDraft(), []byte("encrypted-native-config"), times)
	if err != nil {
		t.Fatal(err)
	}
	parent := nodeDraft()
	parent.Kind = 0
	parent.Protocol = nil
	parent.Host = nil
	p, err := o.ImportNode(ctx, parent, nil, times)
	if err != nil {
		t.Fatal(err)
	}
	n := nodeDraft()
	n.ParentID = &p.ID
	n.CredentialID = &credential.ID
	n.CredentialMode = nodePtr(2)
	n.TunnelConfigID = &tunnel.ID
	n.TunnelEnabled = nodePtr(true)
	node, err := o.ImportNode(ctx, n, []SecretChange{{Field: "notes", Value: []byte("imported note")}}, times)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.CreatedAt != times.CreatedAt || tunnel.UpdatedAt != times.UpdatedAt || node.CreatedAt != times.CreatedAt || node.UpdatedAt != times.UpdatedAt {
		t.Fatal("source times overwritten")
	}
	if _, err := o.ImportNode(ctx, n, nil, times); err != vaultstore.ErrConflict {
		t.Fatal("node import overwrote existing record", err)
	}
	if _, err := o.ImportTunnel(ctx, tunnel.TunnelMetadata, []byte("overwrite"), times); err != vaultstore.ErrConflict {
		t.Fatal("tunnel import overwrote existing record", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	got, err := o.ReadNode(ctx, n.ID, 1)
	if err != nil || got.CreatedAt != times.CreatedAt || got.UpdatedAt != times.UpdatedAt {
		t.Fatal("node reopen lost times", err)
	}
	gotTunnel, err := o.ReadTunnel(ctx, tunnel.ID, 1)
	if err != nil || gotTunnel.CreatedAt != times.CreatedAt || gotTunnel.UpdatedAt != times.UpdatedAt {
		t.Fatal("tunnel reopen lost times", err)
	}
	if err := o.WithNodeField(ctx, n.ID, "notes", 1, func(value []byte) error {
		if string(value) != "imported note" {
			t.Fatal("note lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.WithTunnelConfiguration(ctx, tunnel.ID, 1, func(value []byte) error {
		if string(value) != "encrypted-native-config" {
			t.Fatal("configuration lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	n.Name = "edited"
	got, err = o.PutNode(ctx, n, nil, 1)
	if err != nil || got.CreatedAt != times.CreatedAt {
		t.Fatal("edit changed node creation time", err)
	}
	updated, err := time.Parse(time.RFC3339Nano, got.UpdatedAt)
	if err != nil || updated.Before(start) {
		t.Fatal("edit retained old update time")
	}
	tm := tunnel.TunnelMetadata
	tm.Name = "edited tunnel"
	gotTunnel, err = o.PutTunnel(ctx, tm, nil, 1)
	if err != nil || gotTunnel.CreatedAt != times.CreatedAt {
		t.Fatal("edit changed tunnel creation time", err)
	}
	updated, err = time.Parse(time.RFC3339Nano, gotTunnel.UpdatedAt)
	if err != nil || updated.Before(start) {
		t.Fatal("edit retained old update time")
	}
}

func TestImportNodeTunnelRejectsInvalidState(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	valid := ImportTimes{"2020-01-02T03:04:05Z", "2023-02-03T04:05:06Z"}
	for _, times := range []ImportTimes{{}, {"bad", valid.UpdatedAt}, {valid.CreatedAt, "2023-02-03T04:05:06.000Z"}, {valid.CreatedAt, "2023-02-03T05:05:06+01:00"}} {
		n := nodeDraft()
		if _, err := o.ImportNode(ctx, n, nil, times); err != vault.ErrFormat {
			t.Fatal("invalid node provenance accepted", err)
		}
		if _, err := o.ReadNode(ctx, n.ID, 0); err != vaultstore.ErrMissing {
			t.Fatal("invalid node import partially wrote", err)
		}
		tm := tunnelDraft()
		if _, err := o.ImportTunnel(ctx, tm, []byte("config"), times); err != vault.ErrFormat {
			t.Fatal("invalid tunnel provenance accepted", err)
		}
		if _, err := o.ReadTunnel(ctx, tm.ID, 0); err != vaultstore.ErrMissing {
			t.Fatal("invalid tunnel import partially wrote", err)
		}
	}
	if _, err := o.ImportNode(ctx, nodeDraft(), []SecretChange{{Field: vaultstore.NodeResolverMigrationField, Value: []byte("bypass")}}, valid); err != vault.ErrFormat {
		t.Fatal("reserved field imported through editor path", err)
	}
	n := nodeDraft()
	missing := draft().ID
	n.CredentialID = &missing
	n.CredentialMode = nodePtr(2)
	if _, err := o.ImportNode(ctx, n, nil, valid); err == nil {
		t.Fatal("missing reference accepted")
	}
	if _, err := o.ImportTunnel(ctx, tunnelDraft(), nil, valid); err != vault.ErrFormat {
		t.Fatal("absent configuration accepted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ImportNode(cancelled, nodeDraft(), nil, valid); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled node import continued", err)
	}
	if _, err := o.ImportTunnel(cancelled, tunnelDraft(), []byte("config"), valid); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled tunnel import continued", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportNode(ctx, nodeDraft(), nil, valid); err != vaultstore.ErrClosed {
		t.Fatal("closed node owner imported", err)
	}
	if _, err := o.ImportTunnel(ctx, tunnelDraft(), []byte("config"), valid); err != vaultstore.ErrClosed {
		t.Fatal("closed tunnel owner imported", err)
	}
}
