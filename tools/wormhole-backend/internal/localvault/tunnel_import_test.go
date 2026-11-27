package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestTunnelImportStageOwnershipAndLifetime(t *testing.T) {
	ctx := context.Background()
	o, path, _, _ := owner(t)
	editor, id := uuid.NewString(), uuid.NewString()
	target := TunnelImportTarget{Kind: 1}
	plain := []byte("native-import-private-key-material")
	if err := o.StageTunnelImport(ctx, editor, id, target, plain); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, make([]byte, len(plain))) {
		t.Fatal("stage retained caller bytes")
	}
	envelope := o.tunnelImports[id].Envelope
	if bytes.Contains(envelope.Ciphertext, []byte("native-import-private-key-material")) {
		t.Fatal("plaintext stage")
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("native-import-private-key-material")) {
		t.Fatal("stage persisted")
	}
	for i := 0; i < 2; i++ {
		value, err := o.ReadTunnelImport(ctx, editor, id, target)
		if err != nil || string(value) != "native-import-private-key-material" {
			t.Fatal(err)
		}
		vault.Wipe(value)
	}
	if _, err := o.ReadTunnelImport(ctx, uuid.NewString(), id, target); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.ReadTunnelImport(ctx, editor, id, TunnelImportTarget{Kind: 4}); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	o.DiscardTunnelImport(uuid.NewString(), id)
	if len(o.tunnelImports) != 1 {
		t.Fatal("foreign discard")
	}
	replacement := uuid.NewString()
	if err := o.StageTunnelImport(ctx, editor, replacement, target, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadTunnelImport(ctx, editor, id, target); err != vaultstore.ErrMissing {
		t.Fatal("old stage survived", err)
	}
	if !bytes.Equal(envelope.Ciphertext, make([]byte, len(envelope.Ciphertext))) {
		t.Fatal("replaced ciphertext not cleared")
	}
	stage := o.tunnelImports[replacement]
	stage.Expires = time.Now().Add(-time.Second)
	o.tunnelImports[replacement] = stage
	if _, err := o.ReadTunnelImport(ctx, editor, replacement, target); err != vaultstore.ErrMissing || len(o.tunnelImports) != 0 {
		t.Fatal("expired stage", err)
	}
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("last")); err != nil {
		t.Fatal(err)
	}
	envelope = o.tunnelImports[id].Envelope
	o.DiscardTunnelImport(editor, "")
	o.DiscardTunnelImport(editor, id)
	if len(o.tunnelImports) != 0 || !bytes.Equal(envelope.Ciphertext, make([]byte, len(envelope.Ciphertext))) {
		t.Fatal("discard retained ciphertext")
	}
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("close")); err != nil {
		t.Fatal(err)
	}
	envelope = o.tunnelImports[id].Envelope
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if len(o.tunnelImports) != 0 || !bytes.Equal(envelope.Ciphertext, make([]byte, len(envelope.Ciphertext))) {
		t.Fatal("close retained stage")
	}
	if _, err := o.ReadTunnelImport(ctx, editor, id, target); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("closed")); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestTunnelImportStageBoundsAndTampering(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	editor, id := uuid.NewString(), uuid.NewString()
	target := TunnelImportTarget{Kind: 1}
	for _, ids := range [][2]string{{"", id}, {editor, "bad"}, {uuid.Nil.String(), id}} {
		value := []byte("secret")
		if err := o.StageTunnelImport(ctx, ids[0], ids[1], target, value); err != vault.ErrFormat {
			t.Fatal(err)
		}
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("invalid stage retained bytes")
		}
		if _, err := o.ReadTunnelImport(ctx, ids[0], ids[1], target); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	for _, value := range [][]byte{nil, make([]byte, vault.MaxSecretBytes+1)} {
		if err := o.StageTunnelImport(ctx, editor, id, target, value); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	for _, value := range []TunnelImportTarget{{Kind: -1}, {Kind: 10}, {Kind: 1, TunnelID: uuid.NewString()}, {Kind: 1, RowVersion: 1}, {Kind: 1, TunnelID: "bad", RowVersion: 1}, {Kind: 1, TunnelID: uuid.NewString(), RowVersion: math.MaxInt64}} {
		if err := o.StageTunnelImport(ctx, editor, id, value, []byte("value")); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.StageTunnelImport(cancelled, editor, id, target, []byte("value")); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := o.ReadTunnelImport(cancelled, editor, id, target); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("new")); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	original := o.tunnelImports[id]
	for _, modify := range []func(*tunnelImportStage){func(s *tunnelImportStage) {
		s.Envelope.Ciphertext = bytes.Clone(s.Envelope.Ciphertext)
		s.Envelope.Ciphertext[0] ^= 1
	}, func(s *tunnelImportStage) { s.Expires = s.Expires.Add(time.Minute) }, func(s *tunnelImportStage) { s.Envelope.KeyID = uuid.NewString() }} {
		changed := original
		modify(&changed)
		o.tunnelImports[id] = changed
		if value, err := o.ReadTunnelImport(ctx, editor, id, target); err == nil || value != nil {
			t.Fatal("tampered stage opened")
		}
	}
	o.tunnelImports[id] = original
	for i := 1; i < maxTunnelImportStages; i++ {
		if err := o.StageTunnelImport(ctx, uuid.NewString(), uuid.NewString(), target, []byte("other")); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.StageTunnelImport(ctx, uuid.NewString(), uuid.NewString(), target, []byte("overflow")); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.StageTunnelImport(ctx, editor, uuid.NewString(), target, []byte("replacement at capacity")); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelImportStageTracksExactRecord(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	editor, id := uuid.NewString(), uuid.NewString()
	metadata := tunnelDraft()
	saved, err := o.PutTunnel(ctx, metadata, []byte("configuration"), 0)
	if err != nil {
		t.Fatal(err)
	}
	target := TunnelImportTarget{TunnelID: saved.ID, RowVersion: 1, Kind: 4}
	if err = o.StageTunnelImport(ctx, editor, id, target, []byte("new provider configuration")); err != nil {
		t.Fatal(err)
	}
	target.RowVersion = 2
	if _, err = o.ReadTunnelImport(ctx, editor, id, target); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	target.RowVersion = 1
	if _, err = o.PutTunnel(ctx, metadata, nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ReadTunnelImport(ctx, editor, id, target); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	target.RowVersion = 2
	if err = o.DeleteTunnel(ctx, saved.ID, 2); err != nil {
		t.Fatal(err)
	}
	if err = o.StageTunnelImport(ctx, editor, uuid.NewString(), target, []byte("deleted")); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	target.TunnelID = uuid.NewString()
	if err = o.StageTunnelImport(ctx, editor, uuid.NewString(), target, []byte("missing")); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestTunnelImportStageRejectsStorageSubstitution(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	m := tunnelDraft()
	saved, err := o.PutTunnel(ctx, m, []byte("settings"), 0)
	if err != nil {
		t.Fatal(err)
	}
	original := o.store
	defer func() { o.store = original }()
	for _, modify := range []func(vaultstore.Tunnel) (vaultstore.Tunnel, error){func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { v.ID = uuid.NewString(); return v, nil }, func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { v.Name = "tampered"; return v, nil }, func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { return v, vaultstore.ErrStorage }} {
		o.store = tunnelFilter{TunnelStore: original.(vaultstore.TunnelStore), read: modify}
		if err = o.StageTunnelImport(ctx, uuid.NewString(), uuid.NewString(), TunnelImportTarget{TunnelID: saved.ID, RowVersion: 1, Kind: 1}, []byte("settings")); err == nil {
			t.Fatal("invalid storage accepted")
		}
	}
}

func TestTunnelImportStageConcurrentClose(t *testing.T) {
	o, _, _, _ := owner(t)
	editor, id := uuid.NewString(), uuid.NewString()
	target := TunnelImportTarget{Kind: 1}
	ctx := context.Background()
	if err := o.StageTunnelImport(ctx, editor, id, target, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			value, err := o.ReadTunnelImport(ctx, editor, id, target)
			vault.Wipe(value)
			if err != nil && !errors.Is(err, vaultstore.ErrClosed) && !errors.Is(err, vaultstore.ErrMissing) {
				t.Error(err)
			}
		})
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
}
