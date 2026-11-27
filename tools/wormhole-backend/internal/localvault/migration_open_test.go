package localvault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestMigrationRequiresNativeImportOwner(t *testing.T) {
	options, key := options(t)
	options.Slots.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationCopying}
	raw, err := vault.EncodeSlotFile(key, options.Slots)
	if err != nil {
		t.Fatal(err)
	}
	options.Slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "partial.db")
	input := bytes.Clone(key)
	if _, err := Open(context.Background(), path, options, input); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("rejected key retained")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("normal unlock touched SQLite")
	}
	options.AllowImport = true
	owner, err := Open(context.Background(), path, options, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	options.Create, options.AllowImport = false, false
	if _, err := Open(context.Background(), path, options, bytes.Clone(key)); err != vault.ErrPolicy {
		t.Fatal("partial DB opened", err)
	}
}
