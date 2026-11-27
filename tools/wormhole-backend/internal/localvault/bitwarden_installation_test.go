package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func installationFixture() BitwardenInstallation {
	return BitwardenInstallation{Enabled: true, InstallationID: uuid.NewString(), ExtensionID: strings.Repeat("a", 32), ContentSHA256: strings.Repeat("b", 64)}
}

func TestBitwardenInstallationEncryptedLifecycle(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	value, revision, err := o.ReadBitwardenInstallation(ctx, 0)
	if err != nil || revision != 0 || value != (BitwardenInstallation{}) {
		t.Fatal(value, revision, err)
	}
	want := installationFixture()
	revision, err = o.SaveBitwardenInstallation(ctx, want, 0)
	if err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	if _, err = o.SaveBitwardenInstallation(ctx, want, 0); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("stale write", err)
	}
	if _, _, err = o.ReadBitwardenInstallation(ctx, 2); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("future minimum", err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(want.ContentSHA256)) || bytes.Contains(disk, []byte(want.InstallationID)) {
		t.Fatal("installation payload persisted in plaintext")
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	value, revision, err = reopened.ReadBitwardenInstallation(ctx, 1)
	if err != nil || revision != 1 || value != want {
		t.Fatal(value, revision, err)
	}
	want.Enabled = false
	if revision, err = reopened.SaveBitwardenInstallation(ctx, want, 1); err != nil || revision != 2 {
		t.Fatal(revision, err)
	}
	value, revision, err = reopened.ReadBitwardenInstallation(ctx, 2)
	if err != nil || revision != 2 || value != want {
		t.Fatal(value, revision, err)
	}
}

func TestBitwardenInstallationValidationAndScope(t *testing.T) {
	valid := installationFixture()
	invalid := []BitwardenInstallation{{Enabled: true}, {ExtensionID: valid.ExtensionID}, valid, valid, valid, valid, valid, valid}
	invalid[2].InstallationID = "../foreign"
	invalid[3].InstallationID = uuid.Nil.String()
	invalid[4].ExtensionID = strings.Repeat("q", 32)
	invalid[5].ExtensionID = "short"
	invalid[6].ContentSHA256 = strings.Repeat("B", 64)
	invalid[7].ContentSHA256 = strings.Repeat("g", 64)
	o, _, _, _ := owner(t)
	ctx := context.Background()
	for _, v := range invalid {
		if _, err := o.SaveBitwardenInstallation(ctx, v, 0); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(v, err)
		}
	}
	if _, err := o.PutLocalState(ctx, bitwardenInstallationKind, uuid.NewString(), nil, 0); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("foreign workspace", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.SaveBitwardenInstallation(canceled, valid, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.ReadBitwardenInstallation(ctx, 0); err == nil {
		t.Fatal("closed read")
	}
	if _, err := o.SaveBitwardenInstallation(ctx, valid, 0); err == nil {
		t.Fatal("closed write")
	}
}

func TestBitwardenInstallationRejectsMalformedAuthenticatedRecords(t *testing.T) {
	canonical, _ := json.Marshal(bitwardenInstallationRecord{Version: 1, Installation: installationFixture()})
	for _, raw := range [][]byte{
		[]byte("null"), []byte("{"), []byte(`{"version":2,"installation":{}}`),
		[]byte(`{"version":1,"installation":{"enabled":true}}`),
		bytes.Replace(canonical, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		append(append([]byte{}, canonical...), ' '), bytes.Repeat([]byte("x"), 4097),
	} {
		t.Run(string(raw[:min(len(raw), 30)]), func(t *testing.T) {
			o, _, opts, _ := owner(t)
			ctx := context.Background()
			if _, err := o.PutLocalState(ctx, bitwardenInstallationKind, opts.Identity.WorkspaceID, raw, 0); err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrFormat) {
				t.Fatal("malformed accepted", err)
			}
			if _, err := o.SaveBitwardenInstallation(ctx, installationFixture(), 1); !errors.Is(err, vault.ErrFormat) {
				t.Fatal("silent repair", err)
			}
		})
	}
}

func TestBitwardenInstallationActiveProfilesAndTampering(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	want := installationFixture()
	if _, err := o.SaveBitwardenInstallation(ctx, want, 0); err != nil {
		t.Fatal(err)
	}
	// An admitted transfer can precede its first committed browser profile.
	o.bitwardenTransfers = map[string]*bitwardenTransferStage{"pending": {}}
	_, blocked := o.SaveBitwardenInstallation(ctx, want, 1)
	o.bitwardenTransfers = nil
	if !errors.Is(blocked, vault.ErrPolicy) {
		t.Fatal("pending transfer replacement", blocked)
	}
	id := uuid.NewString()
	browserRead(t, o, id)
	if _, err := o.SaveBitwardenInstallation(ctx, want, 1); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("active replacement", err)
	}
	if err := o.CloseBitwardenBrowserProfile(id); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SaveBitwardenInstallation(ctx, want, 1); err != nil {
		t.Fatal(err)
	}
	original := o.store.(*vaultstore.SQLite)
	defer func() { o.store = original }()
	o.store = installationStoreProbe{SQLite: original, change: func(v vaultstore.LocalState) (vaultstore.LocalState, error) { v.Seal[0] ^= 1; return v, nil }}
	if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("unsealed record", err)
	}
	o.store = installationStoreProbe{SQLite: original, change: func(v vaultstore.LocalState) (vaultstore.LocalState, error) {
		return vaultstore.LocalState{}, vaultstore.ErrMissing
	}}
	if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("deleted observed record", err)
	}
	if _, err := o.SaveBitwardenInstallation(ctx, want, 0); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("deleted reset", err)
	}

}

func TestBitwardenInstallationTombstoneFailsClosed(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	if _, err := o.SaveBitwardenInstallation(ctx, BitwardenInstallation{}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.DeleteLocalState(ctx, bitwardenInstallationKind, opts.Identity.WorkspaceID, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("tombstone enabled", err)
	}
}

type installationStoreProbe struct {
	*vaultstore.SQLite
	change func(vaultstore.LocalState) (vaultstore.LocalState, error)
}

func (s installationStoreProbe) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	v, err := s.SQLite.ReadLocalState(ctx, kind, scope)
	if err != nil {
		return v, err
	}
	return s.change(v)
}

func TestBitwardenInstallationLayoutVersions(t *testing.T) {
	ctx := context.Background()
	for _, layout := range []int{0, 1} {
		t.Run(string(rune('0'+layout)), func(t *testing.T) {
			o, _, _, _ := owner(t)
			value := installationFixture()
			value.Layout = layout
			if _, err := o.SaveBitwardenInstallation(ctx, value, 0); err != nil {
				t.Fatal(err)
			}
			actual, revision, err := o.ReadBitwardenInstallation(ctx, 1)
			if err != nil || revision != 1 || actual != value {
				t.Fatal(actual, revision, err)
			}
			// Verify the authenticated format, not just an in-memory value.
			err = o.withLocalState(ctx, bitwardenInstallationKind, o.store.Identity().WorkspaceID, 1, func(raw []byte) error {
				var record bitwardenInstallationRecord
				if json.Unmarshal(raw, &record) != nil || record.Version != 1+layout {
					t.Fatal(string(raw))
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, layout := range []int{-1, 2} {
		o, _, _, _ := owner(t)
		value := installationFixture()
		value.Layout = layout
		if _, err := o.SaveBitwardenInstallation(ctx, value, 0); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]int{{1, 1}, {2, 0}, {3, 1}} {
		o, _, opts, _ := owner(t)
		value := installationFixture()
		value.Layout = pair[1]
		raw, _ := json.Marshal(bitwardenInstallationRecord{Version: pair[0], Installation: value})
		if _, err := o.PutLocalState(ctx, bitwardenInstallationKind, opts.Identity.WorkspaceID, raw, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(err)
		}
	}
}
