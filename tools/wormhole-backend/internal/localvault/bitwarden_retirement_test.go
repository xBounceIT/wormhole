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

func TestBitwardenRetirementAtomicEncryptedLifecycle(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	legacy := installationFixture()
	a, b := installationFixture(), installationFixture()
	a.Layout, b.Layout = 1, 1
	for i, value := range []BitwardenInstallation{legacy, a, b} {
		if _, err := o.SaveBitwardenInstallation(ctx, value, uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, revision, err := o.readBitwardenInstallationRecord(ctx, 3)
	if err != nil || revision != 3 || r.Version != 3 || r.Installation != b || len(r.Retired) != 1 || r.Retired[0] != a.InstallationID {
		t.Fatal(r, revision, err)
	}
	if _, err = o.SaveBitwardenInstallation(ctx, a, 3); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("reactivated retired package", err)
	}
	if _, err = o.SaveBitwardenInstallation(ctx, installationFixture(), 2); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("stale retirement", err)
	}
	// Disabling the same installed ID leaves it owned, rather than retiring it.
	b.Enabled = false
	if _, err = o.SaveBitwardenInstallation(ctx, b, 3); err != nil {
		t.Fatal(err)
	}
	r, _, err = o.readBitwardenInstallationRecord(ctx, 4)
	if err != nil || len(r.Retired) != 1 {
		t.Fatal(r, err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(a.InstallationID)) || bytes.Contains(disk, []byte(b.InstallationID)) {
		t.Fatal("plaintext package journal")
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, revision, err = reopened.readBitwardenInstallationRecord(ctx, 4)
	if err != nil || revision != 4 || r.Installation != b || len(r.Retired) != 1 || r.Retired[0] != a.InstallationID {
		t.Fatal(r, revision, err)
	}
	// Clearing the installation retires its scoped directory in the same commit.
	if _, err = reopened.SaveBitwardenInstallation(ctx, BitwardenInstallation{}, 4); err != nil {
		t.Fatal(err)
	}
	r, _, err = reopened.readBitwardenInstallationRecord(ctx, 5)
	if err != nil || r.Version != 3 || r.Installation != (BitwardenInstallation{}) || len(r.Retired) != 2 || r.Retired[1] != b.InstallationID {
		t.Fatal(r, err)
	}
}

func TestBitwardenRetirementRejectsMalformedAuthenticatedJournals(t *testing.T) {
	valid := installationFixture()
	valid.Layout = 1
	id := uuid.NewString()
	cases := []bitwardenInstallationRecord{
		{Version: 3, Installation: valid},
		{Version: 2, Installation: valid, Retired: []string{id}},
		{Version: 3, Installation: valid, Retired: []string{id, id}},
		{Version: 3, Installation: valid, Retired: []string{valid.InstallationID}},
		{Version: 3, Installation: valid, Retired: []string{"../foreign"}},
		{Version: 3, Installation: valid, Retired: []string{uuid.Nil.String()}},
		{Version: 3, Installation: valid, Retired: []string{strings.ToUpper("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")}},
		{Version: 3, Installation: BitwardenInstallation{Enabled: true}, Retired: []string{id}},
	}
	oversized := bitwardenInstallationRecord{Version: 3, Installation: valid}
	for range bitwardenMaxRetiredInstallations + 1 {
		oversized.Retired = append(oversized.Retired, uuid.NewString())
	}
	cases = append(cases, oversized)
	for i, record := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			o, _, opts, _ := owner(t)
			ctx := context.Background()
			raw, _ := json.Marshal(record)
			if _, err := o.PutLocalState(ctx, bitwardenInstallationKind, opts.Identity.WorkspaceID, raw, 0); err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.ReadBitwardenInstallation(ctx, 0); !errors.Is(err, vault.ErrFormat) {
				t.Fatal("bad journal admitted", err)
			}
			if _, err := o.SaveBitwardenInstallation(ctx, valid, 1); !errors.Is(err, vault.ErrFormat) {
				t.Fatal("bad journal overwritten", err)
			}
		})
	}
}

func TestBitwardenRetirementCapacityDoesNotLoseActiveOrRetiredIDs(t *testing.T) {
	ctx := context.Background()
	o, _, opts, _ := owner(t)
	value := installationFixture()
	value.Layout = 1
	r := bitwardenInstallationRecord{Version: 3, Installation: value}
	for range bitwardenMaxRetiredInstallations {
		r.Retired = append(r.Retired, uuid.NewString())
	}
	raw, _ := json.Marshal(r)
	if len(raw) > 4096 {
		t.Fatal("record bound", len(raw))
	}
	if _, err := o.PutLocalState(ctx, bitwardenInstallationKind, opts.Identity.WorkspaceID, raw, 0); err != nil {
		t.Fatal(err)
	}
	replacement := installationFixture()
	replacement.Layout = 1
	if _, err := o.SaveBitwardenInstallation(ctx, replacement, 1); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("discarded full journal", err)
	}
	actual, revision, err := o.readBitwardenInstallationRecord(ctx, 1)
	encoded, _ := json.Marshal(actual)
	if err != nil || revision != 1 || !bytes.Equal(encoded, raw) {
		t.Fatal(actual, revision, err)
	}
	// Keeping the current package (including disabling it) needs no journal slot.
	value.Enabled = false
	if _, err = o.SaveBitwardenInstallation(ctx, value, 1); err != nil {
		t.Fatal(err)
	}
}
