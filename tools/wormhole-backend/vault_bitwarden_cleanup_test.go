package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestVaultBitwardenCleanupWirePreservesCurrentAndUnjournaledPackages(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	_, source := installerRoots(t)
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var retired string
	for i := range 2 {
		q := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": strconv.Itoa(i)})
		if _, err = h.Handle(ctx, "bitwarden-install-folder", q); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			value, _, err := h.owner.ReadBitwardenInstallation(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			retired = value.InstallationID
		}
	}
	base, err := openVaultBitwardenInstallRoot(h.databasePath, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	unjournaled := uuid.NewString()
	if err = base.Mkdir(unjournaled, 0700); err != nil {
		t.Fatal(err)
	}
	legacyID := uuid.NewString()
	legacyPath := filepath.Join(filepath.Dir(h.databasePath), vaultBitwardenInstallDirectory, legacyID)
	if err = os.Mkdir(legacyPath, 0700); err != nil {
		t.Fatal(err)
	}
	q := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "expectedRevision": "2"})
	// A destination-root failure leaves the authenticated journal available for retry.
	originalDatabase := h.databasePath
	h.databasePath = filepath.Join(t.TempDir(), "missing-parent", "vault.db")
	if _, err = h.Handle(ctx, "bitwarden-cleanup", q); err == nil {
		t.Fatal("unavailable root acknowledged")
	}
	h.databasePath = originalDatabase
	raw, err := h.Handle(ctx, "bitwarden-cleanup", q)
	if err != nil || string(raw) != `{"workspaceId":"`+workspace+`","revision":"3"}` {
		t.Fatal(string(raw), err)
	}
	if _, err = base.Stat(retired); !os.IsNotExist(err) {
		t.Fatal("retired retained", err)
	}
	if _, err = base.Stat(unjournaled); err != nil {
		t.Fatal("unknown package deleted", err)
	}
	if _, err = os.Stat(legacyPath); err != nil {
		t.Fatal("shared package deleted", err)
	}
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "3"})); err != nil {
		t.Fatal("active package damaged", err)
	}
	if _, err = h.Handle(ctx, "bitwarden-cleanup", q); err == nil {
		t.Fatal("stale cleanup")
	}
	for _, bad := range []string{`{}`, `null`, strings.Repeat("x", 1025), `{"workspaceId":"` + workspace + `","expectedRevision":"01"}`, `{"workspaceId":"` + uuid.NewString() + `","expectedRevision":"3"}`, `{"workspaceId":"` + workspace + `","expectedRevision":"3","path":"outside"}`} {
		if _, err = h.Handle(ctx, "bitwarden-cleanup", []byte(bad)); err == nil {
			t.Fatal("invalid request")
		}
	}
	if _, err = (&vaultFoundationHandler{}).Handle(ctx, "bitwarden-cleanup", q); err == nil {
		t.Fatal("locked cleanup")
	}
	if !vaultFreshAction("bitwarden-cleanup") || !h.ExitOnCancel("bitwarden-cleanup") {
		t.Fatal("missing action gates")
	}
}

func TestVaultBitwardenRetiredRemovalIsConfinedAndRetryable(t *testing.T) {
	ctx := context.Background()
	base, _ := installerRoots(t)
	id := uuid.NewString()
	if err := base.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile(id+"/package", []byte("retired"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := removeVaultBitwardenRetiredPackage(ctx, base, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"../outside", uuid.Nil.String(), ""} {
		if removeVaultBitwardenRetiredPackage(ctx, base, bad) == nil {
			t.Fatal("bad id")
		}
	}
	if removeVaultBitwardenRetiredPackage(ctx, nil, id) == nil {
		t.Fatal("missing root")
	}
	if err := base.WriteFile(id, []byte("unexpected file"), 0600); err != nil {
		t.Fatal(err)
	}
	if removeVaultBitwardenRetiredPackage(ctx, base, id) == nil {
		t.Fatal("unexpected file deleted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if removeVaultBitwardenRetiredPackage(canceled, base, id) == nil {
		t.Fatal("canceled remove")
	}
	base.Close()
	if removeVaultBitwardenRetiredPackage(ctx, base, id) == nil {
		t.Fatal("closed root")
	}
}
