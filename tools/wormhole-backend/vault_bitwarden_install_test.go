package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func installerRoots(t *testing.T) (*os.Root, *os.Root) {
	t.Helper()
	base, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	parent, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Close() })
	id := preparedVaultExtension(t, parent, vaultExtensionTestManifest)
	source, err := parent.OpenRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return base, source
}
func TestVaultBitwardenFolderInstallCommitAndCleanup(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	base, source := installerRoots(t)
	revision, err := installVaultBitwardenFolder(ctx, h.owner, base, source, 0)
	if err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	first, _, err := h.owner.ReadBitwardenInstallation(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyVaultBitwardenInstallation(ctx, base, first); err != nil {
		t.Fatal(err)
	}
	if first.InstallationID == "" {
		t.Fatal("no installation")
	}
	if err = source.WriteFile("background.js", []byte("updated package"), 0600); err != nil {
		t.Fatal(err)
	}
	revision, err = installVaultBitwardenFolder(ctx, h.owner, base, source, 1)
	if err != nil || revision != 2 {
		t.Fatal(revision, err)
	}
	second, _, err := h.owner.ReadBitwardenInstallation(ctx, 2)
	if err != nil || first.InstallationID == second.InstallationID || first.ContentSHA256 == second.ContentSHA256 {
		t.Fatal(second, err)
	}
	if err = verifyVaultBitwardenInstallation(ctx, base, first); err != nil {
		t.Fatal("old package modified", err)
	}
	if err = verifyVaultBitwardenInstallation(ctx, base, second); err != nil {
		t.Fatal(err)
	}
	q, _ := browserTransferBeginInput(t, h, uuid.NewString(), "hydrate", "0")
	if _, err = h.Handle(ctx, "bitwarden-transfer-begin", browserTransferJSON(t, q)); err != nil {
		t.Fatal(err)
	}
	if _, err = installVaultBitwardenFolder(ctx, h.owner, base, source, 2); err == nil {
		t.Fatal("active stage replaced")
	}
	entries, err := fs.ReadDir(base.FS(), ".")
	if err != nil || len(entries) != 2 {
		t.Fatal("failed stage not cleaned", len(entries), err)
	}
	current, rev, err := h.owner.ReadBitwardenInstallation(ctx, 2)
	if err != nil || current != second || rev != 2 {
		t.Fatal("failed install changed record", err)
	}
	if _, err = installVaultBitwardenFolder(ctx, h.owner, base, source, 1); err == nil {
		t.Fatal("stale install")
	}
}
func TestVaultBitwardenFolderInstallInvalidInputs(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	base, source := installerRoots(t)
	if _, err := installVaultBitwardenFolder(ctx, nil, base, source, 0); err == nil {
		t.Fatal("missing owner")
	}
	if _, err := installVaultBitwardenFolder(ctx, h.owner, nil, source, 0); err == nil {
		t.Fatal("missing base")
	}
	if _, err := installVaultBitwardenFolder(ctx, h.owner, base, nil, 0); err == nil {
		t.Fatal("missing source")
	}
	if _, err := installVaultBitwardenFolder(ctx, h.owner, source, source, 0); err == nil {
		t.Fatal("self copy")
	}
	if err := source.Mkdir("nested", 0700); err != nil {
		t.Fatal(err)
	}
	nested, err := source.OpenRoot("nested")
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()
	if _, err := installVaultBitwardenFolder(ctx, h.owner, nested, source, 0); err == nil {
		t.Fatal("nested destination")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := installVaultBitwardenFolder(canceled, h.owner, base, source, 0); err == nil {
		t.Fatal("canceled install")
	}
	if err := source.WriteFile("manifest.json", []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installVaultBitwardenFolder(ctx, h.owner, base, source, 0); err == nil {
		t.Fatal("invalid package")
	}
	entries, err := fs.ReadDir(base.FS(), ".")
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid package staged", err)
	}
}
func TestVaultBitwardenCopyTreeFailureBoundaries(t *testing.T) {
	makeRoot := func() *os.Root {
		r, e := os.OpenRoot(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { r.Close() })
		return r
	}
	if err := copyVaultExtensionTree(context.Background(), nil, makeRoot()); err == nil {
		t.Fatal("nil source")
	}
	for _, failure := range []string{"open", "read", "stat", "close"} {
		source := extensionFaultFS{FS: extensionTree(), path: "background.js", failure: failure}
		if err := copyVaultExtensionTree(context.Background(), source, makeRoot()); err == nil {
			t.Fatal(failure)
		}
	}
	for _, source := range []fstest.MapFS{
		{"link": {Mode: fs.ModeSymlink}},
		{strings.Repeat("x", 1025): {}},
		{strings.Repeat("d/", 34) + "x": {}},
	} {
		if err := copyVaultExtensionTree(context.Background(), source, makeRoot()); err == nil {
			t.Fatal("unsafe source")
		}
	}
	destination := makeRoot()
	if err := copyVaultExtensionTree(context.Background(), extensionTree(), destination); err != nil {
		t.Fatal(err)
	}
	if err := copyVaultExtensionTree(context.Background(), extensionTree(), destination); err == nil {
		t.Fatal("overwrote existing package")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyVaultExtensionTree(canceled, extensionTree(), makeRoot()); err == nil {
		t.Fatal("canceled copy")
	}
}
func TestVaultBitwardenActivationRequiresSourceDigest(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	base, _ := installerRoots(t)
	id := preparedVaultExtension(t, base, vaultExtensionTestManifest)
	for _, digest := range []string{"", strings.Repeat("0", 64)} {
		if _, err := activateVaultBitwardenInstallation(ctx, h.owner, base, id, 0, digest); err == nil {
			t.Fatal("unchecked source accepted")
		}
	}
	current, rev, err := h.owner.ReadBitwardenInstallation(ctx, 0)
	if err != nil || rev != 0 || current.Enabled {
		t.Fatal("mismatch activated", err)
	}
}

func TestVaultBitwardenFolderInstallWire(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	_, source := installerRoots(t)
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "0"}
	raw, err := h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, q))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"workspaceId":"`+workspace+`","revision":"1"}` {
		t.Fatal(string(raw))
	}
	if _, err = h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, q)); err == nil {
		t.Fatal("replayed mutation")
	}
	plan, err := h.Handle(ctx, "bitwarden-installation-plan", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "1"}))
	if err != nil || !json.Valid(plan) || !bytes.Contains(plan, []byte(`"popup":"popup.html"`)) {
		t.Fatal(string(plan), err)
	}
	for _, bad := range []map[string]any{
		{"workspaceId": uuid.NewString(), "sourceDirectory": source.Name(), "expectedRevision": "1"},
		{"workspaceId": workspace, "sourceDirectory": "../relative", "expectedRevision": "1"},
		{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "01"},
		{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "1", "digest": "untrusted"},
	} {
		if _, err = h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, bad)); err == nil {
			t.Fatal("invalid mutation")
		}
	}
	if !vaultFreshAction("bitwarden-install-folder") || !h.ExitOnCancel("bitwarden-install-folder") {
		t.Fatal("missing authentication/cancellation gate")
	}
	if _, err = (&vaultFoundationHandler{}).Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, q)); err == nil {
		t.Fatal("locked mutation")
	}
}
func TestVaultBitwardenFolderInstallRequiresFreshStandardAuthentication(t *testing.T) {
	for _, kind := range []string{"folder", "zip", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			archive := kind == "zip"
			ctx := context.Background()
			doc, key := localSlotFixture(t)
			defer vault.Wipe(key)
			password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("fixture-password"), nil, vault.KDFV1)
			if err != nil {
				t.Fatal(err)
			}
			doc.Slots = append(doc.Slots, password)
			doc.Initializing = true
			database := filepath.Join(t.TempDir(), "vault.db")
			owner, err := initializeVaultFiles(ctx, database, doc, key)
			if err != nil {
				t.Fatal(err)
			}
			h := &vaultFoundationHandler{databasePath: database, owner: owner}
			defer h.Close()
			policy, err := owner.ReadLocalPolicy(ctx)
			if err != nil {
				t.Fatal(err)
			}
			previous := policy.Policy.Sequence
			policy.Policy.Sequence++
			policy.Policy.Profile = vault.Standard
			if _, err = owner.PutLocalPolicy(ctx, policy.Policy, vault.Default, previous); err != nil {
				t.Fatal(err)
			}
			_, source := installerRoots(t)
			operation, field, path := "bitwarden-install-folder", "sourceDirectory", source.Name()
			if archive {
				operation, field = "bitwarden-install-zip", "sourceFile"
				path = filepath.Join(t.TempDir(), "package.zip")
				if err = os.WriteFile(path, vaultZipBytes(t, vaultZipPackage(), 0), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fields := map[string]any{"workspaceId": doc.VaultID, field: path, "expectedRevision": "0"}
			if kind == "cleanup" {
				operation = "bitwarden-cleanup"
				delete(fields, field)
			}
			action := browserTransferJSON(t, fields)
			if _, err = h.Handle(ctx, operation, action); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("unlock authorized install", err)
			}
			if _, err = h.Handle(ctx, "fresh-action", freshActionInput(t, operation, action, bytes.Repeat([]byte{8}, 32))); !errors.Is(err, vault.ErrAuthentication) {
				t.Fatal("wrong factor", err)
			}
			if _, err = h.Handle(ctx, "fresh-action", freshActionInput(t, operation, action, bytes.Repeat([]byte{0x32}, 32))); err != nil {
				t.Fatal(err)
			}
			if _, err = h.Handle(ctx, operation, action); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("authentication persisted", err)
			}
		})
	}
}

type uncertainInstallationOwner struct {
	*localvault.Owner
	wrote, unreadable, noCommit bool
}

func (o *uncertainInstallationOwner) SaveBitwardenInstallation(ctx context.Context, v localvault.BitwardenInstallation, revision uint64) (uint64, error) {
	if !o.noCommit {
		if _, err := o.Owner.SaveBitwardenInstallation(ctx, v, revision); err != nil {
			return 0, err
		}
	}
	o.wrote = true
	return 0, errors.New("synthetic uncertain commit")
}
func (o *uncertainInstallationOwner) ReadBitwardenInstallation(ctx context.Context, minimum uint64) (localvault.BitwardenInstallation, uint64, error) {
	if o.wrote && o.unreadable {
		return localvault.BitwardenInstallation{}, 0, errors.New("synthetic unavailable state")
	}
	return o.Owner.ReadBitwardenInstallation(ctx, minimum)
}
func TestVaultBitwardenFolderInstallRetainsUncertainCommit(t *testing.T) {
	for _, noCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "unconfirmed"}[noCommit], func(t *testing.T) {
			ctx := context.Background()
			h := vaultCredentialFixture(t)
			base, source := installerRoots(t)
			owner := &uncertainInstallationOwner{Owner: h.owner, noCommit: noCommit, unreadable: noCommit}
			if _, err := installVaultBitwardenFolder(ctx, owner, base, source, 0); !errors.Is(err, errVaultExtensionCommit) {
				t.Fatal(err)
			}
			entries, err := fs.ReadDir(base.FS(), ".")
			if err != nil || len(entries) != 1 {
				t.Fatal("possibly active files removed", err)
			}
			value, revision, err := h.owner.ReadBitwardenInstallation(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			if noCommit {
				if revision != 0 || value.Enabled {
					t.Fatal("fixture unexpectedly committed")
				}
			} else {
				if revision != 1 || value.InstallationID != entries[0].Name() {
					t.Fatal("committed identity lost")
				}
				if err = verifyVaultBitwardenInstallation(ctx, base, value); err != nil {
					t.Fatal("committed package broken", err)
				}
			}
		})
	}
}

func TestVaultExtensionDirectoryPublicationDoesNotReplace(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "package"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := publishVaultExtensionDirectory(source, target); err == nil {
		t.Fatal("existing empty directory replaced")
	}
	if raw, err := os.ReadFile(filepath.Join(source, "package")); err != nil || string(raw) != "new" {
		t.Fatal("failed publication changed source", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := publishVaultExtensionDirectory(source, target); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(target, "package")); err != nil || string(raw) != "new" {
		t.Fatal("publication lost contents", err)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging remained", err)
	}
}
