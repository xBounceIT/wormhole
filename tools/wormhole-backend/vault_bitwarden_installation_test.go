package main

import (
	"context"
	"encoding/json"

	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

const vaultExtensionTestManifest = `{"name":"Fixture","manifest_version":2,"version":"1.0","key":"dGVzdA==","browser_action":{"default_popup":"popup.html"},"background":{"scripts":["background.js"]}}`

func preparedVaultExtension(t *testing.T, base *os.Root, manifest string) string {
	t.Helper()
	id := uuid.NewString()
	if err := base.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := base.OpenRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for path, body := range map[string]string{"manifest.json": manifest, "popup.html": "popup", "background.js": "background", "background.html": "background page"} {
		if err := root.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return id
}
func TestVaultBitwardenInstallationController(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	base, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	p, revision, err := planVaultBitwardenInstallation(ctx, h.owner, base, 0)
	if err != nil || revision != 0 || p != (vaultBitwardenPackage{}) {
		t.Fatal(p, revision, err)
	}
	id := preparedVaultExtension(t, base, vaultExtensionTestManifest)
	revision, err = activatePreparedVaultExtension(ctx, h.owner, base, id, 0)
	if err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	p, revision, err = planVaultBitwardenInstallation(ctx, h.owner, base, 1)
	if err != nil || revision != 1 || p.Background != "_generated_background_page.html" || p.Popup != "popup.html" || p.Version != "1.0" || p.InstallationID != id {
		t.Fatal(p, revision, err)
	}
	// Pinned Chromium GenerateId("test") vector: first16 SHA256 bytes, a-p alphabet.
	if p.ExtensionID != "jpignaibiiemhngfjkcpokkamffknabf" {
		t.Fatal("origin algorithm drift", p.ExtensionID)
	}
	if _, err := activatePreparedVaultExtension(ctx, h.owner, base, id, 1); err == nil {
		t.Fatal("active directory replaced")
	}
	other := preparedVaultExtension(t, base, vaultExtensionTestManifest)
	if _, err := activatePreparedVaultExtension(ctx, h.owner, base, other, 0); err == nil {
		t.Fatal("stale activation")
	}
	q, _ := browserTransferBeginInput(t, h, uuid.NewString(), "hydrate", "0")
	if _, err := h.Handle(ctx, "bitwarden-transfer-begin", browserTransferJSON(t, q)); err != nil {
		t.Fatal(err)
	}
	if _, err := activatePreparedVaultExtension(ctx, h.owner, base, other, 1); err == nil {
		t.Fatal("active transfer replaced")
	}
	value, rev, err := h.owner.ReadBitwardenInstallation(ctx, 1)
	if err != nil || rev != 1 || value.InstallationID != id {
		t.Fatal("failed commit changed record", err)
	}
	if err := base.WriteFile(id+"/background.js", []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := planVaultBitwardenInstallation(ctx, h.owner, base, 1); err == nil {
		t.Fatal("tampered load")
	}
}
func TestVaultBitwardenPackageValidation(t *testing.T) {
	base, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	invalid := []string{
		strings.Replace(vaultExtensionTestManifest, `"popup.html"`, `"popup\n.html"`, 1), "{}", "null", `{"manifest_version":2,"manifest_version":2}`,
		strings.Replace(vaultExtensionTestManifest, `"manifest_version":2`, `"Manifest_version":2`, 1),
		strings.Replace(vaultExtensionTestManifest, `"manifest_version":2`, `"manifest_version":3`, 1),
		strings.Replace(vaultExtensionTestManifest, `"scripts":["background.js"]`, `"persistent":false,"scripts":["background.js"]`, 1),
		strings.Replace(vaultExtensionTestManifest, `"scripts":["background.js"]`, `"scripts":["missing.js"]`, 1),
		strings.Replace(vaultExtensionTestManifest, `"scripts":["background.js"]`, `"page":"background.html","scripts":["background.js"]`, 1),
		strings.Replace(vaultExtensionTestManifest, `"scripts":["background.js"]`, `"scripts":null`, 1),
		strings.Replace(vaultExtensionTestManifest, `"popup.html"`, `"../popup.html"`, 1),
		strings.Replace(vaultExtensionTestManifest, `"dGVzdA=="`, `"%%%"`, 1),
		strings.Replace(vaultExtensionTestManifest, `"default_popup":"popup.html"`, `"default_popup":"popup.html","default_popup":"popup.html"`, 1),
	}
	for _, raw := range invalid {
		id := preparedVaultExtension(t, base, raw)
		root, err := base.OpenRoot(id)
		if err != nil {
			t.Fatal(err)
		}
		_, err = readVaultBitwardenPackage(root)
		root.Close()
		if !errors.Is(err, errVaultExtensionFiles) {
			t.Fatalf("accepted %s: %v", raw, err)
		}
	}
	raw := strings.Replace(vaultExtensionTestManifest, `"scripts":["background.js"]`, `"page":"background.html"`, 1)
	id := preparedVaultExtension(t, base, raw)
	root, err := base.OpenRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if p, err := readVaultBitwardenPackage(root); err != nil || p.Background != "background.html" {
		t.Fatal(p, err)
	}
}
func TestVaultBitwardenOriginAndInvalidOwners(t *testing.T) {
	for _, key := range []string{"?", strings.Repeat("x", 4097), "dGVzdA=", "dGVzdA==\n"} {
		if _, err := vaultExtensionOriginID(key, ""); err == nil {
			t.Fatal("invalid key")
		}
	}
	if _, err := vaultExtensionOriginID("", "relative"); err == nil {
		t.Fatal("relative path")
	}
	path := filepath.Join(t.TempDir(), "extension")
	a, err := vaultExtensionOriginID("", path)
	if err != nil || len(a) != 32 {
		t.Fatal(a, err)
	}
	b, err := vaultExtensionOriginID("", path+"2")
	if err != nil || a == b {
		t.Fatal("path not bound")
	}
	if _, err := activatePreparedVaultExtension(context.Background(), nil, nil, "", 0); err == nil {
		t.Fatal("missing owner")
	}
	if _, _, err := planVaultBitwardenInstallation(context.Background(), nil, nil, 0); err == nil {
		t.Fatal("missing owner")
	}
	if _, err := openVaultBitwardenPackage(nil, "../escape"); err == nil {
		t.Fatal("bad root")
	}

}

func TestVaultBitwardenManifestVersion(t *testing.T) {
	for _, value := range []string{"", "0", "0.0.0.0", "01", "1.2.3.4.5", "65536", "1.-2", "1. 2"} {
		if validVaultExtensionVersion(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"1", "0.0.1", "2026.10.0", "65535.65535.65535.65535"} {
		if !validVaultExtensionVersion(value) {
			t.Fatal(value)
		}
	}
}

func TestVaultBitwardenInstallationPlanWire(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "0"})
	raw, err := h.Handle(ctx, "bitwarden-installation-plan", input)
	if err != nil || !strings.Contains(string(raw), `"installation":null`) {
		t.Fatal(string(raw), err)
	}
	directory := filepath.Join(filepath.Dir(h.databasePath), vaultBitwardenInstallDirectory)
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	base, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	id := preparedVaultExtension(t, base, vaultExtensionTestManifest)
	if _, err = activatePreparedVaultExtension(ctx, h.owner, base, id, 0); err != nil {
		t.Fatal(err)
	}
	raw, err = h.Handle(ctx, "bitwarden-installation-plan", input)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		WorkspaceID  string            `json:"workspaceId"`
		Revision     string            `json:"revision"`
		Installation map[string]string `json:"installation"`
	}
	if json.Unmarshal(raw, &result) != nil || result.WorkspaceID != workspace || result.Revision != "1" || result.Installation["id"] != id || len(result.Installation) != 5 {
		t.Fatal(string(raw))
	}
	for _, forbidden := range []string{directory, "contentSha256", "seal", "key", "path"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private/native metadata", forbidden)
		}
	}
	for _, bad := range []string{`{}`, `null`, `{"workspaceId":"` + workspace + `","minimumRevision":"01"}`, `{"workspaceId":"` + uuid.NewString() + `","minimumRevision":"0"}`, `{"workspaceId":"` + workspace + `","minimumRevision":"0","path":"outside"}`, strings.Repeat("x", 1025)} {
		if _, err = h.Handle(ctx, "bitwarden-installation-plan", []byte(bad)); err == nil {
			t.Fatal("bad wire accepted")
		}
	}
	if _, err = (&vaultFoundationHandler{}).Handle(ctx, "bitwarden-installation-plan", input); err == nil {
		t.Fatal("locked plan")
	}
	if err = base.WriteFile(id+"/popup.html", []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", input); err == nil {
		t.Fatal("tampered plan")
	}
}

func activatePreparedVaultExtension(ctx context.Context, owner *localvault.Owner, base *os.Root, id string, expected uint64) (uint64, error) {
	digest := ""
	if root, err := openVaultBitwardenPackage(base, id); err == nil {
		digest, _ = hashVaultExtensionFiles(ctx, root.FS())
		root.Close()
	}
	return activateVaultBitwardenInstallation(ctx, owner, base, id, expected, digest)
}

func TestVaultBitwardenRevisionAllowsRepairWithoutUncheckedAdmission(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(strconv.FormatBool(missing), func(t *testing.T) {
			ctx := context.Background()
			h := vaultCredentialFixture(t)
			_, source := installerRoots(t)
			workspace, err := h.owner.WorkspaceID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			action := map[string]any{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "0"}
			if _, err = h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, action)); err != nil {
				t.Fatal(err)
			}
			installed, _, err := h.owner.ReadBitwardenInstallation(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			base, err := openVaultBitwardenInstallRoot(h.databasePath, installed.Layout, false)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			if !vaultCredentialID(installed.InstallationID) {
				t.Fatal("invalid fixture directory")
			}
			if missing {
				err = base.RemoveAll(installed.InstallationID)
			} else {
				err = base.WriteFile(installed.InstallationID+"/manifest.json", []byte("{}"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			input := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "1"})
			if _, err = h.Handle(ctx, "bitwarden-installation-plan", input); err == nil {
				t.Fatal("unchecked package admitted")
			}
			raw, err := h.Handle(ctx, "bitwarden-installation-revision", input)
			if err != nil || string(raw) != `{"workspaceId":"`+workspace+`","revision":"1"}` {
				t.Fatal(string(raw), err)
			}
			for _, q := range []map[string]any{{"workspaceId": workspace, "minimumRevision": "2"}, {"workspaceId": uuid.NewString(), "minimumRevision": "0"}, {"workspaceId": workspace, "minimumRevision": "0", "path": "untrusted"}} {
				if _, err = h.Handle(ctx, "bitwarden-installation-revision", browserTransferJSON(t, q)); err == nil {
					t.Fatal("invalid revision request")
				}
			}
			action["expectedRevision"] = "1"
			if _, err = h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, action)); err != nil {
				t.Fatal("repair denied", err)
			}
			if _, err = h.Handle(ctx, "bitwarden-installation-plan", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "2"})); err != nil {
				t.Fatal("repaired package unavailable", err)
			}
		})
	}
}
